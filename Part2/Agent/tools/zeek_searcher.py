"""
Phase 2 – Zeek JSON correlation.

Performance-critical path: the Zeek file is up to 31 GB with ~14 M lines.
Parsing every line with Python's json.loads() would take hours.

Strategy
--------
1.  Write all IOC identifiers (community IDs + quoted IP strings) to a
    temporary pattern file.
2.  Hand that file to `grep -F -f` (or `rg -F -f` if ripgrep is available).
    Both tools use the Aho-Corasick algorithm and scan at I/O speed in C —
    filtering 31 GB down to a few MB of matching lines in ~30 seconds.
3.  Stream grep's stdout into Python and call json.loads() ONLY on the
    already-filtered lines (~tens of thousands, not 14 million).
4.  One final Python-side check verifies the match is not a grep false
    positive before storing.

IPs are written as "x.x.x.x" (with surrounding double-quotes) so that
grep does not substring-match e.g. "10.1.1.1" inside "10.1.1.10".

Fallback
--------
If neither grep nor rg is found in PATH, we fall back to the slow Python
streaming reader (works but may take hours on the full file).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

MAX_PER_PROTOCOL = 500_000
_KNOWN_PROTOCOLS = ("conn", "connection", "dns", "ssl", "http", "dce_rpc", "rdp", "smb", "smb_mapping", "smb_files", "weird", "files", "x509", "kerberos", "dhcp", "notice")

# Substrings that pull Zeek lines via grep even when neither IP is in the Suricata IOC set
# (e.g. workstation→resolver DNS for temp.sh). Python verification still applies below.
_EXFIL_GREP_MARKERS = (
    "temp.sh", "file.io", "transfer.sh", "anonfiles", "gofile",
    "filetransfer.io", "we.tl", "mega.nz",
)

_EMPTY_RECORDS = lambda: {p: [] for p in list(_KNOWN_PROTOCOLS) + ["other"]}  # noqa: E731


# --------------------------------------------------------------------------- #
# Record normalisation
# --------------------------------------------------------------------------- #

def normalize_zeek_record(raw: dict) -> dict:
    """
    Flatten an Elastic/Filebeat-wrapped Zeek record to a consistent structure.
    All downstream analysis tools use this format.
    """
    src = raw.get("source", {})
    dst = raw.get("destination", {})
    net = raw.get("network", {})
    zeek = raw.get("zeek", {})

    return {
        "ts": raw.get("@timestamp", ""),
        "src_ip": src.get("ip", ""),
        "src_port": src.get("port", 0),
        "dst_ip": dst.get("ip", ""),
        "dst_port": dst.get("port", 0),
        "protocol": net.get("protocol", ""),
        "transport": net.get("transport", ""),
        "direction": net.get("direction", ""),
        "community_id": net.get("community_id", ""),
        "session_id": zeek.get("session_id", ""),
        "log_type": raw.get("fileset", {}).get("name", ""),
        # Protocol-specific nested blobs for downstream consumers
        "dns": raw.get("dns", {}),
        "url": raw.get("url", {}),
        "tls": raw.get("tls", {}),
        "zeek_detail": zeek,
        # Geo / ASN enrichment (empty for internal traffic)
        "src_geo": src.get("geo", {}),
        "dst_geo": dst.get("geo", {}),
        "src_as": src.get("as", {}),
        "dst_as": dst.get("as", {}),
    }


# --------------------------------------------------------------------------- #
# Pattern file builder
# --------------------------------------------------------------------------- #

def _write_pattern_file(ioc_ips: Set[str], ioc_community_ids: Set[str]) -> str:
    """
    Write all IOC patterns to a temp file and return its path.

    Community IDs are used verbatim.
    IPs are wrapped in double-quotes (e.g. "10.1.2.3") so grep's fixed-string
    match cannot match "10.1.2.30" as a false positive.
    """
    fd, path = tempfile.mkstemp(suffix=".txt", prefix="zeek_ioc_")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        for cid in sorted(ioc_community_ids):
            if cid:
                fh.write(cid + "\n")
        for ip in sorted(ioc_ips):
            if ip:
                fh.write(f'"{ip}"\n')
        for marker in _EXFIL_GREP_MARKERS:
            fh.write(marker + "\n")
    return path


def _record_has_exfil_network_marker(rec: dict) -> bool:
    """True if DNS question, TLS SNI, or HTTP host/URI references a known exfil domain."""
    def _hit(s: str) -> bool:
        sl = (s or "").lower()
        return any(m in sl for m in _EXFIL_GREP_MARKERS)

    dns = rec.get("dns", {}) or {}
    q = dns.get("question")
    if isinstance(q, dict) and _hit(q.get("name", "")):
        return True
    if isinstance(dns.get("query"), str) and _hit(dns["query"]):
        return True

    tls = rec.get("tls", {}) or {}
    if _hit(tls.get("server_name", "")):
        return True
    zeek = rec.get("zeek", {}) or {}
    sslz = zeek.get("ssl", {}) if isinstance(zeek, dict) else {}
    if isinstance(sslz, dict) and _hit(sslz.get("server_name", "")):
        return True

    url = rec.get("url", {}) or {}
    if _hit(str(url.get("domain", ""))) or _hit(str(url.get("original", ""))):
        return True

    return False


# --------------------------------------------------------------------------- #
# Core processor shared by both grep-backed and Python-fallback paths
# --------------------------------------------------------------------------- #

def _process_lines(
    line_iter,
    ioc_ips: Set[str],
    ioc_community_ids: Set[str],
    progress_cb: Optional[Callable[[int, int], None]],
    progress_interval: int,
) -> Dict[str, Any]:
    import random
    records: Dict[str, List[dict]] = _EMPTY_RECORDS()
    # Protected records: exfil-related records that must NEVER be dropped
    # by reservoir sampling.  These are rare (tens of records) but critical
    # for exfiltration quantification (temp.sh DNS, TLS sessions, etc.).
    protected: Dict[str, List[dict]] = _EMPTY_RECORDS()
    # Track how many matched records we've seen per bucket (for reservoir sampling)
    bucket_seen: Dict[str, int] = {k: 0 for k in records}
    scanned = matched = 0

    # Known exfil destination IPs — records involving these are protected
    _EXFIL_IPS = {
        "51.91.79.17", "65.22.162.9", "65.22.160.9",   # temp.sh
        "144.76.136.153", "144.76.136.154",             # file.io
        "95.216.22.32",                                  # transfer.sh
    }

    # Beachhead IPs — external connections TO/FROM these are protected from
    # sampling because they contain attacker RDP sessions, return sessions,
    # and other critical initial-access / deployment evidence.
    from case_brief import CASE_BEACHHEAD_IPS
    _BEACHHEAD_IPS = set(CASE_BEACHHEAD_IPS)

    # Fast external-IP check using string prefixes instead of ipaddress module.
    # ipaddress.ip_address() on every record (9M+) was causing OOM/hang.
    _INTERNAL_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                          "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                          "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                          "172.30.", "172.31.", "192.168.", "127.", "0.")
    def _is_external_ip(ip: str) -> bool:
        return bool(ip) and not ip.startswith(_INTERNAL_PREFIXES)

    MAX_PROTECTED_PER_BUCKET = 10_000  # safety cap on protected records

    for raw_line in line_iter:
        # Handle both bytes (binary Popen stdout) and str (text fallback)
        if isinstance(raw_line, bytes):
            raw_line = raw_line.decode("utf-8", errors="replace")
        raw_line = raw_line.strip()
        if not raw_line:
            continue

        scanned += 1
        if progress_cb and scanned % progress_interval == 0:
            progress_cb(scanned, matched)

        try:
            rec = json.loads(raw_line)
        except json.JSONDecodeError:
            continue

        src_ip = rec.get("source", {}).get("ip", "")
        dst_ip = rec.get("destination", {}).get("ip", "")
        cid = rec.get("network", {}).get("community_id", "")

        is_exfil_marker = _record_has_exfil_network_marker(rec)

        # Exact Python-side verification eliminates any grep false positives.
        # Also keep DNS/TLS/HTTP rows that only match on exfil hostnames (no IOC IP on the line).
        if not (
            (src_ip and src_ip in ioc_ips)
            or (dst_ip and dst_ip in ioc_ips)
            or (cid and cid in ioc_community_ids)
            or is_exfil_marker
        ):
            continue

        matched += 1
        log_type = rec.get("fileset", {}).get("name", "other")
        bucket = log_type if log_type in records else "other"

        normalized = normalize_zeek_record(rec)

        # Protect rare but critical records from reservoir sampling:
        # 1. Exfil-related: DNS/TLS/HTTP for temp.sh etc., conn to exfil IPs
        # 2. Beachhead-external RDP/SSL: external sessions to beachhead carry
        #    attacker cookies, return sessions, etc. — conn records are too
        #    numerous (52K+ spray) so only protect rdp/ssl/kerberos log types.
        is_exfil_ip = (src_ip in _EXFIL_IPS or dst_ip in _EXFIL_IPS)
        is_beachhead_external = False
        if _BEACHHEAD_IPS and bucket in ("rdp", "ssl", "kerberos"):
            # Protect ALL external rdp/ssl/kerberos records involving beachhead
            if src_ip in _BEACHHEAD_IPS and _is_external_ip(dst_ip):
                is_beachhead_external = True
            elif dst_ip in _BEACHHEAD_IPS and _is_external_ip(src_ip):
                is_beachhead_external = True
        elif _BEACHHEAD_IPS and bucket in ("conn", "connection"):
            # For conn: only protect external connections on RDP port (3389)
            # to avoid protecting millions of C2/DNS conn records
            dst_port = rec.get("destination", {}).get("port", 0)
            if dst_ip in _BEACHHEAD_IPS and dst_port == 3389 and _is_external_ip(src_ip):
                is_beachhead_external = True
        if is_exfil_marker or is_exfil_ip or is_beachhead_external:
            if len(protected[bucket]) < MAX_PROTECTED_PER_BUCKET:
                protected[bucket].append(normalized)
            continue  # don't count toward reservoir sampling budget

        bucket_seen[bucket] += 1
        n = bucket_seen[bucket]

        if n <= MAX_PER_PROTOCOL:
            # Haven't hit the cap yet — just append
            records[bucket].append(normalized)
        else:
            # Reservoir sampling: randomly replace an existing record.
            # This ensures records from ALL time periods (including late-stage
            # March 6-8 activity) have an equal chance of being in the sample.
            j = random.randint(0, n - 1)
            if j < MAX_PER_PROTOCOL:
                records[bucket][j] = normalized

    # Merge protected records back into the main buckets (they bypass the cap)
    for bucket in records:
        records[bucket].extend(protected[bucket])

    # Sort each bucket by timestamp so the DB has chronological order
    for bucket in records:
        if records[bucket]:
            records[bucket].sort(key=lambda r: r.get("ts", ""))

    return {"scanned": scanned, "matched": matched, "records": records}


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def search_zeek(
    zeek_json_path: str,
    ioc_ips: Set[str],
    ioc_community_ids: Set[str],
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> Dict[str, Any]:
    """
    Search the Zeek JSON file for records matching the IOC sets.

    Uses grep/rg for high-speed pre-filtering (Aho-Corasick, C-speed).
    Falls back to Python line-by-line reading if neither tool is available.

    Parameters
    ----------
    zeek_json_path    : path to the large Zeek JSON file
    ioc_ips           : set of suspicious IP addresses
    ioc_community_ids : set of community IDs from alerts
    progress_cb       : optional callable(lines_processed, lines_matched)

    Returns
    -------
    {"scanned": int, "matched": int, "records": {protocol: [...]}}
    """
    path = Path(zeek_json_path)
    if not path.exists():
        return {
            "error": f"Zeek file not found: {zeek_json_path}",
            "scanned": 0,
            "matched": 0,
            "records": _EMPTY_RECORDS(),
        }

    if not ioc_ips and not ioc_community_ids:
        return {"scanned": 0, "matched": 0, "records": _EMPTY_RECORDS()}

    # ── grep / rg fast path ───────────────────────────────────────────────────
    grep_bin = shutil.which("rg") or shutil.which("grep")

    if grep_bin:
        pattern_file = _write_pattern_file(ioc_ips, ioc_community_ids)
        try:
            use_rg = Path(grep_bin).name == "rg"
            if use_rg:
                cmd = [grep_bin, "--fixed-strings", "-f", pattern_file,
                       "--no-filename", "--no-line-number", str(path)]
            else:
                # grep -F: fixed strings, -f: pattern file
                cmd = [grep_bin, "-F", "-f", pattern_file, str(path)]

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                bufsize=1 << 20,   # 1 MB read buffer
            )

            result = _process_lines(
                proc.stdout,
                ioc_ips,
                ioc_community_ids,
                progress_cb,
                progress_interval=50_000,   # grep output is already filtered
            )
            rc = proc.wait()
            if rc == 2:
                import warnings
                warnings.warn(f"grep/rg returned exit code 2 (error) — results may be incomplete", RuntimeWarning)
            return result

        finally:
            try:
                os.unlink(pattern_file)
            except OSError:
                pass

    # ── Python fallback (slow – use only if grep/rg unavailable) ─────────────
    import warnings
    warnings.warn(
        "Neither 'rg' nor 'grep' found in PATH. "
        "Falling back to slow Python streaming — this may take hours on large files.",
        RuntimeWarning,
        stacklevel=2,
    )

    with path.open("r", encoding="utf-8", errors="replace") as fh:
        return _process_lines(
            fh,
            ioc_ips,
            ioc_community_ids,
            progress_cb,
            progress_interval=500_000,
        )
