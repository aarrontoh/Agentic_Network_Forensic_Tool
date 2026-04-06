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

MAX_PER_PROTOCOL = 60_000
_KNOWN_PROTOCOLS = ("conn", "connection", "dns", "ssl", "http", "dce_rpc", "rdp", "smb", "smb_mapping", "smb_files", "weird", "files", "x509", "kerberos", "dhcp", "notice")

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
    return path


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
    records: Dict[str, List[dict]] = _EMPTY_RECORDS()
    bucket_full: Dict[str, bool] = {k: False for k in records}
    scanned = matched = 0

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

        # Exact Python-side verification eliminates any grep false positives
        if not (
            (src_ip and src_ip in ioc_ips)
            or (dst_ip and dst_ip in ioc_ips)
            or (cid and cid in ioc_community_ids)
        ):
            continue

        matched += 1
        log_type = rec.get("fileset", {}).get("name", "other")
        bucket = log_type if log_type in records else "other"

        if not bucket_full[bucket]:
            records[bucket].append(normalize_zeek_record(rec))
            if len(records[bucket]) >= MAX_PER_PROTOCOL:
                bucket_full[bucket] = True

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
            proc.wait()
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
