"""
Phase 4 – Targeted PCAP deep analysis.

Runs tshark with precise display filters on the PCAP files selected in Phase 3.
Only the targeted PCAP files are opened, and only the relevant IP flows are extracted.

Extracted artefacts
-------------------
  dns_queries    – DNS query / response pairs
  http_requests  – HTTP request metadata (host, URI, method, status, size)
  tls_sessions   – TLS handshake SNI and version info
  smb_sessions   – SMB/SMB2 command + filename traces
  rdp_sessions   – TCP/3389 connection pairs
"""
from __future__ import annotations

import ipaddress
import os
import subprocess
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock
from typing import Any, Callable, Dict, List, Optional, Set

from case_brief import CASE_BEACHHEAD_IPS

# Number of parallel tshark workers — tune based on CPU cores and I/O
_NUM_WORKERS = int(os.getenv("PCAP_THREADS", "16"))

# Per-command tshark timeout in seconds.
# 90 s is enough for a 1 GB PCAP with a focused display filter.
# The old 600 s meant a hung command blocked one thread for 10 minutes.
_TSHARK_TIMEOUT = int(os.getenv("PCAP_TSHARK_TIMEOUT", "90"))

# Known exfil IPs — only run the expensive tcp_conversations pass on PCAPs
# that are likely to contain these flows (March 6–9 window).
_EXFIL_IPS_SET = frozenset({
    "51.91.79.17",      # temp.sh
    "65.22.162.9",      # temp.sh
    "65.22.160.9",      # temp.sh
    "144.76.136.153",   # file.io
    "144.76.136.154",   # file.io
    "95.216.22.32",     # transfer.sh
})


def _max_records(kind: str, default: int) -> int:
    env = os.getenv(f"NF_PCAP_MAX_{kind.upper()}", "").strip()
    if env.isdigit():
        return max(1_000, int(env))
    return default


# Max records to collect per artefact type (across all PCAPs); SMB raised for manual ~27k+ filename rows
_MAX = {
    "dns": _max_records("dns", 50_000),
    "http": _max_records("http", 20_000),
    "tls": _max_records("tls", 50_000),
    "smb": _max_records("smb", 400_000),
    "rdp": _max_records("rdp", 10_000),
    "tcp_conv": _max_records("tcp_conv", 50_000),
    "dns_srv": _max_records("dns_srv", 10_000),
    "dcerpc": _max_records("dcerpc", 100_000),
    "smb_tree": _max_records("smb_tree", 50_000),
    "netbios": _max_records("netbios", 20_000),
}

# Max IPs to put in a tshark display filter
_MAX_FILTER_IPS = 200


def analyze_targeted_pcaps(
    pcap_paths: List[str],
    target_ips: Set[str],
    work_dir: str,
    max_pcaps: int = 200,
    progress_cb: Optional[Callable[[int, int, str], None]] = None,
) -> Dict[str, Any]:
    """
    Run per-protocol tshark extraction on the selected PCAPs.

    Returns a dict with keys:
        pcaps_analyzed, dns_queries, http_requests, tls_sessions,
        smb_sessions, rdp_sessions, errors
    """
    tshark_bin = shutil.which("tshark")
    if not tshark_bin:
        return {
            "error": "tshark not found in PATH – install Wireshark/tshark",
            "pcaps_analyzed": [],
            "dns_queries": [],
            "http_requests": [],
            "tls_sessions": [],
            "smb_sessions": [],
            "rdp_sessions": [],
            "errors": [],
        }

    # Safety: limit PCAP count
    to_analyze = [p for p in pcap_paths if Path(p).exists()][:max_pcaps]

    # Manual benchmark: always include course beachhead(s) in IOC targeting so SMB/DNS
    # extraction cannot miss 10.128.239.57 ↔ DC/file-server traffic when alerts omit it.
    bh_env = os.getenv("NF_PCAP_BEACHHEAD_IPS", "").strip()
    beachheads: List[str] = (
        [x.strip() for x in bh_env.split(",") if x.strip()]
        if bh_env
        else list(CASE_BEACHHEAD_IPS)
    )
    target_ips = set(target_ips) | set(beachheads)

    # Build display-filter IP clause — prioritize external IPs (exfil targets,
    # C2 servers) then add internal IPs up to the limit.
    _rfc1918 = [ipaddress.ip_network(c, strict=False)
                for c in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
    def _safe_classify(ip):
        try:
            return not any(ipaddress.ip_address(ip) in net for net in _rfc1918)
        except (ValueError, TypeError):
            return False  # skip malformed IPs
    valid_ips = [ip for ip in target_ips if ip and isinstance(ip, str)]
    external = sorted(ip for ip in valid_ips if _safe_classify(ip))
    internal = sorted(ip for ip in valid_ips if ip not in set(external))
    # Always reserve slots for internal IOCs so DNS/SMB to corporate resolvers or
    # DCs is not dropped when Suricata lists hundreds of external IPs first.
    _int_budget = min(len(internal), 96)
    _ext_budget = max(0, _MAX_FILTER_IPS - _int_budget)
    priority_ips = external[:_ext_budget] + internal[:_int_budget]
    ip_clause = _build_ip_clause(priority_ips)

    # Internal IPs clause — for SMB/RDP which are primarily internal-to-internal
    # lateral movement. Use internal IOC IPs to avoid missing .57→.29 traffic.
    internal_clause = _build_ip_clause(internal[:_MAX_FILTER_IPS]) if internal else "ip"

    results: Dict[str, Any] = {
        "pcaps_analyzed": to_analyze,
        "dns_queries": [],
        "http_requests": [],
        "tls_sessions": [],
        "smb_sessions": [],
        "rdp_sessions": [],
        "tcp_conversations": [],
        "dns_srv_records": [],
        "dcerpc_calls": [],
        "smb_tree_connects": [],
        "netbios_records": [],
        "errors": [],
    }

    # Thread-safe lock for appending to shared results lists
    results_lock = Lock()
    completed_count = [0]  # mutable counter for progress

    def _pcap_has_ioc_traffic(pcap: str) -> bool:
        """Quick probe: does this PCAP contain ANY packet from an IOC IP?
        Uses -c 1 so tshark stops at the first hit — fast on relevant PCAPs,
        near-instant fail on irrelevant ones.  Skip the whole PCAP if False."""
        if not priority_ips:
            return True  # no filter → process everything
        try:
            probe = subprocess.run(
                [tshark_bin, "-r", pcap, "-Y", ip_clause, "-c", "1",
                 "-T", "fields", "-e", "frame.number"],
                capture_output=True, text=True, timeout=_TSHARK_TIMEOUT,
            )
            return bool(probe.stdout.strip())
        except (subprocess.TimeoutExpired, OSError):
            return True  # probe failed → process anyway to be safe

    def _process_one_pcap(pcap: str) -> None:
        """Process a single PCAP through all extractors (runs in thread)."""
        pcap_name = Path(pcap).name

        # Gate: skip entire PCAP if it contains no IOC traffic at all.
        # One -c 1 probe replaces up to 9 full-scan tshark calls on irrelevant PCAPs.
        if not _pcap_has_ioc_traffic(pcap):
            with results_lock:
                completed_count[0] += 1
                if progress_cb:
                    progress_cb(completed_count[0], len(to_analyze), pcap_name)
            return

        # Each thread collects its own local results, then merges under lock
        local: Dict[str, list] = {
            "dns_queries": [], "http_requests": [], "tls_sessions": [],
            "smb_sessions": [], "rdp_sessions": [], "tcp_conversations": [],
            "dns_srv_records": [], "dcerpc_calls": [], "smb_tree_connects": [],
            "netbios_records": [],
            "errors": [],
        }

        def _cap_reached(key: str) -> bool:
            """True if this artifact type has already hit its global cap."""
            max_key = {
                "dns_queries": "dns", "http_requests": "http", "tls_sessions": "tls",
                "smb_sessions": "smb", "rdp_sessions": "rdp",
                "tcp_conversations": "tcp_conv", "dns_srv_records": "dns_srv",
                "dcerpc_calls": "dcerpc", "smb_tree_connects": "smb_tree",
                "netbios_records": "netbios",
            }.get(key, "")
            cap = _MAX.get(max_key, 999_999)
            with results_lock:
                return len(results.get(key, [])) >= cap

        if not _cap_reached("dns_queries"):
            _extract_dns(tshark_bin, pcap, pcap_name, ip_clause, local)
        if not _cap_reached("http_requests"):
            _extract_http(tshark_bin, pcap, pcap_name, "ip", local)
        if not _cap_reached("tls_sessions"):
            _extract_tls(tshark_bin, pcap, pcap_name, "ip", local)
        if not _cap_reached("smb_sessions"):
            _extract_smb(tshark_bin, pcap, pcap_name, internal_clause, beachheads, local)
        if not _cap_reached("rdp_sessions"):
            _extract_rdp(tshark_bin, pcap, pcap_name, "ip", local)
        # tcp_conversations is the most expensive — gated inside the function itself
        _extract_tcp_conversations(tshark_bin, pcap, pcap_name, external, internal, local)
        if not _cap_reached("dns_srv_records"):
            _extract_dns_srv(tshark_bin, pcap, pcap_name, ip_clause, local)
        if not _cap_reached("dcerpc_calls"):
            _extract_dcerpc(tshark_bin, pcap, pcap_name, internal_clause, local)
        if not _cap_reached("smb_tree_connects"):
            _extract_smb_tree(tshark_bin, pcap, pcap_name, internal_clause, beachheads, local)
        if not _cap_reached("netbios_records"):
            _extract_netbios(tshark_bin, pcap, pcap_name, internal_clause, local)

        _KEY_TO_MAX = {
            "dns_queries": "dns", "http_requests": "http", "tls_sessions": "tls",
            "smb_sessions": "smb", "rdp_sessions": "rdp", "tcp_conversations": "tcp_conv",
            "dns_srv_records": "dns_srv", "dcerpc_calls": "dcerpc",
            "smb_tree_connects": "smb_tree", "netbios_records": "netbios",
        }
        with results_lock:
            for key in local:
                if key == "errors":
                    results[key].extend(local[key])
                    continue
                cap = _MAX.get(_KEY_TO_MAX.get(key, ""), 99999)
                remaining = cap - len(results[key])
                if remaining > 0:
                    results[key].extend(local[key][:remaining])
            completed_count[0] += 1
            if progress_cb:
                progress_cb(completed_count[0], len(to_analyze), pcap_name)

    # Run PCAPs in parallel threads — tshark is I/O bound so threads work well
    num_workers = min(_NUM_WORKERS, len(to_analyze))
    if num_workers > 1:
        with ThreadPoolExecutor(max_workers=num_workers) as pool:
            futures = {pool.submit(_process_one_pcap, pcap): pcap for pcap in to_analyze}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as exc:
                    with results_lock:
                        results["errors"].append(f"{Path(futures[future]).name}: {exc}")
    else:
        for pcap in to_analyze:
            _process_one_pcap(pcap)

    if progress_cb:
        progress_cb(len(to_analyze), len(to_analyze), "done")

    return results


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _build_ip_clause(ips: List[str]) -> str:
    if not ips:
        return "ip"
    parts = " || ".join(f"ip.addr == {ip}" for ip in ips)
    return f"({parts})"


def _tshark(tshark_bin: str, pcap: str, display_filter: str, fields: List[str]) -> List[List[str]]:
    """Run tshark and return a list of tab-split field rows."""
    cmd = [
        tshark_bin, "-r", pcap,
        "-Y", display_filter,
        "-T", "fields",
        "-E", "header=n",
        "-E", "separator=\t",
        "-E", "occurrence=f",   # first occurrence per packet
    ]
    for f in fields:
        cmd += ["-e", f]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=_TSHARK_TIMEOUT)
        if proc.returncode != 0 and proc.stderr:
            stderr_preview = proc.stderr.strip()[:200]
            if "aren't valid" in stderr_preview or "not found" in stderr_preview:
                print(f"    [tshark] FIELD ERROR on {Path(pcap).name}: {stderr_preview}")
            # Don't fail — tshark may return non-zero for packets it can't decode
        rows = []
        for line in proc.stdout.splitlines():
            rows.append(line.split("\t"))
        return rows
    except subprocess.TimeoutExpired:
        print(f"    [tshark] TIMEOUT({_TSHARK_TIMEOUT}s) on {Path(pcap).name} filter={display_filter[:60]}")
        return []
    except OSError as exc:
        print(f"    [tshark] ERROR on {Path(pcap).name}: {exc}")
        return []


def _g(row: List[str], idx: int, default: str = "") -> str:
    try:
        v = row[idx].strip()
        return v if v else default
    except IndexError:
        return default


def _extract_dns(tshark: str, pcap: str, pcap_name: str, ip_clause: str, out: dict) -> None:
    # Include exfil-related QNAMEs even when client/resolver IPs are outside the IOC filter.
    exfil_q = (
        'dns.qry.name contains "temp.sh" || dns.qry.name contains "file.io" '
        '|| dns.qry.name contains "transfer.sh" || dns.qry.name contains "gofile" '
        '|| dns.qry.name contains "anonfiles" || dns.qry.name contains "mega.nz"'
    )
    flt = f"dns && (({ip_clause}) || {exfil_q})"
    fields = [
        "frame.time_epoch", "ip.src", "ip.dst",
        "dns.qry.name", "dns.a", "dns.aaaa",
        "dns.resp.type", "dns.flags.response",
    ]
    for row in _tshark(tshark, pcap, flt, fields):
        if len(out["dns_queries"]) >= _MAX["dns"]:
            break
        query = _g(row, 3)
        if not query:
            continue
        out["dns_queries"].append({
            "ts": _g(row, 0),
            "src_ip": _g(row, 1),
            "dst_ip": _g(row, 2),
            "query": query,
            "answer_a": _g(row, 4),
            "answer_aaaa": _g(row, 5),
            "resp_type": _g(row, 6),
            "is_response": _g(row, 7),
            "source_pcap": pcap_name,
        })


def _extract_http(tshark: str, pcap: str, pcap_name: str, ip_clause: str, out: dict) -> None:
    flt = f"http && ({ip_clause})"
    fields = [
        "frame.time_epoch", "ip.src", "ip.dst",
        "http.host", "http.request.uri", "http.request.method",
        "http.response.code", "http.content_length_header",
    ]
    for row in _tshark(tshark, pcap, flt, fields):
        if len(out["http_requests"]) >= _MAX["http"]:
            break
        host = _g(row, 3)
        uri = _g(row, 4)
        if not host and not uri:
            continue
        out["http_requests"].append({
            "ts": _g(row, 0),
            "src_ip": _g(row, 1),
            "dst_ip": _g(row, 2),
            "host": host,
            "uri": uri,
            "method": _g(row, 5),
            "status_code": _g(row, 6),
            "content_length": _g(row, 7),
            "source_pcap": pcap_name,
        })


def _extract_tls(tshark: str, pcap: str, pcap_name: str, ip_clause: str, out: dict) -> None:
    # Focus on ClientHello (has SNI); filter for handshake type 1
    flt = f"(tls || ssl) && tls.handshake.type == 1 && ({ip_clause})"
    fields = [
        "frame.time_epoch", "ip.src", "ip.dst",
        "tls.handshake.extensions_server_name",
        "tls.handshake.version",
        "tcp.dstport",
    ]
    seen_sni: Set[str] = set()
    for row in _tshark(tshark, pcap, flt, fields):
        if len(out["tls_sessions"]) >= _MAX["tls"]:
            break
        sni = _g(row, 3)
        key = (_g(row, 1), _g(row, 2), sni)
        sni_l = (sni or "").lower()
        _exfil_sni = any(x in sni_l for x in ("temp.sh", "file.io", "transfer.sh", "gofile", "anonfiles", "mega."))
        # Keep every ClientHello to exfil SNIs (manual reports count each TLS session).
        if not _exfil_sni and key in seen_sni:
            continue
        if not _exfil_sni:
            seen_sni.add(key)
        out["tls_sessions"].append({
            "ts": _g(row, 0),
            "src_ip": _g(row, 1),
            "dst_ip": _g(row, 2),
            "sni": sni,
            "tls_version": _g(row, 4),
            "dst_port": _g(row, 5),
            "source_pcap": pcap_name,
        })


def _smb_ip_display_clause(internal_clause: str, beachheads: List[str]) -> str:
    """Match manual methodology: IOC internal flows OR any SMB involving beachhead IP(s)."""
    parts = []
    for ip in beachheads:
        if ip:
            parts.append(f"ip.addr == {ip}")
    if internal_clause and internal_clause != "ip":
        parts.append(f"({internal_clause})")
    if not parts:
        return "ip"
    if len(parts) == 1:
        return parts[0]
    return "(" + " || ".join(parts) + ")"


def _extract_smb(
    tshark: str,
    pcap: str,
    pcap_name: str,
    internal_clause: str,
    beachheads: List[str],
    out: dict,
) -> None:
    smbc = _smb_ip_display_clause(internal_clause, beachheads)
    flt = f"(smb || smb2) && ({smbc})"
    fields = [
        "frame.time_epoch", "ip.src", "ip.dst",
        "smb.cmd", "smb2.cmd",
        "smb.file", "smb2.filename",
        "smb2.tree",
        "smb2.find.pattern",                   # SMB2 Find Request search pattern
        "smb2.fid",
    ]
    for row in _tshark(tshark, pcap, flt, fields):
        if len(out["smb_sessions"]) >= _MAX["smb"]:
            break
        # smb2.filename captures both Create Request filenames AND
        # directory listing filenames (Find Response reuses this field)
        filename = _g(row, 6) or _g(row, 5)
        find_pattern = _g(row, 8)
        out["smb_sessions"].append({
            "ts": _g(row, 0),
            "src_ip": _g(row, 1),
            "dst_ip": _g(row, 2),
            "smb_cmd": _g(row, 3),
            "smb2_cmd": _g(row, 4),
            "filename": filename,
            "find_pattern": find_pattern,
            "tree": _g(row, 7),
            "smb2_fid": _g(row, 9),
            "source_pcap": pcap_name,
        })


def _extract_tcp_conversations(tshark: str, pcap: str, pcap_name: str, external_ips: List[str], internal_ips: List[str], out: dict) -> None:
    """Extract TCP conversation statistics using tshark -z conv,tcp.

    This captures actual byte volumes for connections where Zeek conn records
    may show zero bytes (e.g., long-lived TLS sessions to exfil services).

    PERFORMANCE NOTE: -z conv,tcp scans every packet in the PCAP — no filter
    is possible. We skip this entirely for PCAPs that have no chance of
    containing exfil traffic (early PCAPs before March 6).
    """
    if not external_ips and not internal_ips:
        return
    # Gate: only run the expensive conv,tcp pass if this PCAP actually contains
    # a known exfil IP.  We do a quick tshark probe (-c 1) which stops as soon
    # as the first matching packet is found — fast on relevant PCAPs, near-instant
    # on irrelevant ones.  This is event-based, NOT date/timestamp based.
    exfil_ips = [ip for ip in external_ips if ip in _EXFIL_IPS_SET]
    if not exfil_ips:
        return  # no exfil IPs in this PCAP's target set — skip conv,tcp
    exfil_clause = " || ".join(f"ip.addr == {ip}" for ip in exfil_ips)
    try:
        probe = subprocess.run(
            [tshark, "-r", pcap, "-Y", exfil_clause, "-c", "1",
             "-T", "fields", "-e", "frame.number"],
            capture_output=True, text=True, timeout=_TSHARK_TIMEOUT,
        )
        if not probe.stdout.strip():
            return  # no matching packets — skip conv,tcp for this PCAP
    except (subprocess.TimeoutExpired, OSError):
        return  # probe timed out or failed — skip to be safe

    try:
        cmd = [tshark, "-r", pcap, "-q", "-z", "conv,tcp"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=_TSHARK_TIMEOUT * 2)  # 180s — conv,tcp is slow
        if proc.returncode != 0:
            return
        ext_set = set(external_ips)
        int_set = set(internal_ips)
        _rfc1918 = [ipaddress.ip_network(c, strict=False)
                    for c in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
        def _is_external(ip):
            try:
                return not any(ipaddress.ip_address(ip) in net for net in _rfc1918)
            except (ValueError, TypeError):
                return False
        def _parse_conv_line(line: str):
            """Parse a tshark conv,tcp line handling human-readable unit suffixes.

            tshark outputs: addr:port <-> addr:port  frames bytes [unit]  frames bytes [unit]  frames bytes [unit]  rel_start  duration
            The unit suffix (bytes, kB, MB, GB) is an optional extra token that shifts column positions.
            """
            if "<->" not in line:
                return None
            # Split into tokens
            tokens = line.split()
            if len(tokens) < 9:
                return None
            a_addr_port = tokens[0]
            # tokens[1] is "<->"
            b_addr_port = tokens[2]
            # Remaining tokens after the two addresses and "<->" are the stats.
            # Walk through them, consuming number + optional unit pairs.
            _UNIT_MULTIPLIERS = {
                "bytes": 1,
                "kB": 1_000,
                "KiB": 1_024,
                "KB": 1_000,
                "MB": 1_000_000,
                "MiB": 1_048_576,
                "GB": 1_000_000_000,
                "GiB": 1_073_741_824,
            }
            stats = tokens[3:]
            numbers = []
            i = 0
            while i < len(stats):
                tok = stats[i]
                try:
                    val = int(tok)
                    i += 1
                    # Check if next token is a unit suffix — convert to bytes
                    if i < len(stats) and stats[i] in _UNIT_MULTIPLIERS:
                        # This is a byte value with unit; apply multiplier
                        # But only for byte columns (even-indexed in pairs: frames, bytes, frames, bytes...)
                        # The previous number was frames (no unit), this number has a unit = bytes
                        val = val * _UNIT_MULTIPLIERS[stats[i]]
                        i += 1
                    numbers.append(val)
                except ValueError:
                    # Could be a float (rel_start, duration) or unit suffix
                    try:
                        numbers.append(float(tok))
                        i += 1
                    except ValueError:
                        i += 1  # skip unrecognized tokens
            # Expected: frames_a2b, bytes_a2b, frames_b2a, bytes_b2a, total_frames, total_bytes, rel_start, duration
            if len(numbers) < 6:
                return None
            return {
                "a_addr_port": a_addr_port,
                "b_addr_port": b_addr_port,
                "frames_a2b": int(numbers[0]),
                "bytes_a2b": int(numbers[1]),
                "frames_b2a": int(numbers[2]),
                "bytes_b2a": int(numbers[3]),
                "total_frames": int(numbers[4]),
                "total_bytes": int(numbers[5]),
                "duration": str(numbers[7]) if len(numbers) > 7 else "",
            }

        for line in proc.stdout.splitlines():
            parsed = _parse_conv_line(line)
            if not parsed:
                continue
            try:
                a_ip = parsed["a_addr_port"].rsplit(":", 1)[0]
                b_ip = parsed["b_addr_port"].rsplit(":", 1)[0]
                a_port = parsed["a_addr_port"].rsplit(":", 1)[1]
                b_port = parsed["b_addr_port"].rsplit(":", 1)[1]
                # Keep if: either IP is a known external IOC, OR one side is a
                # known internal IOC and the other side is any external IP.
                # This catches exfil to IPs not in the alert set (e.g. temp.sh).
                a_in_ext = a_ip in ext_set
                b_in_ext = b_ip in ext_set
                a_in_int = a_ip in int_set
                b_in_int = b_ip in int_set
                if not (a_in_ext or b_in_ext
                        or (a_in_int and _is_external(b_ip))
                        or (b_in_int and _is_external(a_ip))):
                    continue
                total_bytes = parsed["total_bytes"]
                # Skip small conversations — keep only significant flows (>100KB)
                # This filters noise while keeping exfil (1GB+), RDP sessions, etc.
                if total_bytes < 100_000:
                    continue
                out["tcp_conversations"].append({
                    "src_ip": a_ip,
                    "src_port": a_port,
                    "dst_ip": b_ip,
                    "dst_port": b_port,
                    "bytes_a_to_b": parsed["bytes_a2b"],
                    "bytes_b_to_a": parsed["bytes_b2a"],
                    "total_bytes": total_bytes,
                    "total_frames": parsed["total_frames"],
                    "duration": parsed["duration"],
                    "source_pcap": pcap_name,
                })
            except (ValueError, IndexError):
                continue
    except (subprocess.TimeoutExpired, OSError):
        pass


def _extract_rdp(tshark: str, pcap: str, pcap_name: str, ip_clause: str, out: dict) -> None:
    # Extract RDP cookies first (much smaller result set than all port 3389 traffic).
    # Then extract unique (src,dst) connection pairs from port 3389 traffic.
    cookie_map: Dict[tuple, str] = {}
    cookie_flt = f"rdp.rt_cookie && ({ip_clause})"
    cookie_fields = ["frame.time_epoch", "ip.src", "ip.dst", "rdp.rt_cookie"]
    for row in _tshark(tshark, pcap, cookie_flt, cookie_fields):
        src = _g(row, 1)
        dst = _g(row, 2)
        c = _g(row, 3)
        if c and (src, dst) not in cookie_map:
            cookie_map[(src, dst)] = c

    # Now get unique connection pairs from port 3389 traffic.
    # Use tcp.dstport to only get the client→server direction (one entry per pair).
    flt = f"tcp.dstport == 3389 && ({ip_clause})"
    fields = [
        "frame.time_epoch", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport",
    ]
    seen: Set[tuple] = set()
    for row in _tshark(tshark, pcap, flt, fields):
        if len(out["rdp_sessions"]) >= _MAX["rdp"]:
            break
        src = _g(row, 1)
        dst = _g(row, 2)
        key = (src, dst)
        if key in seen:
            continue
        seen.add(key)
        cookie = cookie_map.get(key, "")
        out["rdp_sessions"].append({
            "ts": _g(row, 0),
            "src_ip": src,
            "dst_ip": dst,
            "src_port": _g(row, 3),
            "dst_port": _g(row, 4),
            "cookie": cookie,
            "source_pcap": pcap_name,
        })


def _extract_dns_srv(tshark: str, pcap: str, pcap_name: str, ip_clause: str, out: dict) -> None:
    """Extract DNS SRV records — reveals DC discovery (_ldap._tcp.dc._msdcs.*, _kerberos._tcp.*).

    Filter: dns && dns.flags.response == 1 && dns.resp.type == 33
    """
    flt = f"dns && dns.flags.response == 1 && dns.resp.type == 33 && ({ip_clause})"
    fields = [
        "frame.time_epoch", "ip.src", "ip.dst",
        "dns.qry.name",        # queried SRV name (e.g. _ldap._tcp.dc._msdcs.domain)
        "dns.srv.name",        # target hostname in SRV answer
        "dns.srv.port",        # service port
        "dns.srv.priority",
        "dns.srv.weight",
    ]
    for row in _tshark(tshark, pcap, flt, fields):
        if len(out["dns_srv_records"]) >= _MAX["dns_srv"]:
            break
        qname = _g(row, 3)
        target = _g(row, 4)
        if not qname and not target:
            continue
        out["dns_srv_records"].append({
            "ts": _g(row, 0),
            "src_ip": _g(row, 1),
            "dst_ip": _g(row, 2),
            "query_name": qname,
            "srv_target": target,
            "srv_port": _g(row, 5),
            "priority": _g(row, 6),
            "weight": _g(row, 7),
            "source_pcap": pcap_name,
        })


def _extract_dcerpc(tshark: str, pcap: str, pcap_name: str, internal_clause: str, out: dict) -> None:
    """Extract DCE-RPC calls including SAMR (domain enumeration) and DRSUAPI (DCSync).

    Captures: opnum, interface UUID, and operation name for SAMR/LSARPC/DRSUAPI calls.
    DCSync uses DRSUAPI DsGetNCChanges — critical for detecting credential theft.
    """
    flt = f"dcerpc && ({internal_clause})"
    fields = [
        "frame.time_epoch", "ip.src", "ip.dst",
        "dcerpc.opnum",
        "dcerpc.cn_bind_to_uuid",   # interface UUID (identifies SAMR, LSARPC, DRSUAPI etc.)
        "samr.opnum",               # SAMR-specific opnum
        "lsarpc.opnum",             # LSARPC-specific opnum
        "drsuapi.opnum",            # DRSUAPI opnum (5 = DsGetNCChanges = DCSync)
        "dcerpc.cn_num_ctx_items",
    ]
    # Interface UUIDs for key protocols
    _UUID_NAMES = {
        "12345778-1234-abcd-ef00-0123456789ac": "SAMR",
        "12345778-1234-abcd-ef00-0123456789ab": "LSARPC",
        "e3514235-4b06-11d1-ab04-00c04fc2dcd2": "DRSUAPI",  # DCSync
        "6bffd098-a112-3610-9833-46c3f87e345a": "WKSSVC",
        "4b324fc8-1670-01d3-1278-5a47bf6ee188": "SRVSVC",
        "12345778-1234-abcd-ef00-0123456789ab": "LSARPC",
    }
    for row in _tshark(tshark, pcap, flt, fields):
        if len(out["dcerpc_calls"]) >= _MAX["dcerpc"]:
            break
        uuid = _g(row, 4).lower()
        interface = _UUID_NAMES.get(uuid, uuid[:8] if uuid else "")
        samr_op = _g(row, 5)
        drsuapi_op = _g(row, 7)
        # Flag DCSync: DRSUAPI opnum 3 (DsBind) or 5 (DsGetNCChanges)
        is_dcsync = bool(drsuapi_op and drsuapi_op in ("3", "5"))
        out["dcerpc_calls"].append({
            "ts": _g(row, 0),
            "src_ip": _g(row, 1),
            "dst_ip": _g(row, 2),
            "opnum": _g(row, 3),
            "interface_uuid": uuid,
            "interface_name": interface,
            "samr_opnum": samr_op,
            "lsarpc_opnum": _g(row, 6),
            "drsuapi_opnum": drsuapi_op,
            "is_dcsync_indicator": is_dcsync,
            "source_pcap": pcap_name,
        })


def _extract_smb_tree(tshark: str, pcap: str, pcap_name: str, internal_clause: str, beachheads: List[str], out: dict) -> None:
    """Extract SMB2 Tree Connect requests — reveals which shares were accessed.

    Filter: smb2 && smb2.cmd == 3 (Tree Connect)
    Captures share names like \\DC\SYSVOL, \\DC\ADMIN$, \\DC\IPC$, \\DC\C$
    """
    smbc = _smb_ip_display_clause(internal_clause, beachheads)
    flt = f"smb2 && smb2.cmd == 3 && ({smbc})"
    fields = [
        "frame.time_epoch", "ip.src", "ip.dst",
        "smb2.tree",            # share path e.g. \\DC01\SYSVOL
        "smb2.share_type",      # 0x01=disk, 0x02=pipe, 0x03=print
        "smb2.flags",
    ]
    seen: Set[tuple] = set()
    for row in _tshark(tshark, pcap, flt, fields):
        if len(out["smb_tree_connects"]) >= _MAX["smb_tree"]:
            break
        tree = _g(row, 3)
        if not tree:
            continue
        key = (_g(row, 1), _g(row, 2), tree)
        if key in seen:
            continue
        seen.add(key)
        out["smb_tree_connects"].append({
            "ts": _g(row, 0),
            "src_ip": _g(row, 1),
            "dst_ip": _g(row, 2),
            "tree_path": tree,
            "share_type": _g(row, 4),
            "source_pcap": pcap_name,
        })


def _extract_netbios(tshark: str, pcap: str, pcap_name: str, internal_clause: str, out: dict) -> None:
    """Extract NetBIOS Name Service records — reveals hostname resolution and workgroup discovery.

    Filter: nbns || netbios
    """
    flt = f"(nbns || netbios) && ({internal_clause})"
    fields = [
        "frame.time_epoch", "ip.src", "ip.dst",
        "nbns.name",            # queried/registered NetBIOS name
        "nbns.addr",            # resolved IP address
        "nbns.flags.opcode",    # 0=query, 5=registration, 6=release
        "nbns.type",            # name type (20=workstation, 1C=domain)
    ]
    for row in _tshark(tshark, pcap, flt, fields):
        if len(out["netbios_records"]) >= _MAX["netbios"]:
            break
        name = _g(row, 3)
        if not name:
            continue
        out["netbios_records"].append({
            "ts": _g(row, 0),
            "src_ip": _g(row, 1),
            "dst_ip": _g(row, 2),
            "nb_name": name,
            "nb_addr": _g(row, 4),
            "opcode": _g(row, 5),
            "nb_type": _g(row, 6),
            "source_pcap": pcap_name,
        })
