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

# Number of parallel tshark workers — tune based on CPU cores and I/O
_NUM_WORKERS = int(os.getenv("PCAP_THREADS", "8"))


# Max records to collect per artefact type (across all PCAPs)
_MAX = {
    "dns": 5_000,
    "http": 2_000,
    "tls": 5_000,
    "smb": 2_000,
    "rdp": 1_000,
}

# Max IPs to put in a tshark display filter (keep it reasonable)
_MAX_FILTER_IPS = 50


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

    # Build display-filter IP clause — prioritize external IPs (exfil targets,
    # C2 servers) then add internal IPs up to the limit.
    _rfc1918 = [ipaddress.ip_network(c, strict=False)
                for c in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
    external = sorted(ip for ip in target_ips
                      if not any(ipaddress.ip_address(ip) in net for net in _rfc1918))
    internal = sorted(ip for ip in target_ips if ip not in set(external))
    priority_ips = external[:_MAX_FILTER_IPS] + internal[:max(0, _MAX_FILTER_IPS - len(external))]
    ip_clause = _build_ip_clause(priority_ips)

    # For TLS and HTTP, use a broader or no-IP filter since these are low-volume
    # protocols and the exfil destination may not be in our IOC list.
    ip_clause_broad = _build_ip_clause(priority_ips) if len(priority_ips) > 0 else "ip"

    results: Dict[str, Any] = {
        "pcaps_analyzed": to_analyze,
        "dns_queries": [],
        "http_requests": [],
        "tls_sessions": [],
        "smb_sessions": [],
        "rdp_sessions": [],
        "errors": [],
    }

    # Thread-safe lock for appending to shared results lists
    results_lock = Lock()
    completed_count = [0]  # mutable counter for progress

    def _process_one_pcap(pcap: str) -> None:
        """Process a single PCAP through all 5 extractors (runs in thread)."""
        pcap_name = Path(pcap).name
        # Each thread collects its own local results, then merges under lock
        local: Dict[str, list] = {
            "dns_queries": [], "http_requests": [], "tls_sessions": [],
            "smb_sessions": [], "rdp_sessions": [], "errors": [],
        }

        _extract_dns(tshark_bin, pcap, pcap_name, ip_clause, local)
        _extract_http(tshark_bin, pcap, pcap_name, "ip", local)
        _extract_tls(tshark_bin, pcap, pcap_name, "ip", local)
        _extract_smb(tshark_bin, pcap, pcap_name, ip_clause, local)
        _extract_rdp(tshark_bin, pcap, pcap_name, ip_clause, local)

        _KEY_TO_MAX = {
            "dns_queries": "dns", "http_requests": "http", "tls_sessions": "tls",
            "smb_sessions": "smb", "rdp_sessions": "rdp",
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
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        rows = []
        for line in proc.stdout.splitlines():
            rows.append(line.split("\t"))
        return rows
    except (subprocess.TimeoutExpired, OSError) as exc:
        return []


def _g(row: List[str], idx: int, default: str = "") -> str:
    try:
        v = row[idx].strip()
        return v if v else default
    except IndexError:
        return default


def _extract_dns(tshark: str, pcap: str, pcap_name: str, ip_clause: str, out: dict) -> None:
    flt = f"dns && ({ip_clause})"
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
        "http.request_number",
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
        if key in seen_sni:
            continue
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


def _extract_smb(tshark: str, pcap: str, pcap_name: str, ip_clause: str, out: dict) -> None:
    flt = f"(smb || smb2) && ({ip_clause})"
    fields = [
        "frame.time_epoch", "ip.src", "ip.dst",
        "smb.cmd", "smb2.cmd",
        "smb.file", "smb2.filename",
        "smb2.tree",
    ]
    for row in _tshark(tshark, pcap, flt, fields):
        if len(out["smb_sessions"]) >= _MAX["smb"]:
            break
        out["smb_sessions"].append({
            "ts": _g(row, 0),
            "src_ip": _g(row, 1),
            "dst_ip": _g(row, 2),
            "smb_cmd": _g(row, 3),
            "smb2_cmd": _g(row, 4),
            "filename": _g(row, 6) or _g(row, 5),
            "tree": _g(row, 7),
            "source_pcap": pcap_name,
        })


def _extract_rdp(tshark: str, pcap: str, pcap_name: str, ip_clause: str, out: dict) -> None:
    flt = f"tcp.port == 3389 && ({ip_clause})"
    fields = [
        "frame.time_epoch", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport",
        "rdp.cookie",          # RDP cookie reveals attempted username
        "rdp.neg_length",
    ]
    seen: Set[tuple] = set()
    for row in _tshark(tshark, pcap, flt, fields):
        if len(out["rdp_sessions"]) >= _MAX["rdp"]:
            break
        src = _g(row, 1)
        dst = _g(row, 2)
        cookie = _g(row, 5)
        key = (src, dst)
        if key in seen:
            # Update cookie if we find one for an existing pair
            if cookie:
                for sess in out["rdp_sessions"]:
                    if sess["src_ip"] == src and sess["dst_ip"] == dst and not sess.get("cookie"):
                        sess["cookie"] = cookie
                        break
            continue
        seen.add(key)
        out["rdp_sessions"].append({
            "ts": _g(row, 0),
            "src_ip": src,
            "dst_ip": dst,
            "src_port": _g(row, 3),
            "dst_port": _g(row, 4),
            "cookie": cookie,
            "source_pcap": pcap_name,
        })
