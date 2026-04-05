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

import subprocess
import shutil
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set


# Max records to collect per artefact type (across all PCAPs)
_MAX = {
    "dns": 5_000,
    "http": 2_000,
    "tls": 5_000,
    "smb": 2_000,
    "rdp": 1_000,
}


def analyze_targeted_pcaps(
    pcap_paths: List[str],
    target_ips: Set[str],
    work_dir: str,
    max_pcaps: int = 25,
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

    # Build display-filter IP clause (limit to 20 IPs to keep filter short)
    ip_clause = _build_ip_clause(sorted(target_ips)[:20])

    results: Dict[str, Any] = {
        "pcaps_analyzed": to_analyze,
        "dns_queries": [],
        "http_requests": [],
        "tls_sessions": [],
        "smb_sessions": [],
        "rdp_sessions": [],
        "errors": [],
    }

    for idx, pcap in enumerate(to_analyze):
        pcap_name = Path(pcap).name
        if progress_cb:
            progress_cb(idx, len(to_analyze), pcap_name)

        if len(results["dns_queries"]) < _MAX["dns"]:
            _extract_dns(tshark_bin, pcap, pcap_name, ip_clause, results)
        if len(results["http_requests"]) < _MAX["http"]:
            _extract_http(tshark_bin, pcap, pcap_name, ip_clause, results)
        if len(results["tls_sessions"]) < _MAX["tls"]:
            _extract_tls(tshark_bin, pcap, pcap_name, ip_clause, results)
        if len(results["smb_sessions"]) < _MAX["smb"]:
            _extract_smb(tshark_bin, pcap, pcap_name, ip_clause, results)
        if len(results["rdp_sessions"]) < _MAX["rdp"]:
            _extract_rdp(tshark_bin, pcap, pcap_name, ip_clause, results)

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
    fields = ["frame.time_epoch", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport"]
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
        out["rdp_sessions"].append({
            "ts": _g(row, 0),
            "src_ip": src,
            "dst_ip": dst,
            "src_port": _g(row, 3),
            "dst_port": _g(row, 4),
            "source_pcap": pcap_name,
        })
