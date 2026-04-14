"""
Load the ingest pipeline's artifacts dict into the forensic SQLite database.

This bridges the existing 4-phase ingest pipeline with the multi-agent system:
the ingest pipeline produces in-memory lists/dicts, and this module inserts
them into queryable SQL tables.
"""
from __future__ import annotations

import os
import sqlite3
from typing import Any, Dict, List


_NUMERIC_COLUMNS = {
    "src_port", "dst_port", "severity", "duration", "orig_bytes", "resp_bytes",
    "status_code", "request_body_len", "response_body_len", "content_length",
    "bytes_a_to_b", "bytes_b_to_a", "total_bytes", "total_frames",
    "packet_count", "is_response",
}


def _bulk_insert(conn: sqlite3.Connection, table: str, rows: List[dict], columns: List[str]) -> int:
    """Insert rows into table, returning count inserted."""
    if not rows:
        return 0
    placeholders = ", ".join("?" for _ in columns)
    col_names = ", ".join(columns)
    sql = f"INSERT INTO {table} ({col_names}) VALUES ({placeholders})"
    values = []
    for row in rows:
        vals = []
        for c in columns:
            v = row.get(c)
            if v is None or v == "":
                vals.append(0 if c in _NUMERIC_COLUMNS else "")
            else:
                vals.append(v)
        values.append(tuple(vals))
    conn.executemany(sql, values)
    conn.commit()
    return len(values)


def _safe_nested(rec: dict, *keys: str) -> str:
    """Safely traverse nested dicts, returning '' if any level is None/missing."""
    val = rec
    for k in keys:
        if not isinstance(val, dict):
            return ""
        val = val.get(k)
        if val is None:
            return ""
    return val if isinstance(val, str) else ""


def load_alerts(conn: sqlite3.Connection, artifacts: Dict[str, Any]) -> int:
    """Load categorised alerts into the alerts table."""
    total = 0
    columns = [
        "ts", "src_ip", "src_port", "dst_ip", "dst_port",
        "protocol", "direction", "community_id",
        "rule_name", "rule_id", "category", "severity",
        "src_country", "dst_country",
    ]
    for cat_key, alerts in artifacts.items():
        if not cat_key.startswith("alerts_") or not isinstance(alerts, list):
            continue
        category = cat_key.replace("alerts_", "")
        enriched = []
        for a in alerts:
            row = {**a, "category": category}
            enriched.append(row)
        total += _bulk_insert(conn, "alerts", enriched, columns)
    return total


def load_zeek_conn(conn: sqlite3.Connection, records: List[dict]) -> int:
    columns = [
        "ts", "src_ip", "src_port", "dst_ip", "dst_port",
        "protocol", "transport", "direction", "community_id", "session_id",
        "duration", "orig_bytes", "resp_bytes", "conn_state",
        "src_country", "dst_country", "src_asn_org", "dst_asn_org",
    ]
    rows = []
    for rec in records:
        zd = rec.get("zeek_detail", {})
        zeek_conn = zd.get("conn", {}) or zd.get("connection", {})
        rows.append({
            "ts": rec.get("ts", ""),
            "src_ip": rec.get("src_ip", ""),
            "src_port": rec.get("src_port", 0),
            "dst_ip": rec.get("dst_ip", ""),
            "dst_port": rec.get("dst_port", 0),
            "protocol": rec.get("protocol", ""),
            "transport": rec.get("transport", ""),
            "direction": rec.get("direction", ""),
            "community_id": rec.get("community_id", ""),
            "session_id": rec.get("session_id", ""),
            "duration": zeek_conn.get("duration", 0),
            "orig_bytes": zeek_conn.get("orig_bytes", 0),
            "resp_bytes": zeek_conn.get("resp_bytes", 0),
            "conn_state": zeek_conn.get("conn_state", ""),
            "src_country": rec.get("src_geo", {}).get("country_name", ""),
            "dst_country": rec.get("dst_geo", {}).get("country_name", ""),
            "src_asn_org": _safe_nested(rec, "src_as", "organization", "name"),
            "dst_asn_org": _safe_nested(rec, "dst_as", "organization", "name"),
        })
    return _bulk_insert(conn, "zeek_conn", rows, columns)


def load_zeek_dns(conn: sqlite3.Connection, records: List[dict]) -> int:
    columns = ["ts", "src_ip", "dst_ip", "query", "qtype_name", "answers", "rcode_name", "community_id", "session_id"]
    rows = []
    for rec in records:
        dns = rec.get("dns", {})
        answers = dns.get("answers", [])
        if isinstance(answers, list):
            answers = ", ".join(str(a.get("data", "")) for a in answers if isinstance(a, dict))
        rows.append({
            "ts": rec.get("ts", ""),
            "src_ip": rec.get("src_ip", ""),
            "dst_ip": rec.get("dst_ip", ""),
            "query": dns.get("question", {}).get("name", "") if isinstance(dns.get("question"), dict) else "",
            "qtype_name": dns.get("question", {}).get("type", "") if isinstance(dns.get("question"), dict) else "",
            "answers": answers,
            "rcode_name": dns.get("response_code", ""),
            "community_id": rec.get("community_id", ""),
            "session_id": rec.get("session_id", ""),
        })
    return _bulk_insert(conn, "zeek_dns", rows, columns)


def load_zeek_ssl(conn: sqlite3.Connection, records: List[dict]) -> int:
    columns = [
        "ts", "src_ip", "src_port", "dst_ip", "dst_port",
        "server_name", "version", "subject", "issuer",
        "community_id", "session_id", "src_country", "src_asn_org",
    ]
    rows = []
    for rec in records:
        zeek_ssl = rec.get("zeek_detail", {}).get("ssl", {})
        tls = rec.get("tls", {})
        rows.append({
            "ts": rec.get("ts", ""),
            "src_ip": rec.get("src_ip", ""),
            "src_port": rec.get("src_port", 0),
            "dst_ip": rec.get("dst_ip", ""),
            "dst_port": rec.get("dst_port", 0),
            "server_name": zeek_ssl.get("server_name", "") or tls.get("server_name", ""),
            "version": zeek_ssl.get("version", ""),
            "subject": zeek_ssl.get("subject", ""),
            "issuer": zeek_ssl.get("issuer", ""),
            "community_id": rec.get("community_id", ""),
            "session_id": rec.get("session_id", ""),
            "src_country": rec.get("src_geo", {}).get("country_name", ""),
            "src_asn_org": _safe_nested(rec, "src_as", "organization", "name"),
        })
    return _bulk_insert(conn, "zeek_ssl", rows, columns)


def load_zeek_http(conn: sqlite3.Connection, records: List[dict]) -> int:
    columns = [
        "ts", "src_ip", "dst_ip", "method", "host", "uri",
        "status_code", "request_body_len", "response_body_len",
        "user_agent", "community_id", "session_id",
    ]
    rows = []
    for rec in records:
        url = rec.get("url", {})
        zeek_http = rec.get("zeek_detail", {}).get("http", {})
        rows.append({
            "ts": rec.get("ts", ""),
            "src_ip": rec.get("src_ip", ""),
            "dst_ip": rec.get("dst_ip", ""),
            "method": zeek_http.get("method", ""),
            "host": url.get("domain", ""),
            "uri": url.get("original", ""),
            "status_code": zeek_http.get("status_code", 0),
            "request_body_len": zeek_http.get("request_body_len", 0),
            "response_body_len": zeek_http.get("response_body_len", 0),
            "user_agent": zeek_http.get("user_agent", ""),
            "community_id": rec.get("community_id", ""),
            "session_id": rec.get("session_id", ""),
        })
    return _bulk_insert(conn, "zeek_http", rows, columns)


def load_zeek_dce_rpc(conn: sqlite3.Connection, records: List[dict]) -> int:
    columns = ["ts", "src_ip", "dst_ip", "endpoint", "operation", "named_pipe", "community_id", "session_id"]
    rows = []
    for rec in records:
        dce = rec.get("zeek_detail", {}).get("dce_rpc", {})
        rows.append({
            "ts": rec.get("ts", ""),
            "src_ip": rec.get("src_ip", ""),
            "dst_ip": rec.get("dst_ip", ""),
            "endpoint": dce.get("endpoint", ""),
            "operation": dce.get("operation", ""),
            "named_pipe": dce.get("named_pipe", ""),
            "community_id": rec.get("community_id", ""),
            "session_id": rec.get("session_id", ""),
        })
    return _bulk_insert(conn, "zeek_dce_rpc", rows, columns)


def load_zeek_rdp(conn: sqlite3.Connection, records: List[dict]) -> int:
    columns = ["ts", "src_ip", "dst_ip", "cookie", "result", "community_id", "session_id"]
    rows = []
    for rec in records:
        rdp = rec.get("zeek_detail", {}).get("rdp", {})
        rows.append({
            "ts": rec.get("ts", ""),
            "src_ip": rec.get("src_ip", ""),
            "dst_ip": rec.get("dst_ip", ""),
            "cookie": rdp.get("cookie", ""),
            "result": rdp.get("result", ""),
            "community_id": rec.get("community_id", ""),
            "session_id": rec.get("session_id", ""),
        })
    return _bulk_insert(conn, "zeek_rdp", rows, columns)


def load_zeek_smb(conn: sqlite3.Connection, records: List[dict]) -> int:
    columns = ["ts", "src_ip", "dst_ip", "command", "path", "filename", "share_type", "community_id", "session_id"]
    rows = []
    for rec in records:
        zd = rec.get("zeek_detail", {})
        smb = zd.get("smb", {}) or zd.get("smb_mapping", {}) or zd.get("smb_files", {})
        rows.append({
            "ts": rec.get("ts", ""),
            "src_ip": rec.get("src_ip", ""),
            "dst_ip": rec.get("dst_ip", ""),
            "command": smb.get("command", "") or smb.get("action", ""),
            "path": smb.get("path", "") or smb.get("share_type", ""),
            "filename": smb.get("filename", "") or smb.get("name", ""),
            "share_type": smb.get("share_type", ""),
            "community_id": rec.get("community_id", ""),
            "session_id": rec.get("session_id", ""),
        })
    return _bulk_insert(conn, "zeek_smb", rows, columns)


def load_pcap_extractions(conn: sqlite3.Connection, artifacts: Dict[str, Any]) -> dict:
    """Load all PCAP-extracted data into their respective tables."""
    counts = {}

    # DNS
    dns_cols = ["ts", "src_ip", "dst_ip", "query", "answer_a", "answer_aaaa", "resp_type", "is_response", "source_pcap"]
    counts["pcap_dns"] = _bulk_insert(conn, "pcap_dns", artifacts.get("pcap_dns_queries", []), dns_cols)

    # HTTP
    http_cols = ["ts", "src_ip", "dst_ip", "host", "uri", "method", "status_code", "content_length", "source_pcap"]
    counts["pcap_http"] = _bulk_insert(conn, "pcap_http", artifacts.get("pcap_http_requests", []), http_cols)

    # TLS
    tls_cols = ["ts", "src_ip", "dst_ip", "sni", "tls_version", "dst_port", "source_pcap"]
    counts["pcap_tls"] = _bulk_insert(conn, "pcap_tls", artifacts.get("pcap_tls_sessions", []), tls_cols)

    # SMB
    smb_cols = ["ts", "src_ip", "dst_ip", "smb_cmd", "smb2_cmd", "filename", "find_pattern", "tree", "smb2_fid", "source_pcap"]
    counts["pcap_smb"] = _bulk_insert(conn, "pcap_smb", artifacts.get("pcap_smb_sessions", []), smb_cols)

    # RDP
    rdp_cols = ["ts", "src_ip", "dst_ip", "src_port", "dst_port", "cookie", "source_pcap"]
    counts["pcap_rdp"] = _bulk_insert(conn, "pcap_rdp", artifacts.get("pcap_rdp_sessions", []), rdp_cols)

    # TCP conversation statistics
    tcp_cols = ["src_ip", "src_port", "dst_ip", "dst_port", "bytes_a_to_b", "bytes_b_to_a", "total_bytes", "total_frames", "duration", "source_pcap"]
    counts["pcap_tcp_conv"] = _bulk_insert(conn, "pcap_tcp_conv", artifacts.get("pcap_tcp_conversations", []), tcp_cols)

    # DNS SRV records (DC/Kerberos discovery)
    srv_cols = ["ts", "src_ip", "dst_ip", "query_name", "srv_target", "srv_port", "priority", "weight", "source_pcap"]
    counts["pcap_dns_srv"] = _bulk_insert(conn, "pcap_dns_srv", artifacts.get("pcap_dns_srv_records", []), srv_cols)

    # DCE-RPC calls (SAMR/LSARPC/DRSUAPI including DCSync indicators)
    dcerpc_cols = ["ts", "src_ip", "dst_ip", "opnum", "interface_uuid", "interface_name", "samr_opnum", "lsarpc_opnum", "drsuapi_opnum", "is_dcsync_indicator", "source_pcap"]
    counts["pcap_dcerpc"] = _bulk_insert(conn, "pcap_dcerpc", artifacts.get("pcap_dcerpc_calls", []), dcerpc_cols)

    # SMB2 Tree Connect (share access mapping)
    smbtree_cols = ["ts", "src_ip", "dst_ip", "tree_path", "share_type", "source_pcap"]
    counts["pcap_smb_tree"] = _bulk_insert(conn, "pcap_smb_tree", artifacts.get("pcap_smb_tree_connects", []), smbtree_cols)

    # NetBIOS/NBNS records (hostname and workgroup discovery)
    nbns_cols = ["ts", "src_ip", "dst_ip", "nb_name", "nb_addr", "opcode", "nb_type", "source_pcap"]
    counts["pcap_netbios"] = _bulk_insert(conn, "pcap_netbios", artifacts.get("pcap_netbios_records", []), nbns_cols)

    return counts


def load_all(
    conn: sqlite3.Connection,
    artifacts: Dict[str, Any],
    progress_cb=None,
) -> dict:
    """Load all ingest artifacts into the database. Returns insertion counts.

    progress_cb(step: int, total: int, table: str, rows: int) is called after
    each table is loaded so the UI can show real-time DB loading progress.
    """
    steps = [
        ("alerts",       lambda: load_alerts(conn, artifacts)),
        ("zeek_conn",    lambda: load_zeek_conn(conn, artifacts.get("zeek_conn", []))),
        ("zeek_dns",     lambda: load_zeek_dns(conn, artifacts.get("zeek_dns", []))),
        ("zeek_ssl",     lambda: load_zeek_ssl(conn, artifacts.get("zeek_ssl", []))),
        ("zeek_http",    lambda: load_zeek_http(conn, artifacts.get("zeek_http", []))),
        ("zeek_dce_rpc", lambda: load_zeek_dce_rpc(conn, artifacts.get("zeek_dce_rpc", []))),
        ("zeek_rdp",     lambda: load_zeek_rdp(conn, artifacts.get("zeek_rdp", []))),
        ("zeek_smb",     lambda: load_zeek_smb(conn, artifacts.get("zeek_smb", []))),
        ("pcap_tables",  lambda: load_pcap_extractions(conn, artifacts)),
    ]
    total_steps = len(steps)
    counts = {}
    for i, (name, loader) in enumerate(steps, 1):
        result = loader()
        if isinstance(result, dict):
            counts.update(result)
        else:
            counts[name] = result
        if progress_cb:
            progress_cb(i, total_steps, name, counts.get(name, sum(result.values()) if isinstance(result, dict) else result))

    # Post-load: credential extraction (correlates attacker RDP sessions with
    # credential evidence in raw PCAP frames — handles wrong sensor clocks)
    pcap_dir = artifacts.get("pcap_dir", "")
    if pcap_dir and os.path.isdir(pcap_dir):
        try:
            from tools.pcap_credential_extractor import run_credential_extraction
            tshark_bin = artifacts.get("tshark_bin", "tshark")
            cred_count = run_credential_extraction(
                conn, pcap_dir, tshark_bin=tshark_bin,
                progress_callback=lambda msg: print(f"    {msg}"),
            )
            counts["pcap_credentials"] = cred_count
        except Exception as exc:
            print(f"  [CredExtract] WARNING: credential extraction failed: {exc}")
            counts["pcap_credentials"] = 0

    return counts
