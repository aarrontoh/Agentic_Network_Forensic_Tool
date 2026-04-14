"""
Forensic evidence database schema.

Stores all ingested evidence (alerts, Zeek records, PCAP extractions) in a
structured SQLite database so that LLM agents can query it with SQL instead
of scanning raw JSON.  This solves the token-limit problem: agents ask
precise questions via SQL and receive only the rows they need.

Why SQLite over PostgreSQL
--------------------------
SQLite is zero-config (ships with Python), produces a single portable file,
and handles the data volumes in this investigation (~200 K rows) easily.
The SQL dialect is close enough to PostgreSQL that queries are transferable.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Optional


# ──────────────────────────────────────────────────────────────────────────────
# Table definitions
# ──────────────────────────────────────────────────────────────────────────────

_SCHEMA_SQL = """
-- Suricata EVE alerts (Phase 1)
CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT,
    src_ip      TEXT,
    src_port    INTEGER,
    dst_ip      TEXT,
    dst_port    INTEGER,
    protocol    TEXT,
    direction   TEXT,
    community_id TEXT,
    rule_name   TEXT,
    rule_id     TEXT,
    category    TEXT,       -- coarse bucket: c2, trojan, lateral, scan, ransomware, exfiltration, policy, other
    severity    INTEGER,
    src_country TEXT,
    dst_country TEXT
);

-- Zeek conn records (Phase 2)
CREATE TABLE IF NOT EXISTS zeek_conn (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT,
    src_ip       TEXT,
    src_port     INTEGER,
    dst_ip       TEXT,
    dst_port     INTEGER,
    protocol     TEXT,
    transport    TEXT,
    direction    TEXT,
    community_id TEXT,
    session_id   TEXT,
    duration     REAL,
    orig_bytes   INTEGER,
    resp_bytes   INTEGER,
    conn_state   TEXT,
    src_country  TEXT,
    dst_country  TEXT,
    src_asn_org  TEXT,
    dst_asn_org  TEXT
);

-- Zeek DNS records (Phase 2)
CREATE TABLE IF NOT EXISTS zeek_dns (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT,
    src_ip       TEXT,
    dst_ip       TEXT,
    query        TEXT,
    qtype_name   TEXT,
    answers      TEXT,       -- comma-separated
    rcode_name   TEXT,
    community_id TEXT,
    session_id   TEXT
);

-- Zeek SSL/TLS records (Phase 2)
CREATE TABLE IF NOT EXISTS zeek_ssl (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT,
    src_ip       TEXT,
    src_port     INTEGER,
    dst_ip       TEXT,
    dst_port     INTEGER,
    server_name  TEXT,       -- SNI
    version      TEXT,
    subject      TEXT,
    issuer       TEXT,
    community_id TEXT,
    session_id   TEXT,
    src_country  TEXT,
    src_asn_org  TEXT
);

-- Zeek HTTP records (Phase 2)
CREATE TABLE IF NOT EXISTS zeek_http (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT,
    src_ip       TEXT,
    dst_ip       TEXT,
    method       TEXT,
    host         TEXT,
    uri          TEXT,
    status_code  INTEGER,
    request_body_len  INTEGER,
    response_body_len INTEGER,
    user_agent   TEXT,
    community_id TEXT,
    session_id   TEXT
);

-- Zeek DCERPC records (Phase 2)
CREATE TABLE IF NOT EXISTS zeek_dce_rpc (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT,
    src_ip       TEXT,
    dst_ip       TEXT,
    endpoint     TEXT,
    operation    TEXT,
    named_pipe   TEXT,
    community_id TEXT,
    session_id   TEXT
);

-- Zeek RDP records (Phase 2)
CREATE TABLE IF NOT EXISTS zeek_rdp (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT,
    src_ip       TEXT,
    dst_ip       TEXT,
    cookie       TEXT,
    result       TEXT,
    community_id TEXT,
    session_id   TEXT
);

-- Zeek SMB records (Phase 2)
CREATE TABLE IF NOT EXISTS zeek_smb (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT,
    src_ip       TEXT,
    dst_ip       TEXT,
    command      TEXT,
    path         TEXT,
    filename     TEXT,
    share_type   TEXT,
    community_id TEXT,
    session_id   TEXT
);

-- PCAP-extracted DNS (Phase 4)
CREATE TABLE IF NOT EXISTS pcap_dns (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT,
    src_ip       TEXT,
    dst_ip       TEXT,
    query        TEXT,
    answer_a     TEXT,
    answer_aaaa  TEXT,
    resp_type    TEXT,
    is_response  TEXT,
    source_pcap  TEXT
);

-- PCAP-extracted HTTP (Phase 4)
CREATE TABLE IF NOT EXISTS pcap_http (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT,
    src_ip       TEXT,
    dst_ip       TEXT,
    host         TEXT,
    uri          TEXT,
    method       TEXT,
    status_code  TEXT,
    content_length TEXT,
    source_pcap  TEXT
);

-- PCAP-extracted TLS (Phase 4)
CREATE TABLE IF NOT EXISTS pcap_tls (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT,
    src_ip       TEXT,
    dst_ip       TEXT,
    sni          TEXT,
    tls_version  TEXT,
    dst_port     TEXT,
    source_pcap  TEXT
);

-- PCAP-extracted SMB (Phase 4)
CREATE TABLE IF NOT EXISTS pcap_smb (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT,
    src_ip       TEXT,
    dst_ip       TEXT,
    smb_cmd      TEXT,
    smb2_cmd     TEXT,
    filename     TEXT,
    find_pattern TEXT,
    tree         TEXT,
    smb2_fid     TEXT,
    source_pcap  TEXT
);

-- PCAP-extracted TCP conversation statistics (Phase 4)
-- Captures actual byte volumes from tshark -z conv,tcp
-- Critical for exfiltration quantification when Zeek conn shows zero bytes
CREATE TABLE IF NOT EXISTS pcap_tcp_conv (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    src_ip       TEXT,
    src_port     TEXT,
    dst_ip       TEXT,
    dst_port     TEXT,
    bytes_a_to_b INTEGER,
    bytes_b_to_a INTEGER,
    total_bytes  INTEGER,
    total_frames INTEGER,
    duration     TEXT,
    source_pcap  TEXT
);

-- PCAP-extracted RDP (Phase 4)
CREATE TABLE IF NOT EXISTS pcap_rdp (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT,
    src_ip       TEXT,
    dst_ip       TEXT,
    src_port     TEXT,
    dst_port     TEXT,
    cookie       TEXT,
    source_pcap  TEXT
);

-- PCAP-extracted DNS SRV records (Phase 4) — DC/Kerberos discovery
CREATE TABLE IF NOT EXISTS pcap_dns_srv (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT,
    src_ip       TEXT,
    dst_ip       TEXT,
    query_name   TEXT,
    srv_target   TEXT,
    srv_port     TEXT,
    priority     TEXT,
    weight       TEXT,
    source_pcap  TEXT
);

-- PCAP-extracted DCE-RPC calls (Phase 4) — SAMR/LSARPC/DRSUAPI enumeration + DCSync
CREATE TABLE IF NOT EXISTS pcap_dcerpc (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    ts                  TEXT,
    src_ip              TEXT,
    dst_ip              TEXT,
    opnum               TEXT,
    interface_uuid      TEXT,
    interface_name      TEXT,
    samr_opnum          TEXT,
    lsarpc_opnum        TEXT,
    drsuapi_opnum       TEXT,
    is_dcsync_indicator INTEGER DEFAULT 0,
    source_pcap         TEXT
);

-- PCAP-extracted SMB2 Tree Connect requests (Phase 4) — share access mapping
CREATE TABLE IF NOT EXISTS pcap_smb_tree (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT,
    src_ip       TEXT,
    dst_ip       TEXT,
    tree_path    TEXT,
    share_type   TEXT,
    source_pcap  TEXT
);

-- PCAP-extracted NetBIOS/NBNS records (Phase 4) — hostname and workgroup discovery
CREATE TABLE IF NOT EXISTS pcap_netbios (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT,
    src_ip       TEXT,
    dst_ip       TEXT,
    nb_name      TEXT,
    nb_addr      TEXT,
    opcode       TEXT,
    nb_type      TEXT,
    source_pcap  TEXT
);

CREATE TABLE IF NOT EXISTS pcap_credentials (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    attacker_ip     TEXT,
    target_ip       TEXT,
    credential      TEXT,
    credential_type TEXT,
    pcap_epoch_rdp  REAL,
    pcap_epoch_cred REAL,
    real_ts_rdp     TEXT,
    real_ts_cred    TEXT,
    clock_offset    REAL,
    delta_secs      REAL,
    evidence_note   TEXT,
    source_pcap     TEXT
);

-- Indexes for common query patterns used by agents
CREATE INDEX IF NOT EXISTS idx_pcap_cred_ip     ON pcap_credentials(attacker_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_src       ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_dst       ON alerts(dst_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_category  ON alerts(category);
CREATE INDEX IF NOT EXISTS idx_alerts_ts        ON alerts(ts);

CREATE INDEX IF NOT EXISTS idx_conn_src         ON zeek_conn(src_ip);
CREATE INDEX IF NOT EXISTS idx_conn_dst         ON zeek_conn(dst_ip);
CREATE INDEX IF NOT EXISTS idx_conn_dport       ON zeek_conn(dst_port);

CREATE INDEX IF NOT EXISTS idx_ssl_sni          ON zeek_ssl(server_name);
CREATE INDEX IF NOT EXISTS idx_ssl_src          ON zeek_ssl(src_ip);
CREATE INDEX IF NOT EXISTS idx_ssl_dst          ON zeek_ssl(dst_ip);

CREATE INDEX IF NOT EXISTS idx_dce_src          ON zeek_dce_rpc(src_ip);
CREATE INDEX IF NOT EXISTS idx_dce_op           ON zeek_dce_rpc(operation);
CREATE INDEX IF NOT EXISTS idx_dce_pipe         ON zeek_dce_rpc(named_pipe);

CREATE INDEX IF NOT EXISTS idx_dns_query        ON zeek_dns(query);
CREATE INDEX IF NOT EXISTS idx_dns_src          ON zeek_dns(src_ip);

CREATE INDEX IF NOT EXISTS idx_smb_src          ON zeek_smb(src_ip);
CREATE INDEX IF NOT EXISTS idx_smb_filename     ON zeek_smb(filename);
CREATE INDEX IF NOT EXISTS idx_smb_ts           ON zeek_smb(ts);

CREATE INDEX IF NOT EXISTS idx_rdp_src          ON zeek_rdp(src_ip);
CREATE INDEX IF NOT EXISTS idx_rdp_dst          ON zeek_rdp(dst_ip);

CREATE INDEX IF NOT EXISTS idx_conn_ts          ON zeek_conn(ts);
CREATE INDEX IF NOT EXISTS idx_ssl_ts           ON zeek_ssl(ts);

CREATE INDEX IF NOT EXISTS idx_pcap_tls_sni     ON pcap_tls(sni);
CREATE INDEX IF NOT EXISTS idx_pcap_smb_file    ON pcap_smb(filename);
CREATE INDEX IF NOT EXISTS idx_pcap_rdp_src     ON pcap_rdp(src_ip);
CREATE INDEX IF NOT EXISTS idx_pcap_srv_query   ON pcap_dns_srv(query_name);
CREATE INDEX IF NOT EXISTS idx_pcap_dcerpc_src  ON pcap_dcerpc(src_ip);
CREATE INDEX IF NOT EXISTS idx_pcap_dcerpc_if   ON pcap_dcerpc(interface_name);
CREATE INDEX IF NOT EXISTS idx_pcap_dcerpc_dc   ON pcap_dcerpc(is_dcsync_indicator);
CREATE INDEX IF NOT EXISTS idx_pcap_smbtree_src ON pcap_smb_tree(src_ip);
CREATE INDEX IF NOT EXISTS idx_pcap_smbtree_path ON pcap_smb_tree(tree_path);
CREATE INDEX IF NOT EXISTS idx_pcap_nbns_name   ON pcap_netbios(nb_name);
"""


def init_db(db_path: str) -> sqlite3.Connection:
    """Create (or open) the forensic database and ensure all tables exist.

    check_same_thread=False allows the connection to be shared across worker
    threads in the multi-agent manager (all queries are read-only SELECTs).
    """
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA_SQL)
    # Lightweight migrations for existing DB files
    try:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(pcap_smb)").fetchall()}
        if cols and "smb2_fid" not in cols:
            conn.execute("ALTER TABLE pcap_smb ADD COLUMN smb2_fid TEXT")
            conn.commit()
    except sqlite3.Error:
        pass
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def get_table_stats(conn: sqlite3.Connection) -> dict:
    """Return row counts for every evidence table (useful for agent context)."""
    tables = [
        "alerts", "zeek_conn", "zeek_dns", "zeek_ssl", "zeek_http",
        "zeek_dce_rpc", "zeek_rdp", "zeek_smb",
        "pcap_dns", "pcap_http", "pcap_tls", "pcap_smb", "pcap_rdp",
        "pcap_tcp_conv",
    ]
    stats = {}
    for t in tables:
        try:
            row = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()
            stats[t] = row[0]
        except Exception:
            stats[t] = 0
    return stats
