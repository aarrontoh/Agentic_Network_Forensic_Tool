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
    tree         TEXT,
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

-- Indexes for common query patterns used by agents
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

CREATE INDEX IF NOT EXISTS idx_dns_query        ON zeek_dns(query);
CREATE INDEX IF NOT EXISTS idx_pcap_tls_sni     ON pcap_tls(sni);
CREATE INDEX IF NOT EXISTS idx_pcap_smb_file    ON pcap_smb(filename);
CREATE INDEX IF NOT EXISTS idx_pcap_rdp_src     ON pcap_rdp(src_ip);
"""


def init_db(db_path: str) -> sqlite3.Connection:
    """Create (or open) the forensic database and ensure all tables exist.

    check_same_thread=False allows the connection to be shared across worker
    threads in the multi-agent manager (all queries are read-only SELECTs).
    """
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA_SQL)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def get_table_stats(conn: sqlite3.Connection) -> dict:
    """Return row counts for every evidence table (useful for agent context)."""
    tables = [
        "alerts", "zeek_conn", "zeek_dns", "zeek_ssl", "zeek_http",
        "zeek_dce_rpc", "zeek_rdp", "zeek_smb",
        "pcap_dns", "pcap_http", "pcap_tls", "pcap_smb", "pcap_rdp",
    ]
    stats = {}
    for t in tables:
        try:
            row = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()
            stats[t] = row[0]
        except Exception:
            stats[t] = 0
    return stats
