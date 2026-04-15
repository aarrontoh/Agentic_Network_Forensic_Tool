"""
Phase 2 Investigation Notes Generator

After the SQLite DB is loaded (Phase 5), this module queries all key tables
and writes a structured Markdown investigation notes file to:
  <work_dir>/phase2_notes.md

This file serves two purposes:
  1. Human review of data quality before spending API credits on LLM workers
  2. Pre-computed context injected into worker prompts so workers don't waste
     turns re-discovering basics

Covers:
  - Suricata alert summary by category
  - RDP spray analysis + attacker candidate identification
  - Kerberos event summary (successes, failures, escalation patterns)
  - DCE-RPC operation breakdown (SAMR, LSARPC, DRSUAPI)
  - SMB file activity summary (specialist filenames, delete.me waves)
  - DNS top queries + exfil domain hits
  - TLS/SSL sessions (exfil SNI, no-SNI to external)
  - DHCP hostname map (IP → hostname)
  - Zeek Weird anomalies (ZeroLogon candidates)
  - Multi-protocol burst detection (BloodHound/NetExec signature)
  - Beaconing candidates (periodic connection patterns)
  - PCAP extraction summary
"""
from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# SQL helpers
# ─────────────────────────────────────────────────────────────────────────────

def _q(conn: sqlite3.Connection, sql: str, params=()) -> list:
    """Run a query and return list of Row objects. Never raises."""
    try:
        return conn.execute(sql, params).fetchall()
    except Exception as e:
        return [{"_error": str(e)}]


def _scalar(conn: sqlite3.Connection, sql: str, default=0) -> object:
    """Return first cell of first row."""
    try:
        row = conn.execute(sql).fetchone()
        return row[0] if row and row[0] is not None else default
    except Exception:
        return default


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone()
    return bool(row)


def _fmt_rows(rows: list, cols: list[str], max_rows: int = 30) -> str:
    """Format query rows as a Markdown table."""
    if not rows:
        return "_No results._\n"
    if hasattr(rows[0], "_error"):
        return f"_Query error: {rows[0]['_error']}_\n"
    header = "| " + " | ".join(cols) + " |"
    sep = "|" + "|".join("---" for _ in cols) + "|"
    lines = [header, sep]
    for row in rows[:max_rows]:
        cells = []
        for c in cols:
            try:
                v = row[c] if hasattr(row, "keys") else row[cols.index(c)]
            except (KeyError, IndexError, TypeError):
                v = ""
            cells.append(str(v) if v is not None else "")
        lines.append("| " + " | ".join(cells) + " |")
    if len(rows) > max_rows:
        lines.append(f"_... {len(rows) - max_rows} more rows truncated._")
    return "\n".join(lines) + "\n"


# ─────────────────────────────────────────────────────────────────────────────
# Section generators
# ─────────────────────────────────────────────────────────────────────────────

def _section_summary(conn: sqlite3.Connection) -> str:
    lines = ["## 1. Database Summary\n"]
    tables = [
        "alerts", "zeek_conn", "zeek_rdp", "zeek_kerberos", "zeek_dce_rpc",
        "zeek_smb", "zeek_dns", "zeek_ssl", "zeek_http", "zeek_dhcp", "zeek_weird",
        "pcap_rdp", "pcap_smb", "pcap_tcp_conv", "pcap_dcerpc", "pcap_tls",
    ]
    lines.append("| Table | Rows |")
    lines.append("|-------|------|")
    for t in tables:
        if _table_exists(conn, t):
            cnt = _scalar(conn, f"SELECT COUNT(*) FROM {t}", 0)
            lines.append(f"| {t} | {cnt:,} |")
        else:
            lines.append(f"| {t} | _missing_ |")
    lines.append("")
    return "\n".join(lines)


def _section_alerts(conn: sqlite3.Connection) -> str:
    lines = ["## 2. Suricata Alert Summary\n"]

    total = _scalar(conn, "SELECT COUNT(*) FROM alerts", 0)
    lines.append(f"**Total alerts:** {total:,}\n")

    rows = _q(conn, """
        SELECT category, COUNT(*) cnt, COUNT(DISTINCT src_ip) unique_srcs,
               MIN(ts) first_ts, MAX(ts) last_ts
        FROM alerts
        GROUP BY category ORDER BY cnt DESC
    """)
    lines.append("### By Category\n")
    lines.append(_fmt_rows(rows, ["category", "cnt", "unique_srcs", "first_ts", "last_ts"]))

    rows = _q(conn, """
        SELECT rule_name, COUNT(*) cnt, src_ip, dst_ip
        FROM alerts
        GROUP BY rule_name ORDER BY cnt DESC LIMIT 20
    """)
    lines.append("### Top 20 Alert Rules\n")
    lines.append(_fmt_rows(rows, ["rule_name", "cnt", "src_ip", "dst_ip"]))

    return "\n".join(lines)


def _section_rdp_spray(conn: sqlite3.Connection, beachhead_ip: str) -> str:
    lines = [f"## 3. RDP Spray Analysis (target: {beachhead_ip})\n"]

    total_spray, unique_ips = _scalar(conn, f"""
        SELECT COUNT(*) FROM zeek_rdp
        WHERE dst_ip='{beachhead_ip}' AND src_ip NOT LIKE '10.%' AND src_ip NOT LIKE '172.%'
    """, 0), _scalar(conn, f"""
        SELECT COUNT(DISTINCT src_ip) FROM zeek_rdp
        WHERE dst_ip='{beachhead_ip}' AND src_ip NOT LIKE '10.%' AND src_ip NOT LIKE '172.%'
    """, 0)
    spray_start = _scalar(conn, f"SELECT MIN(ts) FROM zeek_rdp WHERE dst_ip='{beachhead_ip}'", "")
    spray_end = _scalar(conn, f"SELECT MAX(ts) FROM zeek_rdp WHERE dst_ip='{beachhead_ip}'", "")
    lines.append(f"- **Total external RDP attempts:** {total_spray:,} from {unique_ips:,} unique IPs\n")
    lines.append(f"- **Spray window:** {spray_start} → {spray_end}\n")

    lines.append("### Top spray sources (high volume = background noise)\n")
    rows = _q(conn, f"""
        SELECT src_ip, COUNT(*) cnt, MIN(ts) first_ts, MAX(ts) last_ts,
               GROUP_CONCAT(DISTINCT cookie) cookies
        FROM zeek_rdp
        WHERE dst_ip='{beachhead_ip}' AND src_ip NOT LIKE '10.%'
        GROUP BY src_ip ORDER BY cnt DESC LIMIT 15
    """)
    lines.append(_fmt_rows(rows, ["src_ip", "cnt", "first_ts", "last_ts", "cookies"]))

    lines.append("### Low-volume external RDP (attacker candidates — low count + valid credential)\n")
    rows = _q(conn, f"""
        SELECT src_ip, COUNT(*) cnt, MIN(ts) first_ts,
               GROUP_CONCAT(DISTINCT cookie) cookies
        FROM zeek_rdp
        WHERE dst_ip='{beachhead_ip}' AND src_ip NOT LIKE '10.%'
        GROUP BY src_ip ORDER BY cnt ASC LIMIT 10
    """)
    lines.append(_fmt_rows(rows, ["src_ip", "cnt", "first_ts", "cookies"]))

    lines.append("### Kerberos correlation within 60s of external RDP (PROOF OF REAL ATTACKER)\n")
    if _table_exists(conn, "zeek_kerberos"):
        rows = _q(conn, f"""
            SELECT r.src_ip attacker_ip, r.ts rdp_ts, r.cookie,
                   k.ts kerberos_ts, k.client_name, k.client, k.success,
                   CAST((julianday(k.ts)-julianday(r.ts))*86400 AS INTEGER) delta_s
            FROM zeek_rdp r
            JOIN zeek_kerberos k ON k.src_ip='{beachhead_ip}'
              AND julianday(k.ts) >= julianday(r.ts)
              AND (julianday(k.ts)-julianday(r.ts))*86400 <= 60
            WHERE r.dst_ip='{beachhead_ip}' AND r.src_ip NOT LIKE '10.%'
            ORDER BY delta_s LIMIT 20
        """)
        lines.append(_fmt_rows(rows, ["attacker_ip", "rdp_ts", "cookie", "kerberos_ts", "client_name", "client", "success", "delta_s"]))
    else:
        lines.append("_zeek_kerberos table not populated._\n")

    return "\n".join(lines)


def _section_kerberos(conn: sqlite3.Connection, beachhead_ip: str) -> str:
    if not _table_exists(conn, "zeek_kerberos"):
        return "## 4. Kerberos Events\n_Table not populated._\n"

    lines = ["## 4. Kerberos Events\n"]

    total = _scalar(conn, "SELECT COUNT(*) FROM zeek_kerberos", 0)
    successes = _scalar(conn, "SELECT COUNT(*) FROM zeek_kerberos WHERE success='True'", 0)
    failures = _scalar(conn, "SELECT COUNT(*) FROM zeek_kerberos WHERE success='False'", 0)
    lines.append(f"**Total:** {total:,} | **Success:** {successes:,} | **Failures:** {failures:,}\n")

    lines.append("### Unique clients + request types from beachhead\n")
    rows = _q(conn, f"""
        SELECT client_name, request_type, COUNT(*) cnt, MIN(ts) first_ts,
               GROUP_CONCAT(DISTINCT cipher) ciphers
        FROM zeek_kerberos WHERE src_ip='{beachhead_ip}'
        GROUP BY client_name, request_type ORDER BY first_ts LIMIT 20
    """)
    lines.append(_fmt_rows(rows, ["client_name", "request_type", "cnt", "first_ts", "ciphers"]))

    lines.append("### Kerberos failures (error codes — brute force / invalid creds)\n")
    rows = _q(conn, """
        SELECT error_code, COUNT(*) cnt, COUNT(DISTINCT src_ip) unique_srcs,
               COUNT(DISTINCT client_name) unique_clients
        FROM zeek_kerberos WHERE success='False'
        GROUP BY error_code ORDER BY cnt DESC LIMIT 10
    """)
    lines.append(_fmt_rows(rows, ["error_code", "cnt", "unique_srcs", "unique_clients"]))

    lines.append("### Machine account Kerberos ($ accounts — lateral movement / DCSync signal)\n")
    rows = _q(conn, """
        SELECT client_name, src_ip, dst_ip, service, COUNT(*) cnt, MIN(ts) first_ts
        FROM zeek_kerberos WHERE client_name LIKE '%$%'
        GROUP BY client_name, src_ip ORDER BY cnt DESC LIMIT 15
    """)
    lines.append(_fmt_rows(rows, ["client_name", "src_ip", "dst_ip", "service", "cnt", "first_ts"]))

    lines.append("### krbtgt service requests (TGT issuance — track escalation)\n")
    rows = _q(conn, """
        SELECT client_name, src_ip, dst_ip, success, MIN(ts) first_ts
        FROM zeek_kerberos WHERE service LIKE '%krbtgt%'
        GROUP BY client_name, src_ip ORDER BY first_ts LIMIT 15
    """)
    lines.append(_fmt_rows(rows, ["client_name", "src_ip", "dst_ip", "success", "first_ts"]))

    return "\n".join(lines)


def _section_dcerpc(conn: sqlite3.Connection, beachhead_ip: str) -> str:
    lines = ["## 5. DCE-RPC Operations (AD Enumeration + Credential Access)\n"]

    total = _scalar(conn, f"SELECT COUNT(*) FROM zeek_dce_rpc WHERE src_ip='{beachhead_ip}'", 0)
    lines.append(f"**Total DCE-RPC calls from {beachhead_ip}:** {total:,}\n")

    lines.append("### Operation breakdown from beachhead\n")
    rows = _q(conn, f"""
        SELECT operation, COUNT(*) cnt, COUNT(DISTINCT dst_ip) unique_dcs,
               MIN(ts) first_ts
        FROM zeek_dce_rpc WHERE src_ip='{beachhead_ip}'
        GROUP BY operation ORDER BY cnt DESC LIMIT 25
    """)
    lines.append(_fmt_rows(rows, ["operation", "cnt", "unique_dcs", "first_ts"]))

    lines.append("### DCSync indicators (DRSUAPI GetNCChanges)\n")
    rows = _q(conn, """
        SELECT ts, src_ip, dst_ip, operation, endpoint
        FROM zeek_dce_rpc
        WHERE operation LIKE '%DRSGetNCChanges%' OR operation LIKE '%drsuapi%'
        ORDER BY ts LIMIT 10
    """)
    lines.append(_fmt_rows(rows, ["ts", "src_ip", "dst_ip", "operation", "endpoint"]))

    lines.append("### DPAPI BackupKey (credential material theft)\n")
    rows = _q(conn, """
        SELECT ts, src_ip, dst_ip, operation, endpoint, named_pipe
        FROM zeek_dce_rpc
        WHERE operation LIKE '%bkrp%' OR operation LIKE '%BackupKey%'
        ORDER BY ts LIMIT 10
    """)
    lines.append(_fmt_rows(rows, ["ts", "src_ip", "dst_ip", "operation", "endpoint", "named_pipe"]))

    lines.append("### SAMR operations (AD user/group enumeration)\n")
    rows = _q(conn, f"""
        SELECT operation, COUNT(*) cnt
        FROM zeek_dce_rpc
        WHERE src_ip='{beachhead_ip}' AND operation LIKE 'Samr%'
        GROUP BY operation ORDER BY cnt DESC
    """)
    lines.append(_fmt_rows(rows, ["operation", "cnt"]))

    lines.append("### NetrLogonSamLogonEx (credential validation — expect 240k+)\n")
    rows = _q(conn, """
        SELECT COUNT(*) total, COUNT(DISTINCT dst_ip) unique_dcs,
               MIN(ts) first_ts, MAX(ts) last_ts
        FROM zeek_dce_rpc WHERE operation='NetrLogonSamLogonEx'
    """)
    lines.append(_fmt_rows(rows, ["total", "unique_dcs", "first_ts", "last_ts"]))

    return "\n".join(lines)


def _section_smb(conn: sqlite3.Connection, beachhead_ip: str) -> str:
    lines = ["## 6. SMB File Activity\n"]

    total = _scalar(conn, f"SELECT COUNT(*) FROM zeek_smb WHERE src_ip='{beachhead_ip}'", 0)
    lines.append(f"**Total SMB ops from {beachhead_ip}:** {total:,}\n")

    lines.append("### delete.me write-testing (discovery waves)\n")
    rows = _q(conn, f"""
        SELECT DATE(ts) wave_date, COUNT(*) total_ops,
               COUNT(DISTINCT dst_ip) unique_hosts,
               SUM(CASE WHEN command LIKE '%FILE_OPEN%' THEN 1 ELSE 0 END) opens,
               SUM(CASE WHEN command LIKE '%FILE_DELETE%' THEN 1 ELSE 0 END) deletes
        FROM zeek_smb
        WHERE src_ip='{beachhead_ip}' AND filename='delete.me'
        GROUP BY DATE(ts) ORDER BY wave_date
    """)
    lines.append(_fmt_rows(rows, ["wave_date", "total_ops", "unique_hosts", "opens", "deletes"]))

    lines.append("### Ransomware + payload files\n")
    rows = _q(conn, """
        SELECT ts, src_ip, dst_ip, filename, command
        FROM zeek_smb
        WHERE filename IN ('kkwlo.exe','hfs.exe','hfs.ips.txt','Microsofts.exe',
                           'UninstallWinClient.exe')
           OR filename LIKE '%HOW TO BACK%'
        ORDER BY ts
    """)
    lines.append(_fmt_rows(rows, ["ts", "src_ip", "dst_ip", "filename", "command"]))

    lines.append("### Sensitive data files accessed\n")
    rows = _q(conn, """
        SELECT ts, src_ip, dst_ip, filename, command
        FROM zeek_smb
        WHERE filename LIKE '%user_db%' OR filename LIKE '%credit_card%'
           OR filename LIKE '%.vib%' OR filename LIKE '%.vbk%'
           OR filename LIKE '%arrestees%' OR filename LIKE '%offenders%'
           OR filename LIKE '%victims%'
           OR filename IN ('Groups.xml','Registry.xml')
        ORDER BY ts LIMIT 30
    """)
    lines.append(_fmt_rows(rows, ["ts", "src_ip", "dst_ip", "filename", "command"]))

    lines.append("### GPO files (Groups.xml + Registry.xml — Defender disable / RDP grant)\n")
    rows = _q(conn, """
        SELECT ts, src_ip, dst_ip, filename, command
        FROM zeek_smb WHERE filename IN ('Groups.xml','Registry.xml')
        ORDER BY ts LIMIT 10
    """)
    lines.append(_fmt_rows(rows, ["ts", "src_ip", "dst_ip", "filename", "command"]))

    lines.append("### All .exe files transferred via SMB\n")
    rows = _q(conn, f"""
        SELECT ts, src_ip, dst_ip, filename, command
        FROM zeek_smb
        WHERE src_ip='{beachhead_ip}' AND filename LIKE '%.exe'
        ORDER BY ts LIMIT 30
    """)
    lines.append(_fmt_rows(rows, ["ts", "src_ip", "dst_ip", "filename", "command"]))

    lines.append("### SYSVOL / NETLOGON access (GPO tampering)\n")
    rows = _q(conn, """
        SELECT ts, src_ip, dst_ip, path, filename
        FROM zeek_smb
        WHERE path LIKE '%SYSVOL%' OR path LIKE '%NETLOGON%'
           OR filename LIKE '%SYSVOL%' OR filename LIKE '%NETLOGON%'
        ORDER BY ts LIMIT 10
    """)
    lines.append(_fmt_rows(rows, ["ts", "src_ip", "dst_ip", "path", "filename"]))

    return "\n".join(lines)


def _section_dns(conn: sqlite3.Connection) -> str:
    lines = ["## 7. DNS Analysis\n"]

    lines.append("### Top 20 queried domains\n")
    rows = _q(conn, """
        SELECT query, COUNT(*) cnt, COUNT(DISTINCT src_ip) unique_srcs,
               GROUP_CONCAT(DISTINCT answers) resolved
        FROM zeek_dns WHERE query != ''
        GROUP BY query ORDER BY cnt DESC LIMIT 20
    """)
    lines.append(_fmt_rows(rows, ["query", "cnt", "unique_srcs", "resolved"]))

    lines.append("### Exfil domain DNS queries (temp.sh / file.io / transfer.sh)\n")
    rows = _q(conn, """
        SELECT ts, src_ip, dst_ip, query, answers
        FROM zeek_dns
        WHERE query LIKE '%temp.sh%' OR query LIKE '%file.io%'
           OR query LIKE '%transfer.sh%' OR query LIKE '%anonfiles%'
        ORDER BY ts
    """)
    lines.append(_fmt_rows(rows, ["ts", "src_ip", "dst_ip", "query", "answers"]))

    lines.append("### SRV record queries (DC / Kerberos / LDAP discovery)\n")
    rows = _q(conn, """
        SELECT ts, src_ip, query, answers FROM zeek_dns
        WHERE query LIKE '%_kerberos%' OR query LIKE '%_ldap%'
           OR query LIKE '%_gc%' OR qtype_name='SRV'
        ORDER BY ts LIMIT 20
    """)
    lines.append(_fmt_rows(rows, ["ts", "src_ip", "query", "answers"]))

    return "\n".join(lines)


def _section_tls(conn: sqlite3.Connection) -> str:
    lines = ["## 8. TLS/SSL Sessions\n"]

    lines.append("### Exfil destinations (temp.sh SNI)\n")
    rows = _q(conn, """
        SELECT ts, src_ip, dst_ip, server_name, version
        FROM zeek_ssl WHERE server_name='temp.sh'
        ORDER BY ts
    """)
    lines.append(_fmt_rows(rows, ["ts", "src_ip", "dst_ip", "server_name", "version"]))

    total_exfil_tls = _scalar(conn, "SELECT COUNT(*) FROM zeek_ssl WHERE server_name='temp.sh'", 0)
    lines.append(f"**Total TLS sessions to temp.sh:** {total_exfil_tls}\n")

    lines.append("### No-SNI external TLS (suspicious — may be C2 or AnyNet backdoor)\n")
    rows = _q(conn, """
        SELECT ts, src_ip, dst_ip, src_port, dst_port, version
        FROM zeek_ssl
        WHERE (server_name='' OR server_name IS NULL)
          AND dst_ip NOT LIKE '10.%' AND dst_ip NOT LIKE '172.%' AND dst_ip NOT LIKE '192.168.%'
        ORDER BY ts LIMIT 20
    """)
    lines.append(_fmt_rows(rows, ["ts", "src_ip", "dst_ip", "src_port", "dst_port", "version"]))

    lines.append("### TLS to AnyNet / C2 candidates (92.38.177.14)\n")
    rows = _q(conn, """
        SELECT ts, src_ip, dst_ip, server_name, version
        FROM zeek_ssl WHERE dst_ip='92.38.177.14' OR src_ip='92.38.177.14'
        ORDER BY ts LIMIT 10
    """)
    lines.append(_fmt_rows(rows, ["ts", "src_ip", "dst_ip", "server_name", "version"]))

    return "\n".join(lines)


def _section_dhcp(conn: sqlite3.Connection) -> str:
    if not _table_exists(conn, "zeek_dhcp"):
        return "## 9. DHCP Hostname Map\n_Table not populated._\n"

    total = _scalar(conn, "SELECT COUNT(*) FROM zeek_dhcp", 0)
    if total == 0:
        return "## 9. DHCP Hostname Map\n_No DHCP records._\n"

    lines = [f"## 9. DHCP Hostname Map ({total:,} records)\n"]
    rows = _q(conn, """
        SELECT assigned_ip, host_name, mac, COUNT(*) cnt, MAX(ts) last_seen
        FROM zeek_dhcp WHERE host_name != ''
        GROUP BY assigned_ip, host_name ORDER BY assigned_ip
    """)
    lines.append(_fmt_rows(rows, ["assigned_ip", "host_name", "mac", "cnt", "last_seen"]))
    return "\n".join(lines)


def _section_weird(conn: sqlite3.Connection) -> str:
    if not _table_exists(conn, "zeek_weird"):
        return "## 10. Zeek Weird (Protocol Anomalies)\n_Table not populated._\n"

    total = _scalar(conn, "SELECT COUNT(*) FROM zeek_weird", 0)
    if total == 0:
        return "## 10. Zeek Weird (Protocol Anomalies)\n_No weird records._\n"

    lines = [f"## 10. Zeek Weird (Protocol Anomalies) — {total:,} total\n"]

    lines.append("### Anomaly types\n")
    rows = _q(conn, """
        SELECT name, COUNT(*) cnt, COUNT(DISTINCT src_ip) unique_srcs
        FROM zeek_weird GROUP BY name ORDER BY cnt DESC LIMIT 20
    """)
    lines.append(_fmt_rows(rows, ["name", "cnt", "unique_srcs"]))

    lines.append("### ZeroLogon / NTLM anomaly candidates\n")
    rows = _q(conn, """
        SELECT ts, src_ip, dst_ip, name, addl
        FROM zeek_weird
        WHERE name LIKE '%netlogon%' OR name LIKE '%zerolog%'
           OR name LIKE '%ntlm%' OR addl LIKE '%netlogon%'
        ORDER BY ts LIMIT 20
    """)
    lines.append(_fmt_rows(rows, ["ts", "src_ip", "dst_ip", "name", "addl"]))

    return "\n".join(lines)


def _section_multi_protocol_burst(conn: sqlite3.Connection, beachhead_ip: str) -> str:
    """
    Detect BloodHound/NetExec signature: same source IP hitting many protocols
    in a short time window. We look at the first 60 minutes after the RDP access.
    """
    lines = ["## 11. Multi-Protocol Burst Detection (BloodHound/NetExec Signature)\n"]

    # Get first post-intrusion activity window
    first_rdp_ts = _scalar(conn, f"""
        SELECT MIN(ts) FROM zeek_conn
        WHERE src_ip='{beachhead_ip}' AND dst_ip NOT LIKE '10.128.239.5%'
        AND ts > (SELECT MIN(ts) FROM zeek_rdp WHERE dst_ip='{beachhead_ip}' AND src_ip NOT LIKE '10.%')
    """, "")

    lines.append(f"_Analysis window: first 60 min after initial access from {beachhead_ip}_\n")

    rows = _q(conn, f"""
        SELECT SUBSTR(ts,1,16) minute_bucket,
               COUNT(DISTINCT dst_ip) unique_dsts,
               COUNT(DISTINCT dst_port) unique_ports,
               COUNT(*) total_conns,
               GROUP_CONCAT(DISTINCT CAST(dst_port AS TEXT)) ports
        FROM zeek_conn WHERE src_ip='{beachhead_ip}'
        GROUP BY SUBSTR(ts,1,16)
        HAVING COUNT(DISTINCT dst_port) > 5
        ORDER BY total_conns DESC LIMIT 20
    """)
    lines.append("### High-activity minutes (>5 distinct ports in 1 min = tool activity)\n")
    lines.append(_fmt_rows(rows, ["minute_bucket", "unique_dsts", "unique_ports", "total_conns", "ports"]))

    return "\n".join(lines)


def _section_exfil_volume(conn: sqlite3.Connection) -> str:
    lines = ["## 12. Exfiltration Volume (pcap_tcp_conv)\n"]

    rows = _q(conn, """
        SELECT src_ip, dst_ip,
               bytes_a_to_b, bytes_b_to_a,
               MAX(bytes_a_to_b, bytes_b_to_a) dominant_bytes,
               ROUND(MAX(bytes_a_to_b, bytes_b_to_a)*1.0/1048576,1) dominant_mb,
               total_frames, source_pcap
        FROM pcap_tcp_conv
        WHERE dst_ip='51.91.79.17' OR src_ip='51.91.79.17'
        ORDER BY dominant_bytes DESC LIMIT 20
    """)
    lines.append("### Conversations to/from 51.91.79.17 (temp.sh)\n")
    lines.append(_fmt_rows(rows, ["src_ip", "dst_ip", "bytes_a_to_b", "bytes_b_to_a", "dominant_bytes", "dominant_mb", "total_frames", "source_pcap"]))

    total_dominant = _scalar(conn, """
        SELECT SUM(MAX(bytes_a_to_b,bytes_b_to_a))
        FROM pcap_tcp_conv WHERE dst_ip='51.91.79.17' OR src_ip='51.91.79.17'
    """, 0)
    total_mb = round(int(total_dominant) / 1048576, 1) if total_dominant else 0
    lines.append(f"\n**Total dominant bytes to/from 51.91.79.17:** {total_dominant:,} bytes ({total_mb} MB)\n")
    lines.append("> ⚠️ DIRECTION NOTE: `MAX(bytes_a_to_b, bytes_b_to_a)` = upload direction (larger value). Do NOT add both columns.\n")

    return "\n".join(lines)


def _section_ntlm(conn: sqlite3.Connection) -> str:
    if not _table_exists(conn, "zeek_ntlm"):
        return "## 13a. NTLM Authentication\n_Table not populated._\n"

    total = _scalar(conn, "SELECT COUNT(*) FROM zeek_ntlm", 0)
    if total == 0:
        return "## 13a. NTLM Authentication\n_No NTLM records._\n"

    lines = [f"## 13a. NTLM Authentication — {total:,} records\n"]

    lines.append("### NTLM auth failures (credential spraying / pass-the-hash)\n")
    rows = _q(conn, """
        SELECT username, domain_name, src_ip, dst_ip, COUNT(*) cnt, MIN(ts) first_ts
        FROM zeek_ntlm WHERE success='False'
        GROUP BY username, src_ip ORDER BY cnt DESC LIMIT 20
    """)
    lines.append(_fmt_rows(rows, ["username", "domain_name", "src_ip", "dst_ip", "cnt", "first_ts"]))

    lines.append("### NTLM successes from external IPs\n")
    rows = _q(conn, """
        SELECT ts, src_ip, dst_ip, username, hostname, domain_name, status
        FROM zeek_ntlm
        WHERE success='True'
          AND src_ip NOT LIKE '10.%' AND src_ip NOT LIKE '172.%' AND src_ip NOT LIKE '192.168.%'
        ORDER BY ts LIMIT 15
    """)
    lines.append(_fmt_rows(rows, ["ts", "src_ip", "dst_ip", "username", "hostname", "domain_name", "status"]))

    return "\n".join(lines)


def _section_beaconing(conn: sqlite3.Connection) -> str:
    """
    Beaconing candidates: external destinations contacted with periodic regularity.
    Proxy: IPs with many connections AND similar inter-connection intervals.
    We approximate with: count of distinct minutes with connections (regularity proxy).
    """
    lines = ["## 13. Beaconing Candidates (Periodic Connection Patterns)\n"]

    rows = _q(conn, """
        SELECT dst_ip,
               COUNT(*) total_conns,
               COUNT(DISTINCT SUBSTR(ts,1,16)) active_minutes,
               MIN(ts) first_seen, MAX(ts) last_seen
        FROM zeek_conn
        WHERE dst_ip NOT LIKE '10.%' AND dst_ip NOT LIKE '172.%'
          AND dst_ip NOT LIKE '192.168.%'
          AND dst_ip NOT IN ('51.91.79.17','65.22.162.9','65.22.160.9')  -- exfil
        GROUP BY dst_ip
        HAVING total_conns > 10 AND active_minutes > 5
        ORDER BY active_minutes DESC LIMIT 20
    """)
    lines.append("_High `active_minutes` with moderate `total_conns` suggests periodic beaconing._\n")
    lines.append(_fmt_rows(rows, ["dst_ip", "total_conns", "active_minutes", "first_seen", "last_seen"]))

    return "\n".join(lines)


def _section_timeline(conn: sqlite3.Connection, beachhead_ip: str) -> str:
    lines = ["## 14. Key Event Timeline\n"]
    lines.append("_Rough chronological order — treat timestamps as approximate._\n")
    lines.append("| Timestamp | Event | Source | Destination | Detail |")
    lines.append("|-----------|-------|--------|-------------|--------|")

    # External RDP first contact to beachhead
    row = _q(conn, f"SELECT ts, src_ip, dst_ip, cookie FROM zeek_rdp WHERE dst_ip='{beachhead_ip}' AND src_ip NOT LIKE '10.%' ORDER BY ts LIMIT 1")
    if row and not hasattr(row[0], "_error"):
        r = row[0]
        lines.append(f"| {r[0]} | First external RDP to patient zero | {r[1]} | {r[2]} | cookie={r[3]} |")

    # First Kerberos from beachhead
    if _table_exists(conn, "zeek_kerberos"):
        row = _q(conn, f"SELECT ts, src_ip, dst_ip, client_name, request_type FROM zeek_kerberos WHERE src_ip='{beachhead_ip}' ORDER BY ts LIMIT 1")
        if row and not hasattr(row[0], "_error") and row[0][0]:
            r = row[0]
            lines.append(f"| {r[0]} | First Kerberos from beachhead | {r[1]} | {r[2]} | client={r[3]} type={r[4]} |")

    # First DCE-RPC from beachhead
    row = _q(conn, f"SELECT ts, src_ip, dst_ip, operation FROM zeek_dce_rpc WHERE src_ip='{beachhead_ip}' ORDER BY ts LIMIT 1")
    if row and not hasattr(row[0], "_error") and row[0][0]:
        r = row[0]
        lines.append(f"| {r[0]} | First DCE-RPC from beachhead | {r[1]} | {r[2]} | op={r[3]} |")

    # First SMB from beachhead
    row = _q(conn, f"SELECT ts, src_ip, dst_ip, filename, command FROM zeek_smb WHERE src_ip='{beachhead_ip}' ORDER BY ts LIMIT 1")
    if row and not hasattr(row[0], "_error") and row[0][0]:
        r = row[0]
        lines.append(f"| {r[0]} | First SMB from beachhead | {r[1]} | {r[2]} | file={r[3]} cmd={r[4]} |")

    # delete.me first wave
    row = _q(conn, f"SELECT MIN(ts), COUNT(DISTINCT dst_ip) FROM zeek_smb WHERE src_ip='{beachhead_ip}' AND filename='delete.me'")
    if row and row[0][0]:
        lines.append(f"| {row[0][0]} | delete.me probe (Wave 1) | {beachhead_ip} | {row[0][1]} hosts | write-test |")

    # DNS query for temp.sh
    row = _q(conn, "SELECT ts, src_ip, answers FROM zeek_dns WHERE query='temp.sh' ORDER BY ts LIMIT 1")
    if row and not hasattr(row[0], "_error") and row[0][0]:
        r = row[0]
        lines.append(f"| {r[0]} | DNS query for temp.sh | {r[1]} | DNS | resolved={r[2]} |")

    # First TLS to temp.sh
    row = _q(conn, "SELECT ts, src_ip, dst_ip, version FROM zeek_ssl WHERE server_name='temp.sh' ORDER BY ts LIMIT 1")
    if row and not hasattr(row[0], "_error") and row[0][0]:
        r = row[0]
        lines.append(f"| {r[0]} | First TLS session to temp.sh | {r[1]} | {r[2]} | TLS {r[3]} |")

    # First payload file
    row = _q(conn, "SELECT ts, src_ip, dst_ip, filename FROM zeek_smb WHERE filename='kkwlo.exe' ORDER BY ts LIMIT 1")
    if row and not hasattr(row[0], "_error") and row[0][0]:
        r = row[0]
        lines.append(f"| {r[0]} | kkwlo.exe first seen | {r[1]} | {r[2]} | primary ransomware |")

    # Ransom note
    row = _q(conn, "SELECT ts, src_ip, dst_ip FROM zeek_smb WHERE filename LIKE '%HOW TO BACK%' ORDER BY ts LIMIT 1")
    if row and not hasattr(row[0], "_error") and row[0][0]:
        r = row[0]
        lines.append(f"| {r[0]} | Ransom note first seen | {r[1]} | {r[2]} | encryption complete |")

    # March 8 return RDP
    row = _q(conn, f"SELECT ts, src_ip, dst_ip, cookie FROM zeek_rdp WHERE ts LIKE '2025-03-08%' AND src_ip NOT LIKE '10.%' ORDER BY ts LIMIT 1")
    if row and not hasattr(row[0], "_error") and row[0][0]:
        r = row[0]
        lines.append(f"| {r[0]} | March 8 return RDP | {r[1]} | {r[2]} | cookie={r[3]} |")

    lines.append("")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────────────────────────────────────

def generate_phase2_notes(
    conn: sqlite3.Connection,
    output_path: str,
    beachhead_ip: str = "10.128.239.57",
) -> str:
    """
    Generate the Phase 2 investigation notes Markdown file.

    Returns the notes content as a string (also written to output_path).
    """
    from case_brief import CASE_NAME, CASE_BEACHHEAD_IPS
    if CASE_BEACHHEAD_IPS:
        beachhead_ip = CASE_BEACHHEAD_IPS[0]

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    sections = [
        f"# Phase 2 Investigation Notes — {CASE_NAME}\n",
        f"_Generated: {now}_\n",
        "> **Purpose:** Pre-computed DB analysis for investigation reference and LLM worker context.\n",
        "> Timestamps should be treated as approximate until cross-validated.\n\n",
        "---\n",
        _section_summary(conn),
        "---\n",
        _section_alerts(conn),
        "---\n",
        _section_rdp_spray(conn, beachhead_ip),
        "---\n",
        _section_kerberos(conn, beachhead_ip),
        "---\n",
        _section_dcerpc(conn, beachhead_ip),
        "---\n",
        _section_smb(conn, beachhead_ip),
        "---\n",
        _section_dns(conn),
        "---\n",
        _section_tls(conn),
        "---\n",
        _section_dhcp(conn),
        "---\n",
        _section_weird(conn),
        "---\n",
        _section_multi_protocol_burst(conn, beachhead_ip),
        "---\n",
        _section_ntlm(conn),
        "---\n",
        _section_exfil_volume(conn),
        "---\n",
        _section_beaconing(conn),
        "---\n",
        _section_timeline(conn, beachhead_ip),
    ]

    content = "\n".join(sections)

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(content, encoding="utf-8")
    print(f"  [Phase2Notes] Written {len(content):,} chars to {output_path}")

    return content
