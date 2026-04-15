# Network Forensic Framework — Complete Build Plan
**Target output:** NTU SC4063-style report (4 sections: Initial Access, Lateral Movement, Exfiltration, Payload Deployment) with full attacker timeline, IOC tables, MITRE ATT&CK mapping, and evidence-backed narrative.

**Data inputs:** ~30 GB Zeek JSON logs, ~50 GB PCAPs, supplementary Suricata EVE JSON.

**Architecture:** Hybrid Method 1 + Method 2. Use Method 1's rapid Zeek-only IOC triage (first 2–3 hours) to seed your IOC list, then commit to Method 2's structured SQLite pipeline and multi-agent LLM report assembly.

---

## Phase 0 — Environment Setup

### 0.1 Directory Structure

```
/forensics/
├── raw/
│   ├── zeek/           # Your Zeek JSON log files (~30 GB)
│   ├── pcap/           # Your PCAP files (~50 GB)
│   └── suricata/       # Suricata EVE JSON
├── db/
│   └── forensics.db    # SQLite database (built in Phase 2)
├── ioc/
│   ├── ioc_seed.json   # Phase 1 output: your initial IOC list
│   └── ioc_expanded.json
├── findings/
│   ├── section_A.md
│   ├── section_B.md
│   ├── section_C.md
│   └── section_D.md
├── extracted/          # tshark-extracted PCAP subsets
├── scripts/            # All your Python scripts live here
└── report/
    └── final_report.md
```

### 0.2 Tool Installation

```bash
# Python packages
pip install duckdb sqlite3 ijson orjson tqdm rich colorama

# System tools — verify versions before Phase 4
tshark --version     # Bug exists in 4.6.4 (http.request_number zeroed). Use 4.2.x or 4.4.x if possible.
capinfos --version
jq --version
ripgrep --version    # rg

# Install ripgrep if missing
sudo apt-get install ripgrep
```

### 0.3 Verify Zeek Log Format

**Critical check before any parsing.** Phase 2's ripgrep scan assumes one JSON object per line (Filebeat/Elastic export format). Run this to verify:

```bash
head -5 /forensics/raw/zeek/conn.log
```

**If you see:** `{"ts":1735747507.989,"uid":"...","id.orig_h":"..."...}` → you're in **NDJSON format** (one object per line). Proceed normally.

**If you see:** Multi-line JSON, or Zeek's native TSV format (lines starting with `#fields`, `#types`, tab-separated) → you need a format conversion step before Phase 2:

```bash
# Convert Zeek TSV to NDJSON using zeek-cut + jq or zeek-to-json
# For TSV:
python scripts/convert_zeek_tsv.py /forensics/raw/zeek/ /forensics/raw/zeek_json/
```

---

## Phase 1 — Rapid Zeek Triage (Method 1 Spirit, 2–3 Hours)

**Goal:** Extract your IOC seed list before touching PCAPs. This feeds Phase 2's ripgrep filter. Do NOT skip this.

### 1.1 Script: `scripts/phase1_zeek_triage.py`

This script streams Zeek logs using `ijson` (memory-safe for 30 GB), extracts indicators, and writes a Markdown investigation note and a JSON IOC seed.

```python
#!/usr/bin/env python3
"""
Phase 1: Rapid Zeek triage — IOC extraction, no PCAPs.
Streams logs with ijson to stay within memory limits.
Output: ioc/ioc_seed.json + findings/phase1_notes.md
"""

import ijson
import json
import os
import re
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime
import ipaddress

# ─── CONFIG ───────────────────────────────────────────────
ZEEK_DIR = Path("/forensics/raw/zeek")
IOC_OUT  = Path("/forensics/ioc/ioc_seed.json")
NOTES_OUT = Path("/forensics/findings/phase1_notes.md")

# Internal subnet — adjust to your environment
INTERNAL_SUBNET = ipaddress.ip_network("10.128.239.0/24")

# Known-suspicious external IP to probe (from your context: AnyNet backdoor)
PROBE_IPS = {"92.38.177.14"}

# Beacon detection: flag sources with >30 connections to single external dest
BEACON_THRESHOLD = 30

# Ports considered "weird" if seen on non-standard services
WEIRD_PORTS = {4444, 5555, 8888, 9999, 31337, 1337, 6666}
# ──────────────────────────────────────────────────────────

def is_external(ip_str):
    try:
        return ipaddress.ip_address(ip_str) not in INTERNAL_SUBNET
    except ValueError:
        return False

def stream_ndjson(filepath):
    """Stream a newline-delimited JSON file one record at a time."""
    with open(filepath, 'rb') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue

# ─── COLLECTORS ───────────────────────────────────────────
suspicious_ips = set()
external_rdp_sources = Counter()   # IP -> count of RDP connections to internal
kerberos_failures = []
dce_rpc_suspicious = []
smb_interesting_files = []
ssl_no_sni = []
dns_top = Counter()
beaconing_candidates = []          # (src, dst, count)
conn_state_summary = Counter()
internal_scan_sources = defaultdict(set)  # src -> set of dst IPs (for multi-target detection)
multi_protocol_bursts = defaultdict(set)  # src -> set of protocols

# ─── CONN LOG ─────────────────────────────────────────────
print("[*] Parsing zeek/conn.log ...")
src_dst_counter = defaultdict(int)
for rec in stream_ndjson(ZEEK_DIR / "conn.log"):
    src = rec.get("id.orig_h", "")
    dst = rec.get("id.resp_h", "")
    dport = rec.get("id.resp_p", 0)
    state = rec.get("conn_state", "")
    proto = rec.get("proto", "")
    
    conn_state_summary[state] += 1
    
    # Track what protocols each src uses (for BloodHound/NetExec burst detection)
    multi_protocol_bursts[src].add(proto + str(dport))
    
    # Beacon candidates: count (src, dst) pairs
    pair = (src, dst)
    src_dst_counter[pair] += 1
    
    # Internal scan detection: one internal src hitting many internal dsts on same port
    if not is_external(src) and not is_external(dst):
        internal_scan_sources[f"{src}:{dport}"].add(dst)
    
    # Flag weird ports
    if dport in WEIRD_PORTS:
        suspicious_ips.add(src)
        suspicious_ips.add(dst)

# Beacon candidates: high-frequency periodic pairs to external
for (src, dst), count in src_dst_counter.items():
    if count >= BEACON_THRESHOLD and is_external(dst):
        beaconing_candidates.append((src, dst, count))
        suspicious_ips.add(src)
        suspicious_ips.add(dst)

# Internal scanners: one host touching >20 internal targets on same port
scan_results = {k: v for k, v in internal_scan_sources.items() if len(v) > 20}

# Multi-protocol burst hosts (>5 distinct protocol+port combos = NetExec/BloodHound candidate)
burst_hosts = {src: protos for src, protos in multi_protocol_bursts.items() if len(protos) > 5}

# ─── RDP LOG ──────────────────────────────────────────────
print("[*] Parsing zeek/rdp.log ...")
rdp_cookies = defaultdict(list)  # cookie -> [src IPs]
rdp_external = []
for rec in stream_ndjson(ZEEK_DIR / "rdp.log"):
    src = rec.get("id.orig_h", "")
    dst = rec.get("id.resp_h", "")
    cookie = rec.get("cookie", "")
    result = rec.get("result", "")
    cert_count = rec.get("cert_count", 0)
    ts = rec.get("ts", 0)
    
    if is_external(src):
        rdp_external.append({
            "ts": ts, "src": src, "dst": dst,
            "cookie": cookie, "result": result, "cert_count": cert_count
        })
        external_rdp_sources[src] += 1
        if cookie:
            rdp_cookies[cookie].append(src)
        suspicious_ips.add(src)

rdp_external.sort(key=lambda x: x["ts"])

# ─── KERBEROS LOG ─────────────────────────────────────────
print("[*] Parsing zeek/kerberos.log ...")
kerberos_events = []
for rec in stream_ndjson(ZEEK_DIR / "kerberos.log"):
    success = rec.get("success", True)
    error   = rec.get("error_msg", "")
    client  = rec.get("client", "")
    service = rec.get("service", "")
    cipher  = rec.get("cipher", "")
    ts      = rec.get("ts", 0)
    src     = rec.get("id.orig_h", "")
    
    kerberos_events.append({
        "ts": ts, "src": src, "client": client,
        "service": service, "success": success,
        "error": error, "cipher": cipher
    })
    
    # Escalation pattern: machine account → krbtgt (Kerberoasting / Golden Ticket prep)
    if service and "krbtgt" in service.lower():
        suspicious_ips.add(src)
    
    # RC4 cipher (downgrade attack indicator)
    if cipher and "rc4" in cipher.lower():
        suspicious_ips.add(src)

kerberos_events.sort(key=lambda x: x["ts"])

# ─── DCE_RPC LOG ──────────────────────────────────────────
print("[*] Parsing zeek/dce_rpc.log ...")
for rec in stream_ndjson(ZEEK_DIR / "dce_rpc.log"):
    endpoint  = rec.get("endpoint", "")
    operation = rec.get("operation", "")
    named_pipe = rec.get("named_pipe", "")
    src = rec.get("id.orig_h", "")
    dst = rec.get("id.resp_h", "")
    ts  = rec.get("ts", 0)
    
    # DCSync indicators: DRSUAPI DsGetNCChanges
    if operation in ("DsGetNCChanges", "DsCrackNames", "DsBind") or \
       endpoint in ("drsuapi", "samr") or \
       (named_pipe and named_pipe in ("lsass", "netlogon")):
        dce_rpc_suspicious.append({
            "ts": ts, "src": src, "dst": dst,
            "endpoint": endpoint, "operation": operation, "pipe": named_pipe
        })
        suspicious_ips.add(src)

# ─── SMB FILES LOG ────────────────────────────────────────
print("[*] Parsing zeek/smb_files.log ...")
INTERESTING_SMB = re.compile(
    r'(\.exe|\.ps1|\.bat|\.vbs|ManageEngine|TeamCity|delete\.me|'
    r'HOW TO|kkwlo|hfs|Microsofts|backup|\.7z|\.zip)',
    re.IGNORECASE
)
for rec in stream_ndjson(ZEEK_DIR / "smb_files.log"):
    name = rec.get("name", "")
    path = rec.get("path", "")
    action = rec.get("action", "")
    size = rec.get("size", 0)
    src  = rec.get("id.orig_h", "")
    dst  = rec.get("id.resp_h", "")
    ts   = rec.get("ts", 0)
    
    full = f"{path}\\{name}"
    if INTERESTING_SMB.search(full):
        smb_interesting_files.append({
            "ts": ts, "src": src, "dst": dst,
            "path": full, "action": action, "size": size
        })

# ─── SSL LOG ──────────────────────────────────────────────
print("[*] Parsing zeek/ssl.log ...")
ssl_to_probe = []
for rec in stream_ndjson(ZEEK_DIR / "ssl.log"):
    sni  = rec.get("server_name", "")
    estab = rec.get("established", False)
    resumed = rec.get("resumed", False)
    src  = rec.get("id.orig_h", "")
    dst  = rec.get("id.resp_h", "")
    ts   = rec.get("ts", 0)
    
    if not sni and estab:
        ssl_no_sni.append({"ts": ts, "src": src, "dst": dst})
    
    if dst in PROBE_IPS:
        ssl_to_probe.append({"ts": ts, "src": src, "dst": dst, "sni": sni})
        suspicious_ips.add(src)

# ─── DNS LOG ──────────────────────────────────────────────
print("[*] Parsing zeek/dns.log ...")
for rec in stream_ndjson(ZEEK_DIR / "dns.log"):
    qname = rec.get("query", "")
    if qname:
        dns_top[qname] += 1

# ─── DHCP LOG ─────────────────────────────────────────────
print("[*] Parsing zeek/dhcp.log ...")
dhcp_map = {}  # IP -> {hostname, mac}
for rec in stream_ndjson(ZEEK_DIR / "dhcp.log"):
    ip  = rec.get("assigned_ip", "")
    mac = rec.get("mac", "")
    hn  = rec.get("host_name", "")
    if ip:
        dhcp_map[ip] = {"hostname": hn, "mac": mac}

# ─── WEIRD LOG ────────────────────────────────────────────
print("[*] Parsing zeek/weird.log ...")
weird_events = []
for rec in stream_ndjson(ZEEK_DIR / "weird.log"):
    name = rec.get("name", "")
    src  = rec.get("id.orig_h", "")
    ts   = rec.get("ts", 0)
    weird_events.append({"ts": ts, "name": name, "src": src})
    suspicious_ips.add(src)

# ─── HTTP LOG (large downloads) ───────────────────────────
print("[*] Parsing zeek/http.log for large transfers ...")
large_http = []
for rec in stream_ndjson(ZEEK_DIR / "http.log"):
    resp_bytes = rec.get("resp_body_len", 0) or 0
    req_bytes  = rec.get("request_body_len", 0) or 0
    if resp_bytes > 10_000_000 or req_bytes > 10_000_000:  # >10 MB
        large_http.append({
            "ts": rec.get("ts", 0),
            "src": rec.get("id.orig_h", ""),
            "dst": rec.get("id.resp_h", ""),
            "uri": rec.get("uri", ""),
            "host": rec.get("host", ""),
            "resp_bytes": resp_bytes,
            "req_bytes": req_bytes
        })

# ─── WRITE IOC SEED JSON ──────────────────────────────────
ioc_seed = {
    "generated_at": datetime.utcnow().isoformat(),
    "suspicious_ips": sorted(list(suspicious_ips)),
    "external_rdp_sources": dict(external_rdp_sources.most_common(20)),
    "rdp_cookies": {k: v for k, v in rdp_cookies.items() if k},
    "top_dns_queries": dict(dns_top.most_common(50)),
    "beaconing_candidates": sorted(beaconing_candidates, key=lambda x: -x[2])[:20],
    "internal_scan_candidates": {k: len(v) for k, v in scan_results.items()},
    "multi_protocol_burst_hosts": {k: len(v) for k, v in burst_hosts.items()},
    "dhcp_hostname_map": dhcp_map,
    "smb_interesting_files": sorted(smb_interesting_files, key=lambda x: x["ts"])[:200],
    "kerberos_events": sorted(kerberos_events, key=lambda x: x["ts"])[:500],
    "dce_rpc_suspicious": sorted(dce_rpc_suspicious, key=lambda x: x["ts"])[:200],
    "ssl_no_sni": ssl_no_sni[:100],
    "ssl_to_probe_ips": ssl_to_probe,
    "weird_events": sorted(weird_events, key=lambda x: x["ts"])[:100],
    "large_http_transfers": sorted(large_http, key=lambda x: -x["req_bytes"])[:50],
    "conn_state_summary": dict(conn_state_summary),
    "rdp_external_events": rdp_external[:200],
}

IOC_OUT.parent.mkdir(parents=True, exist_ok=True)
with open(IOC_OUT, 'w') as f:
    json.dump(ioc_seed, f, indent=2, default=str)

print(f"[+] IOC seed written: {IOC_OUT}")

# ─── WRITE PHASE 1 MARKDOWN NOTES ─────────────────────────
lines = []
lines.append("# Phase 1 Investigation Notes\n")
lines.append(f"_Generated: {datetime.utcnow().isoformat()} UTC_\n\n")

lines.append("## Suspicious IPs\n")
for ip in sorted(suspicious_ips):
    hn = dhcp_map.get(ip, {}).get("hostname", "")
    lines.append(f"- `{ip}` {('— ' + hn) if hn else ''}\n")

lines.append("\n## External RDP Sources (Top 20)\n")
for ip, cnt in external_rdp_sources.most_common(20):
    lines.append(f"- `{ip}` — {cnt} connections\n")

lines.append("\n## RDP Cookies Observed\n")
for cookie, srcs in sorted(rdp_cookies.items()):
    lines.append(f"- `{cookie}` from: {', '.join(set(srcs))}\n")

lines.append("\n## Beaconing Candidates (>30 connections to single external)\n")
for src, dst, cnt in sorted(beaconing_candidates, key=lambda x: -x[2])[:20]:
    lines.append(f"- `{src}` → `{dst}` — {cnt} connections\n")

lines.append("\n## Internal Scan Sources (hitting >20 hosts on same port)\n")
for key, cnt in scan_results.items():
    lines.append(f"- `{key}` — {cnt} targets\n")

lines.append("\n## Interesting SMB Files\n")
lines.append("| Timestamp | Src | Dst | Path | Action | Size |\n")
lines.append("|-----------|-----|-----|------|--------|------|\n")
for f in sorted(smb_interesting_files, key=lambda x: x["ts"])[:50]:
    ts_str = datetime.utcfromtimestamp(f["ts"]).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines.append(f"| {ts_str} | {f['src']} | {f['dst']} | `{f['path']}` | {f['action']} | {f['size']} |\n")

lines.append("\n## Top DNS Queries\n")
for q, cnt in dns_top.most_common(30):
    lines.append(f"- `{q}` — {cnt}\n")

lines.append("\n## Suspicious DCE-RPC Operations\n")
lines.append("| Timestamp | Src | Dst | Endpoint | Operation | Pipe |\n")
lines.append("|-----------|-----|-----|----------|-----------|------|\n")
for r in sorted(dce_rpc_suspicious, key=lambda x: x["ts"])[:50]:
    ts_str = datetime.utcfromtimestamp(r["ts"]).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines.append(f"| {ts_str} | {r['src']} | {r['dst']} | {r['endpoint']} | {r['operation']} | {r['pipe']} |\n")

lines.append("\n## Kerberos Events (First 50)\n")
lines.append("| Timestamp | Src | Client | Service | Success | Cipher |\n")
lines.append("|-----------|-----|--------|---------|---------|--------|\n")
for k in sorted(kerberos_events, key=lambda x: x["ts"])[:50]:
    ts_str = datetime.utcfromtimestamp(k["ts"]).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines.append(f"| {ts_str} | {k['src']} | {k['client']} | {k['service']} | {k['success']} | {k['cipher']} |\n")

NOTES_OUT.parent.mkdir(parents=True, exist_ok=True)
with open(NOTES_OUT, 'w') as f:
    f.writelines(lines)

print(f"[+] Phase 1 notes written: {NOTES_OUT}")
print(f"\n[SUMMARY]")
print(f"  Suspicious IPs found:      {len(suspicious_ips)}")
print(f"  External RDP sources:      {len(external_rdp_sources)}")
print(f"  Beaconing candidates:      {len(beaconing_candidates)}")
print(f"  Interesting SMB files:     {len(smb_interesting_files)}")
print(f"  Suspicious DCE-RPC ops:    {len(dce_rpc_suspicious)}")
```

### 1.2 Run Phase 1

```bash
python scripts/phase1_zeek_triage.py
```

**Expected runtime:** 20–40 minutes for 30 GB.

### 1.3 Review Output

```bash
# Read your notes
cat /forensics/findings/phase1_notes.md | head -200

# Check your IOC seed
cat /forensics/ioc/ioc_seed.json | python3 -m json.tool | head -100

# Find your beachhead host (should be most active internal scanner)
jq '.internal_scan_candidates | to_entries | sort_by(-.value) | .[0:5]' /forensics/ioc/ioc_seed.json
```

**After this step you should know:**
- The beachhead IP (patient zero)
- The initial external attacker IP
- Key time windows (earliest suspicious activity timestamp)
- Key domain controllers targeted
- Whether exfiltration IPs appear in DNS or SSL logs

---

## Phase 2 — Database Ingestion (SQLite, 17 Tables)

**Goal:** Load all Zeek logs and Suricata alerts into a queryable SQLite database with indexed IOC columns. This is the source of truth for all downstream analysis and LLM queries.

### 2.1 Schema: `scripts/phase2_schema.sql`

```sql
-- Run this first to create all 17 tables

CREATE TABLE IF NOT EXISTS conn (
    ts REAL, uid TEXT, src_ip TEXT, src_port INTEGER,
    dst_ip TEXT, dst_port INTEGER, proto TEXT,
    service TEXT, duration REAL, orig_bytes INTEGER,
    resp_bytes INTEGER, conn_state TEXT,
    orig_pkts INTEGER, resp_pkts INTEGER,
    PRIMARY KEY (ts, uid)
);

CREATE TABLE IF NOT EXISTS rdp (
    ts REAL, uid TEXT, src_ip TEXT, dst_ip TEXT,
    result TEXT, cookie TEXT, cert_count INTEGER,
    security_protocol TEXT
);

CREATE TABLE IF NOT EXISTS kerberos (
    ts REAL, uid TEXT, src_ip TEXT, dst_ip TEXT,
    client TEXT, service TEXT, success BOOLEAN,
    error_msg TEXT, cipher TEXT
);

CREATE TABLE IF NOT EXISTS dce_rpc (
    ts REAL, uid TEXT, src_ip TEXT, dst_ip TEXT,
    endpoint TEXT, operation TEXT, named_pipe TEXT
);

CREATE TABLE IF NOT EXISTS smb_files (
    ts REAL, uid TEXT, src_ip TEXT, dst_ip TEXT,
    action TEXT, name TEXT, path TEXT, size INTEGER
);

CREATE TABLE IF NOT EXISTS smb_mapping (
    ts REAL, uid TEXT, src_ip TEXT, dst_ip TEXT,
    path TEXT, service TEXT, share_type TEXT, native_file_system TEXT
);

CREATE TABLE IF NOT EXISTS ssl (
    ts REAL, uid TEXT, src_ip TEXT, dst_ip TEXT,
    version TEXT, cipher TEXT, server_name TEXT,
    established BOOLEAN, resumed BOOLEAN, cert_chain_fuids TEXT
);

CREATE TABLE IF NOT EXISTS dns (
    ts REAL, uid TEXT, src_ip TEXT, dst_ip TEXT,
    query TEXT, qtype TEXT, rcode TEXT, answers TEXT
);

CREATE TABLE IF NOT EXISTS http (
    ts REAL, uid TEXT, src_ip TEXT, dst_ip TEXT,
    method TEXT, host TEXT, uri TEXT, user_agent TEXT,
    status_code INTEGER, resp_body_len INTEGER, request_body_len INTEGER
);

CREATE TABLE IF NOT EXISTS dhcp (
    ts REAL, uid TEXT, client_ip TEXT, assigned_ip TEXT,
    hostname TEXT, mac TEXT, msg_types TEXT
);

CREATE TABLE IF NOT EXISTS weird (
    ts REAL, uid TEXT, src_ip TEXT, dst_ip TEXT,
    name TEXT, addl TEXT, notice BOOLEAN
);

CREATE TABLE IF NOT EXISTS ntlm (
    ts REAL, uid TEXT, src_ip TEXT, dst_ip TEXT,
    username TEXT, domainname TEXT, hostname TEXT,
    success BOOLEAN, status TEXT
);

CREATE TABLE IF NOT EXISTS suricata (
    ts TEXT, src_ip TEXT, src_port INTEGER,
    dst_ip TEXT, dst_port INTEGER, proto TEXT,
    alert_action TEXT, alert_signature TEXT,
    alert_category TEXT, alert_severity INTEGER,
    app_proto TEXT
);

CREATE TABLE IF NOT EXISTS pcap_metadata (
    filename TEXT, start_time REAL, end_time REAL,
    packet_count INTEGER, file_size_mb REAL,
    PRIMARY KEY (filename)
);

CREATE TABLE IF NOT EXISTS ioc_ips (
    ip TEXT PRIMARY KEY, role TEXT, confidence TEXT,
    first_seen REAL, notes TEXT
);

CREATE TABLE IF NOT EXISTS ioc_domains (
    domain TEXT PRIMARY KEY, role TEXT, confidence TEXT,
    first_seen REAL, notes TEXT
);

CREATE TABLE IF NOT EXISTS protected_records (
    record_type TEXT, src_ip TEXT, dst_ip TEXT,
    ts REAL, data_json TEXT, reason TEXT
);

-- Indexes on key columns used in WHERE clauses
CREATE INDEX IF NOT EXISTS idx_conn_src ON conn(src_ip);
CREATE INDEX IF NOT EXISTS idx_conn_dst ON conn(dst_ip);
CREATE INDEX IF NOT EXISTS idx_conn_ts  ON conn(ts);
CREATE INDEX IF NOT EXISTS idx_smb_src  ON smb_files(src_ip);
CREATE INDEX IF NOT EXISTS idx_smb_name ON smb_files(name);
CREATE INDEX IF NOT EXISTS idx_ssl_sni  ON ssl(server_name);
CREATE INDEX IF NOT EXISTS idx_dns_query ON dns(query);
CREATE INDEX IF NOT EXISTS idx_suri_sig ON suricata(alert_signature);
CREATE INDEX IF NOT EXISTS idx_kerberos_client ON kerberos(client);
CREATE INDEX IF NOT EXISTS idx_dce_op   ON dce_rpc(operation);
```

### 2.2 Ingestion Script: `scripts/phase2_ingest.py`

```python
#!/usr/bin/env python3
"""
Phase 2: Stream-ingest all Zeek and Suricata logs into SQLite.
Uses IOC seed from Phase 1 to populate ioc_ips table.
Uses reservoir sampling (500K cap) for conn table to stay manageable.
"""

import sqlite3
import json
import os
import random
from pathlib import Path
from datetime import datetime
from tqdm import tqdm

DB_PATH    = Path("/forensics/db/forensics.db")
ZEEK_DIR   = Path("/forensics/raw/zeek")
SURI_DIR   = Path("/forensics/raw/suricata")
IOC_SEED   = Path("/forensics/ioc/ioc_seed.json")
SCHEMA_SQL = Path("/forensics/scripts/phase2_schema.sql")

CONN_RESERVOIR_SIZE = 500_000  # Cap on conn table rows
BATCH_SIZE = 5_000

def stream_ndjson(filepath):
    with open(filepath, 'rb') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue

def ingest_table(db, table, rows):
    """Batch-insert rows dict into table."""
    if not rows:
        return
    cols = list(rows[0].keys())
    placeholders = ",".join(["?"] * len(cols))
    col_str = ",".join(cols)
    sql = f"INSERT OR IGNORE INTO {table} ({col_str}) VALUES ({placeholders})"
    vals = [[r.get(c) for c in cols] for r in rows]
    db.executemany(sql, vals)

def main():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(str(DB_PATH))
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=NORMAL")
    db.execute("PRAGMA cache_size=-500000")  # 500 MB cache

    # Apply schema
    with open(SCHEMA_SQL) as f:
        db.executescript(f.read())
    db.commit()

    # Load IOC seed
    with open(IOC_SEED) as f:
        ioc = json.load(f)

    # Populate ioc_ips from seed
    for ip in ioc.get("suspicious_ips", []):
        db.execute(
            "INSERT OR IGNORE INTO ioc_ips (ip, role, confidence) VALUES (?, ?, ?)",
            (ip, "suspicious", "medium")
        )
    # Mark known external attacker IPs
    for ip in ioc.get("external_rdp_sources", {}).keys():
        db.execute(
            "INSERT OR REPLACE INTO ioc_ips (ip, role, confidence) VALUES (?, ?, ?)",
            (ip, "external_rdp_source", "high")
        )
    db.commit()
    print("[+] IOC IPs seeded into ioc_ips table")

    # ── INGEST EACH LOG TYPE ─────────────────────────────────────────

    log_map = {
        "conn.log":       ("conn",    ["ts","uid","id.orig_h","id.orig_p","id.resp_h","id.resp_p",
                                        "proto","service","duration","orig_bytes","resp_bytes",
                                        "conn_state","orig_pkts","resp_pkts"]),
        "rdp.log":        ("rdp",     ["ts","uid","id.orig_h","id.resp_h","result","cookie",
                                        "cert_count","security_protocol"]),
        "kerberos.log":   ("kerberos",["ts","uid","id.orig_h","id.resp_h","client","service",
                                        "success","error_msg","cipher"]),
        "dce_rpc.log":    ("dce_rpc", ["ts","uid","id.orig_h","id.resp_h","endpoint","operation",
                                        "named_pipe"]),
        "smb_files.log":  ("smb_files",["ts","uid","id.orig_h","id.resp_h","action","name",
                                         "path","size"]),
        "smb_mapping.log":("smb_mapping",["ts","uid","id.orig_h","id.resp_h","path","service",
                                           "share_type","native_file_system"]),
        "ssl.log":        ("ssl",     ["ts","uid","id.orig_h","id.resp_h","version","cipher",
                                        "server_name","established","resumed","cert_chain_fuids"]),
        "dns.log":        ("dns",     ["ts","uid","id.orig_h","id.resp_h","query","qtype",
                                        "rcode","answers"]),
        "http.log":       ("http",    ["ts","uid","id.orig_h","id.resp_h","method","host","uri",
                                        "user_agent","status_code","resp_body_len","request_body_len"]),
        "dhcp.log":       ("dhcp",    ["ts","uid","client_ip","assigned_ip","host_name","mac",
                                        "msg_types"]),
        "weird.log":      ("weird",   ["ts","uid","id.orig_h","id.resp_h","name","addl","notice"]),
        "ntlm.log":       ("ntlm",    ["ts","uid","id.orig_h","id.resp_h","username","domainname",
                                        "hostname","success","status"]),
    }

    # Column rename map: Zeek field names → DB column names
    rename = {
        "id.orig_h": "src_ip", "id.orig_p": "src_port",
        "id.resp_h": "dst_ip", "id.resp_p": "dst_port",
        "host_name": "hostname"
    }

    for filename, (table, zeek_fields) in log_map.items():
        filepath = ZEEK_DIR / filename
        if not filepath.exists():
            print(f"[!] Skipping {filename} (not found)")
            continue

        print(f"[*] Ingesting {filename} → {table} ...")
        batch = []
        total = 0
        reservoir = []  # only used for conn
        is_conn = (table == "conn")

        for rec in tqdm(stream_ndjson(filepath)):
            row = {}
            for zf in zeek_fields:
                val = rec.get(zf)
                # Handle nested dot-notation fields
                if val is None and "." in zf:
                    parts = zf.split(".")
                    v = rec
                    for p in parts:
                        v = v.get(p, None) if isinstance(v, dict) else None
                    val = v
                db_col = rename.get(zf, zf.replace(".", "_"))
                row[db_col] = val if not isinstance(val, (list, dict)) else json.dumps(val)
            
            if is_conn:
                # Reservoir sampling for conn table
                total += 1
                if len(reservoir) < CONN_RESERVOIR_SIZE:
                    reservoir.append(row)
                else:
                    j = random.randint(0, total - 1)
                    if j < CONN_RESERVOIR_SIZE:
                        reservoir[j] = row
            else:
                batch.append(row)
                if len(batch) >= BATCH_SIZE:
                    ingest_table(db, table, batch)
                    db.commit()
                    batch = []

        if is_conn:
            print(f"  → Reservoir: {len(reservoir)} / {total} conn records")
            for i in range(0, len(reservoir), BATCH_SIZE):
                ingest_table(db, table, reservoir[i:i+BATCH_SIZE])
            db.commit()
        elif batch:
            ingest_table(db, table, batch)
            db.commit()

        print(f"  ✓ Done.")

    # ── SURICATA ────────────────────────────────────────────────────
    eve_file = SURI_DIR / "eve.json"
    if eve_file.exists():
        print("[*] Ingesting suricata/eve.json → suricata ...")
        batch = []
        for rec in tqdm(stream_ndjson(eve_file)):
            if rec.get("event_type") != "alert":
                continue
            alert = rec.get("alert", {})
            batch.append({
                "ts":               rec.get("timestamp"),
                "src_ip":           rec.get("src_ip"),
                "src_port":         rec.get("src_port"),
                "dst_ip":           rec.get("dest_ip"),
                "dst_port":         rec.get("dest_port"),
                "proto":            rec.get("proto"),
                "alert_action":     alert.get("action"),
                "alert_signature":  alert.get("signature"),
                "alert_category":   alert.get("category"),
                "alert_severity":   alert.get("severity"),
                "app_proto":        rec.get("app_proto"),
            })
            if len(batch) >= BATCH_SIZE:
                ingest_table(db, "suricata", batch)
                db.commit()
                batch = []
        if batch:
            ingest_table(db, "suricata", batch)
            db.commit()
        print("  ✓ Done.")

    # ── PCAP METADATA ──────────────────────────────────────────────
    pcap_dir = Path("/forensics/raw/pcap")
    print("[*] Collecting PCAP metadata with capinfos ...")
    import subprocess
    for pcap in sorted(pcap_dir.glob("*.pcap")):
        try:
            result = subprocess.run(
                ["capinfos", "-T", "-m", str(pcap)],
                capture_output=True, text=True, timeout=60
            )
            # capinfos TSV output: File name, Number of packets, Start time, End time, ...
            lines = result.stdout.strip().split("\n")
            if len(lines) >= 2:
                vals = lines[1].split(",")
                db.execute(
                    "INSERT OR IGNORE INTO pcap_metadata VALUES (?,?,?,?,?)",
                    (
                        pcap.name,
                        float(vals[3]) if len(vals) > 3 else None,  # Start time
                        float(vals[4]) if len(vals) > 4 else None,  # End time
                        int(vals[1]) if len(vals) > 1 else None,    # Packet count
                        pcap.stat().st_size / 1_000_000              # MB
                    )
                )
        except Exception as e:
            print(f"  [!] capinfos failed for {pcap.name}: {e}")
    db.commit()

    db.close()
    print(f"\n[+] Phase 2 complete. Database: {DB_PATH}")
    print(f"    Size: {DB_PATH.stat().st_size / 1_000_000:.1f} MB")

if __name__ == "__main__":
    main()
```

### 2.3 Run Phase 2

```bash
python scripts/phase2_ingest.py
# Expected runtime: 60–120 minutes for 30 GB Zeek logs
# Expected DB size: 5–15 GB depending on log volume
```

---

## Phase 3 — Structured Analysis (SQL Queries + Protected Records)

**Goal:** Run targeted SQL queries against the database to reconstruct the 4-section timeline. Write findings to Markdown as you go.

### 3.1 Core Query Script: `scripts/phase3_analysis.py`

```python
#!/usr/bin/env python3
"""
Phase 3: Structured SQL analysis — runs all pre-built queries,
writes findings to section markdown files.
"""

import sqlite3
import json
from pathlib import Path
from datetime import datetime

DB_PATH   = Path("/forensics/db/forensics.db")
FIND_DIR  = Path("/forensics/findings")
FIND_DIR.mkdir(parents=True, exist_ok=True)

db = sqlite3.connect(str(DB_PATH))
db.row_factory = sqlite3.Row

def run(sql, params=()):
    return [dict(r) for r in db.execute(sql, params).fetchall()]

def ts(epoch):
    if epoch is None:
        return "N/A"
    return datetime.utcfromtimestamp(float(epoch)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

# ══════════════════════════════════════════════════════════════════════
# SECTION A — INITIAL ACCESS
# ══════════════════════════════════════════════════════════════════════
print("[*] Running Section A queries ...")

# A1: External RDP sources, volume and timing
external_rdp = run("""
    SELECT src_ip, COUNT(*) as attempts,
           MIN(ts) as first_seen, MAX(ts) as last_seen,
           GROUP_CONCAT(DISTINCT cookie) as cookies
    FROM rdp
    WHERE src_ip NOT LIKE '10.%' AND src_ip NOT LIKE '192.168.%' AND src_ip NOT LIKE '172.%'
    GROUP BY src_ip
    ORDER BY attempts DESC
    LIMIT 30
""")

# A2: The specific attacker RDP session sequence (credential-bearing)
attacker_rdp = run("""
    SELECT r.ts, r.src_ip, r.dst_ip, r.cookie, r.result,
           r.security_protocol, r.cert_count,
           k.client as kerberos_client, k.service as kerberos_service,
           k.ts as kerberos_ts
    FROM rdp r
    LEFT JOIN kerberos k ON k.src_ip = r.dst_ip
        AND k.ts BETWEEN r.ts AND r.ts + 60
    WHERE r.src_ip NOT LIKE '10.%'
      AND r.cookie IS NOT NULL AND r.cookie != ''
    ORDER BY r.ts
    LIMIT 20
""")

# A3: Kerberos AS requests within 30 seconds of external RDP
post_rdp_kerberos = run("""
    SELECT k.ts, k.src_ip, k.client, k.service, k.success, k.cipher
    FROM kerberos k
    JOIN rdp r ON r.dst_ip = k.src_ip
        AND k.ts BETWEEN r.ts AND r.ts + 30
    WHERE r.src_ip NOT LIKE '10.%'
    ORDER BY k.ts
    LIMIT 20
""")

# A4: First internal pivots from beachhead within 10 minutes of access
# (Edit BEACHHEAD_IP after Phase 1)
BEACHHEAD_IP = None  # Will be populated from ioc_seed
with open("/forensics/ioc/ioc_seed.json") as f:
    ioc = json.load(f)
# Heuristic: most active internal scanner in Phase 1
scan_cands = ioc.get("internal_scan_candidates", {})
if scan_cands:
    BEACHHEAD_IP = max(scan_cands, key=lambda k: scan_cands[k]).split(":")[0]
    print(f"  → Detected beachhead candidate: {BEACHHEAD_IP}")

if BEACHHEAD_IP:
    post_access_ntlm = run("""
        SELECT ts, src_ip, dst_ip, username, domainname, success
        FROM ntlm
        WHERE src_ip = ?
        ORDER BY ts
        LIMIT 30
    """, (BEACHHEAD_IP,))

    first_internal_rdp = run("""
        SELECT ts, src_ip, dst_ip, cookie, result
        FROM rdp
        WHERE src_ip = ?
        ORDER BY ts
        LIMIT 20
    """, (BEACHHEAD_IP,))

# A5: Suricata alerts on the attacker IP
attacker_alerts = run("""
    SELECT ts, src_ip, dst_ip, alert_signature, alert_category, alert_severity
    FROM suricata
    ORDER BY ts
    LIMIT 50
""")

# ── Write Section A ───────────────────────────────────────────────────
with open(FIND_DIR / "section_A.md", "w") as f:
    f.write("# Section A: Initial Access (Patient Zero)\n\n")
    f.write("## External RDP Sources\n\n")
    f.write("| IP | Attempts | First Seen | Last Seen | Cookies |\n")
    f.write("|----|---------:|------------|-----------|----------|\n")
    for r in external_rdp:
        f.write(f"| {r['src_ip']} | {r['attempts']} | {ts(r['first_seen'])} | {ts(r['last_seen'])} | `{r['cookies']}` |\n")
    
    f.write("\n## Credential-Bearing RDP Sessions\n\n")
    f.write("| Timestamp | Src | Dst | Cookie | Kerberos Client | Kerberos Ts |\n")
    f.write("|-----------|-----|-----|--------|-----------------|-------------|\n")
    for r in attacker_rdp:
        f.write(f"| {ts(r['ts'])} | {r['src_ip']} | {r['dst_ip']} | `{r['cookie']}` | {r['kerberos_client']} | {ts(r['kerberos_ts'])} |\n")
    
    f.write("\n## Post-RDP Kerberos (within 30s of external RDP)\n\n")
    for r in post_rdp_kerberos:
        f.write(f"- `{ts(r['ts'])}` — {r['src_ip']} → {r['client']} / {r['service']} (success={r['success']}, cipher={r['cipher']})\n")
    
    if BEACHHEAD_IP:
        f.write(f"\n## Beachhead Host Activity ({BEACHHEAD_IP})\n\n")
        f.write("### NTLM Authentication From Beachhead\n")
        for r in post_access_ntlm:
            f.write(f"- `{ts(r['ts'])}` → {r['dst_ip']} as {r['domainname']}\\{r['username']} (success={r['success']})\n")
        
        f.write("\n### Internal RDP Pivots From Beachhead\n")
        for r in first_internal_rdp:
            f.write(f"- `{ts(r['ts'])}` → {r['dst_ip']} (cookie={r['cookie']}, result={r['result']})\n")
    
    f.write("\n## Suricata Alerts\n\n")
    for r in attacker_alerts:
        f.write(f"- `{r['ts']}` {r['src_ip']} → {r['dst_ip']} | {r['alert_signature']}\n")

print("  ✓ section_A.md written")

# ══════════════════════════════════════════════════════════════════════
# SECTION B — LATERAL MOVEMENT & DISCOVERY
# ══════════════════════════════════════════════════════════════════════
print("[*] Running Section B queries ...")

if BEACHHEAD_IP:
    # B1: SMB connections from beachhead per day
    smb_waves = run("""
        SELECT DATE(ts, 'unixepoch') as date,
               COUNT(*) as connections,
               COUNT(DISTINCT dst_ip) as unique_targets
        FROM conn
        WHERE src_ip = ? AND dst_port = 445
        GROUP BY date
        ORDER BY date
    """, (BEACHHEAD_IP,))

    # B2: SAMR operations
    samr_ops = run("""
        SELECT operation, COUNT(*) as count,
               COUNT(DISTINCT dst_ip) as unique_targets,
               MIN(ts) as first_seen
        FROM dce_rpc
        WHERE src_ip = ?
          AND (endpoint LIKE '%samr%' OR operation LIKE '%Samr%')
        GROUP BY operation
        ORDER BY count DESC
    """, (BEACHHEAD_IP,))

    # B3: Delete.me waves
    delete_me_waves = run("""
        SELECT DATE(ts, 'unixepoch') as date,
               COUNT(*) as events,
               COUNT(DISTINCT dst_ip) as unique_hosts
        FROM smb_files
        WHERE src_ip = ? AND name LIKE '%delete.me%'
        GROUP BY date
        ORDER BY date
    """, (BEACHHEAD_IP,))

    # B4: Interactive RDP sessions from beachhead (identify destinations)
    internal_rdp = run("""
        SELECT dst_ip, COUNT(*) as sessions,
               MIN(ts) as first_seen, MAX(ts) as last_seen
        FROM rdp
        WHERE src_ip = ?
          AND dst_ip LIKE '10.%'
        GROUP BY dst_ip
        ORDER BY first_seen
    """, (BEACHHEAD_IP,))

    # B5: ADMIN$ access
    admin_share_access = run("""
        SELECT ts, src_ip, dst_ip, path, action
        FROM smb_files
        WHERE src_ip = ?
          AND (path LIKE '%ADMIN$%' OR path LIKE '%C$%' OR path LIKE '%SYSVOL%' OR path LIKE '%IPC$%')
        ORDER BY ts
        LIMIT 100
    """, (BEACHHEAD_IP,))

    # B6: Cross-domain DC enumeration
    dc_dce = run("""
        SELECT dst_ip, endpoint, operation, COUNT(*) as count
        FROM dce_rpc
        WHERE src_ip = ?
        GROUP BY dst_ip, endpoint, operation
        ORDER BY count DESC
        LIMIT 30
    """, (BEACHHEAD_IP,))

    with open(FIND_DIR / "section_B.md", "w") as f:
        f.write("# Section B: Lateral Movement & Discovery\n\n")
        
        f.write("## SMB Enumeration Waves\n\n")
        f.write("| Date | Connections | Unique Targets |\n")
        f.write("|------|------------:|---------------:|\n")
        for r in smb_waves:
            f.write(f"| {r['date']} | {r['connections']} | {r['unique_targets']} |\n")
        
        f.write("\n## SAMR Operations\n\n")
        f.write("| Operation | Count | Unique Targets | First Seen |\n")
        f.write("|-----------|------:|---------------:|------------|\n")
        for r in samr_ops:
            f.write(f"| {r['operation']} | {r['count']} | {r['unique_targets']} | {ts(r['first_seen'])} |\n")
        
        f.write("\n## Delete.me Waves\n\n")
        for r in delete_me_waves:
            f.write(f"- **{r['date']}**: {r['events']} events across {r['unique_hosts']} hosts\n")
        
        f.write("\n## Interactive RDP Sessions From Beachhead\n\n")
        f.write("| Destination | Sessions | First Seen | Last Seen |\n")
        f.write("|-------------|:--------:|------------|----------|\n")
        for r in internal_rdp:
            f.write(f"| {r['dst_ip']} | {r['sessions']} | {ts(r['first_seen'])} | {ts(r['last_seen'])} |\n")
        
        f.write("\n## Admin Share Access\n\n")
        for r in admin_share_access[:30]:
            f.write(f"- `{ts(r['ts'])}` → {r['dst_ip']} | `{r['path']}` | {r['action']}\n")
        
        f.write("\n## DCE-RPC to Domain Controllers\n\n")
        f.write("| DC IP | Endpoint | Operation | Count |\n")
        f.write("|-------|----------|-----------|------:|\n")
        for r in dc_dce:
            f.write(f"| {r['dst_ip']} | {r['endpoint']} | {r['operation']} | {r['count']} |\n")

print("  ✓ section_B.md written")

# ══════════════════════════════════════════════════════════════════════
# SECTION C — EXFILTRATION
# ══════════════════════════════════════════════════════════════════════
print("[*] Running Section C queries ...")

# C1: DNS queries suggesting exfiltration domain
exfil_dns = run("""
    SELECT query, COUNT(*) as count,
           MIN(ts) as first_seen, COUNT(DISTINCT src_ip) as sources
    FROM dns
    WHERE query NOT LIKE '%10.%'
      AND query NOT LIKE '%.local'
      AND query NOT LIKE '%.arpa'
    GROUP BY query
    ORDER BY count DESC
    LIMIT 50
""")

# C2: TLS connections to external IPs (potential exfil)
external_tls = run("""
    SELECT dst_ip, server_name,
           COUNT(*) as sessions,
           SUM(CASE WHEN established=1 THEN 1 ELSE 0 END) as established_count,
           MIN(ts) as first_seen
    FROM ssl
    WHERE dst_ip NOT LIKE '10.%' AND dst_ip NOT LIKE '192.168.%'
    GROUP BY dst_ip, server_name
    ORDER BY sessions DESC
    LIMIT 30
""")

# C3: Large outbound transfers (conn table)
large_outbound = run("""
    SELECT src_ip, dst_ip, SUM(orig_bytes) as total_bytes,
           COUNT(*) as connections,
           MIN(ts) as first_seen, MAX(ts) as last_seen
    FROM conn
    WHERE dst_ip NOT LIKE '10.%' AND orig_bytes IS NOT NULL
    GROUP BY src_ip, dst_ip
    ORDER BY total_bytes DESC
    LIMIT 20
""")

# C4: SMB file access on file servers (data collection)
if BEACHHEAD_IP:
    file_server_access = run("""
        SELECT dst_ip, COUNT(*) as access_events,
               COUNT(DISTINCT name) as unique_files,
               MIN(ts) as first_access
        FROM smb_files
        WHERE src_ip = ?
        GROUP BY dst_ip
        ORDER BY access_events DESC
        LIMIT 20
    """, (BEACHHEAD_IP,))

    # C5: Archive files in SMB traffic (staging indicators)
    archive_files = run("""
        SELECT ts, src_ip, dst_ip, name, path, size, action
        FROM smb_files
        WHERE src_ip = ? AND (name LIKE '%.7z' OR name LIKE '%.zip' OR name LIKE '%.tar%')
        ORDER BY ts
    """, (BEACHHEAD_IP,))

with open(FIND_DIR / "section_C.md", "w") as f:
    f.write("# Section C: Data Exfiltration\n\n")
    
    f.write("## External DNS Queries (Potential Exfil Domains)\n\n")
    f.write("| Domain | Queries | First Seen | Sources |\n")
    f.write("|--------|--------:|------------|--------:|\n")
    for r in exfil_dns[:20]:
        f.write(f"| `{r['query']}` | {r['count']} | {ts(r['first_seen'])} | {r['sources']} |\n")
    
    f.write("\n## External TLS Sessions (SNI)\n\n")
    f.write("| Dst IP | SNI | Sessions | Established | First Seen |\n")
    f.write("|--------|-----|:--------:|:-----------:|------------|\n")
    for r in external_tls[:20]:
        f.write(f"| {r['dst_ip']} | `{r['server_name']}` | {r['sessions']} | {r['established_count']} | {ts(r['first_seen'])} |\n")
    
    f.write("\n## Large Outbound Transfers\n\n")
    f.write("| Src | Dst | Total Bytes | Connections | First Seen |\n")
    f.write("|-----|-----|------------:|:-----------:|------------|\n")
    for r in large_outbound:
        mb = (r['total_bytes'] or 0) / 1_000_000
        f.write(f"| {r['src_ip']} | {r['dst_ip']} | {mb:.1f} MB | {r['connections']} | {ts(r['first_seen'])} |\n")
    
    if BEACHHEAD_IP:
        f.write("\n## File Server SMB Access\n\n")
        for r in file_server_access:
            f.write(f"- `{r['dst_ip']}` — {r['access_events']} access events, {r['unique_files']} unique files (first: {ts(r['first_access'])})\n")
        
        f.write("\n## Archive Files in SMB Traffic\n\n")
        for r in archive_files:
            f.write(f"- `{ts(r['ts'])}` | {r['src_ip']} → {r['dst_ip']} | `{r['path']}\\{r['name']}` | {r['size']} bytes | {r['action']}\n")

print("  ✓ section_C.md written")

# ══════════════════════════════════════════════════════════════════════
# SECTION D — PAYLOAD DEPLOYMENT
# ══════════════════════════════════════════════════════════════════════
print("[*] Running Section D queries ...")

if BEACHHEAD_IP:
    # D1: Suricata executable transfer alerts
    exe_alerts = run("""
        SELECT ts, src_ip, dst_ip, alert_signature, alert_category
        FROM suricata
        WHERE alert_signature LIKE '%Executable%' OR alert_signature LIKE '%exe%'
        ORDER BY ts
        LIMIT 100
    """)

    # D2: Suspicious executables in SMB
    suspicious_exes = run("""
        SELECT ts, src_ip, dst_ip, name, path, size, action
        FROM smb_files
        WHERE src_ip = ?
          AND (name LIKE '%.exe' OR name LIKE '%.ps1' OR name LIKE '%.dll' OR name LIKE '%.bat')
        ORDER BY ts
    """, (BEACHHEAD_IP,))

    # D3: bkrp_BackupKey credential access
    backup_key_access = run("""
        SELECT ts, src_ip, dst_ip, endpoint, operation, named_pipe
        FROM dce_rpc
        WHERE operation LIKE '%BackupKey%' OR named_pipe LIKE '%lsass%'
        ORDER BY ts
    """)

    # D4: Inbound RDP session to beachhead (attacker returning)
    inbound_rdp_to_beachhead = run("""
        SELECT ts, src_ip, dst_ip, cookie, result,
               (SELECT ts FROM rdp r2 WHERE r2.src_ip = rdp.src_ip AND r2.ts > rdp.ts ORDER BY r2.ts LIMIT 1) - ts as session_duration_approx
        FROM rdp
        WHERE dst_ip = ?
          AND src_ip NOT LIKE '10.%'
        ORDER BY ts
    """, (BEACHHEAD_IP,))

    # D5: UninstallWinClient.exe or security tool uninstall indicators
    defense_evasion = run("""
        SELECT ts, src_ip, dst_ip, name, path, action
        FROM smb_files
        WHERE src_ip = ?
          AND (name LIKE '%Uninstall%' OR name LIKE '%disable%' OR name LIKE '%defender%')
        ORDER BY ts
    """, (BEACHHEAD_IP,))

    with open(FIND_DIR / "section_D.md", "w") as f:
        f.write("# Section D: Payload Deployment\n\n")
        
        f.write("## Suricata: Executable Transfer Alerts\n\n")
        for r in exe_alerts[:30]:
            f.write(f"- `{r['ts']}` {r['src_ip']} → {r['dst_ip']} | {r['alert_signature']}\n")
        
        f.write("\n## Suspicious Executables in SMB\n\n")
        f.write("| Timestamp | Src | Dst | File | Size | Action |\n")
        f.write("|-----------|-----|-----|------|-----:|--------|\n")
        for r in suspicious_exes:
            f.write(f"| {ts(r['ts'])} | {r['src_ip']} | {r['dst_ip']} | `{r['path']}\\{r['name']}` | {r['size']} | {r['action']} |\n")
        
        f.write("\n## Credential/Backup Key Access\n\n")
        for r in backup_key_access:
            f.write(f"- `{ts(r['ts'])}` {r['src_ip']} → {r['dst_ip']} | {r['operation']} via `{r['named_pipe']}`\n")
        
        f.write("\n## Inbound Attacker RDP to Beachhead\n\n")
        for r in inbound_rdp_to_beachhead:
            f.write(f"- `{ts(r['ts'])}` from {r['src_ip']} | cookie=`{r['cookie']}` | result={r['result']}\n")
        
        f.write("\n## Defense Evasion Indicators\n\n")
        for r in defense_evasion:
            f.write(f"- `{ts(r['ts'])}` → {r['dst_ip']} | `{r['name']}` | {r['action']}\n")

print("  ✓ section_D.md written")
db.close()
print("\n[+] Phase 3 analysis complete. Check /forensics/findings/")
```

---

## Phase 4 — Targeted PCAP Deep-Dive

**Goal:** Only touch PCAPs to confirm or deepen what the Zeek+SQL analysis found. Do NOT scan all 50 GB.

### 4.1 Check tshark Version

```bash
tshark --version
# If 4.6.4: http.request_number field is bugged (zeroed). Use alternatives:
#   - Use 'frame.number' instead
#   - Install tshark 4.2.x: sudo apt-get install -t stable tshark
```

### 4.2 Identify Relevant PCAPs

```bash
# Check which PCAP files overlap your key time windows from Phase 3
sqlite3 /forensics/db/forensics.db \
  "SELECT filename, datetime(start_time,'unixepoch'), datetime(end_time,'unixepoch'), packet_count FROM pcap_metadata ORDER BY start_time;"
```

### 4.3 Filter Script: `scripts/phase4_pcap.sh`

```bash
#!/bin/bash
# Phase 4: Targeted PCAP extractions
# Edit BEACHHEAD, ATTACKER_IP, EXFIL_IP before running

BEACHHEAD="10.128.239.57"      # ← from Phase 1/3
ATTACKER_IP="195.211.190.189"  # ← from Phase 1/3
EXFIL_IP="51.91.79.17"         # ← from Phase 3 (DNS → temp.sh)
PCAP_DIR="/forensics/raw/pcap"
OUT_DIR="/forensics/extracted"
mkdir -p "$OUT_DIR"

# ── SECTION A: Initial RDP access ────────────────────────────────
echo "[*] Extracting initial RDP access ..."
for pcap in "$PCAP_DIR"/*.pcap; do
    tshark -r "$pcap" -Y "ip.addr == $ATTACKER_IP && tcp.port == 3389" \
           -w "$OUT_DIR/A_initial_rdp.pcap" 2>/dev/null
done

# Extract RDP cookies from initial access
tshark -r "$OUT_DIR/A_initial_rdp.pcap" \
       -Y "rdp.rt_cookie" \
       -T fields -e frame.time -e ip.src -e ip.dst -e rdp.rt_cookie \
       > "$OUT_DIR/A_rdp_cookies.txt"

# ── SECTION B: SAMR enumeration packets ──────────────────────────
echo "[*] Extracting SAMR enumeration ..."
for pcap in "$PCAP_DIR"/*.pcap; do
    tshark -r "$pcap" \
           -Y "ip.src == $BEACHHEAD && (samr || dcerpc)" \
           -w "$OUT_DIR/B_samr_enum.pcap" 2>/dev/null
done

# Extract SAMR operation names
tshark -r "$OUT_DIR/B_samr_enum.pcap" \
       -Y "samr" \
       -T fields -e frame.time -e ip.src -e ip.dst -e samr.opnum \
       > "$OUT_DIR/B_samr_ops.txt"

# RDP SYN scan (March 8)
echo "[*] Extracting RDP port scan ..."
for pcap in "$PCAP_DIR"/*.pcap; do
    tshark -r "$pcap" \
           -Y "ip.src == $BEACHHEAD && tcp.dstport == 3389 && tcp.flags.syn == 1 && tcp.flags.ack == 0" \
           -T fields -e frame.time -e ip.dst \
           >> "$OUT_DIR/B_rdp_syn_scan.txt"
done
sort "$OUT_DIR/B_rdp_syn_scan.txt" | uniq -c | sort -rn | head -50

# ── SECTION C: Exfiltration traffic ──────────────────────────────
echo "[*] Extracting exfiltration traffic ..."
for pcap in "$PCAP_DIR"/*.pcap; do
    tshark -r "$pcap" \
           -Y "ip.addr == $EXFIL_IP" \
           -w "$OUT_DIR/C_exfil_traffic.pcap" 2>/dev/null
done

# TCP statistics for exfil flow
tshark -r "$OUT_DIR/C_exfil_traffic.pcap" \
       -q -z "conv,tcp,ip.addr==$BEACHHEAD && ip.addr==$EXFIL_IP" \
       > "$OUT_DIR/C_exfil_tcp_stats.txt"

# TLS SNI verification
tshark -r "$OUT_DIR/C_exfil_traffic.pcap" \
       -Y "tls.handshake.type == 1" \
       -T fields -e frame.time -e ip.src -e ip.dst \
       -e tls.handshake.extensions.server_name \
       > "$OUT_DIR/C_tls_sni.txt"

# Extract readable strings for archive filenames (look for .7z, .zip in early TLS frames)
tshark -r "$OUT_DIR/C_exfil_traffic.pcap" \
       -T fields -e data.text 2>/dev/null | strings | grep -i '\.zip\|\.7z\|\.tar' \
       > "$OUT_DIR/C_archive_names.txt"

# ── SECTION D: SMB executable transfers ──────────────────────────
echo "[*] Extracting SMB executable transfers ..."
for pcap in "$PCAP_DIR"/*.pcap; do
    tshark -r "$pcap" \
           -Y "ip.src == $BEACHHEAD && smb2" \
           -w "$OUT_DIR/D_smb_transfers.pcap" 2>/dev/null
done

# Extract filenames from SMB2 Find/Create responses
tshark -r "$OUT_DIR/D_smb_transfers.pcap" \
       -Y "smb2.filename" \
       -T fields -e frame.time -e ip.src -e ip.dst -e smb2.filename \
       | grep -i '\.exe\|\.ps1\|\.dll\|kkwlo\|hfs\|Microsofts' \
       > "$OUT_DIR/D_suspicious_files.txt"

# TCP stream of specific suspicious executable transfer (find stream number first)
# tshark -r "$OUT_DIR/D_smb_transfers.pcap" -Y "smb2.filename contains 'kkwlo'" \
#        -T fields -e tcp.stream | head -1
# Then: tshark -r <pcap> -q -z "follow,tcp,ascii,<STREAM_NUMBER>"

# ── SECTION D: Ransom note presence ──────────────────────────────
echo "[*] Searching for ransom note strings ..."
for pcap in "$PCAP_DIR"/*.pcap; do
    tshark -r "$pcap" -T fields -e data.text 2>/dev/null \
    | strings | grep -i 'HOW TO BACK\|YOUR FILES\|DECRYPT\|ransom' \
    >> "$OUT_DIR/D_ransom_strings.txt"
done

echo "[+] Phase 4 extractions complete. Check: $OUT_DIR"
ls -lh "$OUT_DIR/"
```

```bash
chmod +x scripts/phase4_pcap.sh
bash scripts/phase4_pcap.sh
```

### 4.4 Verify PCAP Timestamps

```bash
# IMPORTANT: capinfos timestamps are not always reliable
# Use as approximate window only — Zeek timestamps are more authoritative
capinfos /forensics/raw/pcap/*.pcap | grep -E "First packet|Last packet|File name"
```

---

## Phase 5 — LLM-Assisted Analysis and Report Generation

**Goal:** Feed structured Markdown findings (not raw 30 GB) to an LLM to correlate events, fill analytical gaps, and draft the final report.

### 5.1 What to Feed the LLM

**Do feed:**
- `/forensics/findings/section_A.md` (~5–20 KB)
- `/forensics/findings/section_B.md`
- `/forensics/findings/section_C.md`
- `/forensics/findings/section_D.md`
- `/forensics/findings/phase1_notes.md`
- Specific tshark output files from Phase 4 (each <10 KB)

**Do NOT feed:**
- Raw Zeek JSON files (30 GB — context window overflow)
- Raw PCAPs
- The full SQLite database

### 5.2 LLM Prompt Templates

Use these prompts with your LLM for each section:

**For Section A (Initial Access):**

```
You are a network forensics analyst writing a formal incident report in the style of the DFIR Report.

Below is structured evidence extracted from Zeek logs and PCAPs for a ransomware intrusion.
Your task is to write Section A (Initial Access) of the report.

Requirements:
- Identify patient zero (beachhead host IP and hostname if known)
- Identify the external attacker IP and first-seen timestamp
- Explain credential validation sequence (RDP cookie → Kerberos AS timing)
- Note any Suricata alerts or lack thereof
- Include a formatted IOC table: Type | Value | Context | First Seen
- Include a detailed timeline table: Timestamp | Src | Dst | Activity | Evidence Source
- Map to MITRE ATT&CK techniques (T-codes)
- Write in formal investigative prose, not bullet points

Evidence:
[PASTE section_A.md content here]
```

**For Section B (Lateral Movement):**

```
You are writing Section B (Lateral Movement & Discovery) of a network forensics report.

Based on the structured evidence below:
- Identify and number the discovery waves (date, SMB conn count, SAMR packet count, unique targets)
- Document ADMIN$ access to domain controllers (evidence of authenticated lateral movement)
- Document interactive RDP sessions to internal hosts
- Map cross-domain infrastructure (list DC IPs, domain names, evidence source)
- Include a MITRE ATT&CK mapping table
- Note what is NOT observed (e.g., no account creation in SAMR) and explain why (e.g., local GUI ops not visible on network)

Evidence:
[PASTE section_B.md content here]
```

**For the Master Timeline:**

```
Below are four sections of evidence from a network forensics investigation.
Create a master chronological timeline table with these columns:
Date/Time (UTC) | Phase | Activity | Evidence Source

Rules:
- One row per distinct event (not per log entry)
- Use Zeek timestamps as authoritative (not PCAP if they conflict)
- Label phase as: Reconnaissance | Initial Access | Credential Validation | Discovery | Lateral Movement | Exfil Staging | Exfiltration | Payload Transfer | Defense Evasion | Impact
- Include the specific evidence type (Zeek rdp, Zeek kerberos, Suricata, PCAP tshark, etc.)

Evidence:
[PASTE all four section markdown files]
```

### 5.3 Iterative LLM Loop

For each gap in your analysis, use this loop:

1. Identify the gap (e.g., "I can see the exfil IP but don't know what files were uploaded")
2. Run the targeted SQL query to get raw data
3. Feed raw data + context to LLM
4. LLM suggests next filter or explains the finding
5. Add finding to the relevant section Markdown
6. Repeat

```python
# Example: Ask LLM to suggest the next tshark filter
prompt = f"""
I am investigating exfiltration to 51.91.79.17 (temp.sh).
I have confirmed 11 TLS 1.3 sessions and 1,033 MB outbound.
I want to see if any archive filenames leaked before full TLS encryption.

My tshark version: 4.4.2
Extracted PCAP: C_exfil_traffic.pcap (contains only flows to/from 51.91.79.17)

Suggest the exact tshark command to extract any pre-encryption HTTP metadata 
(form field names, Content-Disposition headers) that might reveal archive filenames.
"""
```

---

## Phase 6 — Report Assembly

### 6.1 Report Structure (Mirror the Target Report)

```
/forensics/report/final_report.md

# [Client Name] Network Security Incident Report

## A. Initial Access (Patient Zero)
   A.1 Pre-Intrusion Reconnaissance and Probing
   A.1.1 External Reconnaissance Activity
   A.1.2 Credential Testing and Validation
   A.1.3 Suricata and Detection Context
   → IOC Table A.2
   → Timeline Table A.3

## B. Lateral Movement & Discovery
   B.1 Overview
   B.2 Discovery
      B.2.1 Discovery Waves and Scale
      B.2.2 Active Directory and Directory Enumeration
      B.2.3 RDP Port Scanning
      B.2.4 Cross-Domain Infrastructure Mapping
   B.3 Lateral Movement
      B.3.1 Administrative Share Access
      B.3.2 Movement into Domain Infrastructure
      B.3.3 Interactive RDP Sessions
   B.4 MITRE ATT&CK Mapping

## C. Data Exfiltration (Double Extortion)
   C.1 Overview
   C.2 Network Infrastructure Identification
   C.3 DNS Resolution Evidence
   C.4 TLS Connection Evidence
   C.5 Data Volume Analysis
   C.6 Compromised Data Identification
   C.7 Archive Compression and Staging
   C.8 Encryption and Analytical Limitations

## D. Payload Deployment
   D.1 Overview
   D.2 How the Payload was Deployed
   D.3 Reconnaissance before Payload Deployment
   D.4 Payload Transfer
   D.5 Impact (Final Encryption)

## MITRE ATT&CK Master Mapping

## Conclusion and Recommendations
   Critical (48–72 hours)
   High Priority (1–2 weeks)
   Medium Priority (1–3 months)
   Strategic (3–6 months)

## Appendix: Master Timeline
## Appendix: Full IOC List
```

### 6.2 Assembly Script: `scripts/phase6_assemble.py`

```python
#!/usr/bin/env python3
"""
Phase 6: Assemble all section findings into final_report.md
with consistent formatting.
"""

from pathlib import Path
from datetime import datetime

FIND_DIR  = Path("/forensics/findings")
REPORT    = Path("/forensics/report/final_report.md")
REPORT.parent.mkdir(parents=True, exist_ok=True)

sections = [
    ("A. Initial Access (Patient Zero)", FIND_DIR / "section_A.md"),
    ("B. Lateral Movement & Discovery",  FIND_DIR / "section_B.md"),
    ("C. Data Exfiltration",             FIND_DIR / "section_C.md"),
    ("D. Payload Deployment",            FIND_DIR / "section_D.md"),
]

with open(REPORT, "w") as out:
    out.write(f"# Network Forensics Incident Report\n")
    out.write(f"_Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}_\n\n")
    out.write("---\n\n")
    
    for title, path in sections:
        if path.exists():
            content = path.read_text()
            out.write(content)
            out.write("\n\n---\n\n")
        else:
            out.write(f"## {title}\n\n_Section not yet completed._\n\n---\n\n")

print(f"[+] Report assembled: {REPORT}")
print(f"    Size: {REPORT.stat().st_size / 1024:.1f} KB")
```

---

## Appendix A — Critical Notes and Gotchas

### Data Format Verification (Do First)

```bash
# Determine your actual Zeek log format before Phase 1
head -3 /forensics/raw/zeek/conn.log
# NDJSON: {"ts":..., "id.orig_h":...}
# TSV: #separator \t
#       #set_separator ,
#       #fields ts  uid  id.orig_h  id.orig_p  ...
```

If TSV: the ripgrep approach in Phase 2 will return wrong results. Convert with `zeek-cut` first.

### Reservoir Sampling Implication

The 500K cap on the `conn` table means early connections may be statistically dropped. For rare protocols (dce_rpc, rdp, kerberos, smb_files) this is not an issue — those tables are ingested in full. The reservoir only applies to conn (the high-volume table). If you need exact results for conn, remove the reservoir and expect a much larger DB.

### Timestamp Reliability

- **Zeek timestamps**: Most reliable. Use as primary source.
- **PCAP timestamps**: Can be offset by capture hardware clock drift. Use `capinfos` to check, but treat as approximate ±minutes.
- **Suricata timestamps**: Generally reliable but may differ slightly from Zeek for the same flow.

### What Network Evidence Cannot Show

The following attacker actions are invisible to network sensors and will require host forensics if available:

- Local account creation via dsa.msc (AD Users and Computers GUI) — no network SAMR call
- Actual ransomware encryption (file I/O on local disk)
- Local credential dumping via Task Manager or process injection
- Clipboard content during RDP sessions

Document these gaps explicitly in the report as analytical limitations.

### tshark Filter Reference

```bash
# RDP sessions with cookies
tshark -r file.pcap -Y "rdp.rt_cookie" -T fields -e ip.src -e ip.dst -e rdp.rt_cookie

# SAMR operations (for MITRE T1087.002)
tshark -r file.pcap -Y "samr" -T fields -e frame.time -e ip.src -e ip.dst -e samr.opnum

# TLS SNI verification
tshark -r file.pcap -Y "tls.handshake.type==1" -T fields -e ip.dst -e tls.handshake.extensions.server_name

# Verify NO account creation (zero results = network-invisible, not non-existent)
tshark -r file.pcap -Y "samr.opnum==12 || samr.opnum==22 || samr.opnum==37"

# TCP byte totals for exfil calculation
tshark -r file.pcap -q -z "conv,tcp,ip.addr==<INTERNAL> && ip.addr==<EXFIL>"

# SMB filenames (find ransomware executables)
tshark -r file.pcap -Y "smb2.filename" -T fields -e frame.time -e ip.src -e ip.dst -e smb2.filename
```

---

## Appendix B — End-to-End Run Order

```bash
# 0. Setup
mkdir -p /forensics/{raw/{zeek,pcap,suricata},db,ioc,findings,extracted,scripts,report}
# Place Zeek logs in /forensics/raw/zeek/
# Place PCAPs in /forensics/raw/pcap/
# Place Suricata eve.json in /forensics/raw/suricata/

# 1. Verify format
head -3 /forensics/raw/zeek/conn.log

# 2. Phase 1 (~20–40 min)
python scripts/phase1_zeek_triage.py
# Review: cat /forensics/findings/phase1_notes.md | head -100

# 3. Phase 2 (~60–120 min)
python scripts/phase2_ingest.py
# Verify: sqlite3 /forensics/db/forensics.db "SELECT name, count(*) FROM sqlite_master WHERE type='table';"

# 4. Phase 3 (edit BEACHHEAD_IP if auto-detection fails, ~5 min)
python scripts/phase3_analysis.py

# 5. Phase 4 (edit IPs in script, ~30–60 min depending on PCAPsize)
bash scripts/phase4_pcap.sh

# 6. LLM analysis (interactive — use prompts from Phase 5 section)
# Feed each section Markdown to your LLM, get back polished prose
# Save LLM output back into the same section_*.md files

# 7. Phase 6: Assemble report
python scripts/phase6_assemble.py
# Final report: /forensics/report/final_report.md
```

---

*Total estimated runtime: 3–5 hours compute + 3–6 hours analyst review and LLM iteration.*
