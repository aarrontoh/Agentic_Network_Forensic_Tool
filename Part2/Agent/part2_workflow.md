# SC4063 Part 2 — Agentic Network Forensic Workflow

**Last updated:** 2026-04-13  
**Case:** Apex Global Logistics ransomware incident  
**Entry point:** `agent.py run --network-dir <path> --case <name> --reasoner multi-agent`

---

## Overview

The agent runs an **8-phase pipeline** split into two stages:

- **Phases 1–4 (Ingest):** Parse raw evidence into structured artifacts. Results are cached in `ingest/` — re-runs skip these phases unless `--force-refresh` is passed.
- **Phases 5–8 (Multi-Agent Analysis):** Load into SQLite → autonomous LLM agents query the DB → timeline → dual-LLM report synthesis.

```
Raw Evidence
  ├── *alert*.json   (584 MB Suricata EVE, ~162K alerts)
  ├── *zeek*.json    (30 GB Zeek logs, ~14M records)
  └── pcap/          (129 PCAP files, ~51 GB)
        │
        ▼
  Phase 1: Alert Ingestion      → ingest/alerts.json
  Phase 2: Zeek Correlation     → ingest/zeek_records.json
  Phase 3: PCAP Index           → ingest/pcap_index.json
  Phase 4: Deep tshark          → ingest/pcap_analysis.json
        │
        ▼
  Phase 5: SQLite Database (17 tables)
        │
        ▼
  Phase 6: Multi-Agent Investigation (Workers A / B / C / D)
        │
        ▼
  Phase 7: Timeline Assembly
        │
        ▼
  Phase 8: Dual-LLM Report Synthesis
        │
        ▼
  Output: report_synthesized.md (GPT-4o)
          report_commonstack.md (Claude Opus 4.6)
          report.md (deterministic fallback)
          findings.json / timeline.json / agent_log.json
```

---

## Phase 1 — Alert Ingestion

**File:** `tools/alert_reader.py`  
**Orchestrated by:** `tools/ingest.py`  
**Input:** `*alert*.json` (Suricata EVE alerts exported from Elastic/Filebeat)  
**Output:** `ingest/alerts.json` (cached)

### What it does
- Streams all Suricata EVE alerts line by line (584 MB file, ~162K alerts)
- Categorises each alert into one of: `c2`, `trojan`, `lateral`, `scan`, `policy`, `other`
- Extracts **IOC sets**:
  - Unique suspicious IPs (external + internal) → `ioc_ips`
  - Network community IDs from alerts → `ioc_community_ids`
  - Separates "infra IPs" (DNS resolvers, legitimate CDN) from attacker IPs
- Outputs per-category alert lists and counts

### Output artifact keys
```
alert_total              — total alert count
alert_ioc_external_ips   — external (attacker/C2) IPs from alerts
alert_ioc_internal_ips   — internal IPs flagged by alerts
alert_ioc_all_ips        — combined IOC set (infra-filtered)
alert_ioc_all_ips_unfiltered — full unfiltered IOC set (used for Phase 4 tshark filter)
alert_community_ids      — community IDs from all alerts
alert_categories         — dict of category → count
alerts_c2                — list of all C2 alerts
alerts_trojan            — list of all trojan alerts
alerts_lateral           — etc.
```

### Example result
112,500 C2 alerts, 26,032 trojan alerts, 8,000+ lateral alerts

---

## Phase 2 — Zeek Correlation

**File:** `tools/zeek_searcher.py`  
**Orchestrated by:** `tools/ingest.py`  
**Input:** `*zeek*.json` (30 GB Zeek logs from Elastic/Filebeat)  
**Output:** `ingest/zeek_records.json` (cached)

### Strategy: grep + Python (not full parse)
1. All IOC IPs (formatted as `"x.x.x.x"` with quotes to prevent substring match) written to a temp pattern file
2. `ripgrep` / `grep -F -f` performs Aho-Corasick multi-pattern scan at I/O speed — filters 30 GB → tens of MB in ~30s
3. Only matched lines are parsed with `json.loads()` in Python
4. Python-side verification eliminates grep false positives
5. **Well-known exfil service IPs** are hardcoded into the IOC set regardless of alerts:
   - `51.91.79.17`, `65.22.162.9`, `65.22.160.9` — temp.sh (OVH)
   - `144.76.136.153`, `144.76.136.154` — file.io
   - `95.216.22.32` — transfer.sh
6. Community ID grep is disabled — too many matches; IP-based filtering is sufficient

### Internal IP detection
Uses fast string prefix check (not Python `ipaddress` module which OOM'd at 9M records):
```python
_INTERNAL_PREFIXES = ("10.", "172.16.", ..., "192.168.", "127.", "0.")
def _is_external_ip(ip: str) -> bool:
    return bool(ip) and not ip.startswith(_INTERNAL_PREFIXES)
```

### Reservoir Sampling (per-protocol cap: 500,000)
Each protocol bucket capped at 500K records via reservoir sampling to prevent memory exhaustion. Ensures records from all time periods are represented (not just early records).

### Protected Records (exempt from sampling cap, capped at 10,000 per bucket)
Critical rare records are kept regardless of the 500K cap:
- **Exfil IPs:** Records involving `51.91.79.17`, `65.22.162.9`, `65.22.160.9`, `144.76.136.153/154`, `95.216.22.32`
- **Exfil hostnames:** DNS/TLS/HTTP records containing `temp.sh`, `file.io`, `transfer.sh`, `gofile`, `anonfiles`, `mega.nz`
- **Beachhead-external:** RDP/SSL/Kerberos sessions between beachhead `10.128.239.57` and external IPs
- **Beachhead conn:** TCP/3389 connections to beachhead from external (capped at 10,000 per bucket via `MAX_PROTECTED_PER_BUCKET`)

### Protocol buckets collected
`conn`, `dns`, `ssl`, `http`, `dce_rpc`, `rdp`, `smb_mapping`, `smb_files`, `weird`, `kerberos`, `dhcp`, `notice`, `other`

### Output artifact keys
```
zeek_conn     — connection records
zeek_dns      — DNS query records
zeek_ssl      — TLS/SSL session records
zeek_http     — HTTP request records
zeek_dce_rpc  — DCE-RPC operation records
zeek_rdp      — RDP session records
zeek_smb      — SMB file access records (merged from smb_mapping + smb_files)
```

---

## Phase 3 — PCAP Index

**File:** `tools/pcap_selector.py`  
**Orchestrated by:** `tools/ingest.py`  
**Input:** `pcap/` directory (129 PCAPs, ~51 GB)  
**Output:** `ingest/pcap_index.json` (cached)

### What it does
- Runs `capinfos` in parallel (up to 6 threads) on every PCAP to extract:
  - Exact packet start/end timestamps (`earliest`, `latest`)
  - Packet count
  - File size in bytes
- Falls back to filename-derived date (`34936-sensor-YYMMDD-...`) if capinfos unavailable
- Results cached in `pcap/pcap_index_cache.json` — invalidated if PCAP file set changes

### PCAP selection
**ALL 129 PCAPs are selected for Phase 4** — previously the selector filtered by alert timestamps, but this was changed to all-inclusive because:
- temp.sh DNS/TLS records occurred outside alert time windows
- SMB file access and exfil traffic was being missed
- The manual team processed all 129 PCAPs; 8 tshark threads makes this manageable

```python
# ingest.py — always select all PCAPs
targeted_pcaps = [e["path"] for e in pcap_index]
```

### Output artifact keys
```
pcap_index       — list of dicts with path, name, size_bytes, date, earliest, latest, packet_count
pcap_count       — total number of PCAPs indexed
targeted_pcaps   — list of paths to process in Phase 4 (= all PCAPs)
```

---

## Phase 4 — Deep PCAP Analysis

**File:** `tools/pcap_deep_analysis.py`  
**Orchestrated by:** `tools/ingest.py`  
**Input:** All 129 PCAPs from `targeted_pcaps`  
**Output:** `ingest/pcap_analysis.json` (cached)  
**Parallelism:** 8 tshark worker threads (`PCAP_THREADS=8`)  
**Timeout:** 600s per tshark call

### IP filter construction
- Up to 200 IPs in the tshark display filter (`_MAX_FILTER_IPS = 200`)
- Budget split: up to 96 internal IOC IPs reserved first, then external IPs fill remaining slots
- Beachhead IPs (`CASE_BEACHHEAD_IPS`) always added regardless of alerts
- Separate `internal_clause` built from internal IOC IPs only — used for SMB/RDP/DCE-RPC extractors

### 10 extractors per PCAP (run sequentially per PCAP, PCAPs run in parallel)

| Extractor | tshark Display Filter | Fields Extracted | Purpose |
|-----------|----------------------|-----------------|---------|
| `_extract_dns` | `dns && (ioc_ips \|\| exfil_domains)` | frame.time_epoch, ip.src/dst, dns.qry.name, dns.a, dns.aaaa, dns.resp.type, dns.flags.response | All DNS including exfil queries |
| `_extract_http` | `http && ip` | frame.time_epoch, ip.src/dst, http.host, http.request.uri, http.request.method, http.response.code, http.content_length_header | Web exfil, HFS staging server |
| `_extract_tls` | `tls.handshake.type == 1` | frame.time_epoch, ip.src/dst, tls.handshake.extensions_server_name, tls.handshake.version, tcp.dstport | Encrypted sessions SNI extraction |
| `_extract_smb` | `smb \|\| smb2` (internal_clause) | frame.time_epoch, ip.src/dst, smb.cmd, smb2.cmd, smb.file, smb2.filename, smb2.find.pattern, smb2.tree, smb2.fid | File access: kkwlo.exe, user_db_export.json, .vbk/.vib files |
| `_extract_rdp` | `tcp.dstport == 3389` | frame.time_epoch, ip.src/dst, tcp.srcport, tcp.dstport, rdp.rt_cookie | Initial access & lateral RDP (cookie = lgallegos) |
| `_extract_tcp_conversations` | `-z conv,tcp` (tshark stats mode) | src/dst address:port, bytes A↔B, frames, duration | Exfil volume measurement (bypasses TLS 1.3 zero-byte issue in Zeek) |
| `_extract_dns_srv` | `dns.flags.response == 1 && dns.resp.type == 33` | frame.time_epoch, ip.src/dst, dns.qry.name, dns.srv.name, dns.srv.port, dns.srv.priority, dns.srv.weight | DC discovery via `_ldap._tcp.dc._msdcs.*`, `_kerberos._tcp.*` |
| `_extract_dcerpc` | `dcerpc` (internal_clause) | frame.time_epoch, ip.src/dst, dcerpc.opnum, dcerpc.cn_bind_if, dcerpc.cn_bind_if_ver | SAMR enumeration, LSARPC, DRSUAPI (DCSync detection): opnum 5 on DRSUAPI UUID sets `is_dcsync_indicator=1` |
| `_extract_smb_tree` | `smb2.cmd == 3` (internal_clause) | frame.time_epoch, ip.src/dst, smb2.tree | Share access: `\\DC\SYSVOL`, `\\DC\ADMIN$`, `\\DC\C$` — deduped per (src, dst, tree) |
| `_extract_netbios` | `nbns \|\| netbios` (internal_clause) | frame.time_epoch, ip.src/dst, nbns.name, nbns.addr, nbns.flags.opcode, nbns.type | Hostname & workgroup discovery |

### Per-extractor record caps (global across all PCAPs)

| Extractor | Cap |
|-----------|-----|
| dns | 50,000 |
| http | 20,000 |
| tls | 50,000 |
| smb | 400,000 |
| rdp | 10,000 |
| tcp_conv | 50,000 |
| dns_srv | 10,000 |
| dcerpc | 100,000 |
| smb_tree | 50,000 |
| netbios | 20,000 |

Caps are enforced under a thread lock — each thread fills from its local results until the global cap is reached.

### DCSync detection
DRSUAPI interface UUID `e3514235-4b06-11d1-ab04-00c04fc2dcd2`, opnum 5 = `DsGetNCChanges`. Sets `is_dcsync_indicator = 1` on the record.

### Known fix
`http.request_number` was an invalid field in tshark 4.6.4 — it caused the entire HTTP extraction to return 0 rows for every PCAP (tshark exits non-zero when any field is invalid). Removed.

### Output artifact keys
```
pcap_dns_queries        — DNS query/response records
pcap_http_requests      — HTTP request records
pcap_tls_sessions       — TLS ClientHello records with SNI
pcap_smb_sessions       — SMB/SMB2 file access records
pcap_rdp_sessions       — RDP sessions with rdp.rt_cookie
pcap_tcp_conversations  — TCP conversation byte volume stats
pcap_dns_srv_records    — DNS SRV records for DC discovery
pcap_dcerpc_calls       — DCE-RPC calls with DCSync indicators
pcap_smb_tree_connects  — SMB2 Tree Connect (share names)
pcap_netbios_records    — NetBIOS/NBNS hostname records
pcap_analysis_errors    — tshark error messages per PCAP
pcaps_deeply_analyzed   — list of PCAP paths actually processed
```

---

## Phase 5 — SQLite Database Loading

**Files:** `db/schema.py`, `db/ingest_db.py`  
**Output:** `forensic_evidence.db` (17 tables)  
**SQLite settings:** WAL journal mode, NORMAL synchronous (performance-tuned for read-heavy workload)

All Phase 1–4 artifacts are inserted into a structured SQLite database. Workers query this — never the raw JSON files. This solves the LLM token-limit problem: agents ask precise SQL questions and receive only the rows they need.

### Database Tables

| Table | Source | Contents |
|-------|--------|----------|
| `alerts` | Phase 1 | All Suricata EVE alerts with categories, IPs, community IDs, severity |
| `zeek_conn` | Phase 2 | Network connection records with bytes, duration, conn_state, ASN |
| `zeek_dns` | Phase 2 | DNS queries and responses with answers |
| `zeek_ssl` | Phase 2 | TLS/SSL sessions with SNI (server_name), version, subject, issuer |
| `zeek_http` | Phase 2 | HTTP request records with user_agent, status codes |
| `zeek_dce_rpc` | Phase 2 | DCE-RPC operations (endpoint, operation, named_pipe) |
| `zeek_rdp` | Phase 2 | RDP session records with cookie field |
| `zeek_smb` | Phase 2 | SMB file access records (command, path, filename, share_type) |
| `pcap_dns` | Phase 4 | DNS records from PCAP extraction |
| `pcap_http` | Phase 4 | HTTP requests from PCAP extraction |
| `pcap_tls` | Phase 4 | TLS ClientHello records with SNI |
| `pcap_smb` | Phase 4 | SMB/SMB2 file access with filenames and smb2_fid |
| `pcap_rdp` | Phase 4 | RDP sessions with `rdp.rt_cookie` |
| `pcap_tcp_conv` | Phase 4 | TCP conversation byte volumes (critical for exfil quantification when zeek_conn shows 0 bytes) |
| `pcap_dns_srv` | Phase 4 | DNS SRV records — DC/Kerberos discovery (`query_name`, `srv_target`, `srv_port`) |
| `pcap_dcerpc` | Phase 4 | DCE-RPC calls — `interface_name` (SAMR/LSARPC/DRSUAPI), `is_dcsync_indicator` |
| `pcap_smb_tree` | Phase 4 | SMB2 Tree Connect — `tree_path` reveals `\\DC\SYSVOL`, `\\DC\ADMIN$` |
| `pcap_netbios` | Phase 4 | NetBIOS/NBNS records — `nb_name` → `nb_addr` hostname resolution |

### Indexes (on common query patterns)
Indexes on: `alerts(src_ip, dst_ip, category, ts)`, `zeek_conn(src_ip, dst_ip, dst_port, ts)`, `zeek_ssl(server_name, src_ip, dst_ip, ts)`, `zeek_dce_rpc(src_ip, operation, named_pipe)`, `zeek_dns(query, src_ip)`, `zeek_smb(src_ip, filename, ts)`, `zeek_rdp(src_ip, dst_ip)`, `pcap_tls(sni)`, `pcap_smb(filename)`, `pcap_rdp(src_ip)`, `pcap_dns_srv(query_name)`, `pcap_dcerpc(src_ip, interface_name, is_dcsync_indicator)`, `pcap_smb_tree(src_ip, tree_path)`, `pcap_netbios(nb_name)`

### Loading
`db/ingest_db.py` → `load_all()` inserts all artifacts in sequence with a progress callback so the dashboard shows real-time DB loading progress. Numeric columns default to `0` if missing; text columns default to `""`.

---

## Phase 6 — Multi-Agent Investigation

**Files:** `agents/manager.py`, `agents/worker.py`, `agents/worker_prompts.py`, `agents/tool_registry.py`  
**LLM Backend:** OpenAI GPT-4o (`LLM_BACKEND=openai`) or Gemini (`LLM_BACKEND=gemini`)  
**Max iterations per worker:** 30  
**Tools available to workers:** `query_db`, `count_rows`, `get_table_info`, `summarize_db`, `submit_finding`

### Tool descriptions
| Tool | What it does |
|------|-------------|
| `query_db(sql)` | Execute a SELECT query; returns rows as list of dicts (max 500 rows) |
| `count_rows(table, where_clause)` | COUNT(*) shortcut |
| `get_table_info(table)` | Returns column names and types for a table |
| `summarize_db()` | Returns row counts for all 17 tables (used to orient the agent at start) |
| `submit_finding(...)` | Submit the structured final finding — ends the worker loop |

Only SELECT queries are accepted — writes are blocked.

### Dispatch Order (Manager)
Workers run in 3 sequential batches — later workers receive prior findings as context:

```
Batch 1 (parallel):            Worker A + Worker B
Batch 2 (sequential, A+B ctx): Worker C
Batch 3 (sequential, A+B+C ctx): Worker D

Cooldown between batches: WORKER_COOLDOWN_SECONDS (default: 5s)
```

### Worker Assignments

| Worker | Question | MITRE Techniques | Key Tables |
|--------|----------|-----------------|------------|
| **A** | How did the attacker gain initial access? | T1133 External Remote Services, T1078 Valid Accounts | `pcap_rdp`, `zeek_rdp`, `zeek_conn`, `zeek_ssl`, `alerts`, `zeek_dce_rpc`, `zeek_smb`, `zeek_dns` |
| **B** | How did the attacker move laterally and enumerate the environment? | T1046 Network Scan, T1021.002 SMB, T1021.003 DCOM, T1087.002 Account Discovery, T1069.002 Domain Groups, T1003.006 DCSync, T1003 DPAPI, T1135 Share Enum, T1018 Remote System Discovery | `zeek_dce_rpc`, `pcap_dcerpc`, `pcap_dns_srv`, `pcap_smb_tree`, `pcap_netbios`, `zeek_conn`, `zeek_smb`, `pcap_smb`, `zeek_rdp`, `pcap_rdp`, `alerts`, `zeek_dns` |
| **C** | How was data exfiltrated? | T1567 Exfiltration to Cloud Storage, T1560 Archive Collected Data, T1039 Data from Network Shared Drive | `pcap_tls`, `pcap_dns`, `zeek_ssl`, `zeek_dns`, `pcap_tcp_conv`, `pcap_http`, `pcap_smb`, `zeek_smb`, `alerts`, `zeek_conn` |
| **D** | How was the ransomware payload delivered and deployed? | T1021.001 RDP, T1021.002 SMB, T1570 Lateral Tool Transfer, T1562.001 Disable Security Tools, T1486 Data Encrypted for Impact | `pcap_smb`, `pcap_rdp`, `zeek_rdp`, `zeek_smb`, `zeek_conn`, `alerts`, `zeek_dce_rpc` |

### Worker Loop (per worker)
```
Iteration 1–26:  query_db / count_rows / get_table_info / summarize_db freely
Iteration 27:    nudge injected — "start wrapping up, submit within 3-4 calls"
Iteration 30:    FINAL WARNING — tool_choice forced to submit_finding
```

### Guardrails
- **Read-only SQL:** Only `SELECT` statements accepted — write operations rejected
- **No hallucination:** Every claim must cite tool query results
- **Forced submission:** If agent doesn't call `submit_finding` by iteration 30, it is forced to call it
- **Anti-hallucination for DCSync:** Worker B explicitly instructed to report absence of DCSync evidence if `is_dcsync_indicator=0` — do NOT claim DCSync without PCAP evidence

### submit_finding schema
```
status          — "confirmed" | "suspected" | "insufficient_evidence"
confidence      — "HIGH" | "MEDIUM" | "LOW"
summary         — detailed narrative with exact IPs, timestamps, counts, bytes
evidence_items  — array of: { ts, src_ip, dst_ip, protocol, description, artifact }
limitations     — known gaps in evidence
next_steps      — recommended follow-up
```

### Prior findings context
Each sequential worker receives a 300-character summary of all prior findings. Example: Worker C sees "Worker A found beachhead 10.128.239.57 via RDP from 193.x. Worker B found 3 SAMR waves." This allows cross-correlation of attacker IPs across stages.

---

## Phase 7 — Timeline Assembly

**File:** `tools/timeline.py`

- Collects all `evidence_items` from all 4 worker findings
- Sorts chronologically by `ts`
- Categorises each event: `initial_access`, `lateral_movement`, `exfiltration`, `payload_delivery`
- Output: `timeline.json`

---

## Phase 8 — Dual-LLM Report Synthesis

**File:** `agents/synthesizer.py`

Two LLMs run **in parallel** using `ThreadPoolExecutor(max_workers=2)`. Both receive the identical prompt containing:
- All 4 worker findings (status, confidence, summary, evidence_items, mitre_techniques, limitations)
- DB row count statistics (17 tables)
- Timeline JSON
- Case brief

| Report | Model | API | Output File |
|--------|-------|-----|-------------|
| Primary | `gpt-4o` | OpenAI | `report_synthesized.md` |
| Secondary | `anthropic/claude-opus-4-6` | CommonStack AI (`api.commonstack.ai/v1`) | `report_commonstack.md` |
| Fallback | Deterministic template | None | `report.md` |

### CommonStack key rotation
Up to 3 API keys in `.env` under `COMMON_API_KEY` (comma-separated). Tried in sequence on auth error or quota exhaustion:
```python
for i, key in enumerate(api_keys):
    result = _call_llm(key, model, prompt, f"CommonStack key {i+1}/{n}", base_url)
    if result:
        return result
```

### Report Structure (both LLMs)
1. Executive Summary (C-suite, no jargon)
2. Scope and Assumptions
3. Finding A — Initial Access (sub-sections, IOC table, exact timestamps)
4. Finding B — Lateral Movement & Discovery
5. Finding C — Exfiltration (byte counts in raw + human-readable)
6. Finding D — Payload Delivery
7. Attack Timeline (chronological table)
8. MITRE ATT&CK Mapping
9. IOC Summary Table
10. Recommendations (Critical / High / Medium priority tiers)

---

## Output Files

All written to `data/output/<case_name>/`:

| File | Contents |
|------|----------|
| `progress.json` | Live pipeline state (updated every ~30s, polled by dashboard every 2s) |
| `ingest/alerts.json` | Phase 1 cache |
| `ingest/zeek_records.json` | Phase 2 cache |
| `ingest/pcap_index.json` | Phase 3 cache |
| `ingest/pcap_analysis.json` | Phase 4 cache |
| `ingest_summary.json` | Human-readable ingest stats (record counts per extractor) |
| `forensic_evidence.db` | SQLite database (17 tables) |
| `findings.json` | Structured answers to all 4 questions |
| `timeline.json` | Chronological event list |
| `agent_log.json` | Full audit trail of all agent actions |
| `report.md` | Deterministic template report (fallback) |
| `report_synthesized.md` | GPT-4o synthesized report |
| `report_commonstack.md` | Claude Opus 4.6 synthesized report |

---

## Running the Agent

```bash
# Standard run (multi-agent, uses all caches if present)
python3 agent.py run \
  --network-dir /path/to/network \
  --case SC4063_Network_Security \
  --reasoner multi-agent

# Force full re-ingest (clears all phase 1-4 caches)
python3 agent.py run \
  --network-dir /path/to/network \
  --case SC4063_Network_Security \
  --reasoner multi-agent --force-refresh

# Start from Phase 6 (reuse existing DB, re-run agents only)
python3 agent.py run \
  --network-dir /path/to/network \
  --case SC4063_Network_Security \
  --reasoner multi-agent --from-phase 6

# Live dashboard (open http://localhost:8080)
python3 serve_dashboard.py --case SC4063_Network_Security --port 8080
```

### Environment Variables (`.env`)
| Variable | Purpose |
|----------|---------|
| `OPENAI_API_KEY` | GPT-4o for worker agents and primary report |
| `OPENAI_MODEL` | Default: `gpt-4o` |
| `COMMON_API_KEY` | CommonStack API keys (comma-separated, rotates on quota/auth failure) |
| `COMMON_API_MODEL` | Default: `anthropic/claude-opus-4-6` |
| `LLM_BACKEND` | `openai` or `gemini` for worker agents |
| `GEMINI_API_KEYS` | Comma-separated Gemini keys for quota rotation |
| `PCAP_THREADS` | Parallel tshark workers (default: 8) |
| `WORKER_COOLDOWN_SECONDS` | Pause between agent batches (default: 5) |

---

## Known Issues & Fixes Applied

| Issue | Root Cause | Fix |
|-------|-----------|-----|
| Phase 2 hang/crash overnight (OOM) | `ipaddress.ip_address()` called on every matched record (9.3M × 3 containment checks) causing OOM + process kill | Replaced with fast string prefix check `ip.startswith(("10.", "172.16.", ...))` |
| Protected records uncapped (memory) | Beachhead conn port 3389 had no limit on protected records bucket | Added `MAX_PROTECTED_PER_BUCKET = 10,000` cap |
| HTTP extraction returns 0 rows | `http.request_number` invalid in tshark 4.6.4 — when any field is invalid, tshark returns exit code 1 and produces NO output for any field | Removed the field — it was unused in output dict anyway |
| Agents getting 0 rows in all tables | Stale `pcap_analysis.json` from pre-fix run | Delete cache and re-run with `--force-refresh` |
| Wrong attacker IP (193.x vs 195.x) | `pcap_rdp` was empty (0 rows), couldn't see `lgallegos` cookie → fallback to wrong IP | Fixed by clearing stale cache |
| temp.sh DNS/TLS records sampled out | dns/ssl hit 500K cap; rare exfil records replaced by later records | Added protected record mechanism for exfil IPs + hostnames |
| All 129 PCAPs not processed | PCAP selection filtered by alert timestamps; evidence outside windows dropped | Changed Phase 3 to select ALL PCAPs unconditionally |
| Dashboard showing old run | `serve_dashboard.py` pointed at wrong case name | Restart with `--case <correct_case>` |
| DCSync hallucinated in agent report | `pcap_dcerpc` table not queried; Worker B had no prompt guidance on new tables | Added 4 new tshark extractors + Worker B prompt updated to query `pcap_dcerpc`, `pcap_dns_srv`, `pcap_smb_tree`, `pcap_netbios`; explicit anti-hallucination guard added for DCSync |
