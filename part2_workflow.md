# Part 2 – Agentic Network Forensic Workflow

## Invocation

```bash
cd Part2/Agent/
python3 agent.py run \
  --network-dir /Users/aaron/Desktop/Network_Security_Project/network \
  --case apex_global
```

Auto-discovers from `network/`:
- **Alert JSON** → `34936-sensor-alert-*.json` (612 MB)
- **Zeek JSON** → `34936-sensor-zeek-*.json` (31 GB)
- **PCAP dir** → `pcap/` (117 files, 51.5 GB, dates 2025-03-01 to 2025-03-09)

---

## Phase 1 — Alert Ingestion (`tools/alert_reader.py`)

Streams the 612 MB alert file **line by line** (never fully loaded into RAM).

For each of the ~162K Suricata EVE alerts it extracts:
- `src_ip`, `dst_ip`, `community_id`, `rule_name`, `category`, `timestamp`, geo

Classifies each alert into one of 8 buckets:

| Bucket | Example rule |
|---|---|
| `c2` | `ThreatFox botnet C2 traffic (confidence 100%)` |
| `lateral` | `ET POLICY SMB2 NT Create AndX Request For a DLL File` |
| `scan` | `ET SCAN Nmap SYN Scan` |
| `ransomware` | `Lynx Ransomware` |
| `exfiltration` | `ET INFO Transfer.sh Upload` |
| `trojan` | any `A Network Trojan was detected` category |
| `policy` | policy violations |
| `other` | everything else |

**Output:** IOC sets — all suspicious IPs (internal + external) and their community IDs.

Cached at: `data/output/apex_global/ingest/alerts.json`

---

## Phase 2 — Zeek JSON Correlation (`tools/zeek_searcher.py`)

Streams the 31 GB Zeek file **once**, line by line. For each of ~14M records:

```
Check: source.ip ∈ IOC_IPs  OR  destination.ip ∈ IOC_IPs  OR  community_id ∈ IOC_CIDs
```

O(1) set lookups — fast even at 14M lines.

Matching records are **normalised** from Elastic/Filebeat format into flat dicts:

```
Raw Elastic:  source.ip, destination.ip, zeek.ssl.cipher, @timestamp, ...
Normalised:   src_ip, dst_ip, ts, src_geo (country), zeek_detail, community_id, ...
```

Sorted into 6 protocol buckets (capped at 60K each):

| Bucket | What it captures |
|---|---|
| `zeek_ssl` | TLS sessions — includes external→internal RDP with geo data |
| `zeek_dce_rpc` | DCE-RPC calls (NetrLogonSamLogonEx, SAMR, LSARPC, etc.) |
| `zeek_conn` | Connection records — used for fan-out analysis |
| `zeek_dns` | DNS queries and responses |
| `zeek_http` | HTTP metadata (host, URI, method, size) |
| `zeek_other` | weird, files, x509, etc. |

Cached at: `data/output/apex_global/ingest/zeek_records.json`

---

## Phase 3 — PCAP Targeting (`tools/pcap_selector.py`)

Runs `capinfos` on all 117 PCAPs (fast — only reads PCAP file headers) to build a time-range index:

```
34936-sensor-250301-00002364_redacted.pcap  →  date=2025-03-01  ~326 MB
34936-sensor-250301-00002365_redacted.pcap  →  date=2025-03-01  ~374 MB
... (6 files for 2025-03-01)
... (8 files for 2025-03-02)
... (31 files for 2025-03-04)  ← most activity
...
```

PCAP distribution across the 9-day capture:

| Date | Files |
|---|---|
| 2025-03-01 | 6 |
| 2025-03-02 | 8 |
| 2025-03-03 | 7 |
| 2025-03-04 | 31 |
| 2025-03-05 | 7 |
| 2025-03-06 | 10 |
| 2025-03-07 | 8 |
| 2025-03-08 | 22 |
| 2025-03-09 | 18 |

Matches alert timestamps against the index — selects only PCAPs whose time window overlaps the alert dates. Result: **targeted subset** instead of all 117 files.

Cached at: `data/output/apex_global/ingest/pcap_index.json`

---

## Phase 4 — Deep PCAP Analysis (`tools/pcap_deep_analysis.py`)

Runs `tshark` **only on the targeted PCAP subset**, with display filters scoped to IOC IPs:

```
ip.addr == 10.128.239.57 || ip.addr == 194.0.234.17 || ...
```

Five extraction passes per PCAP:

| Pass | tshark filter | Extracted fields |
|---|---|---|
| DNS | `dns && (ip_clause)` | query name, A/AAAA answers |
| HTTP | `http && (ip_clause)` | host, URI, method, status, content-length |
| TLS | `tls.handshake.type==1 && (ip_clause)` | SNI, TLS version, dst port |
| SMB | `(smb\|\|smb2) && (ip_clause)` | cmd, filename, tree share |
| RDP | `tcp.port==3389 && (ip_clause)` | src/dst IP pairs (deduped) |

Cached at: `data/output/apex_global/ingest/pcap_analysis.json`

---

## Analysis Loop

The deterministic reasoner runs the four analysis tools in order: A → B → C → D.

### Question A — Initial Access (`tools/initial_access.py`)
**MITRE: T1133**

1. Scans `zeek_ssl` for **external → internal** on ports 3389/443/8443/1194/500/4500
   - e.g. Iran IP `194.0.234.17` → internal `10.128.239.57` on port 3389 (RDP)
2. Checks `alerts_c2 + alerts_trojan + alerts_ransomware` for internal IPs generating outbound threat activity
3. Scores each candidate by: post-access internal fan-out count + alert count
4. Corroborates with `pcap_rdp_sessions`
5. Emits **Finding A** with geo info, alert rule names, confidence level

### Question B — Lateral Movement (`tools/lateral_movement.py`)
**MITRE: T1046, T1021.002**

1. Scans `zeek_dce_rpc` for DCERPC ops matching keywords: `netr`, `samr`, `lsar`, `svcctl`, `enum`, `logon`, `user`, `group`
   - e.g. `NetrLogonSamLogonEx`, `NetrLogonSamLogonWithFlags`
2. Checks `alerts_lateral + alerts_scan` for SMB/RPC fan-out alerts
3. Analyses `zeek_conn` for internal→internal 135/445 fan-out using a 15-min sliding window
4. Corroborates with `pcap_smb_sessions` (filenames, tree shares, command types)
5. Emits **Finding B**

### Question C — Exfiltration (`tools/exfiltration.py`)
**MITRE: T1567**

1. Checks `alerts_exfiltration + alerts_c2` (outbound direction) for direct alerts
2. Scans `zeek_ssl` for SNI matching: `temp.sh`, `file.io`, `transfer.sh`, `anonfiles`, `gofile`, `we.tl`
3. Scans `zeek_http` for matching host/URI + large POST bodies ≥ 50 MB
4. Scans `zeek_conn` for large outbound transfers ≥ 50 MB
5. Corroborates with `pcap_http_requests` + `pcap_tls_sessions` for SNI confirmation
6. Emits **Finding C**

### Question D — Payload Delivery (`tools/payload_delivery.py`)
**MITRE: T1021.001, T1021.002**

1. Checks `alerts_ransomware` for direct deployment alerts
2. Calculates the **last 24 hours** of the capture window from all timestamps
3. Scans `zeek_ssl` + `zeek_conn` for internal→internal RDP/SMB fan-out **within that window only**
4. Finds the host with the highest fan-out count as the deployment staging host
5. Corroborates with `pcap_rdp_sessions` (internal→internal pairs)
6. Emits **Finding D**

---

## Output

Written to `Part2/Agent/data/output/apex_global/`:

```
ingest/
  alerts.json          ← Phase 1 cache  (re-run skips 612 MB re-scan)
  zeek_records.json    ← Phase 2 cache  (re-run skips 31 GB re-scan)
  pcap_index.json      ← Phase 3 cache  (capinfos index)
  pcap_analysis.json   ← Phase 4 cache  (tshark results)
ingest_summary.json    ← counts for all phases
findings.json          ← structured answers A/B/C/D
report.md              ← full markdown report with evidence tables
timeline.json          ← chronological events sorted by timestamp
agent_log.json         ← every agent decision + finding recorded
progress.json          ← live stage updates (for dashboard)
```

---

## Re-run Behaviour

```bash
# Fast re-run — all 4 phases loaded from cache, skips 31 GB Zeek scan
python3 agent.py run --network-dir ../../../network --case apex_global

# Force fresh scan — ignores all cached results
python3 agent.py run --network-dir ../../../network --case apex_global --force-refresh
```

---

## Artifacts Data Flow

```
alert_reader.py
  └─ alerts_c2, alerts_trojan, alerts_ransomware,
     alerts_lateral, alerts_scan, alerts_exfiltration
     alert_ioc_all_ips, alert_community_ids

zeek_searcher.py  (filtered by IOC IPs/community IDs)
  └─ zeek_ssl, zeek_dce_rpc, zeek_conn,
     zeek_dns, zeek_http, zeek_other

pcap_selector.py  (timestamp → PCAP file mapping)
  └─ pcap_index, targeted_pcaps

pcap_deep_analysis.py  (tshark on targeted PCAPs only)
  └─ pcap_dns_queries, pcap_http_requests, pcap_tls_sessions,
     pcap_smb_sessions, pcap_rdp_sessions

          ↓  all of the above passed as  artifacts  dict  ↓

initial_access.py   →  Finding A
lateral_movement.py →  Finding B
exfiltration.py     →  Finding C
payload_delivery.py →  Finding D

          ↓

timeline.py         →  timeline.json
reporting.py        →  report.md + findings.json + agent_log.json
```

---

## Old vs New

| Old approach | New approach |
|---|---|
| `tools/preprocess.py` runs Zeek on every PCAP | `tools/ingest.py` reads pre-existing Zeek JSON |
| `--pcap` pointing at PCAP dir | `--network-dir` pointing at evidence folder |
| Analysis tools read `zeek_dir/conn.log` etc. | Analysis tools read `zeek_ssl`, `alerts_c2`, `pcap_rdp_sessions` etc. |
| No alert intelligence | Alert categories drive all 4 analysis tools |
| tshark run on all PCAPs | tshark run only on timestamp-targeted subset |
| Re-run re-processes all PCAPs | Re-run loads from cache in seconds |

---

## Environment Variables

| Variable | Purpose |
|---|---|
| `NF_NETWORK_DIR` | Root evidence folder (alternative to `--network-dir`) |
| `NF_ALERT_JSON` | Override alert JSON path |
| `NF_ZEEK_JSON` | Override Zeek JSON path |
| `NF_PCAP_DIR` | Override PCAP directory path |
| `NF_INTERNAL_CIDRS` | Comma-separated CIDRs (default: RFC1918) |
| `OPENAI_API_KEY` + `OPENAI_MODEL` | Enable OpenAI reasoner |
| `GEMINI_API_KEY` + `GEMINI_MODEL` | Enable Gemini reasoner |
