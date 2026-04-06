# Part 2 – Agentic Network Forensic Workflow

## Invocation

```bash
cd Part2/Agent/

# Deterministic mode (no LLM, hardcoded analysis tools)
python3 agent.py run \
  --network-dir /Users/aaron/Desktop/Network_Security_Project/network \
  --case apex_global

# Multi-agent mode (Gemini-powered investigation with SQL tool-calling)
python3 agent.py run \
  --network-dir /Users/aaron/Desktop/Network_Security_Project/network \
  --case apex_global \
  --reasoner multi-agent

# Force re-ingest (wipe cache, re-scan 31 GB Zeek file)
python3 agent.py run \
  --network-dir /Users/aaron/Desktop/Network_Security_Project/network \
  --case apex_global \
  --reasoner multi-agent \
  --force-refresh
```

Auto-discovers from `network/`:
- **Alert JSON** → `34936-sensor-alert-*.json` (584 MB, ~162K Suricata alerts)
- **Zeek JSON** → `34936-sensor-zeek-*.json` (31 GB, ~14M Zeek records)
- **PCAP dir** → `pcap/` (129 files, 51 GB, dates 2025-03-01 to 2025-03-09)

---

## The Big Picture

```
Alerts tell us WHO is suspicious
    → Zeek tells us WHAT they did
        → PCAP targeting tells us WHERE to look deeper
            → tshark tells us the DETAILS
                → Database makes it all QUERYABLE
                    → LLM agents INVESTIGATE with SQL
                        → Report SYNTHESIZES the story
```

Each phase narrows the data: 51 GB → relevant IPs → relevant connections → relevant PCAPs → specific packet fields → structured DB → focused investigation.

---

## Phase 1 — Alert Ingestion (`tools/alert_reader.py`)

The Suricata IDS already flagged suspicious traffic. We stream the 584 MB alert JSON and extract:
- **Which IPs are suspicious** (the IOC list) — e.g., "10.128.239.57 talked to a known botnet C2 server"
- **What categories** — C2, ransomware, lateral movement, exfiltration, etc.
- **Community IDs** — unique flow identifiers that link an alert to a specific connection

Classifies each alert into one of 8 buckets:

| Bucket | Example rule |
|---|---|
| `c2` | `ThreatFox botnet C2 traffic (confidence 100%)` |
| `lateral` | `ET POLICY SMB2 NT Create AndX Request For a DLL File` |
| `scan` | `ET SCAN Nmap SYN Scan` |
| `ransomware` | `Lynx Ransomware` |
| `exfiltration` | `ET INFO Transfer.sh Upload` |
| `trojan` | any `A Network Trojan was detected` category |
| `policy` | policy violations, privacy violations |
| `other` | everything else |

**IOC Filtering:** Internal IPs that appear in >10% of all alerts (DNS servers, domain controllers) are excluded from the IOC set sent to the Zeek grep — they match virtually every record and destroy signal. Only high-priority community IDs (from c2, ransomware, lateral, exfiltration, scan categories) are kept.

**Output:** IOC sets — filtered suspicious IPs and community IDs for Phase 2.

Cached at: `data/output/apex_global/ingest/alerts.json`

---

## Phase 2 — Zeek JSON Correlation (`tools/zeek_searcher.py`)

Zeek logs contain **rich metadata** about every connection — bytes transferred, duration, DNS queries, TLS certificates, DCERPC operations, etc. But the file is 31 GB / 14 million lines.

We can't feed 31 GB to an LLM. So we use `grep -F` (or `rg`) with the IOC IPs from Phase 1 to **filter down** to only the lines mentioning suspicious IPs. This uses the Aho-Corasick algorithm and scans at I/O speed in C — filtering 31 GB in ~30 seconds.

IPs are written as `"x.x.x.x"` (with surrounding double-quotes) so grep's fixed-string match cannot match `10.1.1.1` inside `10.1.1.10`.

Matching records are normalised from Elastic/Filebeat format into flat dicts and sorted into protocol buckets (capped at 60K each):

| Bucket | What it captures |
|---|---|
| `zeek_conn` | Connection records — bytes, duration, used for fan-out and session quality analysis |
| `zeek_dns` | DNS queries and responses |
| `zeek_ssl` | TLS sessions — includes external→internal RDP with geo data, SNI |
| `zeek_http` | HTTP metadata (host, URI, method, body size) |
| `zeek_dce_rpc` | DCE-RPC calls (NetrLogonSamLogonEx, SAMR, LSARPC, DRSUAPI, etc.) |
| `zeek_rdp` | RDP sessions — cookies (attempted usernames), connection results |
| `zeek_smb` | SMB file operations — commands, paths, filenames |
| `zeek_other` | weird, files, x509, etc. |

**Output:** Structured records about what the suspicious IPs actually did — who they talked to, for how long, how many bytes, what services.

Cached at: `data/output/apex_global/ingest/zeek_records.json`

---

## Phase 3 — PCAP Targeting (`tools/pcap_selector.py`)

You have 129 PCAP files (51 GB total). We can't run tshark on all of them — that would take hours.

So we run `capinfos` on each PCAP to get its **time range** (e.g., "this PCAP covers March 5, 10:00–14:00"). Then we match alert timestamps to PCAP time ranges to select only the ~30 PCAPs that actually contain suspicious activity.

**Output:** A shortlist of ~30 PCAPs worth deep-diving into (instead of all 129).

Cached at: `data/output/apex_global/ingest/pcap_index.json`

---

## Phase 4 — Deep PCAP Analysis (`tools/pcap_deep_analysis.py`)

Now we run `tshark` on those ~30 PCAPs to extract **raw packet-level detail** that Zeek/alerts don't capture. Five extraction passes per PCAP:

| Pass | tshark filter | What it captures | IP filter |
|---|---|---|---|
| DNS | `dns && (ip_clause)` | Query/response pairs, A/AAAA answers | IOC IPs |
| HTTP | `http` | Hosts, URIs, methods, status codes, content-length | No IP filter (low-volume, catches exfil) |
| TLS | `tls.handshake.type==1` | SNI (domain name even for encrypted traffic), TLS version | No IP filter (catches exfil to temp.sh etc.) |
| SMB | `(smb\|\|smb2) && (ip_clause)` | Commands, filenames, share paths | IOC IPs |
| RDP | `tcp.port==3389 && (ip_clause)` | Connection pairs, RDP cookies (attempted usernames) | IOC IPs |

**Why not just use Zeek?** Zeek logs are pre-processed summaries. tshark gives us the actual packet fields — like seeing that an SMB session transferred a file called "delete.me" or that a TLS connection went to "temp.sh". HTTP and TLS run **without** IP filtering because they're low-volume protocols and the exfiltration destination might not be in our IOC list.

**Output:** Detailed protocol extractions from the targeted PCAPs.

Cached at: `data/output/apex_global/ingest/pcap_analysis.json`

---

## Phase 5 — Load into Database (`db/`)

All of the above (alerts + Zeek records + PCAP extractions) gets loaded into a **SQLite database** with 13 indexed tables:

| Table | Source | Content |
|---|---|---|
| `alerts` | Phase 1 | Suricata IDS alerts with category, rule name, IPs |
| `zeek_conn` | Phase 2 | Connection logs with bytes, duration, geo |
| `zeek_dns` | Phase 2 | DNS queries and answers |
| `zeek_ssl` | Phase 2 | TLS sessions with SNI, certificates |
| `zeek_http` | Phase 2 | HTTP requests with host, URI, body size |
| `zeek_dce_rpc` | Phase 2 | DCERPC operations (SAMR, Netlogon, etc.) |
| `zeek_rdp` | Phase 2 | RDP sessions with cookies |
| `zeek_smb` | Phase 2 | SMB file operations |
| `pcap_dns` | Phase 4 | Deep DNS extractions |
| `pcap_http` | Phase 4 | Deep HTTP extractions |
| `pcap_tls` | Phase 4 | Deep TLS extractions (SNI) |
| `pcap_smb` | Phase 4 | Deep SMB extractions (filenames) |
| `pcap_rdp` | Phase 4 | Deep RDP extractions (cookies) |

**Why a database?** So the LLM agents can ask precise questions like:
```sql
SELECT src_ip, COUNT(DISTINCT dst_ip) FROM zeek_conn
WHERE dst_port = 3389 GROUP BY src_ip ORDER BY 2 DESC
```
instead of trying to read millions of raw JSON lines. This solves the token-limit problem.

Stored at: `data/output/apex_global/forensic_evidence.db`

---

## Phase 6 — Multi-Agent Investigation (`agents/`)

Four Gemini-powered worker agents each investigate one forensic question independently:

| Agent | Question | MITRE |
|---|---|---|
| **Worker A** | How did the attacker get in? (Initial Access) | T1133 |
| **Worker B** | How did they spread? (Lateral Movement) | T1046, T1021.002 |
| **Worker C** | Did they steal data? (Exfiltration) | T1567 |
| **Worker D** | How was ransomware deployed? (Payload Delivery) | T1021.001, T1021.002 |

Each agent runs an autonomous investigation loop (up to 15 iterations):
1. Calls `summarize_db()` → sees what data is available
2. Calls `get_table_info(table)` → understands column schema
3. Calls `query_db(SQL)` → investigates hypotheses with precise queries
4. Reads the results, forms new hypotheses
5. Writes more queries to validate or refute
6. Repeats until confident
7. Calls `submit_finding()` with evidence-backed conclusions

**Guardrails (no hallucination):**
- Agents can ONLY access data through 4 registered tools: `query_db`, `count_rows`, `get_table_info`, `summarize_db`
- `query_db` only allows `SELECT` statements — writes/drops/deletes are blocked
- Every finding must include evidence items that reference specific query results
- If evidence is weak or absent, the agent must say so honestly
- Maximum 15 tool-calling iterations per worker

The Manager agent dispatches workers A → B → C → D sequentially, passing prior findings as context to each subsequent worker so they can correlate across stages (e.g., "Worker A found patient zero at 10.128.239.57 — check if that IP appears in your lateral movement data").

---

## Phase 7 — Timeline Assembly (`tools/timeline.py`)

All evidence items from the four findings are sorted chronologically to reconstruct the attack narrative:

```
2025-03-01 18:20  Initial Access    — External RDP from 194.0.234.17 → 10.128.239.57
2025-03-01 18:20  Lateral Movement  — DCERPC enumeration begins from 10.128.239.57
2025-03-01 18:20  Exfiltration      — C2 alerts fire for 10.128.239.20, 10.128.239.21
2025-03-08 09:26  Payload Delivery  — RDP fan-out to 14 internal targets
```

---

## Phase 8 — Report Synthesis (`agents/synthesizer.py`)

Gemini writes a professional forensic report from the worker findings:
- **Executive Summary** (2-3 paragraphs for C-suite, no technical jargon)
- **Detailed Findings** per question with MITRE ATT&CK mapping
- **Evidence Tables** with specific IPs, timestamps, byte counts
- **Limitations** and confidence levels
- **Recommendations** for remediation

Falls back to a template-based report if Gemini is unavailable.

---

## Output

Written to `Part2/Agent/data/output/apex_global/`:

```
ingest/
  alerts.json               ← Phase 1 cache (alert summary + categorised lists)
  zeek_records.json         ← Phase 2 cache (IOC-matched Zeek records)
  pcap_index.json           ← Phase 3 cache (PCAP time-range index)
  pcap_analysis.json        ← Phase 4 cache (tshark extraction results)
forensic_evidence.db        ← Phase 5 SQLite database (13 tables)
findings.json               ← Structured answers to all four questions
report.md                   ← Executive summary + detailed findings
timeline.json               ← Chronological event list
agent_log.json              ← Full audit trail of agent decisions + tool calls
progress.json               ← Live progress (for dashboard)
ingest_summary.json         ← Human-readable ingest statistics
```

---

## Data Flow Diagram

```
Phase 1: alert_reader.py
  └─ alerts_c2, alerts_trojan, alerts_ransomware,
     alerts_lateral, alerts_scan, alerts_exfiltration
     alert_ioc_all_ips (filtered), alert_community_ids (high-pri only)

Phase 2: zeek_searcher.py  (grep filtered by IOC IPs/community IDs)
  └─ zeek_conn, zeek_dns, zeek_ssl, zeek_http,
     zeek_dce_rpc, zeek_rdp, zeek_smb

Phase 3: pcap_selector.py  (timestamp → PCAP file mapping)
  └─ pcap_index, targeted_pcaps

Phase 4: pcap_deep_analysis.py  (tshark on targeted PCAPs only)
  └─ pcap_dns_queries, pcap_http_requests, pcap_tls_sessions,
     pcap_smb_sessions, pcap_rdp_sessions

          ↓  all loaded into SQLite database  ↓

Phase 5: db/schema.py + db/ingest_db.py
  └─ forensic_evidence.db (13 tables, indexed)

          ↓  queried by LLM agents via SQL  ↓

Phase 6: agents/manager.py → agents/worker.py
  └─ Worker A (Initial Access)    → Finding A
  └─ Worker B (Lateral Movement)  → Finding B
  └─ Worker C (Exfiltration)      → Finding C
  └─ Worker D (Payload Delivery)  → Finding D

          ↓

Phase 7: timeline.py → timeline.json
Phase 8: agents/synthesizer.py → report.md
```

---

## Deterministic Mode (--reasoner deterministic)

When running without `--reasoner multi-agent`, Phases 5-8 are replaced by:
- Hardcoded Python analysis tools (`tools/initial_access.py`, etc.) consume the artifacts dict directly
- A deterministic reasoner runs tools in order: A → B → C → D
- No LLM required, zero API cost
- Template-based report generation

The analysis tools use the same evidence but with fixed Python logic instead of LLM-driven SQL investigation.

---

## Re-run Behaviour

```bash
# Fast re-run — phases 1-4 loaded from cache, only runs analysis
python3 agent.py run --network-dir .../network --case apex_global --reasoner multi-agent

# Force fresh scan — wipes all cached results, re-scans 31 GB Zeek file
python3 agent.py run --network-dir .../network --case apex_global --reasoner multi-agent --force-refresh
```

---

## Environment Variables

| Variable | Purpose |
|---|---|
| `GEMINI_API_KEY` | Gemini API key (required for multi-agent mode) |
| `GEMINI_MODEL` | Gemini model ID (default: `gemini-2.5-flash`) |
| `NF_NETWORK_DIR` | Root evidence folder (alternative to `--network-dir`) |
| `NF_ALERT_JSON` | Override alert JSON path |
| `NF_ZEEK_JSON` | Override Zeek JSON path |
| `NF_PCAP_DIR` | Override PCAP directory path |
| `NF_INTERNAL_CIDRS` | Comma-separated CIDRs (default: RFC1918) |
| `OPENAI_API_KEY` + `OPENAI_MODEL` | Enable OpenAI planner mode |

---

## Key Architecture Decisions

| Decision | Rationale |
|---|---|
| Alert-first pipeline | Start from known-bad signals, not blind corpus scans |
| IOC IP filtering | Exclude infrastructure IPs (DNS, DC) that match every Zeek record |
| Targeted PCAPs | tshark on ~30 files, not all 129 — saves hours |
| No IP filter on TLS/HTTP | Low-volume protocols; exfil destinations may not be in IOC list |
| SQLite database | Makes 31 GB of data queryable by LLM agents via SQL |
| SQL-only tool calling | Agents cannot hallucinate — every claim must come from a query result |
| Read-only guardrail | Agents can only SELECT, never INSERT/UPDATE/DELETE/DROP |
| Sequential workers with context passing | Later workers benefit from earlier findings |
| Caching | Expensive Zeek scan runs once; subsequent runs load from cache |
