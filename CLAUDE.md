# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Python-based autonomous network forensic agent for the SC4063 Network Security course (Part 2). It investigates a ransomware incident at "Apex Global Logistics" by following an alert-driven, evidence-layered pipeline and automatically answering four forensic questions mapped to MITRE ATT&CK techniques.

## Running the Agent

All commands run from `Part2/Agent/`:

```bash
# Deterministic mode (no API keys required) – point at the network evidence folder
python3 agent.py run \
  --network-dir /path/to/network \
  --case apex_global

# With OpenAI reasoning
OPENAI_API_KEY=sk-... OPENAI_MODEL=gpt-4o \
  python3 agent.py run \
  --network-dir /path/to/network \
  --case apex_global --reasoner openai

# With Gemini reasoning (planner mode)
GEMINI_API_KEY=... GEMINI_MODEL=gemini-2.5-flash \
  python3 agent.py run \
  --network-dir /path/to/network \
  --case apex_global --reasoner gemini

# Multi-agent mode (full Gemini-powered investigation with SQL tool-calling)
# Requires GEMINI_API_KEY in .env or environment
python3 agent.py run \
  --network-dir /path/to/network \
  --case apex_global --reasoner multi-agent

# Force re-ingest (skip cache)
python3 agent.py run --network-dir /path/to/network --case apex_global --force-refresh

# Override individual source paths
python3 agent.py run \
  --alert-json /path/to/network/alert.json \
  --zeek-json  /path/to/network/zeek.json \
  --pcap-dir   /path/to/network/pcap \
  --case apex_global

# Validate environment (checks Python version, tshark, capinfos)
python3 check_env.py
```

The `--network-dir` folder must contain:
- A file matching `*alert*.json`  (Suricata EVE alerts exported from Elastic/Filebeat)
- A file matching `*zeek*.json`   (Zeek logs exported from Elastic/Filebeat)
- A sub-directory named `pcap/`   (containing the 129 .pcap files)

## System Dependencies

- Python 3.10+
- `tshark`/`capinfos` — packet analysis (Wireshark suite; used for targeted PCAP deep-dive)
- `zeek` is **no longer required** – Zeek analysis is sourced from the pre-existing Zeek JSON
- No third-party Python packages required for deterministic mode; `openai` and `google-genai` are optional

## Architecture – Two Analysis Modes

### Mode 1: Deterministic / LLM Planner (--reasoner deterministic|openai|gemini)
Uses hardcoded Python analysis tools or an LLM planner to sequence them.

### Mode 2: Multi-Agent (--reasoner multi-agent)
Full Gemini-powered multi-agent system with SQL-grounded tool calling.

```
Phase 1-4  Existing ingest pipeline (alerts → Zeek → PCAP targeting → tshark)
              ↓
Phase 5    Load artifacts into SQLite forensic database (13 tables)
              ↓
Phase 6    Manager dispatches 4 Worker Agents (A, B, C, D)
           Each worker:
             ├─ Gets system prompt + case brief + DB schema
             ├─ Calls tools: query_db(SQL), count_rows, get_table_info
             ├─ Runs autonomous investigation loop (up to 15 iterations)
             └─ Submits structured Finding via submit_finding tool
              ↓
Phase 7    Timeline assembly
              ↓
Phase 8    Reporting Synthesizer (Gemini) → C-suite Markdown report
```

### Multi-Agent Files

| File | Role |
|---|---|
| `db/schema.py` | SQLite schema (13 evidence tables + indexes) |
| `db/ingest_db.py` | Load ingest artifacts into database |
| `agents/tool_registry.py` | SQL query tools + Gemini function declarations |
| `agents/worker.py` | Worker agent with Gemini function-calling loop |
| `agents/worker_prompts.py` | Specialized system prompts for each question |
| `agents/manager.py` | Orchestrator: dispatches workers, accumulates findings |
| `agents/synthesizer.py` | Gemini-powered report writer |

### Guardrails
- **Read-only SQL**: Agents can only execute SELECT queries — writes are blocked
- **No hallucination**: Every finding must cite tool query results
- **Bounded iterations**: Workers get max 15 tool-calling rounds
- **Structured output**: Findings submitted via `submit_finding` tool with required fields

## Architecture – Alert-First Pipeline (Shared by Both Modes)

The agent now follows a **four-phase ingest + reasoning loop** pattern:

```
Phase 1  Read alert JSON  →  IOC lists (IPs, community IDs, categories)
Phase 2  Stream Zeek JSON →  filter to IOC-matching records (conn, dns, ssl, http, dce_rpc)
Phase 3  Build PCAP index →  select targeted PCAP subset by timestamp
Phase 4  Deep tshark      →  DNS/HTTP/TLS/SMB/RDP extraction from targeted PCAPs only
          ↓
Analysis tools  →  initial_access, lateral_movement, exfiltration, payload_delivery
          ↓
Timeline + Report
```

All ingest results are **cached** in `data/output/<case>/ingest/` so subsequent runs skip the expensive Zeek scan (use `--force-refresh` to invalidate).

### Key files

| File | Role |
|---|---|
| `agent.py` | Entry point; CLI, ingest pipeline, reasoning loop |
| `models.py` | `Finding`, `EvidenceItem`, `AnalysisState` dataclasses |
| `config.py` | Thresholds, network definitions, data-source paths (env-var overrides) |
| `llm.py` | `DeterministicReasoner`, `OpenAIReasoner`, `GeminiReasoner` |
| `case_brief.py` | Four forensic questions and investigation directives |
| `prompts.py` | Builds LLM prompt from current state + available actions |

### Ingest tools (`tools/`)

| File | Phase | Role |
|---|---|---|
| `ingest.py` | Orchestrator | Runs phases 1–4, manages cache |
| `alert_reader.py` | Phase 1 | Streams Suricata EVE alerts; produces IOC sets |
| `zeek_searcher.py` | Phase 2 | Streams 30 GB Zeek JSON; collects IOC-matching records |
| `pcap_selector.py` | Phase 3 | Builds capinfos time-range index; selects targeted PCAPs |
| `pcap_deep_analysis.py` | Phase 4 | Targeted tshark extraction (DNS/HTTP/TLS/SMB/RDP) |

### Analysis tools (`tools/`)

Each maps to one MITRE technique and one forensic question.  All tools now consume the
enriched `artifacts` dict (alert data + Zeek records + PCAP analysis) rather than running
Zeek from scratch.

| File | Question | MITRE | Key signals |
|---|---|---|---|
| `initial_access.py` | A | T1133 | External→internal TLS/RDP, post-access behaviour shift, C2 alerts |
| `lateral_movement.py` | B | T1046 / T1021.002 | DCERPC enumeration, SMB/RPC fan-out, lateral alerts |
| `exfiltration.py` | C | T1567 | temp.sh SNI/HTTP, large outbound flows, exfil alerts |
| `payload_delivery.py` | D | T1021.001 / T1021.002 | Late-stage RDP/SMB fan-out, ransomware alerts |
| `timeline.py` | – | – | Chronological event assembly from all findings |
| `common.py` | – | – | IP validation, JSON helpers |

### Configuration knobs (`config.py`)

All overridable via environment variables:

| Env var | Default | Purpose |
|---|---|---|
| `NF_INTERNAL_CIDRS` | RFC1918 | Internal network CIDR list |
| `NF_NETWORK_DIR` | – | Root network evidence directory |
| `NF_ALERT_JSON` | – | Override alert JSON path |
| `NF_ZEEK_JSON` | – | Override Zeek JSON path |
| `NF_PCAP_DIR` | – | Override PCAP directory path |
| `scan_unique_host_threshold` | 20 | Hosts/window to flag as scan |
| `scan_window_seconds` | 900 | Sliding window (15 min) |
| `exfil_large_bytes_threshold` | 50 MB | Outbound transfer threshold |

## Output

Written to `Part2/Agent/data/output/<case_name>/`:

```
ingest/
  alerts.json               – Phase 1 cache (alert summary + categorised lists)
  zeek_records.json         – Phase 2 cache (IOC-matched Zeek records)
  pcap_index.json           – Phase 3 cache (PCAP time-range index)
  pcap_analysis.json        – Phase 4 cache (tshark extraction results)
ingest_summary.json         – Human-readable ingest statistics
findings.json               – Structured answers to all four questions
report.md                   – Executive summary + detailed findings
timeline.json               – Chronological event list
agent_log.json              – Full audit trail of agent decisions
progress.json               – Live progress (for dashboard)
```

## Data Sources (network/)

```
network/
  34936-sensor-alert-*.json     (584 MB, ~162 K Suricata EVE alerts)
  34936-sensor-zeek-*.json      (30 GB, ~14 M Zeek records via Filebeat)
  pcap/                         (129 PCAP files, 51 GB total, 2025-03-01..03-04)
```

Zeek JSON record schema (Elastic-wrapped):
```json
{
  "@timestamp": "2025-03-01T18:20:01Z",
  "source": {"ip": "10.x.x.x", "port": 56029},
  "destination": {"ip": "10.x.x.x", "port": 49668},
  "network": {"protocol": "dce_rpc", "community_id": "1:..."},
  "zeek": {"session_id": "CHuR...", "dce_rpc": {"operation": "NetrLogonSamLogonEx"}},
  "fileset": {"name": "dce_rpc"}
}
```

Alert JSON record schema (Elastic-wrapped Suricata EVE):
```json
{
  "@timestamp": "2025-03-01T18:20:02Z",
  "source": {"ip": "10.x.x.x", "port": 52085},
  "destination": {"ip": "185.x.x.x", "port": 53},
  "rule": {"name": "ThreatFox botnet C2...", "id": "91409228", "category": "..."},
  "network": {"protocol": "dns", "community_id": "1:...", "direction": "outbound"}
}
```

## Design Constraints

- **No hallucination**: Every finding must cite actual alert/Zeek/PCAP evidence
- **Read-only**: Source PCAPs are never modified; tshark only reads
- **Alert-first**: Analysis starts from known-bad signals, not blind full-corpus scans
- **Targeted PCAPs**: tshark runs on the minimum subset of PCAPs, not all 129
- **Fixed tool allowlist**: The reasoner can only call tools in `tools/`
- **Confidence labels**: Every finding is tagged HIGH/MEDIUM/LOW with explicit limitations
- **Caching**: Expensive Zeek scan is cached; subsequent runs are fast
