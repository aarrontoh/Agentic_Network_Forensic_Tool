# SC4063 Part 2 Implementation Plan
# Agentic Network Forensic Analysis Framework

## 1. Objective

The goal of Part 2 is to design and implement an autonomous network forensic agent that can:

1. ingest a PCAP file
2. analyze the traffic using forensic tools
3. decide what investigative step to perform next without manual step-by-step guidance
4. generate structured findings aligned to the incident questions
5. produce a forensic report comparable to Part 1
6. include guardrails to reduce hallucination and unsupported conclusions

The final solution must demonstrate both:
- technical forensic capability
- controlled and safe agentic reasoning

---

## 2. Scope of the Agent

The agent will answer the four required investigation areas:

### A. Initial Access
Identify possible patient zero by checking for suspicious remote access from external IPs into the environment, especially RDP and similar traffic.

### B. Lateral Movement and Discovery
Identify scanning patterns, SMB/RPC fan-out, and possible account manipulation activity.

### C. Exfiltration
Identify large outbound transfers, suspicious HTTP POST activity, possible temp.sh usage, and signs of compressed archive transfer.

### D. Payload Delivery
Identify probable ransomware deployment patterns, including SMB or RDP based movement shortly before the impact window.

---

## 3. High-Level Architecture

The system will use a **single-agent, tool-using architecture**.

```text
PCAP Input
→ Preprocessing Layer
→ Evidence Store
→ Agent Controller
→ Investigation Tools
→ Findings Store
→ Report Generator
```

### 3.1 Components

1.  **Preprocessing Layer**
    Responsible for converting raw PCAP into structured forensic data.
    - **Tools**: Zeek, TShark
    - **Outputs**: `conn.log`, `http.log`, `dns.log`, `files.log`, protocol summaries, packet statistics

2.  **Evidence Store**
    Stores intermediate outputs in machine-readable format (JSON, CSV, Markdown).
    - **Purpose**: Allow the agent to reason only on extracted evidence and keep all findings auditable.

3.  **Agent Controller**
    Responsible for reading evidence, deciding which tool to call next, updating case state, and stopping when complete.

4.  **Investigation Tools**
    Python tool wrappers around Zeek/TShark/log queries (e.g., `analyze_rdp_initial_access`, `analyze_smb_scanning`, etc.).

5.  **Findings Store**
    Stores structured conclusions (title, description, evidence, confidence, MITRE ATT&CK mapping).

6.  **Report Generator**
    Converts findings into executive summary, detailed findings, timeline, and recommendations.

---

## 4. Environment and Execution Model

### 4.1 Recommended Environment
The agent will run inside a sandboxed forensic environment (SIFT Workstation or Ubuntu VM).

### 4.2 Software Dependencies
- **System**: `python3`, `pip`, `zeek`, `tshark`
- **Python**: `pandas`, `jinja2`, `markdown2`, `python-dotenv`, `openai` (optional)

### 4.3 Execution Mode
```bash
python3 agent.py run --pcap /path/to/case.pcap --case apex_global
```

---

## 5. Evidence Pipeline

### 5.1 Input
- One PCAP file for the case.

### 5.2 Preprocessing Steps
1.  **Zeek Parsing**: Generate protocol-aware logs (`conn`, `http`, `dns`, etc.).
2.  **TShark Statistics**: Extract traffic spikes, protocol distributions, and conversation summaries.
3.  **Structured Conversion**: Convert logs into JSON/CSV for agent consumption.

---

## 6. Agent Workflow

### 6.1 Core Loop
1. Read case objective.
2. Inspect current evidence state.
3. Choose one next tool.
4. Run that tool.
5. Store returned evidence.
6. Update hypotheses.
7. Repeat until stop condition.
8. Generate validated report.

### 6.2 Stop Condition
- All 4 incident questions answered.
- Maximum iteration count reached.
- No further useful tool call available.

### 6.3 Maximum Iterations
- Max 6 to 8 reasoning iterations per run.

---

## 7. Tooling Plan
- **Initial Access**: `analyze_rdp_initial_access`
- **Discovery**: `analyze_smb_scanning`
- **Account Activity**: `analyze_rpc_activity`
- **HTTP Exfiltration**: `analyze_http_exfiltration`
- **Archive Signature**: `detect_archive_signatures`
- **Payload Delivery**: `analyze_payload_delivery`
- **Timeline**: `build_timeline`

---

## 8. Case State Design
Structured JSON object tracking case info, evidence, findings, timeline, and completed objectives.

---

## 9. Reasoning Strategy
- **Baseline**: Deterministic reasoner using simple rules.
- **LLM-Assisted**: Optional OpenAI-backed reasoner for flexible tool selection and natural phrasing.

---

## 10. Guardrails and Safety Controls
- **Evidence-Grounded**: Every finding must be backed by real tool output.
- **Fixed Tool Allowlist**: Agent cannot run arbitrary shell commands.
- **Read-Only**: No modification of source PCAP.
- **Confidence Labels**: HIGH, MEDIUM, LOW.
- **Abstain-on-Uncertainty**: Report "insufficient evidence" rather than overclaiming.

---

## 11. Output Design
Generates `agent_log.json`, `findings.json`, `timeline.json`, and `report.md`.

---

## 12. Implementation Phases
1.  **Phase 1 — Environment Setup**: VM, Zeek, TShark, deps.
2.  **Phase 2 — Preprocessing Pipeline**: Zeek/TShark runners, log parsing.
3.  **Phase 3 — Core Tooling**: Individual forensic analysis tools.
4.  **Phase 4 — Deterministic Agent**: State management, selection logic, loop.
5.  **Phase 5 — LLM-Assisted Reasoner**: OpenAI integration, output validation.
6.  **Phase 6 — Reporting**: Markdown template, executive summary, recommendations.
7.  **Phase 7 — Demo and Presentation**: Diagrams, sample run, performance metrics.

---

## 13. Testing Plan
- **Functional**: PCAP ingestion, log generation, tool output.
- **Forensic Quality**: 4 investigation areas, evidence references, timeline.
- **Guardrails**: Rejection of unsupported claims, confidence labeling.
- **Demo**: End-to-end run, presentation screenshots.

---

## 14. Cost and Efficiency Measurement
Runtime metrics, iteration count, tool count, and API cost.

---

## 15. Deliverables Mapping
Architecture, Demo, Challenges, Guardrails, and Cost/Efficiency.

---

## 16. Submission Folder Structure
```text
Part2/
├── Agent/
├── Deliverable3_Presentation.pdf
└── README.txt
```

---

## 17. Minimum Viable Version
PCAP ingestion, Zeek preprocessing, 4 analysis tools, autonomous loop, findings, report, and guardrails.

---

## 18. Success Criteria
Agent runs with one command, chooses tools autonomously, answers case questions, and generates an evidence-based report.
