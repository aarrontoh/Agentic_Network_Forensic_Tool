SC4063 Network Forensic Final Project - Part 2
Agentic Network Forensic Submission Package

Overview
This package implements a submission-ready Part 2 design for the Apex Global Logistics ransomware case. The solution is built around a constrained network forensic agent that ingests either a single PCAP or a directory of segmented PCAPs, runs deterministic packet-analysis tools, stores evidence as structured artifacts, and generates a report without requiring manual step-by-step analyst guidance.

Why this design fits the brief
- The agent ingests PCAP files, including segmented multi-file case folders.
- The agent performs autonomous analysis through a controlled reasoning loop.
- The agent generates structured findings, a timeline, JSON artifacts, and a markdown report.
- The architecture includes explicit guardrails against hallucination and unsafe actions.
- The deliverables map directly to the marking rubric: architecture, demo flow, challenges, guardrails, and cost/efficiency.

What is included
- Deliverable3_Presentation.pdf
  Rubric-aligned PDF presentation that can be used as the basis for the final slide deck.
- Agent/
  A Python implementation of the forensic agent, analysis tools, prompts, and report generator.

Important note about the video requirement
The course brief requires a recorded demo video link in this README. I cannot record the video from this environment, so add your team's final link here before submission:

VIDEO_LINK_TO_BE_ADDED_BY_TEAM

External references used by the design
- Anthropic, "Disrupting the first reported AI-orchestrated cyber espionage campaign"
  https://www.anthropic.com/news/disrupting-AI-espionage
- Rob T. Lee, "Introducing Protocol SIFT: Meeting AI Threat Speed with Defensive AI Orchestration"
  https://robtlee73.substack.com/p/introducing-protocol-sift-meeting

Recommended execution environment
- Best: SIFT Workstation VM
- Good: Ubuntu 22.04 or later VM

Required system tools
- Python 3.10 or later
- Zeek
- TShark

Optional Python dependency
- openai
  Only required if you want to enable LLM-guided tool selection instead of the built-in deterministic reasoner.
- google-genai
  Only required if you want to enable Gemini-guided tool selection.

Suggested setup on SIFT or Ubuntu
1. Install Zeek and TShark with your package manager.
2. Put the provided PCAP or PCAP directory into a working directory.
3. Copy this Agent folder into the VM.
4. Run the agent in deterministic mode first.
5. If you have API access and want a stronger "AI-assisted" story, install the OpenAI SDK and enable the OpenAI reasoner.
6. If you prefer Gemini, install the Google GenAI SDK and enable the Gemini reasoner.

Example package installation
Deterministic mode:
  No extra Python packages are required.

Optional LLM mode:
  python3 -m pip install openai

Optional Gemini mode:
  python3 -m pip install google-genai

How to run
From inside the Agent directory:

1. Deterministic autonomous run
  python3 agent.py run --pcap /path/to/apex_case.pcap --case apex_global

  or for a segmented case folder:
  python3 agent.py run --pcap /path/to/34936-sensor-250304-00002389_redacted --case apex_global

2. Optional OpenAI-backed autonomous run
  export OPENAI_API_KEY=your_key_here
  export OPENAI_MODEL=your_model_here
  python3 agent.py run --pcap /path/to/apex_case.pcap --case apex_global --reasoner openai

3. Optional Gemini-backed autonomous run
  export GEMINI_API_KEY=your_key_here
  export GEMINI_MODEL=gemini-2.5-flash
  python3 agent.py run --pcap /path/to/apex_case.pcap --case apex_global --reasoner gemini

Useful environment variables
- OPENAI_API_KEY
  Required only when --reasoner openai is used.
- OPENAI_MODEL
  Required only when --reasoner openai is used.
- GEMINI_API_KEY or GOOGLE_API_KEY
  Required only when --reasoner gemini is used.
- GEMINI_MODEL
  Required only when --reasoner gemini is used.
- NF_INTERNAL_CIDRS
  Comma-separated CIDR list for the internal network if the default private ranges are too broad.
  Example:
    export NF_INTERNAL_CIDRS=10.0.0.0/8,192.168.10.0/24

Outputs
After a run, the agent writes artifacts under:
  Agent/data/output/<case_name>/

Expected outputs include:
- preprocessing/zeek/
  Zeek-generated JSON logs
- preprocessing/tshark/
  TShark summaries and selected extracts
- findings.json
  Structured findings from each investigative stage
- report.md
  Human-readable forensic report
- timeline.json
  Chronological event timeline
- agent_log.json
  Audit trail of the autonomous reasoning loop

How the autonomous agent works
The agent uses a controlled reasoning loop instead of free-form command execution.

High-level flow:
1. Ingest the PCAP or PCAP directory.
2. Build a capture inventory from actual packet timestamps.
3. Preprocess with Zeek and TShark.
4. Decide the next investigative action.
5. Run only approved analysis tools.
6. Store evidence and limitations.
7. Stop when all core questions have been addressed.
8. Generate findings and a report.

Implemented analysis stages
- Initial access
  Looks for external-to-internal remote access candidates, especially RDP and VPN-like ports, and correlates those candidates with immediate internal behavior changes.
- Lateral movement and discovery
  Looks for noisy scanning behavior to ports 445 and 135, plus optional DCERPC-related evidence if available.
- Exfiltration
  Looks for temp.sh usage, large HTTP POST activity, large outbound transfers, and optional archive indicators such as 7z signatures.
- Payload deployment
  Looks for likely late-stage fan-out or administrative access patterns consistent with ransomware staging or deployment.
- Timeline construction
  Merges evidence across stages into a chronological attack story.

Multi-PCAP case handling
- The agent inventories every file with capinfos when available.
- Chronology is based on actual packet timestamps, not file names.
- Zeek logs are generated per segment and then aggregated into a unified evidence view.
- TShark summaries are generated per segment so the agent can reason about coverage and protocol mix without blindly rescanning the entire dataset.

Guardrails and safety controls
- Read-only evidence handling
  The agent never modifies the source PCAP.
- Fixed tool allowlist
  The agent can only invoke the analysis functions implemented in this package.
- No arbitrary shell execution by the reasoner
  Shell commands are generated only inside deterministic preprocessing routines.
- Evidence-linked conclusions
  Findings are written from returned artifacts, not invented by the model.
- Confidence labels and limitations
  Every major section explicitly records uncertainty and missing evidence.
- Safe abstention
  If the logs do not support a conclusion, the agent records "insufficient evidence" instead of overclaiming.

Important forensic limitations
- PCAP evidence does not always prove successful authentication.
- PCAP evidence may suggest account creation or payload deployment without conclusively proving it.
- Encrypted exfiltration may limit visibility into payload contents.
- 7z confirmation depends on payload visibility or extracted artifacts.

How this package maps to the marking rubric
1. Agent Effectiveness and Forensic Quality
   The toolchain focuses on the exact questions in the addendum and produces structured, audit-friendly findings.
2. Guardrails and Safety Controls
   The agent uses evidence grounding, restricted actions, confidence scoring, and explicit limitations.
3. Cost and Efficiency
   The design defaults to deterministic tooling and optional LLM use, which keeps cost predictable.
4. Demo Quality
   The package includes a presentation PDF, a clear architecture story, and a reproducible CLI workflow.

What your team still needs to do before final submission
1. Run the agent on the provided PCAP in your chosen VM.
2. Review and refine the findings for the actual case data.
3. Replace the placeholder video link above.
4. If needed, rename the final PDF to match your team's preferred submission naming.
5. Zip the Part2 folder as Part2.zip.
