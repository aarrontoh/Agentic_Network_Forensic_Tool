from __future__ import annotations

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import landscape, letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


OUTPUT_PATH = Path(__file__).resolve().parents[2] / "Deliverable3_Presentation.pdf"


def add_title(story, styles):
    story.append(Paragraph("SC4063 Part 2: Agentic Network Forensic", styles["Title"]))
    story.append(Spacer(1, 0.2 * inch))
    story.append(
        Paragraph(
            "Submission-ready presentation outline for the SC4063 Network Security ransomware case",
            styles["Subtitle"],
        )
    )
    story.append(Spacer(1, 0.3 * inch))
    story.append(
        Paragraph(
            "This deck is built directly from the project brief and addendum. It focuses on a constrained forensic agent that ingests a PCAP, uses deterministic tooling for evidence extraction, and applies bounded reasoning to decide the next analysis step.",
            styles["BodyText"],
        )
    )


def add_slide(story, styles, title, bullets):
    story.append(PageBreak())
    story.append(Paragraph(title, styles["Heading1"]))
    story.append(Spacer(1, 0.15 * inch))
    for bullet in bullets:
        story.append(Paragraph(f"- {bullet}", styles["BulletText"]))
        story.append(Spacer(1, 0.06 * inch))


def add_architecture_slide(story, styles):
    story.append(PageBreak())
    story.append(Paragraph("Architecture And Data Flow", styles["Heading1"]))
    story.append(Spacer(1, 0.15 * inch))
    diagram = """
PCAP Input
  -> Preprocessing Layer (Zeek, TShark)
  -> Evidence Store (JSON logs, summaries, signatures)
  -> Agent Controller (deterministic or optional LLM reasoner)
  -> Approved Analysis Tools
      - Initial Access
      - Lateral Movement
      - Exfiltration
      - Payload Delivery
      - Timeline Builder
  -> Report Generator
  -> Findings JSON, Timeline JSON, Markdown Report
""".strip().replace("  ", "&nbsp;&nbsp;").replace("\n", "<br/>")
    story.append(Paragraph(diagram, styles["CodeBlock"]))
    story.append(Spacer(1, 0.2 * inch))
    story.append(
        Paragraph(
            "The architecture follows the assignment's emphasis on machine-speed orchestration while keeping evidence extraction deterministic and auditable. The Protocol SIFT reference reinforces the value of orchestration plus tool integration rather than pure free-form chatbot analysis.",
            styles["BodyText"],
        )
    )


def add_cost_table(story, styles):
    story.append(PageBreak())
    story.append(Paragraph("Cost And Efficiency", styles["Heading1"]))
    story.append(Spacer(1, 0.15 * inch))
    data = [
        ["Mode", "Main Cost Driver", "Strength", "Trade-off"],
        ["Deterministic", "Zeek/TShark runtime", "Cheap and reproducible", "Less flexible reasoning"],
        ["Hybrid LLM", "Tool runtime + model planning", "More adaptive narrative and prioritization", "API cost and governance"],
        ["Full open-ended agent", "Model, tooling, and validation overhead", "Most flexible", "Harder to control and defend"],
    ]
    table = Table(data, colWidths=[1.8 * inch, 2.2 * inch, 2.3 * inch, 2.3 * inch])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEADING", (0, 0), (-1, -1), 12),
                ("FONTSIZE", (0, 0), (-1, -1), 12),
            ]
        )
    )
    story.append(table)
    story.append(Spacer(1, 0.2 * inch))
    story.append(
        Paragraph(
            "This project uses the hybrid position: deterministic evidence extraction plus optional narrow LLM planning. That keeps cost bounded while still supporting the assignment's AI-assisted angle.",
            styles["BodyText"],
        )
    )


def main():
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(OUTPUT_PATH),
        pagesize=landscape(letter),
        leftMargin=0.55 * inch,
        rightMargin=0.55 * inch,
        topMargin=0.45 * inch,
        bottomMargin=0.45 * inch,
    )
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="Subtitle",
            parent=styles["Heading2"],
            fontName="Helvetica",
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#334155"),
        )
    )
    styles.add(
        ParagraphStyle(
            name="BulletText",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=15,
            leading=19,
            textColor=colors.HexColor("#0f172a"),
        )
    )
    styles.add(
        ParagraphStyle(
            name="CodeBlock",
            parent=styles["BodyText"],
            fontName="Courier",
            fontSize=12,
            leading=15,
            backColor=colors.HexColor("#e2e8f0"),
            borderPadding=10,
        )
    )
    styles["Title"].fontName = "Helvetica-Bold"
    styles["Title"].fontSize = 28
    styles["Heading1"].fontName = "Helvetica-Bold"
    styles["Heading1"].fontSize = 24
    styles["Heading1"].textColor = colors.HexColor("#0f172a")
    styles["BodyText"].fontName = "Helvetica"
    styles["BodyText"].fontSize = 14
    styles["BodyText"].leading = 18

    story = []
    add_title(story, styles)
    add_slide(
        story,
        styles,
        "Project Objective",
        [
            "Build a network forensic agent that autonomously analyzes PCAP evidence and produces a report comparable to Part 1 findings.",
            "Answer the four case questions from the addendum: initial access, lateral movement, exfiltration, and payload deployment.",
            "Show not only the result, but also the architecture, decision logic, guardrails, and runtime trade-offs.",
        ],
    )
    add_architecture_slide(story, styles)
    add_slide(
        story,
        styles,
        "Tools Available To The Agent",
        [
            "Zeek for protocol-aware log generation from the PCAP.",
            "TShark for deterministic traffic summaries and packet-level validation.",
            "Python analysis modules for initial access, scanning, exfiltration, payload-delivery, timeline, and reporting.",
            "Optional LLM reasoner for narrow next-step selection and synthesis only.",
        ],
    )
    add_slide(
        story,
        styles,
        "Decision Logic",
        [
            "The agent is constrained to an allowlist of approved actions and cannot invent new tools.",
            "Default autonomous order: patient zero, lateral movement, exfiltration, payload, then timeline.",
            "If an LLM reasoner is enabled, it chooses the next action from the allowlist using only current findings and the briefing.",
            "Every output is grounded in artifacts produced by Zeek or TShark rather than direct raw-packet summarization by the model.",
        ],
    )
    add_slide(
        story,
        styles,
        "Demo Flow",
        [
            "Show the PCAP entering the workflow and the preprocessing stage generating Zeek logs and TShark summaries.",
            "Run the agent from the command line and display the autonomous action log.",
            "Open the resulting findings JSON and markdown report to show structured evidence, limitations, and confidence labels.",
            "Close with the timeline and a short comparison to how the same questions would be answered manually in Part 1.",
        ],
    )
    add_slide(
        story,
        styles,
        "Key Challenges",
        [
            "PCAP-only investigations do not always prove successful authentication or exact payload execution.",
            "Encrypted exfiltration can hide payload content and archive signatures.",
            "Late-stage administrative traffic may resemble normal operations, so overclaiming is a risk.",
            "Large captures create runtime and parsing overhead, especially if the pipeline reruns broad scans too often.",
        ],
    )
    add_slide(
        story,
        styles,
        "Guardrails And Safety Controls",
        [
            "Read-only source evidence handling; the PCAP is never modified.",
            "Fixed tool allowlist; the agent cannot execute arbitrary shell commands or binaries.",
            "Evidence-linked findings; every claim must tie back to timestamps, source and destination addresses, protocols, and artifacts.",
            "Confidence labels and explicit limitations reduce hallucination and make uncertainty visible.",
            "Human review remains mandatory before the final report is treated as authoritative.",
        ],
    )
    add_cost_table(story, styles)
    add_slide(
        story,
        styles,
        "Why This Design Matches The Brief",
        [
            "It is autonomous without being reckless: the agent makes decisions, but only inside clear bounds.",
            "It is forensic rather than purely generative: deterministic tooling does the evidence extraction.",
            "It is explainable in class: the architecture, logic, cost, and limitations are easy to defend during Q and A.",
            "It is realistic to build in a student project and strong enough to stand next to the Part 1 investigation workflow.",
        ],
    )
    add_slide(
        story,
        styles,
        "References",
        [
            "SC4063 Network Forensic Final Project brief and addendum.",
            "Anthropic, Disrupting the first reported AI-orchestrated cyber espionage campaign.",
            "Rob T. Lee, Introducing Protocol SIFT: Meeting AI Threat Speed with Defensive AI Orchestration.",
        ],
    )
    doc.build(story)


if __name__ == "__main__":
    main()
