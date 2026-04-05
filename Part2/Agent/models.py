from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List


@dataclass
class EvidenceItem:
    ts: str
    src_ip: str
    dst_ip: str
    protocol: str
    description: str
    artifact: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    question_id: str
    title: str
    status: str
    confidence: str
    summary: str
    mitre: List[str] = field(default_factory=list)
    evidence: List[EvidenceItem] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    next_steps: List[str] = field(default_factory=list)
    tool_name: str = ""

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["evidence"] = [item.to_dict() for item in self.evidence]
        return payload


@dataclass
class Decision:
    next_action: str
    reason: str


@dataclass
class AnalysisState:
    case_id: str
    pcap_path: str
    work_dir: str
    artifacts: Dict[str, Any] = field(default_factory=dict)
    findings: Dict[str, Finding] = field(default_factory=dict)
    completed_actions: List[str] = field(default_factory=list)
    agent_log: List[Dict[str, Any]] = field(default_factory=list)

    def add_finding(self, action_name: str, finding: Finding) -> None:
        self.findings[finding.question_id] = finding
        if action_name not in self.completed_actions:
            self.completed_actions.append(action_name)

    def log(self, event_type: str, payload: Dict[str, Any]) -> None:
        self.agent_log.append({"event_type": event_type, **payload})

    def findings_for_reasoner(self) -> Dict[str, Dict[str, Any]]:
        return {key: finding.to_dict() for key, finding in self.findings.items()}
