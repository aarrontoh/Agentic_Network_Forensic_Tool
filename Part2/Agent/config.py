import ipaddress
import os
from dataclasses import dataclass, field
from typing import List, Optional, Union


def _parse_csv(name: str, default: List[str]) -> List[str]:
    raw = os.getenv(name, "")
    if not raw.strip():
        return default
    return [item.strip() for item in raw.split(",") if item.strip()]


@dataclass
class AgentConfig:
    # ── Network definition ────────────────────────────────────────────────────
    internal_cidrs: List[str] = field(
        default_factory=lambda: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    )

    # ── Remote-access ports (initial access detection) ────────────────────────
    remote_access_ports: List[int] = field(
        default_factory=lambda: [3389, 443, 8443, 1194, 500, 4500]
    )

    # ── Lateral-movement detection ────────────────────────────────────────────
    lateral_ports: List[int] = field(default_factory=lambda: [135, 445])
    scan_unique_host_threshold: int = 20
    scan_window_seconds: int = 900          # 15 minutes

    # ── Exfiltration detection ────────────────────────────────────────────────
    exfil_large_bytes_threshold: int = 50_000_000   # 50 MB

    # ── Behaviour-shift detection (initial access) ────────────────────────────
    behavior_shift_window_seconds: int = 1800
    behavior_shift_min_internal_connections: int = 10

    # ── Agent orchestration ───────────────────────────────────────────────────
    max_agent_steps: int = 6

    # ── LLM back-ends ─────────────────────────────────────────────────────────
    openai_model: Optional[str] = None
    gemini_model: Optional[str] = None

    # ── Data source paths (populated at runtime or via env vars) ─────────────
    # Root folder that contains alert JSON, Zeek JSON, and pcap/ sub-directory.
    network_dir: str = ""
    # Individual overrides (leave empty to use auto-discovery from network_dir)
    alert_json_path: str = ""
    zeek_json_path: str = ""
    pcap_dir: str = ""

    @property
    def cached_networks(self) -> List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
        return [ipaddress.ip_network(cidr, strict=False) for cidr in self.internal_cidrs]

    @classmethod
    def from_env(cls) -> "AgentConfig":
        config = cls()
        config.internal_cidrs = _parse_csv("NF_INTERNAL_CIDRS", config.internal_cidrs)
        config.openai_model = os.getenv("OPENAI_MODEL", "gpt-4o").strip()
        # Gemini disabled
        config.gemini_model = None
        config.network_dir = os.getenv("NF_NETWORK_DIR", "").strip()
        config.alert_json_path = os.getenv("NF_ALERT_JSON", "").strip()
        config.zeek_json_path = os.getenv("NF_ZEEK_JSON", "").strip()
        config.pcap_dir = os.getenv("NF_PCAP_DIR", "").strip()
        return config
