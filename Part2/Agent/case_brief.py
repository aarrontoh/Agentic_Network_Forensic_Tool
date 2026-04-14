CASE_NAME = "SC4063 Network Security"

# IPs the manual investigation treats as the primary beachhead / staging host for PCAP SMB
# filename extraction (tshark: smb2.filename && ip.src/dst == beachhead). Override with NF_PCAP_BEACHHEAD_IPS.
CASE_BEACHHEAD_IPS = ("10.128.239.57",)

INCIDENT_SUMMARY = """
SC4063 Network Security investigation: a ransomware incident attributed to the Lynx group.
The available evidence is a 9-day PCAP captured from a core-switch tap. There is no
endpoint telemetry or memory image, so all conclusions must be grounded in network data.
""".strip()

INVESTIGATION_DIRECTIVES = {
    "A": {
        "title": "Initial Access",
        "question": "Which host is the most likely patient zero, and what remote access path led to compromise?",
        "hints": [
            "Look for external remote-management traffic such as RDP or VPN entering the network.",
            "Correlate candidate access events with an immediate change in the compromised host's traffic behavior.",
        ],
        "primary_mitre": ["T1133", "T1078"],
    },
    "B": {
        "title": "Lateral Movement and Discovery",
        "question": "How did the attacker pivot, enumerate the environment, and possibly manipulate accounts?",
        "hints": [
            "Look for rapid fan-out to SMB port 445 or RPC port 135.",
            "If available, inspect DCERPC-related activity that may suggest account creation or group changes.",
        ],
        "primary_mitre": ["T1046", "T1021.002", "T1003.006", "T1003", "T1087.002", "T1069.002", "T1135", "T1018", "T1021.003"],
    },
    "C": {
        "title": "Exfiltration",
        "question": "What evidence exists that data left the network, and how strong is the proof?",
        "hints": [
            "Look for temp.sh usage, large HTTP POST activity, and outbound spikes.",
            "If payload data is visible, search for archive indicators such as 7z magic bytes.",
        ],
        "primary_mitre": ["T1567", "T1560", "T1039"],
    },
    "D": {
        "title": "Payload Deployment",
        "question": "What network evidence most strongly suggests how the ransomware was staged or deployed?",
        "hints": [
            "Look for late-stage RDP or SMB fan-out from a high-value system.",
            "Be careful to distinguish suspicion from proof.",
        ],
        "primary_mitre": ["T1021.001", "T1021.002", "T1570", "T1562.001", "T1486"],
    },
}
