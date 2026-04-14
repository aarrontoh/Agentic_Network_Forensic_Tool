"""
PCAP Credential Extractor — post-processes targeted PCAP files to extract
attacker credential correlations that tshark's normal RDP dissector misses.

Specifically:
  1. Finds PCAPs containing known attacker IPs (from pcap_rdp table)
  2. Computes per-PCAP clock offset against Zeek timestamps (many PCAPs have
     wrong sensor clocks, off by hundreds of days)
  3. Searches for credential strings (usernames, domain accounts) in raw PCAP
     frames using tshark 'frame contains' filter
  4. Correlates Kerberos AS-REP frames near attacker RDP sessions to identify
     which credential was used
  5. Writes results to pcap_credentials table in the forensic DB

This is called after phase 4 (tshark deep extraction) and before phase 6 (workers).
"""
from __future__ import annotations

import datetime
import sqlite3
import subprocess
import statistics
from pathlib import Path
from typing import Optional


# Credential strings to search for in PCAPs
_CREDENTIAL_STRINGS = [
    "lgallegos",
    "LGallegos",
    "lgallego",   # partial match in case of truncation
]

# Max time window (seconds) between attacker RDP and correlated Kerberos ticket
_CORRELATION_WINDOW_SECS = 600  # 10 minutes


def _epoch_to_iso(epoch: float) -> str:
    """Convert Unix epoch to ISO 8601 UTC string."""
    return datetime.datetime.utcfromtimestamp(epoch).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _compute_pcap_clock_offset(
    pcap_path: str,
    conn: sqlite3.Connection,
    tshark_bin: str = "tshark",
    sample_size: int = 500,
) -> Optional[float]:
    """
    Compute the clock offset (pcap_epoch - real_epoch) for a given PCAP by
    matching SYN packets against zeek_conn records.

    Returns offset in seconds, or None if not enough anchors found.
    """
    try:
        result = subprocess.run(
            [tshark_bin, "-r", pcap_path, "-T", "fields",
             "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.dstport",
             "-Y", "tcp.flags.syn==1 && tcp.flags.ack==0"],
            capture_output=True, text=True, timeout=60
        )
    except Exception:
        return None

    offsets = []
    for line in result.stdout.strip().split("\n")[:sample_size]:
        parts = line.strip().split("\t")
        if len(parts) != 4 or not parts[1] or not parts[2] or not parts[3]:
            continue
        try:
            pcap_epoch = float(parts[0])
            src, dst, dport = parts[1], parts[2], int(parts[3])
        except (ValueError, IndexError):
            continue

        rows = conn.execute(
            "SELECT ts FROM zeek_conn WHERE src_ip=? AND dst_ip=? AND dst_port=? ORDER BY ts LIMIT 5",
            (src, dst, dport)
        ).fetchall()
        for (zeek_ts,) in rows:
            try:
                zeek_dt = datetime.datetime.fromisoformat(zeek_ts.replace("Z", ""))
                zeek_epoch = zeek_dt.replace(tzinfo=datetime.timezone.utc).timestamp()
                diff = pcap_epoch - zeek_epoch
                # Keep offsets in a plausible range (50–400 days)
                if 4_000_000 < diff < 35_000_000:
                    offsets.append(diff)
            except Exception:
                continue

    if len(offsets) < 10:
        return None

    # Use median to be robust against outliers
    return statistics.median(offsets)


def _find_kerberos_asrep_near(
    pcap_path: str,
    rdp_pcap_epoch: float,
    window: float,
    tshark_bin: str = "tshark",
) -> list[dict]:
    """
    Find Kerberos AS-REP frames (msg_type=11) within `window` seconds after
    the attacker's RDP connection. These reveal which credential was used.
    """
    t_start = rdp_pcap_epoch
    t_end = rdp_pcap_epoch + window

    try:
        result = subprocess.run(
            [tshark_bin, "-r", pcap_path, "-T", "fields",
             "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst",
             "-e", "kerberos.msg_type", "-e", "kerberos.CNameString",
             "-Y", f"kerberos && frame.time_epoch >= {t_start} && frame.time_epoch <= {t_end}"],
            capture_output=True, text=True, timeout=45
        )
    except Exception:
        return []

    records = []
    for line in result.stdout.strip().split("\n"):
        parts = line.strip().split("\t")
        if len(parts) < 5:
            continue
        try:
            epoch = float(parts[0])
            src, dst = parts[1], parts[2]
            msg_type = parts[3]
            cname = parts[4].strip()
            # msg_type 11 = AS-REP (ticket granted to a user)
            # msg_type 10 = AS-REQ (request by client)
            if cname and msg_type in ("10", "11"):
                records.append({
                    "pcap_epoch": epoch,
                    "src_ip": src,
                    "dst_ip": dst,
                    "msg_type": msg_type,
                    "credential": cname,
                })
        except Exception:
            continue
    return records


def _find_credential_frames(
    pcap_path: str,
    credential: str,
    tshark_bin: str = "tshark",
) -> list[float]:
    """Return pcap_epoch timestamps of all frames containing the credential string."""
    try:
        result = subprocess.run(
            [tshark_bin, "-r", pcap_path, "-T", "fields",
             "-e", "frame.time_epoch",
             "-Y", f'frame contains "{credential}"'],
            capture_output=True, text=True, timeout=45
        )
    except Exception:
        return []

    epochs = []
    for line in result.stdout.strip().split("\n"):
        line = line.strip()
        if line:
            try:
                epochs.append(float(line))
            except ValueError:
                pass
    return epochs


def run_credential_extraction(
    conn: sqlite3.Connection,
    pcap_dir: str,
    tshark_bin: str = "tshark",
    progress_callback=None,
) -> int:
    """
    Main entry point. Finds attacker-linked PCAPs, extracts credential
    correlations, and inserts records into pcap_credentials table.

    Returns number of credential records inserted.
    """
    # Ensure pcap_credentials table exists
    conn.execute("""
        CREATE TABLE IF NOT EXISTS pcap_credentials (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            attacker_ip     TEXT,
            target_ip       TEXT,
            credential      TEXT,
            credential_type TEXT,
            pcap_epoch_rdp  REAL,
            pcap_epoch_cred REAL,
            real_ts_rdp     TEXT,
            real_ts_cred    TEXT,
            clock_offset    REAL,
            delta_secs      REAL,
            evidence_note   TEXT,
            source_pcap     TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_pcap_cred_ip ON pcap_credentials(attacker_ip)")
    conn.commit()

    # Get all unique (attacker_ip, source_pcap) pairs from pcap_rdp where
    # the attacker is external and the destination is an internal host
    external_rdp = conn.execute("""
        SELECT DISTINCT src_ip, dst_ip, source_pcap
        FROM pcap_rdp
        WHERE src_ip NOT LIKE '10.%'
          AND src_ip NOT LIKE '172.%'
          AND src_ip NOT LIKE '192.168.%'
          AND dst_ip LIKE '10.%'
        ORDER BY src_ip
    """).fetchall()

    if not external_rdp:
        print("  [CredExtract] No external RDP entries found in pcap_rdp")
        return 0

    # Focus on PCAPs that also contain credential strings
    # Group by source_pcap to avoid redundant clock offset computation
    pcap_to_sessions: dict[str, list[tuple]] = {}
    for src_ip, dst_ip, source_pcap in external_rdp:
        if source_pcap not in pcap_to_sessions:
            pcap_to_sessions[source_pcap] = []
        pcap_to_sessions[source_pcap].append((src_ip, dst_ip))

    # Hard cap: scan at most 10 PCAPs to keep phase 5 fast.
    # The attacker's initial RDP is in early March 1 PCAPs — the credential
    # extractor only needs to find the first hit, not scan all 129 files.
    _MAX_PCAPS_TO_SCAN = 10
    if len(pcap_to_sessions) > _MAX_PCAPS_TO_SCAN:
        # Prefer PCAPs whose names suggest early March 1 timestamps
        # (the known attacker first appeared on 2025-03-01)
        def _march1_priority(name):
            n = name.lower()
            if "2025-03-01" in n or "20250301" in n:
                return 0
            if "2025-03-02" in n or "20250302" in n:
                return 1
            return 2
        sorted_pcaps = sorted(pcap_to_sessions.keys(), key=_march1_priority)
        pcap_to_sessions = {k: pcap_to_sessions[k] for k in sorted_pcaps[:_MAX_PCAPS_TO_SCAN]}
        print(f"  [CredExtract] Capped to {_MAX_PCAPS_TO_SCAN} PCAPs (prioritising March 1 files)")

    inserted = 0
    pcap_dir_path = Path(pcap_dir)

    for pcap_name, sessions in pcap_to_sessions.items():
        pcap_path = str(pcap_dir_path / pcap_name)
        if not Path(pcap_path).exists():
            continue

        if progress_callback:
            progress_callback(f"CredExtract: scanning {pcap_name}")

        # Step 1: check if any credential string exists in this PCAP
        found_creds: list[tuple[str, list[float]]] = []
        for cred_str in _CREDENTIAL_STRINGS:
            epochs = _find_credential_frames(pcap_path, cred_str, tshark_bin)
            if epochs:
                found_creds.append((cred_str, epochs))

        if not found_creds:
            continue

        print(f"  [CredExtract] Found credential strings in {pcap_name}")

        # Step 2: compute clock offset for this PCAP
        offset = _compute_pcap_clock_offset(pcap_path, conn, tshark_bin)
        if offset is None:
            print(f"  [CredExtract] Could not compute clock offset for {pcap_name}, skipping")
            continue

        print(f"  [CredExtract] Clock offset: {offset:.0f}s ({offset/86400:.1f} days)")

        # Step 3: for each attacker session in this PCAP, get the pcap_epoch
        # of the RDP connection
        for src_ip, dst_ip in sessions:
            # Get the pcap_epoch of the attacker's RDP from pcap_rdp
            rdp_rows = conn.execute(
                "SELECT ts FROM pcap_rdp WHERE src_ip=? AND dst_ip=? AND source_pcap=?",
                (src_ip, dst_ip, pcap_name)
            ).fetchall()

            for (rdp_ts_raw,) in rdp_rows:
                try:
                    rdp_pcap_epoch = float(rdp_ts_raw)
                except (ValueError, TypeError):
                    continue

                # Step 4: find Kerberos AS-REP / credential frames nearby
                kerberos_records = _find_kerberos_asrep_near(
                    pcap_path, rdp_pcap_epoch, _CORRELATION_WINDOW_SECS, tshark_bin
                )

                # Step 5: also check raw credential frame epochs
                for cred_str, cred_epochs in found_creds:
                    nearby_cred_epochs = [
                        e for e in cred_epochs
                        if 0 <= (e - rdp_pcap_epoch) <= _CORRELATION_WINDOW_SECS
                    ]

                    if not nearby_cred_epochs and not kerberos_records:
                        continue

                    # Use Kerberos records if available (more specific)
                    if kerberos_records:
                        for krb in kerberos_records:
                            cred_name = krb["credential"]
                            cred_pcap_epoch = krb["pcap_epoch"]
                            delta = cred_pcap_epoch - rdp_pcap_epoch
                            real_rdp_ts = _epoch_to_iso(rdp_pcap_epoch - offset)
                            real_cred_ts = _epoch_to_iso(cred_pcap_epoch - offset)
                            msg_desc = "Kerberos AS-REP (TGT issued)" if krb["msg_type"] == "11" else "Kerberos AS-REQ (credential attempt)"
                            note = (
                                f"{msg_desc} for '{cred_name}' to {krb['dst_ip']} "
                                f"{delta:.0f}s after RDP from {src_ip}. "
                                f"PCAP clock corrected by {offset/86400:.1f} days."
                            )
                            conn.execute("""
                                INSERT INTO pcap_credentials
                                (attacker_ip, target_ip, credential, credential_type,
                                 pcap_epoch_rdp, pcap_epoch_cred, real_ts_rdp, real_ts_cred,
                                 clock_offset, delta_secs, evidence_note, source_pcap)
                                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                            """, (
                                src_ip, dst_ip, cred_name, "kerberos_ticket",
                                rdp_pcap_epoch, cred_pcap_epoch,
                                real_rdp_ts, real_cred_ts,
                                offset, delta, note, pcap_name
                            ))
                            inserted += 1
                            print(f"  [CredExtract] {src_ip} → {cred_name} @ {real_rdp_ts} (delta {delta:.0f}s)")
                    elif nearby_cred_epochs:
                        # Fall back to raw string match
                        earliest = min(nearby_cred_epochs)
                        delta = earliest - rdp_pcap_epoch
                        real_rdp_ts = _epoch_to_iso(rdp_pcap_epoch - offset)
                        real_cred_ts = _epoch_to_iso(earliest - offset)
                        note = (
                            f"Credential string '{cred_str}' found in raw frame "
                            f"{delta:.0f}s after RDP from {src_ip}. "
                            f"PCAP clock corrected by {offset/86400:.1f} days."
                        )
                        conn.execute("""
                            INSERT INTO pcap_credentials
                            (attacker_ip, target_ip, credential, credential_type,
                             pcap_epoch_rdp, pcap_epoch_cred, real_ts_rdp, real_ts_cred,
                             clock_offset, delta_secs, evidence_note, source_pcap)
                            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                        """, (
                            src_ip, dst_ip, cred_str, "raw_string",
                            rdp_pcap_epoch, earliest,
                            real_rdp_ts, real_cred_ts,
                            offset, delta, note, pcap_name
                        ))
                        inserted += 1
                        print(f"  [CredExtract] {src_ip} → '{cred_str}' (raw) @ {real_rdp_ts} (delta {delta:.0f}s)")

    conn.commit()
    print(f"  [CredExtract] Done. Inserted {inserted} credential records.")
    return inserted
