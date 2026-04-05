"""
Phase 3 – PCAP file targeting.

Builds a time-range index for all PCAP files in the directory (using capinfos for exact
packet timestamps, with filename-date as fallback), then selects the minimum subset of
PCAP files whose time windows overlap with the alert timestamps.

PCAP filename convention: 34936-sensor-YYMMDD-NNNNNNN_redacted.pcap
  e.g. 34936-sensor-250301-00002364_redacted.pcap  →  2025-03-01

PCAP index caching
------------------
Running capinfos on 117+ PCAP files takes several minutes.
build_pcap_index() saves the result to <pcap_dir>/pcap_index_cache.json.
On every subsequent call the cache is loaded instantly.
The cache is invalidated if the set of .pcap filenames changes.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

_CACHE_FILENAME = "pcap_index_cache.json"


# --------------------------------------------------------------------------- #
# PCAP index builder (with persistent cache)
# --------------------------------------------------------------------------- #

def _run_capinfos(capinfos_bin: str, pcap: Path) -> Dict[str, Any]:
    """Run capinfos on a single PCAP and return the parsed metadata."""
    entry: Dict[str, Any] = {
        "path": str(pcap),
        "name": pcap.name,
        "size_bytes": pcap.stat().st_size,
    }

    m = re.search(r"-(\d{6})-", pcap.name)
    if m:
        try:
            entry["date"] = datetime.strptime("20" + m.group(1), "%Y%m%d").strftime("%Y-%m-%d")
        except ValueError:
            entry["date"] = ""
    else:
        entry["date"] = ""

    try:
        result = subprocess.run(
            [capinfos_bin, str(pcap)],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            for pattern, key in [
                (r"Earliest packet time:\s+(.+)", "earliest"),
                (r"Latest packet time:\s+(.+)", "latest"),
                (r"Number of packets:\s+([0-9]+)", "packet_count"),
            ]:
                cm = re.search(pattern, result.stdout)
                if cm:
                    entry[key] = cm.group(1).strip()
    except (subprocess.TimeoutExpired, OSError):
        pass

    return entry


def _cache_valid(cached: List[Dict[str, Any]], current_names: Set[str]) -> bool:
    """Return True if the cached index covers exactly the current set of PCAPs."""
    cached_names = {e.get("name", "") for e in cached}
    return cached_names == current_names


def build_pcap_index(
    pcap_dir: str,
    progress_cb: Optional[Callable[[int, int, str], None]] = None,
) -> List[Dict[str, Any]]:
    """
    Return a list of dicts, one per .pcap file, with metadata:
      path, name, size_bytes, date (YYYY-MM-DD), earliest, latest, packet_count

    Results are cached in <pcap_dir>/pcap_index_cache.json.
    A cached result is reused as long as the set of .pcap filenames has not changed.
    Delete the cache file to force a full rebuild.
    """
    pcap_path = Path(pcap_dir)
    if not pcap_path.is_dir():
        return []

    pcap_files = sorted(pcap_path.glob("*.pcap"))
    if not pcap_files:
        return []

    current_names = {p.name for p in pcap_files}
    cache_file = pcap_path / _CACHE_FILENAME

    # ── Try loading from cache ────────────────────────────────────────────────
    if cache_file.exists():
        try:
            cached = json.loads(cache_file.read_text(encoding="utf-8"))
            if _cache_valid(cached, current_names):
                return cached
        except Exception:
            pass   # corrupt cache → rebuild

    # ── Build index from scratch ──────────────────────────────────────────────
    capinfos_bin = shutil.which("capinfos")
    index: List[Dict[str, Any]] = []

    for idx, pcap in enumerate(pcap_files):
        if progress_cb:
            progress_cb(idx, len(pcap_files), pcap.name)
        if capinfos_bin:
            entry = _run_capinfos(capinfos_bin, pcap)
        else:
            # No capinfos – use filename date only
            entry = {"path": str(pcap), "name": pcap.name, "size_bytes": pcap.stat().st_size, "date": ""}
            m = re.search(r"-(\d{6})-", pcap.name)
            if m:
                try:
                    entry["date"] = datetime.strptime("20" + m.group(1), "%Y%m%d").strftime("%Y-%m-%d")
                except ValueError:
                    pass
        index.append(entry)
    if progress_cb:
        progress_cb(len(pcap_files), len(pcap_files), "done")

    index.sort(key=lambda e: (e.get("earliest", ""), e.get("date", ""), e["name"]))

    # ── Persist cache ─────────────────────────────────────────────────────────
    try:
        cache_file.write_text(json.dumps(index, indent=2), encoding="utf-8")
    except OSError:
        pass   # read-only filesystem or permission error – not fatal

    return index


# --------------------------------------------------------------------------- #
# PCAP selector
# --------------------------------------------------------------------------- #

_CAPINFOS_TS_FMTS = [
    "%b %d, %Y %H:%M:%S.%f UTC",
    "%b %d, %Y %H:%M:%S.%f %Z",
    "%b %d, %Y %H:%M:%S UTC",
    "%b  %d, %Y %H:%M:%S.%f UTC",
]


def _parse_capinfos_ts(ts_str: str) -> Optional[datetime]:
    for fmt in _CAPINFOS_TS_FMTS:
        try:
            dt = datetime.strptime(ts_str.strip(), fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def select_pcaps(
    pcap_index: List[Dict[str, Any]],
    alert_timestamps: List[str],
    max_pcaps: int = 30,
) -> List[str]:
    """
    Given the index and a list of ISO-8601 alert timestamps, return the paths
    of PCAP files that likely contain the corresponding traffic.

    Strategy:
      1. Extract unique dates from alert timestamps (YYYY-MM-DD).
      2. For each PCAP, check whether its time window overlaps with any alert date.
         Use capinfos-derived exact ranges when available; fall back to filename date.
      3. If nothing matched, return the first few PCAPs as a safety net.
    """
    if not alert_timestamps:
        return [e["path"] for e in pcap_index[:max_pcaps]]

    target_dates: Set[str] = set()
    target_dts: List[datetime] = []
    for ts in alert_timestamps:
        m = re.match(r"(\d{4}-\d{2}-\d{2})", ts)
        if m:
            target_dates.add(m.group(1))
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            target_dts.append(dt)
        except ValueError:
            pass

    selected: List[str] = []
    for entry in pcap_index:
        if "earliest" in entry and "latest" in entry:
            pcap_start = _parse_capinfos_ts(entry["earliest"])
            pcap_end = _parse_capinfos_ts(entry["latest"])
            if pcap_start and pcap_end and target_dts:
                if any(pcap_start <= dt <= pcap_end for dt in target_dts):
                    selected.append(entry["path"])
                continue

        if entry.get("date") in target_dates:
            selected.append(entry["path"])

    if not selected:
        for entry in pcap_index:
            if entry.get("date") in target_dates:
                selected.append(entry["path"])
            if len(selected) >= max_pcaps:
                break

    if not selected:
        selected = [e["path"] for e in pcap_index[:5]]

    return selected[:max_pcaps]
