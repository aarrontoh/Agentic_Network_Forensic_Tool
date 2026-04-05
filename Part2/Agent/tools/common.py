from __future__ import annotations

import ipaddress
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List


def ensure_dir(path: str | Path) -> Path:
    target = Path(path)
    target.mkdir(parents=True, exist_ok=True)
    return target


def load_jsonl(path: str | Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    target = Path(path)
    if not target.exists():
        return rows

    with target.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def is_internal_ip(ip_value: str, internal_networks: Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> bool:
    try:
        address = ipaddress.ip_address(ip_value)
    except ValueError:
        return False

    for network in internal_networks:
        if address in network:
            return True
    return False


def ts_to_iso(ts_value: Any) -> str:
    if ts_value in (None, ""):
        return ""
    try:
        numeric = float(ts_value)
    except (TypeError, ValueError):
        return str(ts_value)
    return datetime.fromtimestamp(numeric, tz=timezone.utc).isoformat()


def sliding_windows(rows: Iterable[Dict[str, Any]], bucket_seconds: int) -> Dict[tuple, List[Dict[str, Any]]]:
    windows: Dict[tuple, List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        try:
            ts_value = int(float(row.get("ts", 0)))
        except (TypeError, ValueError):
            continue
        bucket = ts_value - (ts_value % bucket_seconds)
        src = row.get("id.orig_h", "")
        port = str(row.get("id.resp_p", ""))
        windows[(src, port, bucket)].append(row)
    return windows
