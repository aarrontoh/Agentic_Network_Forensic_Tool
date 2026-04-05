from __future__ import annotations

import datetime
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List

from tools.common import ensure_dir


def _write_text(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def _run_command(command: list[str], cwd: Path, stdout_path: Path, stderr_path: Path) -> Dict[str, Any]:
    result = subprocess.run(command, cwd=str(cwd), capture_output=True, text=True)
    _write_text(stdout_path, result.stdout)
    _write_text(stderr_path, result.stderr)
    return {
        "command": command,
        "returncode": result.returncode,
        "stdout": str(stdout_path),
        "stderr": str(stderr_path),
    }


def _discover_pcaps(input_path: Path) -> List[Path]:
    if input_path.is_file():
        return [input_path]
    if input_path.is_dir():
        return sorted(path for path in input_path.glob("*.pcap") if path.is_file())
    return []


def _run_capinfos(capinfos_path: str | None, pcap: Path) -> Dict[str, Any]:
    stat = pcap.stat()
    metadata: Dict[str, Any] = {
        "file_name": pcap.name,
        "path": str(pcap),
        "size_bytes": stat.st_size,
    }
    if not capinfos_path:
        return metadata

    try:
        result = subprocess.run(
            [capinfos_path, str(pcap)],
            capture_output=True, text=True, timeout=30,
        )
    except subprocess.TimeoutExpired:
        # capinfos timed out reading all packets; fall back to filename-based ordering.
        # Files are named with embedded dates (e.g. 250301) so filename sort is correct.
        metadata["capinfos_error"] = "timed out after 30s — skipping metadata"
        return metadata

    if result.returncode != 0:
        metadata["capinfos_error"] = result.stderr.strip() or "capinfos failed"
        return metadata

    patterns = {
        "earliest_packet_time": r"Earliest packet time:\s+(.+)",
        "latest_packet_time": r"Latest packet time:\s+(.+)",
        "capture_duration_seconds": r"Capture duration:\s+([0-9.]+) seconds",
        "number_of_packets": r"Number of packets:\s+([0-9]+(?:\s*k)?)",
    }
    for key, pattern in patterns.items():
        match = re.search(pattern, result.stdout)
        if match:
            metadata[key] = match.group(1).strip()
    return metadata


def _append_zeek_logs(segment_dir: Path, aggregate_dir: Path) -> None:
    for path in segment_dir.glob("*.log"):
        target = aggregate_dir / path.name
        content = path.read_text(encoding="utf-8", errors="ignore")
        with target.open("a", encoding="utf-8") as handle:
            if target.exists() and target.stat().st_size > 0 and not content.startswith("\n"):
                handle.write("\n")
            handle.write(content)


def _write_pcap_progress(
    work_dir: str,
    pcap_progress: Dict[str, Any],
    zeek_results: List[Dict[str, str]],
    tshark_results: List[Dict[str, str]],
) -> None:
    progress_path = Path(work_dir) / "progress.json"
    data: Dict[str, Any] = {}
    if progress_path.exists():
        try:
            data = json.loads(progress_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    data.update({
        "stage": "preprocessing",
        "updated_at": datetime.datetime.utcnow().isoformat(),
        "pcap_progress": pcap_progress,
        "zeek_results": zeek_results,
        "tshark_results": tshark_results,
    })
    progress_path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def run_preprocessing(pcap_path: str, work_dir: str) -> Dict[str, Any]:
    input_path = Path(pcap_path).resolve()
    base_dir = ensure_dir(Path(work_dir) / "preprocessing")
    zeek_dir = ensure_dir(base_dir / "zeek")
    zeek_segments_dir = ensure_dir(base_dir / "zeek_segments")
    tshark_dir = ensure_dir(base_dir / "tshark")

    artifacts: Dict[str, Any] = {
        "pcap_path": str(input_path),
        "zeek_dir": str(zeek_dir),
        "zeek_segments_dir": str(zeek_segments_dir),
        "tshark_dir": str(tshark_dir),
        "tool_status": {},
        "capture_inventory": [],
    }

    if not input_path.exists():
        raise FileNotFoundError(f"PCAP input not found: {input_path}")

    zeek_path = shutil.which("zeek")
    tshark_path = shutil.which("tshark")
    capinfos_path = shutil.which("capinfos")

    pcaps = _discover_pcaps(input_path)
    if not pcaps:
        raise FileNotFoundError(f"No .pcap files found in: {input_path}")

    inventory: List[Dict[str, Any]] = []
    for idx, pcap in enumerate(pcaps):
        _write_pcap_progress(
            work_dir,
            {"done": idx, "total": len(pcaps), "current": str(pcap), "phase": "capinfos"},
            [], [],
        )
        item = _run_capinfos(capinfos_path, pcap)
        inventory.append(item)
        _write_pcap_progress(
            work_dir,
            {"done": idx + 1, "total": len(pcaps), "current": str(pcap), "phase": "capinfos"},
            [], [],
        )
    inventory.sort(key=lambda item: (item.get("earliest_packet_time", ""), item["file_name"]))
    artifacts["capture_inventory"] = inventory
    artifacts["source_mode"] = "directory" if input_path.is_dir() else "single_file"
    artifacts["pcap_count"] = len(pcaps)
    artifacts["pcap_paths"] = [item["path"] for item in inventory]

    if len(pcaps) > 1:
        artifacts["dataset_observations"] = [
            "This input is a directory of segmented PCAPs.",
            "Chronology should be based on actual packet timestamps, not file names.",
            "Multi-file evidence correlation and possible overlap handling are required.",
        ]

    zeek_progress: List[Dict[str, str]] = []
    tshark_progress: List[Dict[str, str]] = []

    if zeek_path:
        zeek_runs = []
        for item in inventory:
            segment_name = Path(item["path"]).stem
            segment_dir = ensure_dir(zeek_segments_dir / segment_name)
            command = [zeek_path, "-C", "-r", item["path"], "LogAscii::use_json=T"]
            result = _run_command(
                command,
                segment_dir,
                segment_dir / "zeek.stdout.txt",
                segment_dir / "zeek.stderr.txt",
            )
            zeek_runs.append({"segment": segment_name, **result})
            if result["returncode"] == 0:
                _append_zeek_logs(segment_dir, zeek_dir)
            zeek_progress.append({"segment": segment_name, "status": "ok" if result["returncode"] == 0 else "error"})
            _write_pcap_progress(
                work_dir,
                {"done": len(zeek_progress), "total": len(inventory), "current": item["path"]},
                zeek_progress,
                tshark_progress,
            )
        artifacts["tool_status"]["zeek"] = zeek_runs
    else:
        artifacts["tool_status"]["zeek"] = {
            "returncode": 127,
            "error": "Zeek not found in PATH.",
        }

    if tshark_path:
        io_runs = []
        phs_runs = []
        conv_runs = []
        for index, item in enumerate(inventory):
            stem = Path(item["path"]).stem
            segment_dir = ensure_dir(tshark_dir / stem)

            io_command = [tshark_path, "-r", item["path"], "-q", "-z", "io,stat,300"]
            io_result = _run_command(io_command, segment_dir, segment_dir / "io_stat.stdout.txt", segment_dir / "io_stat.stderr.txt")
            io_runs.append({"segment": stem, **io_result})

            phs_command = [tshark_path, "-r", item["path"], "-q", "-z", "io,phs"]
            phs_runs.append(
                {"segment": stem, **_run_command(phs_command, segment_dir, segment_dir / "protocol_hierarchy.stdout.txt", segment_dir / "protocol_hierarchy.stderr.txt")}
            )

            # Full TCP conversation output gets very large on multi-file cases, so keep it limited.
            if len(pcaps) == 1 or index == 0:
                conv_command = [tshark_path, "-r", item["path"], "-q", "-z", "conv,tcp"]
                conv_runs.append(
                    {"segment": stem, **_run_command(conv_command, segment_dir, segment_dir / "tcp_conv.stdout.txt", segment_dir / "tcp_conv.stderr.txt")}
                )

            tshark_progress.append({"segment": stem, "status": "ok" if io_result["returncode"] == 0 else "error"})
            _write_pcap_progress(
                work_dir,
                {"done": len(tshark_progress), "total": len(inventory), "current": item["path"]},
                zeek_progress,
                tshark_progress,
            )

        artifacts["tool_status"]["tshark_io"] = io_runs
        artifacts["tool_status"]["tshark_protocol_hierarchy"] = phs_runs
        if conv_runs:
            artifacts["tool_status"]["tshark_conv"] = conv_runs
    else:
        artifacts["tool_status"]["tshark"] = {
            "returncode": 127,
            "error": "TShark not found in PATH.",
        }

    (Path(work_dir) / "preprocessing_summary.json").write_text(
        json.dumps(artifacts, indent=2), encoding="utf-8"
    )
    return artifacts
