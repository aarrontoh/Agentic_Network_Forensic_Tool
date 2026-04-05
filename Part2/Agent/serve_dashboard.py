#!/usr/bin/env python3
"""Serve the forensic agent live dashboard.

Usage:
    python3 serve_dashboard.py --case apex_global
    python3 serve_dashboard.py --case apex_global --port 8080
"""
from __future__ import annotations

import argparse
import http.server
import json
import socketserver
from pathlib import Path


_MIME = {
    ".html": "text/html",
    ".json": "application/json",
    ".md":   "text/plain",
    ".js":   "application/javascript",
    ".css":  "text/css",
}


class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    case: str = ""
    base_dir: Path = Path(".")

    # Files served directly from the case output directory
    _CASE_FILES = {
        "/progress.json":       "progress.json",
        "/findings.json":       "findings.json",
        "/timeline.json":       "timeline.json",
        "/report.md":           "report.md",
        "/agent_log.json":      "agent_log.json",
        "/ingest_summary.json": "ingest_summary.json",
    }

    def do_GET(self) -> None:
        path = self.path.split("?")[0]

        # Dashboard HTML
        if path in ("/", "/index.html", "/dashboard.html"):
            self._serve(self.base_dir / "dashboard.html", "text/html")
            return

        # Case output files
        if path in self._CASE_FILES:
            file_path = (
                self.base_dir / "data" / "output" / self.case / self._CASE_FILES[path]
            )
            suffix = Path(path).suffix
            self._serve(file_path, _MIME.get(suffix, "application/octet-stream"))
            return

        self.send_response(404)
        self.end_headers()

    def _serve(self, file_path: Path, content_type: str) -> None:
        if not file_path.exists():
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":"not found"}')
            return
        data = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache, no-store")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args: object) -> None:
        pass  # suppress request noise


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve the forensic agent live dashboard.")
    parser.add_argument("--case", required=True)
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    DashboardHandler.case = args.case
    DashboardHandler.base_dir = Path(__file__).parent

    with socketserver.TCPServer(("", args.port), DashboardHandler) as httpd:
        httpd.allow_reuse_address = True
        print(f"  Dashboard  →  http://localhost:{args.port}")
        print(f"  Case       →  {args.case}")
        print(f"  Press Ctrl+C to stop")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
