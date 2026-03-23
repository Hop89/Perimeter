"""Report storage and retrieval system organized by IP address."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote, quote


class IPReportStorage:
    """Manage network scan reports organized by target IP address."""

    def __init__(self, base_dir: str | Path = "reports") -> None:
        """Initialize storage with a base directory for reports."""
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def save_report(self, target_ip: str, report: dict[str, Any]) -> Path:
        """
        Save a report for a target IP with timestamp.

        Returns the path where the report was saved.
        """
        ip_dir = self._target_dir(target_ip)
        ip_dir.mkdir(parents=True, exist_ok=True)

        now = datetime.now()
        timestamp = now.strftime("%Y%m%d_%H%M%S_%f")
        report_file = ip_dir / f"report_{timestamp}.json"

        # Add metadata
        report_with_meta = {
            "timestamp": now.isoformat(),
            "target": target_ip,
            **report,
        }

        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(report_with_meta, f, indent=2)

        return report_file

    def get_target_reports(self, target_ip: str) -> list[tuple[Path, dict[str, Any]]]:
        """
        Get all reports for a target IP, ordered by most recent first.

        Returns list of (filepath, report_dict) tuples.
        """
        ip_dir = self._target_dir(target_ip)
        if not ip_dir.exists():
            return []

        reports: list[tuple[Path, dict[str, Any]]] = []
        for report_file in sorted(ip_dir.glob("report_*.json"), reverse=True):
            try:
                with open(report_file, "r", encoding="utf-8") as f:
                    report = json.load(f)
                reports.append((report_file, report))
            except (OSError, json.JSONDecodeError):
                continue

        return reports

    def get_latest_report(
        self, target_ip: str
    ) -> tuple[Path, dict[str, Any]] | None:
        """Get the most recent report for a target IP."""
        reports = self.get_target_reports(target_ip)
        return reports[0] if reports else None

    def list_targets(self) -> list[str]:
        """List all IP addresses that have stored reports."""
        if not self.base_dir.exists():
            return []

        targets = [unquote(d.name) for d in self.base_dir.iterdir() if d.is_dir()]
        return sorted(targets)

    def get_report_count(self, target_ip: str) -> int:
        """Get the number of reports stored for a target IP."""
        ip_dir = self._target_dir(target_ip)
        if not ip_dir.exists():
            return 0
        return len(list(ip_dir.glob("report_*.json")))

    def delete_report(self, target_ip: str, report_file: Path) -> bool:
        """Delete a specific report file."""
        try:
            report_file.unlink()
            return True
        except OSError:
            return False

    def delete_all_target_reports(self, target_ip: str) -> int:
        """Delete all reports for a target IP. Returns count of deleted files."""
        ip_dir = self._target_dir(target_ip)
        if not ip_dir.exists():
            return 0

        deleted_count = 0
        for report_file in ip_dir.glob("report_*.json"):
            try:
                report_file.unlink()
                deleted_count += 1
            except OSError:
                continue

        # Remove directory if empty
        try:
            ip_dir.rmdir()
        except OSError:
            pass

        return deleted_count

    def _target_dir(self, target_ip: str) -> Path:
        encoded = quote(target_ip, safe=".")
        encoded_path = self.base_dir / encoded
        legacy_path = self.base_dir / target_ip
        if legacy_path.exists() and encoded_path != legacy_path:
            return legacy_path
        return encoded_path
