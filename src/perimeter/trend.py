"""Trend analysis for network scan reports."""

from __future__ import annotations

from typing import Any

from perimeter.storage import IPReportStorage


def _finding_key(finding: dict[str, Any]) -> tuple:
    """Generate a unique key for a finding for comparison purposes."""
    return (
        finding.get("host"),
        finding.get("port"),
        finding.get("protocol"),
    )


class TrendAnalyzer:
    """Analyze trends across multiple scan reports for a target IP."""

    def __init__(self, storage: IPReportStorage) -> None:
        """Initialize with a storage instance."""
        self.storage = storage

    def get_trend_summary(self, target_ip: str) -> dict[str, Any] | None:
        """
        Get a summary of trends for a target IP across all stored reports.

        Returns None if no reports exist for the target.
        """
        reports = self.storage.get_target_reports(target_ip)
        if not reports:
            return None

        _, latest_report = reports[0]
        _, oldest_report = reports[-1]

        latest_findings = latest_report.get("findings", [])
        oldest_findings = oldest_report.get("findings", [])

        latest_summary = latest_report.get("summary", {})
        oldest_summary = oldest_report.get("summary", {})

        # Build finding maps for comparison
        latest_findings_map = {_finding_key(f): f for f in latest_findings}
        oldest_findings_map = {_finding_key(f): f for f in oldest_findings}

        # Find new, resolved, and changed findings
        new_findings = []
        resolved_findings = []
        changed_findings = []
        unchanged_findings = []

        for key, finding in latest_findings_map.items():
            if key not in oldest_findings_map:
                new_findings.append(finding)
            else:
                old_finding = oldest_findings_map[key]
                if finding.get("score") != old_finding.get("score"):
                    changed_findings.append(
                        {"finding": finding, "previous_score": old_finding.get("score")}
                    )
                else:
                    unchanged_findings.append(finding)

        for key in oldest_findings_map.keys():
            if key not in latest_findings_map:
                resolved_findings.append(oldest_findings_map[key])

        # Calculate changes in open ports
        latest_open = latest_summary.get("open_ports_analyzed", 0)
        oldest_open = oldest_summary.get("open_ports_analyzed", 0)
        open_ports_delta = latest_open - oldest_open

        # Calculate changes in severity distribution
        severity_trend = {
            "critical": {
                "latest": latest_summary.get("critical_findings", 0),
                "oldest": oldest_summary.get("critical_findings", 0),
            },
            "high": {
                "latest": latest_summary.get("high_findings", 0),
                "oldest": oldest_summary.get("high_findings", 0),
            },
            "medium": {
                "latest": latest_summary.get("medium_findings", 0),
                "oldest": oldest_summary.get("medium_findings", 0),
            },
            "low": {
                "latest": latest_summary.get("low_findings", 0),
                "oldest": oldest_summary.get("low_findings", 0),
            },
        }

        return {
            "target": target_ip,
            "report_count": len(reports),
            "oldest_scan": oldest_report.get("timestamp"),
            "latest_scan": latest_report.get("timestamp"),
            "open_ports_delta": open_ports_delta,
            "severity_trend": severity_trend,
            "new_findings": new_findings,
            "resolved_findings": resolved_findings,
            "changed_findings": changed_findings,
            "unchanged_findings_count": len(unchanged_findings),
            "status": _calculate_status(
                open_ports_delta, new_findings, resolved_findings, changed_findings
            ),
        }

    def compare_reports(
        self, target_ip: str, report_index_1: int = 0, report_index_2: int = 1
    ) -> dict[str, Any] | None:
        """
        Compare two specific reports (by index, 0 = latest).

        Returns detailed comparison or None if reports don't exist.
        """
        reports = self.storage.get_target_reports(target_ip)
        if len(reports) <= max(report_index_1, report_index_2):
            return None

        path1, report1 = reports[report_index_1]
        path2, report2 = reports[report_index_2]

        findings1 = report1.get("findings", [])
        findings2 = report2.get("findings", [])

        findings1_map = {_finding_key(f): f for f in findings1}
        findings2_map = {_finding_key(f): f for f in findings2}

        return {
            "report_1": {
                "timestamp": report1.get("timestamp"),
                "path": str(path1),
                "open_ports": report1.get("summary", {}).get("open_ports_analyzed", 0),
            },
            "report_2": {
                "timestamp": report2.get("timestamp"),
                "path": str(path2),
                "open_ports": report2.get("summary", {}).get("open_ports_analyzed", 0),
            },
            "new_findings": [f for k, f in findings1_map.items() if k not in findings2_map],
            "resolved_findings": [
                f for k, f in findings2_map.items() if k not in findings1_map
            ],
            "changed_findings": [
                {
                    "latest": f1,
                    "previous": findings2_map[k],
                    "score_change": f1.get("score", 0) - findings2_map[k].get("score", 0),
                }
                for k, f1 in findings1_map.items()
                if k in findings2_map
                and f1.get("score") != findings2_map[k].get("score")
            ],
        }


def _calculate_status(
    open_ports_delta: int,
    new_findings: list,
    resolved_findings: list,
    changed_findings: list,
) -> str:
    """Determine overall security posture status based on changes."""
    if open_ports_delta > 0 or len(new_findings) > 0:
        if len(new_findings) >= 3 or open_ports_delta > 2:
            return "worsened"
        return "slightly-worsened"
    elif len(resolved_findings) > 0:
        if len(new_findings) == 0:
            return "improved"
        return "stable"
    return "stable"


def format_trend_report(trend_data: dict[str, Any], max_items: int = 5) -> str:
    """Format trend analysis as human-readable text."""
    if not trend_data:
        return "No trend data available."

    target = trend_data.get("target", "unknown")
    count = trend_data.get("report_count", 0)
    lines = [
        f"Perimeter Trend Analysis for {target}",
        f"Reports analyzed: {count}",
        f"Period: {trend_data.get('oldest_scan')} → {trend_data.get('latest_scan')}",
        "",
        "Security Posture: " + trend_data.get("status", "unknown").upper(),
        f"Open Ports Delta: {trend_data.get('open_ports_delta', 0):+d}",
    ]

    severity = trend_data.get("severity_trend", {})
    lines.append("")
    lines.append("Severity Trend:")
    for sev in ["critical", "high", "medium", "low"]:
        if sev in severity:
            old = severity[sev].get("oldest", 0)
            new = severity[sev].get("latest", 0)
            delta = new - old
            lines.append(f"  {sev.capitalize()}: {old} → {new} {delta:+d}")

    new_findings = trend_data.get("new_findings", [])
    if new_findings:
        lines.append(f"")
        lines.append(f"New Findings ({len(new_findings)} total, showing {min(len(new_findings), max_items)}):")
        for finding in new_findings[:max_items]:
            lines.append(
                f"  - [{finding.get('severity', 'unknown').upper()}] "
                f"{finding.get('host')} {finding.get('port')}/{finding.get('protocol')} "
                f"{finding.get('service')}"
            )

    resolved = trend_data.get("resolved_findings", [])
    if resolved:
        lines.append(f"")
        lines.append(f"Resolved Findings ({len(resolved)} total):")
        for finding in resolved[:max_items]:
            lines.append(
                f"  - {finding.get('host')} {finding.get('port')}/{finding.get('protocol')} "
                f"{finding.get('service')}"
            )

    changed = trend_data.get("changed_findings", [])
    if changed:
        lines.append(f"")
        lines.append(f"Changed Findings ({len(changed)} total, showing {min(len(changed), max_items)}):")
        for item in changed[:max_items]:
            f = item.get("finding", {})
            prev_score = item.get("previous_score", 0)
            curr_score = f.get("score", 0)
            lines.append(
                f"  - {f.get('host')} {f.get('port')}/{f.get('protocol')} "
                f"{f.get('service')}: {prev_score} → {curr_score} {curr_score - prev_score:+d}"
            )

    return "\n".join(lines)
