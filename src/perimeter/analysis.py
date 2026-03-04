"""Deterministic vulnerability triage with optional AI enrichment."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any
from urllib import error, request


@dataclass(frozen=True)
class AnalysisResult:
    summary: dict[str, Any]
    findings: list[dict[str, Any]]


_PORT_RISK_HINTS: dict[int, tuple[str, int, str]] = {
    21: ("ftp", 80, "FTP often exposes cleartext credentials."),
    22: ("ssh", 35, "SSH is expected but should enforce strong authentication."),
    23: ("telnet", 92, "Telnet is insecure and transmits credentials in cleartext."),
    25: ("smtp", 55, "SMTP can be abused if open relay controls are weak."),
    53: ("dns", 40, "Public DNS exposure should be intentional and restricted."),
    80: ("http", 50, "HTTP may expose legacy interfaces; prefer HTTPS."),
    110: ("pop3", 75, "POP3 is legacy and commonly lacks modern protections."),
    139: ("netbios-ssn", 85, "NetBIOS exposure can leak host and share information."),
    143: ("imap", 65, "IMAP should be encrypted and access-controlled."),
    443: ("https", 30, "HTTPS is expected; validate TLS posture and patch level."),
    445: ("microsoft-ds", 95, "SMB exposure is high-risk for lateral movement."),
    3389: ("ms-wbt-server", 88, "RDP exposure is a common brute-force target."),
    5432: ("postgresql", 82, "Database services should not be broadly exposed."),
    6379: ("redis", 96, "Redis exposure is critical if unauthenticated."),
    27017: ("mongodb", 93, "MongoDB exposure can leak sensitive data."),
}


def _severity_label(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 75:
        return "high"
    if score >= 50:
        return "medium"
    if score >= 25:
        return "low"
    return "info"


def analyze_hosts(hosts: list[dict[str, Any]]) -> AnalysisResult:
    """Produce deterministic risk findings from parsed nmap host data."""
    findings: list[dict[str, Any]] = []
    host_count = len(hosts)
    open_port_count = 0

    for host in hosts:
        address = host.get("address", "unknown")
        state = host.get("state", "unknown")
        for port in host.get("ports", []):
            if port.get("state") != "open":
                continue
            open_port_count += 1

            port_num = int(port.get("port", 0))
            service = (port.get("service") or "unknown").lower()
            version = (port.get("version") or "").strip()

            risk_hint = _PORT_RISK_HINTS.get(port_num)
            base_score = 35
            rationale = "Open service detected; verify necessity and patch status."

            if risk_hint is not None:
                _, base_score, rationale = risk_hint
            elif service in {"telnet", "vnc", "ftp"}:
                base_score = 85
                rationale = "Legacy remote access protocol may be insecure by default."
            elif service in {"ssh", "https"}:
                base_score = 30
                rationale = "Generally acceptable if hardened and monitored."
            elif service in {"mysql", "mssql", "postgresql", "mongodb", "redis"}:
                base_score = 84
                rationale = "Database service exposure should be tightly restricted."

            if state != "up":
                base_score = max(15, base_score - 10)
            if version:
                base_score = max(10, base_score - 5)

            findings.append(
                {
                    "host": address,
                    "port": port_num,
                    "protocol": port.get("protocol", "tcp"),
                    "service": service,
                    "version": version or None,
                    "score": base_score,
                    "severity": _severity_label(base_score),
                    "rationale": rationale,
                    "remediation": "Restrict network exposure, patch to latest stable release, and require strong authentication.",
                }
            )

    findings.sort(key=lambda item: item["score"], reverse=True)
    summary = {
        "hosts_analyzed": host_count,
        "open_ports_analyzed": open_port_count,
        "critical_findings": sum(1 for item in findings if item["severity"] == "critical"),
        "high_findings": sum(1 for item in findings if item["severity"] == "high"),
        "medium_findings": sum(1 for item in findings if item["severity"] == "medium"),
        "low_findings": sum(1 for item in findings if item["severity"] == "low"),
    }
    return AnalysisResult(summary=summary, findings=findings)


def maybe_generate_ai_triage(
    report: dict[str, Any],
    *,
    enabled: bool,
    model: str | None = None,
    timeout_seconds: int = 45,
) -> dict[str, Any] | None:
    """
    Optionally call OpenAI for narrative triage.

    Returns None when disabled or when credentials are unavailable.
    Raises RuntimeError on request/parse failures.
    """
    if not enabled:
        return None

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return None

    chosen_model = model or os.getenv("PERIMETER_AI_MODEL") or "gpt-4o-mini"

    prompt = {
        "summary": report.get("summary", {}),
        "top_findings": report.get("findings", [])[:12],
        "instructions": (
            "Return JSON with keys: executive_summary, priority_actions (list), "
            "false_positive_notes (list), confidence (0-1). Keep recommendations "
            "defensive and do not include exploit instructions."
        ),
    }
    body = {
        "model": chosen_model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a defensive security analyst. Provide concise, practical "
                    "triage guidance from scanner findings."
                ),
            },
            {"role": "user", "content": json.dumps(prompt)},
        ],
        "response_format": {"type": "json_object"},
        "temperature": 0.2,
    }
    req = request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=timeout_seconds) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except error.URLError as exc:
        raise RuntimeError(f"AI request failed: {exc}") from exc

    try:
        content = payload["choices"][0]["message"]["content"]
        if not isinstance(content, str):
            raise TypeError("Unexpected AI response content type.")
        parsed = json.loads(content)
    except Exception as exc:
        raise RuntimeError("AI response could not be parsed as JSON.") from exc

    return {
        "provider": "openai",
        "model": chosen_model,
        "triage": parsed,
    }


def format_analysis_text(report: dict[str, Any], max_findings: int = 20) -> str:
    """Render report JSON as compact human-readable text."""
    summary = report.get("summary", {})
    findings = report.get("findings", [])[:max_findings]
    lines = [
        "Perimeter Analysis",
        f"Hosts analyzed: {summary.get('hosts_analyzed', 0)}",
        f"Open ports analyzed: {summary.get('open_ports_analyzed', 0)}",
        (
            "Findings by severity: "
            f"critical={summary.get('critical_findings', 0)}, "
            f"high={summary.get('high_findings', 0)}, "
            f"medium={summary.get('medium_findings', 0)}, "
            f"low={summary.get('low_findings', 0)}"
        ),
        "",
        "Top Findings:",
    ]
    if not findings:
        lines.append("  - No open-port findings were produced.")
    for item in findings:
        version = f" ({item['version']})" if item.get("version") else ""
        lines.append(
            f"  - [{item['severity'].upper()} {item['score']}] {item['host']} "
            f"{item['port']}/{item['protocol']} {item['service']}{version}"
        )
        lines.append(f"    Rationale: {item['rationale']}")
        lines.append(f"    Remediation: {item['remediation']}")

    ai = report.get("ai")
    if ai and isinstance(ai, dict):
        lines.extend(["", f"AI Triage ({ai.get('model', 'unknown model')}):"])
        triage = ai.get("triage", {})
        if isinstance(triage, dict):
            summary_text = triage.get("executive_summary")
            if summary_text:
                lines.append(f"  Summary: {summary_text}")
            actions = triage.get("priority_actions", [])
            if isinstance(actions, list):
                for action in actions[:5]:
                    lines.append(f"  - {action}")

    return "\n".join(lines)
