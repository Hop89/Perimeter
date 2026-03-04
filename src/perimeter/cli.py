"""CLI entrypoints and command wiring for Perimeter."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from perimeter.analysis import (
    analyze_hosts,
    format_analysis_text,
    maybe_generate_ai_triage,
)
from perimeter.nmap_parser import format_scan_summary, parse_nmap_xml
from perimeter.nmap_runner import (
    LocalIPDetectionError,
    NmapNotFoundError,
    detect_connected_ip,
    run_nmap_scan,
)


def _build_parser() -> tuple[argparse.ArgumentParser, dict[str, argparse.ArgumentParser]]:
    parser = argparse.ArgumentParser(prog="perimeter")
    subparsers = parser.add_subparsers(dest="command", required=True)
    command_parsers: dict[str, argparse.ArgumentParser] = {}

    scan = subparsers.add_parser("scan", help="Run an nmap scan against a target.")
    command_parsers["scan"] = scan
    scan.add_argument(
        "target",
        nargs="?",
        help="Target host or network (e.g. 192.168.1.0/24).",
    )
    scan.add_argument(
        "--connected",
        action="store_true",
        help="Scan the local IP currently used by this machine.",
    )
    scan.add_argument(
        "--nmap-arg",
        action="append",
        default=[],
        help="Pass-through argument to nmap (repeatable).",
    )
    scan.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Write XML output to a file instead of stdout.",
    )
    scan.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="Timeout in seconds for the nmap command.",
    )
    scan.add_argument(
        "--raw-xml",
        action="store_true",
        help="Print raw XML output instead of formatted summary.",
    )

    analyze = subparsers.add_parser(
        "analyze",
        help="Analyze nmap XML and produce prioritized vulnerability triage.",
    )
    command_parsers["analyze"] = analyze
    analyze.add_argument(
        "input_xml",
        type=Path,
        help="Path to nmap XML output file.",
    )
    analyze.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format for analysis results.",
    )
    analyze.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Write analysis output to a file instead of stdout.",
    )
    analyze.add_argument(
        "--max-findings",
        type=int,
        default=20,
        help="Maximum findings to print in text mode.",
    )
    analyze.add_argument(
        "--ai",
        action="store_true",
        help="Enable optional AI triage enrichment (requires OPENAI_API_KEY).",
    )
    analyze.add_argument(
        "--ai-model",
        default=None,
        help="Override model used for AI triage (defaults to PERIMETER_AI_MODEL or gpt-4o-mini).",
    )
    help_cmd = subparsers.add_parser("help", help="Show CLI help.")
    command_parsers["help"] = help_cmd
    help_cmd.add_argument(
        "topic",
        nargs="?",
        choices=["scan", "analyze"],
        help="Optional command name to show detailed help for.",
    )
    return parser, command_parsers


def _handle_scan(args: argparse.Namespace) -> int:
    if args.connected and args.target:
        sys.stderr.write("Use either TARGET or --connected, not both.\n")
        return 2
    if not args.connected and not args.target:
        sys.stderr.write("A TARGET is required unless --connected is used.\n")
        return 2

    target = args.target
    if args.connected:
        try:
            target = detect_connected_ip()
        except LocalIPDetectionError as exc:
            sys.stderr.write(f"{exc}\n")
            return 2
        sys.stdout.write(f"Detected local IP: {target}\n")

    try:
        result = run_nmap_scan(
            target,
            extra_args=args.nmap_arg,
            output_path=args.output,
            timeout_seconds=args.timeout,
        )
    except NmapNotFoundError:
        sys.stderr.write("nmap is not installed or not on PATH.\n")
        sys.stderr.write(
            "Windows: install Nmap and enable 'Add to PATH' during setup.\n"
        )
        sys.stderr.write("Linux (Debian/Ubuntu): sudo apt install nmap\n")
        return 2
    if result.stdout:
        if args.raw_xml:
            sys.stdout.write(result.stdout)
            if not result.stdout.endswith("\n"):
                sys.stdout.write("\n")
        else:
            try:
                hosts = parse_nmap_xml(result.stdout)
                sys.stdout.write(format_scan_summary(hosts))
                sys.stdout.write("\n")
            except Exception:
                # Fall back to XML if parser fails on unexpected nmap output.
                sys.stdout.write(result.stdout)
                if not result.stdout.endswith("\n"):
                    sys.stdout.write("\n")
    elif result.output_path is not None:
        sys.stdout.write(f"Scan XML saved to: {result.output_path}\n")
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
    return result.returncode


def _handle_analyze(args: argparse.Namespace) -> int:
    if not args.input_xml.exists():
        sys.stderr.write(f"Input file not found: {args.input_xml}\n")
        return 2

    try:
        xml_text = args.input_xml.read_text(encoding="utf-8")
    except OSError as exc:
        sys.stderr.write(f"Failed to read input XML: {exc}\n")
        return 2

    try:
        hosts = parse_nmap_xml(xml_text)
    except Exception as exc:
        sys.stderr.write(f"Failed to parse nmap XML: {exc}\n")
        return 2

    analysis = analyze_hosts(hosts)
    report: dict[str, object] = {
        "summary": analysis.summary,
        "findings": analysis.findings,
        "source": str(args.input_xml),
    }

    if args.ai:
        try:
            ai_triage = maybe_generate_ai_triage(report, enabled=True, model=args.ai_model)
        except RuntimeError as exc:
            sys.stderr.write(f"{exc}\n")
            return 2
        if ai_triage is None:
            sys.stderr.write(
                "AI triage skipped: set OPENAI_API_KEY to enable remote AI enrichment.\n"
            )
        else:
            report["ai"] = ai_triage

    if args.format == "json":
        rendered = json.dumps(report, indent=2)
    else:
        rendered = format_analysis_text(report, max_findings=max(1, args.max_findings))

    if args.output is not None:
        try:
            args.output.write_text(f"{rendered}\n", encoding="utf-8")
        except OSError as exc:
            sys.stderr.write(f"Failed to write output file: {exc}\n")
            return 2
        sys.stdout.write(f"Analysis written to: {args.output}\n")
        return 0

    sys.stdout.write(rendered)
    if not rendered.endswith("\n"):
        sys.stdout.write("\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser, command_parsers = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _handle_scan(args)
    if args.command == "analyze":
        return _handle_analyze(args)
    if args.command == "help":
        if args.topic:
            command_parsers[args.topic].print_help()
        else:
            parser.print_help()
        return 0

    parser.error(f"Unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
