"""CLI entrypoints and command wiring for Perimeter."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from perimeter.nmap_parser import format_scan_summary, parse_nmap_xml
from perimeter.nmap_runner import NmapNotFoundError, run_nmap_scan


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="perimeter")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Run an nmap scan against a target.")
    scan.add_argument("target", help="Target host or network (e.g. 192.168.1.0/24).")
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
    return parser


def _handle_scan(args: argparse.Namespace) -> int:
    try:
        result = run_nmap_scan(
            args.target,
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


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _handle_scan(args)

    parser.error(f"Unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
