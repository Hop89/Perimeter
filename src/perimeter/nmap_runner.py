"""Nmap invocation and dependency checks for Perimeter."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import shutil
import socket
import subprocess
from typing import Iterable


class NmapNotFoundError(RuntimeError):
    """Raised when nmap is not available on PATH."""


class LocalIPDetectionError(RuntimeError):
    """Raised when the local connected IP cannot be determined."""


@dataclass(frozen=True)
class NmapResult:
    command: list[str]
    returncode: int
    stdout: str | None
    stderr: str
    output_path: Path | None


def _find_nmap() -> str:
    nmap_path = shutil.which("nmap")
    if nmap_path:
        return nmap_path

    # Common Windows install paths in case PATH is not refreshed in current shell.
    if os.name == "nt":
        candidates = (
            Path(r"C:\Program Files (x86)\Nmap\nmap.exe"),
            Path(r"C:\Program Files\Nmap\nmap.exe"),
        )
        for candidate in candidates:
            if candidate.exists():
                return str(candidate)

    raise NmapNotFoundError(
        "nmap not found on PATH. Install nmap and ensure it is available in PATH."
    )


def _normalize_args(extra_args: Iterable[str] | None) -> list[str]:
    if not extra_args:
        return []
    return [str(arg) for arg in extra_args]


def detect_connected_ip() -> str:
    """
    Return the local IPv4 address used for outbound connections.

    Uses a UDP socket connect trick that does not send packets.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        ip_addr = sock.getsockname()[0]
    except OSError as exc:
        raise LocalIPDetectionError("Could not detect connected local IP.") from exc
    finally:
        sock.close()

    if not ip_addr or ip_addr.startswith("127."):
        raise LocalIPDetectionError("Detected loopback IP; no active network adapter.")
    return ip_addr


def build_nmap_command(
    target: str,
    extra_args: Iterable[str] | None = None,
    output_path: Path | None = None,
) -> list[str]:
    nmap_path = _find_nmap()
    args = _normalize_args(extra_args)
    cmd: list[str] = [nmap_path, *args, target]
    if output_path is not None:
        cmd.extend(["-oX", str(output_path)])
    else:
        cmd.extend(["-oX", "-"])
    return cmd


def run_nmap_scan(
    target: str,
    extra_args: Iterable[str] | None = None,
    output_path: Path | None = None,
    timeout_seconds: int | None = None,
) -> NmapResult:
    """
    Run an nmap scan for the given target.

    If output_path is provided, XML output is written to that file.
    Otherwise XML output is returned in stdout.
    """
    cmd = build_nmap_command(target, extra_args=extra_args, output_path=output_path)
    completed = subprocess.run(
        cmd,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
    )
    stdout = None if output_path is not None else completed.stdout
    return NmapResult(
        command=cmd,
        returncode=completed.returncode,
        stdout=stdout,
        stderr=completed.stderr,
        output_path=output_path,
    )
