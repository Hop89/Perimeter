"""Parse nmap XML output and format readable scan summaries."""

from __future__ import annotations

import xml.etree.ElementTree as ET


def parse_nmap_xml(xml_text: str) -> list[dict]:
    """Return normalized host/port data parsed from nmap XML."""
    root = ET.fromstring(xml_text)
    hosts: list[dict] = []

    for host in root.findall("host"):
        address = host.find("address")
        status = host.find("status")
        hostnames = [
            item.attrib.get("name", "")
            for item in host.findall("hostnames/hostname")
            if item.attrib.get("name")
        ]
        ports: list[dict] = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            service = port.find("service")
            ports.append(
                {
                    "port": int(port.attrib.get("portid", "0")),
                    "protocol": port.attrib.get("protocol", "tcp"),
                    "state": (state.attrib.get("state") if state is not None else ""),
                    "service": (
                        service.attrib.get("name") if service is not None else ""
                    ),
                    "version": (
                        service.attrib.get("version") if service is not None else ""
                    ),
                }
            )

        hosts.append(
            {
                "address": address.attrib.get("addr", "unknown")
                if address is not None
                else "unknown",
                "state": status.attrib.get("state", "unknown")
                if status is not None
                else "unknown",
                "hostnames": hostnames,
                "ports": ports,
            }
        )
    return hosts


def format_scan_summary(hosts: list[dict]) -> str:
    """Build a readable multi-line summary from parsed nmap hosts."""
    if not hosts:
        return "No hosts found."

    lines: list[str] = []
    for host in hosts:
        names = ", ".join(host["hostnames"]) if host["hostnames"] else "-"
        lines.append(f"Host: {host['address']}  State: {host['state']}  Names: {names}")
        if not host["ports"]:
            lines.append("  Ports: none reported")
            continue

        for port in host["ports"]:
            service = port["service"] or "unknown"
            version = f" {port['version']}" if port["version"] else ""
            lines.append(
                f"  - {port['port']}/{port['protocol']} {port['state']} {service}{version}"
            )
    return "\n".join(lines)
