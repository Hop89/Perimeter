# Perimeter
> Nmap-powered network scanning + an original analysis layer for risk scoring, misconfiguration detection, and readable reports.

![Status](https://img.shields.io/badge/status-early%20development-orange)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)

## What this is
Perimeter uses **Nmap** for raw scan data and adds a defensive analysis layer on top.  
The goal is not to replace Nmap, but to interpret results in a more actionable way (risk, misconfigs, trends, reporting).

## Planned Features
- Risk-based scoring for hosts/services
- Misconfiguration checks
- Scan history + diffs
- Human-readable reports
- Cross-platform CLI

## Quick Start
> Requires **Nmap** installed and available on PATH.

```bash
# Example (LAN)
netsentry scan 192.168.1.0/24 --top-ports 1000 --out report.md
