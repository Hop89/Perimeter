# Perimeter
> Nmap-powered network scanning + an original analysis layer for risk scoring, misconfiguration detection, readable reports, and trend analysis.

![Status](https://img.shields.io/badge/status-early%20development-orange)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)

## What this is
Perimeter uses **Nmap** for raw scan data and adds a defensive analysis layer on top.  
The goal is not to replace Nmap, but to interpret results in a more actionable way (risk, misconfigs, trends, reporting).

## Features
- Risk-based scoring for hosts/services
- Misconfiguration checks
- **IP-based report storage** with historical tracking
- **Trend analysis** to compare scans over time and identify improvements/regressions
- Scan history + diffs
- Human-readable reports
- AI-powered triage (optional, with OpenAI integration)
- Cross-platform CLI

## Quick Start
> Requires **Nmap** installed and available on PATH.

```bash
# Install Perimeter
pip install -e .

# Scan a target
perimeter scan 192.168.1.0/24 --output scan.xml

# Analyze and store the report (organized by IP)
perimeter analyze scan.xml --store-report

# View trends for a target IP across historical reports
perimeter trend 192.168.1.100

# Compare two specific historical reports
perimeter trend 192.168.1.100 --compare 0 1
```

## Commands

### `perimeter scan [TARGET]`
Run an Nmap scan against a target host or network.

**Options:**
- `--connected`: Scan the local IP currently used by this machine
- `--nmap-arg`: Pass additional arguments to nmap (repeatable)
- `--output <path>`: Write XML output to file instead of stdout
- `--timeout <seconds>`: Timeout for the nmap command
- `--raw-xml`: Print raw XML output instead of formatted summary

**Example:**
```bash
# Scan with custom nmap options
perimeter scan 192.168.1.0/24 --nmap-arg "-p 1-1000" --nmap-arg "-sV" --output scan.xml

# Scan your local machine
perimeter scan --connected --output local_scan.xml
```

### `perimeter analyze <XML_FILE>`
Analyze nmap XML output and produce prioritized vulnerability triage.

**Options:**
- `--format [text|json]`: Output format (default: text)
- `--output <path>`: Write analysis to file instead of stdout
- `--max-findings <n>`: Maximum findings to display in text mode (default: 20)
- `--ai`: Enable AI-powered triage enrichment (requires `OPENAI_API_KEY`)
- `--ai-model <model>`: Override AI model (default: gpt-4o-mini)
- `--store-report`: **Automatically store this report organized by target IP** for trend tracking
- `--reports-dir <path>`: Directory for storing reports (default: reports/)

**Example:**
```bash
# Analyze and store report for trend tracking
perimeter analyze scan.xml --store-report

# Generate JSON analysis output
perimeter analyze scan.xml --format json --output analysis.json

# Enable AI triage enrichment
perimeter analyze scan.xml --ai --store-report
```

### `perimeter trend <TARGET_IP>`
Analyze trends across all historical reports for a target IP.

**Options:**
- `--reports-dir <path>`: Directory where reports are stored (default: reports/)
- `--format [text|json]`: Output format (default: text)
- `--output <path>`: Write trend analysis to file instead of stdout
- `--compare <INDEX1> <INDEX2>`: Compare two specific reports (indices, 0=latest)
- `--max-items <n>`: Maximum items to show per category in text output (default: 5)

**Example:**
```bash
# View trend summary for a target
perimeter trend 192.168.1.100

# Compare latest two scans
perimeter trend 192.168.1.100 --compare 0 1

# Get detailed JSON trend data
perimeter trend 192.168.1.100 --format json

# Save trend analysis to file
perimeter trend 192.168.1.100 --output trends.txt
```

## Report Storage & Trend Tracking

When you use `perimeter analyze` with `--store-report`, reports are automatically organized by target IP:

```
reports/
├── 192.168.1.100/
│   ├── report_20260323_101530.json
│   ├── report_20260323_141200.json
│   └── report_20260323_180945.json
├── 192.168.1.50/
│   ├── report_20260323_100000.json
│   └── report_20260323_160000.json
└── 10.0.0.1/
    └── report_20260323_120000.json
```

Each report includes:
- Timestamp of the scan
- Summary statistics (hosts analyzed, open ports, findings by severity)
- Detailed findings with risk scores
- Optional AI triage insights

The `trend` command analyzes this history to show:
- **Security posture changes**: improved, worsened, stable
- **Open ports delta**: Increase/decrease in exposed services
- **Severity trends**: How critical/high/medium/low findings have changed
- **New findings**: Services that appeared in latest scan
- **Resolved findings**: Services that are no longer present
- **Changed findings**: Services with modified risk scores

## Configuration

### AI Triage (Optional)
To enable AI-powered triage enrichment, set the `OPENAI_API_KEY` environment variable:

```bash
export OPENAI_API_KEY="sk-..."
perimeter analyze scan.xml --ai --store-report
```

Override the default model:
```bash
export PERIMETER_AI_MODEL="gpt-4"
```

## Architecture

- **cli.py**: Command-line interface and argument parsing
- **nmap_runner.py**: Nmap execution and result capture
- **nmap_parser.py**: Parsing nmap XML output
- **analysis.py**: Risk-based vulnerability analysis and scoring
- **storage.py**: IP-based report storage and retrieval
- **trend.py**: Historical trend analysis and comparison

## Quick Start
> Requires **Nmap** installed and available on PATH.

```bash
# Install Perimeter
pip install -e .

# Example (LAN)
perimeter scan 192.168.1.0/24 --top-ports 1000 --out report.md
