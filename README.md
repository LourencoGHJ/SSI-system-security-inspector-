# System Security Inspector (SSI)

A modular, read-only Windows security inspection tool built with Python.

## Features

- Collect system information.
- Inspect running processes.
- Identify TCP listening ports.
- Inspect Windows services.
- Detect services bound to all network interfaces.
- Group IPv4 and IPv6 findings by process and port.
- Generate JSON security reports.

## Security Analysis

### SSI-001 - Wildcard Network Binding

Identifies listening services bound to all network interfaces:

- `0.0.0.0` - IPv4 wildcard address.
- `::` - IPv6 wildcard address.

Findings are classified as LOW and grouped when they belong to the same process and port.

A wildcard binding does not necessarily mean that a service is externally accessible. Actual exposure depends on firewall rules and network configuration.

## Installation

    git clone https://github.com/LourencoGHJ/SSI-system-security-inspector-.git
    cd SSI-system-security-inspector-
    python -m venv .venv
    .venv\Scripts\Activate.ps1
    pip install -r requirements.txt

## Usage

    $env:PYTHONPATH = "src"
    python -m system_inspector scan

Report: reports/security-report.json

## Tests

    pytest -v

## Principles

- Read-only system inspection.
- Modular architecture.
- Clear security findings and evidence.
- Automated testing.
- Minimal dependencies.

## Platform

Windows

## Language

Python 3.13+
