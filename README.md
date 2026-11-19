# System Security Inspector (SSI)

A modular, read-only Windows security inspection tool built with Python.

## Features

- Collect system information.
- Inspect running processes.
- Identify TCP listening ports.
- Inspect Windows services.
- Detect services bound to all network interfaces.
- Group IPv4 and IPv6 findings by process and port.
- Detect potentially unsafe unquoted Windows service executable paths.
- Inspect Windows service executable directory permissions.
- Inspect Windows service executable file permissions.
- Generate JSON security reports.

## Security Analysis

### SSI-001 - Wildcard Network Binding

Identifies listening services bound to all network interfaces:

- `0.0.0.0` - IPv4 wildcard address.
- `::` - IPv6 wildcard address.

Findings are classified as LOW and grouped when they belong to the same process and port.

A wildcard binding does not necessarily mean that a service is externally accessible. Actual exposure depends on firewall rules and network configuration.

### SSI-002 - Unquoted Windows Service Executable Paths

Identifies Windows services whose executable paths:

- Are not enclosed in quotation marks.
- Contain spaces in the executable path.
- Reference an executable ending in `.exe`.

The analysis includes service information such as the service name, binary path, account, startup type, and current status.

Findings are classified as LOW.

This detection identifies a potentially unsafe service configuration. It does not confirm exploitability or verify filesystem permissions.

### SSI-003 - Windows Service Directory Permissions

Inspects the access control lists (ACLs) of directories containing Windows service executables.

The analysis:

- Identifies Allow and Deny entries with potentially relevant write permissions.
- Separates write permissions assigned to known privileged SIDs from other identities.
- Recognizes Local System, Built-in Administrators, and TrustedInstaller by SID.
- Preserves unresolved identities as potential evidence and tracks them separately.
- Excludes entries marked as `InheritOnly` from the inspected directory's analysis.
- Preserves permission evidence, including identities, SIDs, rights, and inheritance information.
- Reuses ACL collection results for services sharing the same executable directory.
- Includes directory permission data in the JSON report.
- Reports privileged-only write permissions separately from potentially relevant permissions.

**Limitations:**

- Does not calculate effective access for users or groups.
- Does not resolve group membership, access tokens, or the complete Windows authorization process.
- Does not confirm whether non-privileged users can modify service directories.
- Does not classify directories as vulnerable based solely on ACL entries.
- Only recognizes a defined set of privileged SIDs; other identities are not automatically considered unprivileged or exploitable.
- Treats ambiguous or unsupported service executable paths as inconclusive.
- Performs read-only inspection and does not modify services or filesystem permissions.

### SSI-004 - Windows Service Executable File Permissions

Inspects the access control lists (ACLs) of the executable files used by Windows services.

The analysis:

- Extracts unambiguous absolute `.exe` paths from service binary paths.
- Identifies Allow entries with potentially relevant file write permissions.
- Separates permissions assigned to known privileged SIDs from other identities.
- Preserves permission evidence, including identities, SIDs, rights, and inheritance information.
- Uses file-specific write permission masks, excluding directory-only permissions.
- Reuses ACL collection results for services referencing the same executable file.
- Includes executable file permission data in the JSON report.
- Reports privileged-only write permissions separately from potentially relevant permissions.

**Limitations:**

- Does not calculate effective access for users or groups.
- Does not resolve group membership, access tokens, or the complete Windows authorization process.
- Does not confirm whether non-privileged users can modify service executables.
- Does not classify executable files as vulnerable based solely on ACL entries.
- Only recognizes a defined set of privileged SIDs; other identities are not automatically considered unprivileged or exploitable.
- Does not expand environment variables in service paths.
- Treats ambiguous, relative, or unsupported executable paths as inconclusive.
- Inspects executable files only; it does not inspect service configuration files or other dependencies.
- Performs read-only inspection and does not modify services or filesystem permissions.

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
