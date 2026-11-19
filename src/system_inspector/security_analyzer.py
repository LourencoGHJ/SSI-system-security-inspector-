import re


WILDCARD_ADDRESSES = {"0.0.0.0", "::"}


def analyze_listening_ports(
    listening_ports: list[dict],
) -> list[dict]:
    """Identify and group listeners bound to all network interfaces."""
    grouped_findings = {}

    for port in listening_ports:
        address = port.get("address")

        if address not in WILDCARD_ADDRESSES:
            continue

        port_number = port.get("port")
        pid = port.get("pid")
        process_name = port.get("process_name")

        finding_key = (port_number, pid, process_name)

        if finding_key not in grouped_findings:
            grouped_findings[finding_key] = {
                "rule_id": "SSI-001",
                "severity": "low",
                "title": "Service listening on all network interfaces",
                "description": (
                    "A listening service is bound to all network interfaces. "
                    "This may increase network exposure depending on firewall "
                    "and network configuration."
                ),
                "evidence": {
                    "addresses": [],
                    "port": port_number,
                    "pid": pid,
                    "process_name": process_name,
                },
                "recommendation": (
                    "Verify whether the service needs to accept connections "
                    "from all network interfaces."
                ),
            }

        addresses = grouped_findings[finding_key]["evidence"]["addresses"]

        if address not in addresses:
            addresses.append(address)

    return list(grouped_findings.values())


def analyze_unquoted_service_paths(
    services: list[dict],
) -> list[dict]:
    """Identify Windows services with unquoted executable paths containing spaces."""
    findings = []

    for service in services:
        binary_path = service.get("binary_path")

        if not isinstance(binary_path, str):
            continue

        binary_path = binary_path.strip()

        if not binary_path or binary_path.startswith('"'):
            continue

        executable_match = re.match(
            r"^(?P<executable>.+?\.exe)(?:\s|$)",
            binary_path,
            flags=re.IGNORECASE,
        )

        if executable_match is None:
            continue

        executable_path = executable_match.group("executable")

        if not any(character.isspace() for character in executable_path):
            continue

        findings.append({
            "rule_id": "SSI-002",
            "severity": "low",
            "title": "Unquoted Windows service executable path",
            "description": (
                "The Windows service executable path contains spaces and "
                "is not enclosed in quotation marks. This may create "
                "ambiguous executable path resolution depending on the "
                "Windows path and directory permissions."
            ),
            "evidence": {
                "service_name": service.get("name"),
                "display_name": service.get("display_name"),
                "binary_path": binary_path,
                "executable_path": executable_path,
                "username": service.get("username"),
                "start_type": service.get("start_type"),
                "status": service.get("status"),
                "exploitability_confirmed": False,
            },
            "recommendation": (
                "Verify the service executable path and directory "
                "permissions. Enclose the executable path in quotation "
                "marks when appropriate."
            ),
        })

    return findings
