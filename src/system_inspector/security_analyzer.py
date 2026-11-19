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
