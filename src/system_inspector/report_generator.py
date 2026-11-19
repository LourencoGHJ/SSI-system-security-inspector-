import json
from datetime import datetime, timezone
from pathlib import Path

from system_inspector import network_inspector
from system_inspector import process_inspector
from system_inspector import security_analyzer
from system_inspector import service_inspector
from system_inspector import system_info


def generate_report(output_path: str | Path) -> dict:
    """Collect system data, analyze security findings, and save a report."""
    listening_ports = network_inspector.get_listening_ports()

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "system": system_info.get_system_info(),
        "processes": process_inspector.get_running_processes(),
        "listening_ports": listening_ports,
        "services": service_inspector.get_windows_services(),
        "security_findings": security_analyzer.analyze_listening_ports(
            listening_ports
        ),
    }

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report, indent=4),
        encoding="utf-8",
    )

    return report
