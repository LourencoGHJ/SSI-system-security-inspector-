import json
import platform
from datetime import datetime, timezone
from pathlib import Path

from system_inspector import network_inspector
from system_inspector import process_inspector
from system_inspector import security_analyzer
from system_inspector import service_inspector
from system_inspector import service_permissions_inspector
from system_inspector import service_file_permissions_inspector
from system_inspector import system_info


def generate_report(output_path: str | Path) -> dict:
    """Collect system data, analyze security findings, and save a report."""
    is_windows = platform.system() == "Windows"

    listening_ports = network_inspector.get_listening_ports()
    services = service_inspector.get_windows_services() if is_windows else []

    if is_windows:
        service_directory_permissions = (
            service_permissions_inspector.inspect_service_permissions(services)
        )
        service_file_permissions = (
            service_file_permissions_inspector.inspect_service_file_permissions(
                services
            )
        )
        service_path_findings = (
            security_analyzer.analyze_unquoted_service_paths(services)
        )
    else:
        service_directory_permissions = []
        service_file_permissions = []
        service_path_findings = []

    security_findings = (
        security_analyzer.analyze_listening_ports(listening_ports)
        + service_path_findings
    )

    platform_support = {
        "windows_services": {
            "supported": is_windows,
            "reason": None if is_windows else "Windows-only functionality.",
        },
        "ssi_002_unquoted_service_paths": {
            "supported": is_windows,
            "reason": None if is_windows else "Requires Windows service data.",
        },
        "ssi_003_service_directory_permissions": {
            "supported": is_windows,
            "reason": None if is_windows else "Windows ACL inspection is required.",
        },
        "ssi_004_service_file_permissions": {
            "supported": is_windows,
            "reason": None if is_windows else "Windows ACL inspection is required.",
        },
    }

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "platform_support": platform_support,
        "system": system_info.get_system_info(),
        "processes": process_inspector.get_running_processes(),
        "listening_ports": listening_ports,
        "services": services,
        "service_directory_permissions": service_directory_permissions,
        "service_file_permissions": service_file_permissions,
        "security_findings": security_findings,
    }

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report, indent=4),
        encoding="utf-8",
    )

    return report
