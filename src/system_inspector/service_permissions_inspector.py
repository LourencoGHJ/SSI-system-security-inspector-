"""Coordinate service directory permission inspection."""

import ntpath

from system_inspector.permission_analyzer import analyze_directory_acl
from system_inspector.permissions_inspector import get_directory_permissions
from system_inspector.service_path_parser import (
    get_service_executable_directory,
)


def inspect_service_permissions(services: list[dict]) -> list[dict]:
    """Inspect service executable directories and reuse collected ACL data."""

    results = []
    acl_cache = {}

    for service in services:
        binary_path = service.get("binary_path")
        directory = get_service_executable_directory(binary_path)

        result = {
            "service_name": service.get("name"),
            "display_name": service.get("display_name"),
            "binary_path": binary_path,
            "directory": directory,
            "effective_access_confirmed": False,
        }

        if directory is None:
            result.update({
                "status": "inconclusive",
                "reason": "Service executable path is ambiguous or unsupported.",
                "analysis": None,
            })
            results.append(result)
            continue

        cache_key = ntpath.normcase(ntpath.normpath(directory))

        if cache_key not in acl_cache:
            acl_cache[cache_key] = get_directory_permissions(directory)

        acl_data = acl_cache[cache_key]
        analysis = analyze_directory_acl(acl_data)

        result.update({
            "status": analysis["status"],
            "acl_owner": (
                acl_data.get("owner")
                if isinstance(acl_data, dict)
                else None
            ),
            "analysis": analysis,
        })

        if not isinstance(acl_data, dict):
            result["reason"] = "Directory ACL data is invalid."
        elif acl_data.get("status") != "success":
            result["reason"] = acl_data.get(
                "error",
                "Directory ACL collection failed.",
            )
        elif analysis["status"] != "success":
            result["reason"] = analysis.get(
                "reason",
                "Directory ACL analysis was inconclusive.",
            )

        results.append(result)

    return results
