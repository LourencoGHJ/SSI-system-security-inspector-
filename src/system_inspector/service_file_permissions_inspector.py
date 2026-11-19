"""Inspect permissions on Windows service executable files."""

import ntpath

from system_inspector.permission_analyzer import analyze_filesystem_acl
from system_inspector.permissions_inspector import get_file_permissions
from system_inspector.service_path_parser import get_service_executable_path


def inspect_service_file_permissions(services: list[dict]) -> list[dict]:
    """Inspect executable ACLs and reuse results for shared files."""

    results = []
    acl_cache = {}

    for service in services:
        binary_path = service.get("binary_path")
        executable_path = get_service_executable_path(binary_path)

        result = {
            "service_name": service.get("name"),
            "display_name": service.get("display_name"),
            "binary_path": binary_path,
            "executable_path": executable_path,
            "effective_access_confirmed": False,
        }

        if executable_path is None:
            result.update({
                "status": "inconclusive",
                "reason": "Service executable path is ambiguous or unsupported.",
                "analysis": None,
                "acl_owner": None,
            })
            results.append(result)
            continue

        cache_key = ntpath.normcase(ntpath.normpath(executable_path))

        if cache_key not in acl_cache:
            acl_cache[cache_key] = get_file_permissions(executable_path)

        acl_data = acl_cache[cache_key]
        analysis = analyze_filesystem_acl(acl_data, object_type="file")

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
            result["reason"] = "File ACL data is invalid."
        elif acl_data.get("status") != "success":
            result["reason"] = acl_data.get(
                "error",
                "File ACL collection failed.",
            )
        elif analysis["status"] != "success":
            result["reason"] = analysis.get(
                "reason",
                "File ACL analysis was inconclusive.",
            )

        results.append(result)

    return results
