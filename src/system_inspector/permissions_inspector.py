import json
import os
import subprocess


def get_directory_permissions(directory_path: str) -> dict:
    """Collect directory ACL information using Windows PowerShell."""

    script = r"""
$path = $env:SSI_TARGET_PATH

try {
    $acl = Get-Acl -LiteralPath $path -ErrorAction Stop

    $rules = @(
        foreach ($rule in $acl.Access) {
            $identitySid = $null

            try {
                $identitySid = $rule.IdentityReference.Translate(
                    [System.Security.Principal.SecurityIdentifier]
                ).Value
            }
            catch {
                $identitySid = $null
            }

            [PSCustomObject]@{
                identity = $rule.IdentityReference.Value
                identity_sid = $identitySid
                rights_value = [long]$rule.FileSystemRights
                access_type = $rule.AccessControlType.ToString()
                is_inherited = $rule.IsInherited
                inheritance_flags = $rule.InheritanceFlags.ToString()
                propagation_flags = $rule.PropagationFlags.ToString()
            }
        }
    )

    [PSCustomObject]@{
        path = $path
        owner = $acl.Owner
        access_rules = $rules
        status = "success"
    } | ConvertTo-Json -Depth 5 -Compress
}
catch {
    [PSCustomObject]@{
        path = $path
        status = "error"
        error = $_.Exception.Message
    } | ConvertTo-Json -Compress
}
"""

    environment = os.environ.copy()
    environment["SSI_TARGET_PATH"] = directory_path

    try:
        completed = subprocess.run(
            [
                "pwsh.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {
            "path": directory_path,
            "status": "error",
            "error": str(error),
        }

    if completed.returncode != 0:
        return {
            "path": directory_path,
            "status": "error",
            "error": completed.stderr.strip() or "PowerShell execution failed.",
        }

    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {
            "path": directory_path,
            "status": "error",
            "error": "Invalid JSON returned by PowerShell.",
        }

    if not isinstance(result, dict):
        return {
            "path": directory_path,
            "status": "error",
            "error": "Invalid ACL response structure.",
        }

    if result.get("status") == "error":
        return result

    if result.get("status") != "success":
        return {
            "path": directory_path,
            "status": "error",
            "error": "Missing or invalid ACL response status.",
        }

    access_rules = result.get("access_rules")

    if not isinstance(access_rules, list):
        return {
            "path": directory_path,
            "status": "error",
            "error": "Invalid ACL access rules structure.",
        }

    for rule in access_rules:
        if not isinstance(rule, dict):
            return {
                "path": directory_path,
                "status": "error",
                "error": "Invalid ACL access rule.",
            }

        rights_value = rule.get("rights_value")

        if isinstance(rights_value, bool):
            return {
                "path": directory_path,
                "status": "error",
                "error": "Invalid ACL rights value.",
            }

        try:
            rule["rights_value"] = int(rights_value) & 0xFFFFFFFF
        except (TypeError, ValueError):
            return {
                "path": directory_path,
                "status": "error",
                "error": "Invalid ACL rights value.",
            }

    return result
