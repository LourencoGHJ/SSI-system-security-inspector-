"""Conservative analysis of Windows directory ACL entries."""

from typing import Any


WRITE_RIGHTS_MASK = (
    0x00000002  # WriteData / CreateFiles
    | 0x00000004  # AppendData / CreateDirectories
    | 0x00000010  # WriteExtendedAttributes
    | 0x00000040  # DeleteSubdirectoriesAndFiles
    | 0x00000100  # WriteAttributes
    | 0x00010000  # Delete
    | 0x00040000  # ChangePermissions / WriteDac
    | 0x00080000  # TakeOwnership / WriteOwner
    | 0x10000000  # GenericAll
    | 0x40000000  # GenericWrite
)


def analyze_directory_acl(acl_data: dict) -> dict:
    """Identify potentially relevant write ACEs without claiming effective access."""

    if not isinstance(acl_data, dict):
        return {
            "status": "inconclusive",
            "reason": "Invalid ACL data.",
            "potential_write_aces": [],
            "deny_write_aces": [],
            "effective_access_confirmed": False,
        }

    if acl_data.get("status") != "success":
        return {
            "status": "inconclusive",
            "reason": acl_data.get("error", "ACL collection was unsuccessful."),
            "potential_write_aces": [],
            "deny_write_aces": [],
            "effective_access_confirmed": False,
        }

    access_rules = acl_data.get("access_rules")

    if not isinstance(access_rules, list):
        return {
            "status": "inconclusive",
            "reason": "ACL access rules are missing or invalid.",
            "potential_write_aces": [],
            "deny_write_aces": [],
            "effective_access_confirmed": False,
        }

    potential_write_aces = []
    deny_write_aces = []
    unresolved_aces = 0

    for rule in access_rules:
        if not isinstance(rule, dict):
            unresolved_aces += 1
            continue

        inheritance_flags = str(rule.get("inheritance_flags", ""))
        propagation_flags = str(rule.get("propagation_flags", ""))

        if "InheritOnly" in propagation_flags:
            continue

        rights_value = rule.get("rights_value")

        try:
            rights_mask = int(rights_value) & 0xFFFFFFFF
        except (TypeError, ValueError):
            unresolved_aces += 1
            continue

        if not rights_mask & WRITE_RIGHTS_MASK:
            continue

        access_type = str(rule.get("access_type", "")).lower()

        evidence = {
            "identity": rule.get("identity"),
            "identity_sid": rule.get("identity_sid"),
            "access_type": rule.get("access_type"),
            "rights_value": rights_mask,
            "inheritance_flags": inheritance_flags,
            "propagation_flags": rule.get("propagation_flags"),
            "is_inherited": rule.get("is_inherited"),
        }

        if not rule.get("identity_sid"):
            unresolved_aces += 1

        if access_type == "allow":
            potential_write_aces.append(evidence)
        elif access_type == "deny":
            deny_write_aces.append(evidence)
        else:
            unresolved_aces += 1

    if potential_write_aces:
        assessment = "potential_write_permissions_detected"
    elif unresolved_aces:
        assessment = "inconclusive"
    else:
        assessment = "no_allow_write_permissions_detected"

    return {
        "status": "success",
        "assessment": assessment,
        "potential_write_aces": potential_write_aces,
        "deny_write_aces": deny_write_aces,
        "unresolved_aces": unresolved_aces,
        "effective_access_confirmed": False,
    }
