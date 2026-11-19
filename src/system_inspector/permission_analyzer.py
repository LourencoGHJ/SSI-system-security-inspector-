"""Conservative analysis of Windows directory ACL entries."""


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

PRIVILEGED_SIDS = {
    "S-1-5-18",  # Local System
    "S-1-5-32-544",  # Built-in Administrators
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
    # NT SERVICE\TrustedInstaller
}


def _inconclusive_result(reason):
    return {
        "status": "inconclusive",
        "reason": reason,
        "potential_write_aces": [],
        "privileged_write_aces": [],
        "deny_write_aces": [],
        "unresolved_aces": 0,
        "effective_access_confirmed": False,
    }


def analyze_directory_acl(acl_data: dict) -> dict:
    """Classify write-related ACEs without claiming effective access."""

    if not isinstance(acl_data, dict):
        return _inconclusive_result("Invalid ACL data.")

    if acl_data.get("status") != "success":
        return _inconclusive_result(
            acl_data.get("error", "ACL collection was unsuccessful.")
        )

    access_rules = acl_data.get("access_rules")

    if not isinstance(access_rules, list):
        return _inconclusive_result(
            "ACL access rules are missing or invalid."
        )

    potential_write_aces = []
    privileged_write_aces = []
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

        try:
            rights_mask = int(rule.get("rights_value")) & 0xFFFFFFFF
        except (TypeError, ValueError):
            unresolved_aces += 1
            continue

        if not rights_mask & WRITE_RIGHTS_MASK:
            continue

        access_type = str(rule.get("access_type", "")).lower()
        identity_sid = rule.get("identity_sid")

        evidence = {
            "identity": rule.get("identity"),
            "identity_sid": identity_sid,
            "access_type": rule.get("access_type"),
            "rights_value": rights_mask,
            "inheritance_flags": inheritance_flags,
            "propagation_flags": rule.get("propagation_flags"),
            "is_inherited": rule.get("is_inherited"),
        }

        if not identity_sid:
            unresolved_aces += 1

        if access_type == "deny":
            deny_write_aces.append(evidence)
            continue

        if access_type != "allow":
            unresolved_aces += 1
            continue

        normalized_sid = (
            str(identity_sid).strip().upper()
            if identity_sid
            else None
        )

        if normalized_sid in PRIVILEGED_SIDS:
            privileged_write_aces.append(evidence)
        else:
            potential_write_aces.append(evidence)

    if potential_write_aces:
        assessment = "potential_write_permissions_detected"
    elif unresolved_aces:
        assessment = "inconclusive"
    elif privileged_write_aces:
        assessment = "privileged_write_permissions_only"
    else:
        assessment = "no_allow_write_permissions_detected"

    return {
        "status": "success",
        "assessment": assessment,
        "potential_write_aces": potential_write_aces,
        "privileged_write_aces": privileged_write_aces,
        "deny_write_aces": deny_write_aces,
        "unresolved_aces": unresolved_aces,
        "effective_access_confirmed": False,
    }
