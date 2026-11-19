from system_inspector.permission_analyzer import analyze_directory_acl


def make_rule(
    rights_value,
    access_type="Allow",
    sid="S-1-5-32-545",
    identity="BUILTIN\\Users",
    inheritance_flags="None",
    propagation_flags="None",
):
    return {
        "identity": identity,
        "identity_sid": sid,
        "rights_value": rights_value,
        "access_type": access_type,
        "is_inherited": False,
        "inheritance_flags": inheritance_flags,
        "propagation_flags": propagation_flags,
    }


def make_acl(rules):
    return {
        "path": "C:\\Test",
        "status": "success",
        "access_rules": rules,
    }


def test_detects_allow_write_permission():
    result = analyze_directory_acl(make_acl([make_rule(0x00000002)]))
    assert result["status"] == "success"
    assert len(result["potential_write_aces"]) == 1
    assert result["effective_access_confirmed"] is False


def test_detects_deny_write_permission_separately():
    result = analyze_directory_acl(
        make_acl([make_rule(0x00000002, access_type="Deny")])
    )
    assert result["potential_write_aces"] == []
    assert len(result["deny_write_aces"]) == 1


def test_ignores_read_only_permission():
    result = analyze_directory_acl(make_acl([make_rule(0x00000001)]))
    assert result["potential_write_aces"] == []
    assert result["deny_write_aces"] == []


def test_ignores_generic_read_and_execute():
    result = analyze_directory_acl(make_acl([make_rule(0xA0000000)]))
    assert result["potential_write_aces"] == []


def test_ignores_inherit_only_permission():
    result = analyze_directory_acl(make_acl([
        make_rule(
            0x00000002,
            inheritance_flags="ContainerInherit",
            propagation_flags="InheritOnly",
        )
    ]))
    assert result["potential_write_aces"] == []


def test_analyzes_container_inherit_permission_without_inherit_only():
    result = analyze_directory_acl(make_acl([
        make_rule(
            0x00000002,
            inheritance_flags="ContainerInherit",
            propagation_flags="None",
        )
    ]))
    assert len(result["potential_write_aces"]) == 1


def test_detects_generic_write_permission():
    result = analyze_directory_acl(make_acl([make_rule(0x40000000)]))
    assert len(result["potential_write_aces"]) == 1


def test_detects_generic_all_permission():
    result = analyze_directory_acl(make_acl([make_rule(0x10000000)]))
    assert len(result["potential_write_aces"]) == 1


def test_preserves_unknown_sid_as_unresolved_evidence():
    result = analyze_directory_acl(make_acl([make_rule(0x00000002, sid=None)]))
    assert len(result["potential_write_aces"]) == 1
    assert result["potential_write_aces"][0]["identity_sid"] is None
    assert result["unresolved_aces"] == 1


def test_handles_failed_acl_collection():
    result = analyze_directory_acl({"status": "error", "error": "Access denied"})
    assert result["status"] == "inconclusive"
    assert result["potential_write_aces"] == []
    assert result["effective_access_confirmed"] is False


def test_handles_invalid_acl_data():
    result = analyze_directory_acl(None)
    assert result["status"] == "inconclusive"


def test_handles_missing_access_rules():
    result = analyze_directory_acl({"status": "success"})
    assert result["status"] == "inconclusive"


def test_handles_invalid_rights_value():
    result = analyze_directory_acl(make_acl([make_rule("invalid")]))
    assert result["potential_write_aces"] == []
    assert result["unresolved_aces"] == 1


def test_handles_unknown_access_type():
    result = analyze_directory_acl(
        make_acl([make_rule(0x00000002, access_type="Unknown")])
    )
    assert result["potential_write_aces"] == []
    assert result["deny_write_aces"] == []
    assert result["unresolved_aces"] == 1


def test_normalizes_signed_rights_value():
    result = analyze_directory_acl(make_acl([make_rule(-2147483648)]))
    assert result["potential_write_aces"] == []


def test_assesses_unresolved_aces_as_inconclusive():
    result = analyze_directory_acl(make_acl([make_rule("invalid")]))
    assert result["assessment"] == "inconclusive"
    assert result["unresolved_aces"] == 1


def test_assesses_deny_only_permissions_without_allow():
    result = analyze_directory_acl(
        make_acl([make_rule(0x00000002, access_type="Deny")])
    )
    assert result["assessment"] == "no_allow_write_permissions_detected"
    assert result["unresolved_aces"] == 0


def test_preserves_potential_assessment_with_unresolved_sid():
    result = analyze_directory_acl(make_acl([make_rule(0x00000002, sid=None)]))
    assert result["assessment"] == "potential_write_permissions_detected"
    assert result["unresolved_aces"] == 1


def test_assesses_unknown_access_type_as_inconclusive():
    result = analyze_directory_acl(
        make_acl([make_rule(0x00000002, access_type="Unknown")])
    )
    assert result["assessment"] == "inconclusive"
    assert result["unresolved_aces"] == 1


def test_classifies_system_write_permission_as_privileged():
    result = analyze_directory_acl(make_acl([
        make_rule(0x00000002, sid="S-1-5-18", identity="NT AUTHORITY\\SYSTEM")
    ]))

    assert result["potential_write_aces"] == []
    assert len(result["privileged_write_aces"]) == 1
    assert result["assessment"] == "privileged_write_permissions_only"


def test_classifies_administrators_write_permission_as_privileged():
    result = analyze_directory_acl(make_acl([
        make_rule(
            0x00000002,
            sid="S-1-5-32-544",
            identity="BUILTIN\\Administrators",
        )
    ]))

    assert result["potential_write_aces"] == []
    assert len(result["privileged_write_aces"]) == 1


def test_classifies_trusted_installer_write_permission_as_privileged():
    trusted_installer_sid = (
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
    )

    result = analyze_directory_acl(make_acl([
        make_rule(0x00000002, sid=trusted_installer_sid)
    ]))

    assert result["potential_write_aces"] == []
    assert len(result["privileged_write_aces"]) == 1


def test_keeps_regular_users_write_permission_as_potential():
    result = analyze_directory_acl(make_acl([
        make_rule(0x00000002, sid="S-1-5-32-545")
    ]))

    assert len(result["potential_write_aces"]) == 1
    assert result["privileged_write_aces"] == []
    assert result["assessment"] == "potential_write_permissions_detected"


def test_preserves_privileged_and_potential_write_permissions_separately():
    result = analyze_directory_acl(make_acl([
        make_rule(0x00000002, sid="S-1-5-18"),
        make_rule(0x00000002, sid="S-1-5-32-545"),
    ]))

    assert len(result["privileged_write_aces"]) == 1
    assert len(result["potential_write_aces"]) == 1
    assert result["assessment"] == "potential_write_permissions_detected"


def test_preserves_unknown_sid_as_potential_and_unresolved():
    result = analyze_directory_acl(make_acl([
        make_rule(0x00000002, sid=None)
    ]))

    assert len(result["potential_write_aces"]) == 1
    assert result["privileged_write_aces"] == []
    assert result["unresolved_aces"] == 1
    assert result["assessment"] == "potential_write_permissions_detected"


def test_never_confirms_effective_access():
    result = analyze_directory_acl(make_acl([
        make_rule(0x00000002, sid="S-1-5-32-545")
    ]))

    assert result["effective_access_confirmed"] is False
