import json
import subprocess

import pytest

from system_inspector import permissions_inspector


def make_process_result(stdout, returncode=0, stderr=""):
    return subprocess.CompletedProcess(
        args=["pwsh.exe"],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


def test_get_directory_permissions_returns_acl_data(monkeypatch):
    payload = {
        "path": "C:\\Test",
        "owner": "NT AUTHORITY\\SYSTEM",
        "status": "success",
        "access_rules": [
            {
                "identity": "NT AUTHORITY\\SYSTEM",
                "identity_sid": "S-1-5-18",
                "rights_value": 1245631,
                "access_type": "Allow",
                "is_inherited": False,
                "inheritance_flags": "None",
                "propagation_flags": "None",
            }
        ],
    }

    monkeypatch.setattr(
        permissions_inspector.subprocess,
        "run",
        lambda *args, **kwargs: make_process_result(json.dumps(payload)),
    )

    result = permissions_inspector.get_directory_permissions("C:\\Test")

    assert result["status"] == "success"
    assert result["owner"] == "NT AUTHORITY\\SYSTEM"
    assert result["access_rules"][0]["identity_sid"] == "S-1-5-18"


def test_get_directory_permissions_normalizes_unsigned_rights(monkeypatch):
    payload = {
        "path": "C:\\Test",
        "owner": "SYSTEM",
        "status": "success",
        "access_rules": [
            {"rights_value": -1}
        ],
    }

    monkeypatch.setattr(
        permissions_inspector.subprocess,
        "run",
        lambda *args, **kwargs: make_process_result(json.dumps(payload)),
    )

    result = permissions_inspector.get_directory_permissions("C:\\Test")

    assert result["access_rules"][0]["rights_value"] == 4294967295


def test_get_directory_permissions_handles_process_failure(monkeypatch):
    monkeypatch.setattr(
        permissions_inspector.subprocess,
        "run",
        lambda *args, **kwargs: make_process_result(
            "",
            returncode=1,
            stderr="PowerShell failed",
        ),
    )

    result = permissions_inspector.get_directory_permissions("C:\\Test")

    assert result["status"] == "error"
    assert result["error"] == "PowerShell failed"


def test_get_directory_permissions_handles_timeout(monkeypatch):
    def raise_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("pwsh.exe", 15)

    monkeypatch.setattr(
        permissions_inspector.subprocess,
        "run",
        raise_timeout,
    )

    result = permissions_inspector.get_directory_permissions("C:\\Test")

    assert result["status"] == "error"
    assert "timed out" in result["error"].lower()


def test_get_directory_permissions_handles_invalid_json(monkeypatch):
    monkeypatch.setattr(
        permissions_inspector.subprocess,
        "run",
        lambda *args, **kwargs: make_process_result("invalid json"),
    )

    result = permissions_inspector.get_directory_permissions("C:\\Test")

    assert result["status"] == "error"
    assert result["error"] == "Invalid JSON returned by PowerShell."


def test_get_directory_permissions_preserves_untranslated_identity(monkeypatch):
    payload = {
        "path": "C:\\Test",
        "owner": "SYSTEM",
        "status": "success",
        "access_rules": [
            {
                "identity": "Unknown identity",
                "identity_sid": None,
                "rights_value": 1,
            }
        ],
    }

    monkeypatch.setattr(
        permissions_inspector.subprocess,
        "run",
        lambda *args, **kwargs: make_process_result(json.dumps(payload)),
    )

    result = permissions_inspector.get_directory_permissions("C:\\Test")

    assert result["status"] == "success"
    assert result["access_rules"][0]["identity"] == "Unknown identity"
    assert result["access_rules"][0]["identity_sid"] is None


def test_get_directory_permissions_accepts_empty_access_rules(monkeypatch):
    payload = {
        "path": "C:\\Test",
        "owner": "SYSTEM",
        "status": "success",
        "access_rules": [],
    }

    monkeypatch.setattr(
        permissions_inspector.subprocess,
        "run",
        lambda *args, **kwargs: make_process_result(json.dumps(payload)),
    )

    result = permissions_inspector.get_directory_permissions("C:\\Test")

    assert result["status"] == "success"
    assert result["access_rules"] == []


def test_get_directory_permissions_handles_missing_executable(monkeypatch):
    def raise_os_error(*args, **kwargs):
        raise OSError("pwsh.exe not found")

    monkeypatch.setattr(
        permissions_inspector.subprocess,
        "run",
        raise_os_error,
    )

    result = permissions_inspector.get_directory_permissions("C:\\Test")

    assert result["status"] == "error"
    assert result["error"] == "pwsh.exe not found"


def test_get_directory_permissions_rejects_non_object_json(monkeypatch):
    monkeypatch.setattr(
        permissions_inspector.subprocess,
        "run",
        lambda *args, **kwargs: make_process_result("null"),
    )

    result = permissions_inspector.get_directory_permissions("C:\\Test")

    assert result["status"] == "error"
    assert result["error"] == "Invalid ACL response structure."


def test_get_directory_permissions_rejects_invalid_access_rules(monkeypatch):
    payload = {"status": "success", "access_rules": {}}

    monkeypatch.setattr(
        permissions_inspector.subprocess,
        "run",
        lambda *args, **kwargs: make_process_result(json.dumps(payload)),
    )

    result = permissions_inspector.get_directory_permissions("C:\\Test")

    assert result["status"] == "error"
    assert result["error"] == "Invalid ACL access rules structure."


def test_get_directory_permissions_rejects_invalid_access_rule(monkeypatch):
    payload = {"status": "success", "access_rules": [None]}

    monkeypatch.setattr(
        permissions_inspector.subprocess,
        "run",
        lambda *args, **kwargs: make_process_result(json.dumps(payload)),
    )

    result = permissions_inspector.get_directory_permissions("C:\\Test")

    assert result["status"] == "error"
    assert result["error"] == "Invalid ACL access rule."


@pytest.mark.parametrize("rights_value", [None, "invalid", True])
def test_get_directory_permissions_rejects_invalid_rights_value(
    monkeypatch,
    rights_value,
):
    payload = {
        "status": "success",
        "access_rules": [{"rights_value": rights_value}],
    }

    monkeypatch.setattr(
        permissions_inspector.subprocess,
        "run",
        lambda *args, **kwargs: make_process_result(json.dumps(payload)),
    )

    result = permissions_inspector.get_directory_permissions("C:\\Test")

    assert result["status"] == "error"
    assert result["error"] == "Invalid ACL rights value."
