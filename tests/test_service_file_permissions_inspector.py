from system_inspector import service_file_permissions_inspector


def successful_acl():
    return {
        "status": "success",
        "owner": "BUILTIN\\Administrators",
        "access_rules": [],
    }


def test_inspects_executable_file_permissions(monkeypatch):
    calls = []

    def fake_get_file_permissions(path):
        calls.append(path)
        return successful_acl()

    monkeypatch.setattr(
        service_file_permissions_inspector,
        "get_file_permissions",
        fake_get_file_permissions,
    )

    results = service_file_permissions_inspector.inspect_service_file_permissions([
        {
            "name": "ExampleService",
            "display_name": "Example Service",
            "binary_path": '"C:\\Example\\service.exe" --run',
        }
    ])

    assert len(calls) == 1
    assert results[0]["executable_path"] == "C:\\Example\\service.exe"
    assert results[0]["status"] == "success"
    assert results[0]["acl_owner"] == "BUILTIN\\Administrators"
    assert results[0]["effective_access_confirmed"] is False


def test_reuses_acl_collection_for_shared_executable(monkeypatch):
    calls = []

    def fake_get_file_permissions(path):
        calls.append(path)
        return successful_acl()

    monkeypatch.setattr(
        service_file_permissions_inspector,
        "get_file_permissions",
        fake_get_file_permissions,
    )

    services = [
        {"name": "One", "binary_path": '"C:\\Vendor\\service.exe"'},
        {"name": "Two", "binary_path": '"c:\\vendor\\SERVICE.EXE"'},
    ]

    results = service_file_permissions_inspector.inspect_service_file_permissions(
        services
    )

    assert len(results) == 2
    assert len(calls) == 1


def test_skips_ambiguous_executable_path(monkeypatch):
    def unexpected_collection(path):
        raise AssertionError("ACL collection should not be called.")

    monkeypatch.setattr(
        service_file_permissions_inspector,
        "get_file_permissions",
        unexpected_collection,
    )

    results = service_file_permissions_inspector.inspect_service_file_permissions([
        {
            "name": "AmbiguousService",
            "binary_path": "C:\\Program Files\\Vendor\\service.exe",
        }
    ])

    assert results[0]["status"] == "inconclusive"
    assert results[0]["executable_path"] is None
    assert results[0]["analysis"] is None


def test_preserves_acl_collection_failure(monkeypatch):
    monkeypatch.setattr(
        service_file_permissions_inspector,
        "get_file_permissions",
        lambda path: {"status": "error", "error": "Access denied."},
    )

    results = service_file_permissions_inspector.inspect_service_file_permissions([
        {
            "name": "RestrictedService",
            "binary_path": '"C:\\Restricted\\service.exe"',
        }
    ])

    assert results[0]["status"] == "inconclusive"
    assert results[0]["reason"] == "Access denied."
    assert results[0]["effective_access_confirmed"] is False


def test_handles_invalid_acl_data(monkeypatch):
    monkeypatch.setattr(
        service_file_permissions_inspector,
        "get_file_permissions",
        lambda path: None,
    )

    results = service_file_permissions_inspector.inspect_service_file_permissions([
        {
            "name": "InvalidService",
            "binary_path": '"C:\\Example\\service.exe"',
        }
    ])

    assert results[0]["status"] == "inconclusive"
    assert results[0]["acl_owner"] is None
    assert results[0]["reason"] == "File ACL data is invalid."
