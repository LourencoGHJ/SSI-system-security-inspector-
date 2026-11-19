from system_inspector import service_permissions_inspector


def successful_acl():
    return {
        "status": "success",
        "owner": "BUILTIN\\Administrators",
        "access_rules": [],
    }


def test_reuses_acl_collection_for_services_in_same_directory(monkeypatch):
    calls = []

    def fake_get_directory_permissions(directory):
        calls.append(directory)
        return successful_acl()

    monkeypatch.setattr(
        service_permissions_inspector,
        "get_directory_permissions",
        fake_get_directory_permissions,
    )

    services = [
        {
            "name": "ServiceOne",
            "display_name": "Service One",
            "binary_path": '"C:\\Program Files\\Vendor\\one.exe"',
        },
        {
            "name": "ServiceTwo",
            "display_name": "Service Two",
            "binary_path": '"c:\\program files\\vendor\\two.exe"',
        },
    ]

    results = service_permissions_inspector.inspect_service_permissions(
        services
    )

    assert len(results) == 2
    assert len(calls) == 1
    assert results[0]["status"] == "success"
    assert results[1]["status"] == "success"


def test_collects_acl_separately_for_different_directories(monkeypatch):
    calls = []

    def fake_get_directory_permissions(directory):
        calls.append(directory)
        return successful_acl()

    monkeypatch.setattr(
        service_permissions_inspector,
        "get_directory_permissions",
        fake_get_directory_permissions,
    )

    services = [
        {"name": "ServiceOne", "binary_path": '"C:\\VendorA\\one.exe"'},
        {"name": "ServiceTwo", "binary_path": '"C:\\VendorB\\two.exe"'},
    ]

    results = service_permissions_inspector.inspect_service_permissions(
        services
    )

    assert len(results) == 2
    assert len(calls) == 2


def test_skips_acl_collection_for_ambiguous_paths(monkeypatch):
    def unexpected_collection(directory):
        raise AssertionError("ACL collection should not be called.")

    monkeypatch.setattr(
        service_permissions_inspector,
        "get_directory_permissions",
        unexpected_collection,
    )

    services = [
        {
            "name": "AmbiguousService",
            "binary_path": "C:\\Program Files\\Vendor\\service.exe",
        }
    ]

    results = service_permissions_inspector.inspect_service_permissions(
        services
    )

    assert len(results) == 1
    assert results[0]["status"] == "inconclusive"
    assert results[0]["directory"] is None
    assert results[0]["analysis"] is None


def test_preserves_inconclusive_status_when_acl_collection_fails(monkeypatch):
    def fake_get_directory_permissions(directory):
        return {
            "status": "error",
            "error": "Access denied.",
        }

    monkeypatch.setattr(
        service_permissions_inspector,
        "get_directory_permissions",
        fake_get_directory_permissions,
    )

    services = [
        {
            "name": "RestrictedService",
            "binary_path": '"C:\\Restricted\\service.exe"',
        }
    ]

    results = service_permissions_inspector.inspect_service_permissions(
        services
    )

    assert results[0]["status"] == "inconclusive"
    assert results[0]["reason"] == "Access denied."
    assert results[0]["effective_access_confirmed"] is False


def test_preserves_service_identity_and_directory_evidence(monkeypatch):
    monkeypatch.setattr(
        service_permissions_inspector,
        "get_directory_permissions",
        lambda directory: successful_acl(),
    )

    services = [
        {
            "name": "ExampleService",
            "display_name": "Example Service",
            "binary_path": '"C:\\Example\\service.exe" --run',
        }
    ]

    results = service_permissions_inspector.inspect_service_permissions(
        services
    )

    result = results[0]

    assert result["service_name"] == "ExampleService"
    assert result["display_name"] == "Example Service"
    assert result["directory"] == "C:\\Example"
    assert result["acl_owner"] == "BUILTIN\\Administrators"
    assert result["effective_access_confirmed"] is False

def test_handles_none_acl_data(monkeypatch):
    monkeypatch.setattr(
        service_permissions_inspector,
        "get_directory_permissions",
        lambda directory: None,
    )

    results = service_permissions_inspector.inspect_service_permissions([
        {
            "name": "InvalidService",
            "binary_path": '"C:\\Example\\service.exe"',
        }
    ])

    assert results[0]["status"] == "inconclusive"
    assert results[0]["acl_owner"] is None
    assert results[0]["reason"] == "Directory ACL data is invalid."
    assert results[0]["analysis"]["status"] == "inconclusive"


def test_handles_non_dictionary_acl_data(monkeypatch):
    monkeypatch.setattr(
        service_permissions_inspector,
        "get_directory_permissions",
        lambda directory: [],
    )

    results = service_permissions_inspector.inspect_service_permissions([
        {
            "name": "InvalidService",
            "binary_path": '"C:\\Example\\service.exe"',
        }
    ])

    assert results[0]["status"] == "inconclusive"
    assert results[0]["acl_owner"] is None
    assert results[0]["reason"] == "Directory ACL data is invalid."


def test_preserves_reason_for_invalid_access_rules(monkeypatch):
    monkeypatch.setattr(
        service_permissions_inspector,
        "get_directory_permissions",
        lambda directory: {
            "status": "success",
            "access_rules": None,
        },
    )

    results = service_permissions_inspector.inspect_service_permissions([
        {
            "name": "InvalidService",
            "binary_path": '"C:\\Example\\service.exe"',
        }
    ])

    assert results[0]["status"] == "inconclusive"
    assert results[0]["reason"] == "ACL access rules are missing or invalid."
    assert results[0]["analysis"]["status"] == "inconclusive"
