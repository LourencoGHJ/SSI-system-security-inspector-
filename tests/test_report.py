from copy import deepcopy
import json

from system_inspector import report_generator


def mock_system_data(
    monkeypatch,
    listening_ports=None,
    binary_path="C:\\Example\\service.exe",
):
    monkeypatch.setattr(
        report_generator.platform,
        "system",
        lambda: "Windows",
    )
    monkeypatch.setattr(
        report_generator.system_info,
        "get_system_info",
        lambda: {"hostname": "test-pc"},
    )
    monkeypatch.setattr(
        report_generator.process_inspector,
        "get_running_processes",
        lambda: [{"pid": 123, "name": "example.exe", "username": "user"}],
    )
    monkeypatch.setattr(
        report_generator.network_inspector,
        "get_listening_ports",
        lambda: listening_ports or [],
    )
    monkeypatch.setattr(
        report_generator.service_inspector,
        "get_windows_services",
        lambda: [{
            "name": "ExampleService",
            "display_name": "Example Service",
            "status": "running",
            "start_type": "automatic",
            "pid": 123,
            "binary_path": binary_path,
            "username": "LocalSystem",
        }],
    )
    monkeypatch.setattr(
        report_generator.service_permissions_inspector,
        "inspect_service_permissions",
        lambda services: [],
    )
    monkeypatch.setattr(
        report_generator.service_file_permissions_inspector,
        "inspect_service_file_permissions",
        lambda services: [],
    )


def test_generate_report_contains_expected_sections(monkeypatch, tmp_path):
    mock_system_data(
        monkeypatch,
        listening_ports=[{
            "address": "127.0.0.1",
            "port": 8080,
            "pid": 123,
            "process_name": "example.exe",
        }],
    )

    output_path = tmp_path / "reports" / "security-report.json"
    report = report_generator.generate_report(output_path)

    assert set(report) == {
        "generated_at",
        "platform_support",
        "system",
        "processes",
        "listening_ports",
        "services",
        "service_directory_permissions",
        "service_file_permissions",
        "security_findings",
    }
    assert report["system"]["hostname"] == "test-pc"
    assert len(report["processes"]) == 1
    assert len(report["listening_ports"]) == 1
    assert len(report["services"]) == 1
    assert report["services"][0]["name"] == "ExampleService"
    assert report["services"][0]["username"] == "LocalSystem"
    assert report["service_directory_permissions"] == []
    assert report["security_findings"] == []
    assert output_path.exists()


def test_generate_report_writes_valid_json(monkeypatch, tmp_path):
    mock_system_data(
        monkeypatch,
        listening_ports=[{
            "address": "0.0.0.0",
            "port": 8080,
            "pid": 123,
            "process_name": "example.exe",
        }],
    )

    output_path = tmp_path / "security-report.json"
    report_generator.generate_report(output_path)

    saved_report = json.loads(output_path.read_text(encoding="utf-8"))

    assert saved_report["system"]["hostname"] == "test-pc"
    assert saved_report["processes"][0]["name"] == "example.exe"
    assert saved_report["service_directory_permissions"] == []
    assert len(saved_report["security_findings"]) == 1
    assert saved_report["security_findings"][0]["rule_id"] == "SSI-001"
    assert saved_report["security_findings"][0]["evidence"]["port"] == 8080


def test_generate_report_includes_unquoted_service_path_finding(
    monkeypatch,
    tmp_path,
):
    mock_system_data(
        monkeypatch,
        binary_path="C:\\Program Files\\Example\\service.exe",
    )

    output_path = tmp_path / "security-report.json"
    report = report_generator.generate_report(output_path)

    assert len(report["security_findings"]) == 1

    finding = report["security_findings"][0]

    assert finding["rule_id"] == "SSI-002"
    assert finding["evidence"]["service_name"] == "ExampleService"
    assert finding["evidence"]["username"] == "LocalSystem"
    assert finding["evidence"]["exploitability_confirmed"] is False

    saved_report = json.loads(output_path.read_text(encoding="utf-8"))
    assert saved_report["security_findings"][0]["rule_id"] == "SSI-002"


def test_generate_report_includes_service_directory_permissions(
    monkeypatch,
    tmp_path,
):
    mock_system_data(monkeypatch)

    expected_permissions = [{
        "service_name": "ExampleService",
        "directory": "C:\\Example",
        "status": "success",
        "effective_access_confirmed": False,
    }]

    received_services = []

    def fake_inspect_service_permissions(services):
        received_services.extend(deepcopy(services))
        return expected_permissions

    monkeypatch.setattr(
        report_generator.service_permissions_inspector,
        "inspect_service_permissions",
        fake_inspect_service_permissions,
    )

    output_path = tmp_path / "security-report.json"
    report = report_generator.generate_report(output_path)

    assert len(received_services) == 1
    assert received_services[0]["name"] == "ExampleService"
    assert report["service_directory_permissions"] == expected_permissions

    saved_report = json.loads(output_path.read_text(encoding="utf-8"))
    assert saved_report["service_directory_permissions"] == expected_permissions



def test_generate_report_includes_service_file_permissions(
    monkeypatch,
    tmp_path,
):
    mock_system_data(monkeypatch)

    expected_permissions = [{
        "service_name": "ExampleService",
        "executable_path": "C:\\Example\\service.exe",
        "status": "success",
        "effective_access_confirmed": False,
    }]

    received_services = []

    def fake_inspect_service_file_permissions(services):
        received_services.extend(deepcopy(services))
        return expected_permissions

    monkeypatch.setattr(
        report_generator.service_file_permissions_inspector,
        "inspect_service_file_permissions",
        fake_inspect_service_file_permissions,
    )

    output_path = tmp_path / "security-report.json"
    report = report_generator.generate_report(output_path)

    assert len(received_services) == 1
    assert received_services[0]["name"] == "ExampleService"
    assert report["service_file_permissions"] == expected_permissions

    saved_report = json.loads(output_path.read_text(encoding="utf-8"))
    assert saved_report["service_file_permissions"] == expected_permissions


def test_generate_report_marks_windows_features_unsupported_on_linux(
    monkeypatch,
    tmp_path,
):
    mock_system_data(
        monkeypatch,
        listening_ports=[{
            "address": "0.0.0.0",
            "port": 8080,
            "pid": 123,
            "process_name": "example",
        }],
    )

    monkeypatch.setattr(
        report_generator.platform,
        "system",
        lambda: "Linux",
    )

    def unexpected_call(services):
        raise AssertionError("Windows-only inspection must not run on Linux.")

    monkeypatch.setattr(
        report_generator.service_permissions_inspector,
        "inspect_service_permissions",
        unexpected_call,
    )
    monkeypatch.setattr(
        report_generator.service_file_permissions_inspector,
        "inspect_service_file_permissions",
        unexpected_call,
    )

    output_path = tmp_path / "linux-report.json"
    report = report_generator.generate_report(output_path)

    assert report["services"] == []
    assert report["service_directory_permissions"] == []
    assert report["service_file_permissions"] == []

    for feature in (
        "windows_services",
        "ssi_002_unquoted_service_paths",
        "ssi_003_service_directory_permissions",
        "ssi_004_service_file_permissions",
    ):
        assert report["platform_support"][feature]["supported"] is False
        assert report["platform_support"][feature]["reason"]

    assert len(report["security_findings"]) == 1
    assert report["security_findings"][0]["rule_id"] == "SSI-001"
