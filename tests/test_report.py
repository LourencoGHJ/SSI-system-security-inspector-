import json

from system_inspector import report_generator


def mock_system_data(monkeypatch, listening_ports=None):
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
            "binary_path": "C:\\Example\\service.exe",
        }],
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
        "system",
        "processes",
        "listening_ports",
        "services",
        "security_findings",
    }
    assert report["system"]["hostname"] == "test-pc"
    assert len(report["processes"]) == 1
    assert len(report["listening_ports"]) == 1
    assert len(report["services"]) == 1
    assert report["services"][0]["name"] == "ExampleService"
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
    assert len(saved_report["security_findings"]) == 1
    assert saved_report["security_findings"][0]["rule_id"] == "SSI-001"
    assert saved_report["security_findings"][0]["evidence"]["port"] == 8080
