import json

from system_inspector import report_generator


def test_generate_report_contains_expected_sections(monkeypatch, tmp_path):
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
        lambda: [{
            "address": "127.0.0.1",
            "port": 8080,
            "pid": 123,
            "process_name": "example.exe",
        }],
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

    output_path = tmp_path / "reports" / "security-report.json"

    report = report_generator.generate_report(output_path)

    assert set(report) == {
        "generated_at",
        "system",
        "processes",
        "listening_ports",
        "services",
    }
    assert report["system"]["hostname"] == "test-pc"
    assert len(report["processes"]) == 1
    assert len(report["listening_ports"]) == 1
    assert len(report["services"]) == 1
    assert report["services"][0]["name"] == "ExampleService"
    assert output_path.exists()


def test_generate_report_writes_valid_json(monkeypatch, tmp_path):
    monkeypatch.setattr(
        report_generator.system_info,
        "get_system_info",
        lambda: {"hostname": "test-pc"},
    )
    monkeypatch.setattr(
        report_generator.process_inspector,
        "get_running_processes",
        lambda: [],
    )
    monkeypatch.setattr(
        report_generator.network_inspector,
        "get_listening_ports",
        lambda: [],
    )
    monkeypatch.setattr(
        report_generator.service_inspector,
        "get_windows_services",
        lambda: [],
    )

    output_path = tmp_path / "security-report.json"

    report_generator.generate_report(output_path)

    saved_report = json.loads(output_path.read_text(encoding="utf-8"))

    assert saved_report["system"]["hostname"] == "test-pc"
    assert saved_report["processes"] == []
    assert saved_report["listening_ports"] == []
    assert saved_report["services"] == []
