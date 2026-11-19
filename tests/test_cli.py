from system_inspector import cli


def test_scan_command_generates_report(monkeypatch, tmp_path, capsys):
    output_path = tmp_path / "report.json"

    monkeypatch.setattr(
        cli,
        "generate_report",
        lambda path: {
            "system": {"hostname": "test-pc"},
            "processes": [{}, {}],
            "listening_ports": [{}],
        },
    )

    result = cli.main(["scan", "--output", str(output_path)])
    output = capsys.readouterr().out

    assert result == 0
    assert "Hostname: test-pc" in output
    assert "Processes: 2" in output
    assert "Listening ports: 1" in output


def test_scan_command_handles_output_errors(monkeypatch, capsys):
    def fail_to_generate_report(path):
        raise OSError("Permission denied")

    monkeypatch.setattr(
        cli,
        "generate_report",
        fail_to_generate_report,
    )

    result = cli.main(["scan"])
    output = capsys.readouterr().out

    assert result == 1
    assert "Scan failed: Permission denied" in output
