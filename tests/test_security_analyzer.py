from system_inspector.security_analyzer import analyze_listening_ports


def test_detects_ipv4_wildcard_address():
    ports = [{
        "address": "0.0.0.0",
        "port": 8080,
        "pid": 123,
        "process_name": "example.exe",
    }]

    findings = analyze_listening_ports(ports)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SSI-001"
    assert findings[0]["severity"] == "low"
    assert findings[0]["evidence"]["port"] == 8080
    assert findings[0]["evidence"]["addresses"] == ["0.0.0.0"]


def test_detects_ipv6_wildcard_address():
    ports = [{
        "address": "::",
        "port": 443,
        "pid": 456,
        "process_name": "server.exe",
    }]

    findings = analyze_listening_ports(ports)

    assert len(findings) == 1
    assert findings[0]["evidence"]["addresses"] == ["::"]


def test_groups_ipv4_and_ipv6_for_same_process():
    ports = [
        {
            "address": "0.0.0.0",
            "port": 8080,
            "pid": 123,
            "process_name": "example.exe",
        },
        {
            "address": "::",
            "port": 8080,
            "pid": 123,
            "process_name": "example.exe",
        },
    ]

    findings = analyze_listening_ports(ports)

    assert len(findings) == 1
    assert findings[0]["evidence"]["addresses"] == ["0.0.0.0", "::"]


def test_keeps_different_processes_separate():
    ports = [
        {
            "address": "0.0.0.0",
            "port": 8080,
            "pid": 123,
            "process_name": "first.exe",
        },
        {
            "address": "::",
            "port": 8080,
            "pid": 456,
            "process_name": "second.exe",
        },
    ]

    findings = analyze_listening_ports(ports)

    assert len(findings) == 2


def test_ignores_localhost_addresses():
    ports = [
        {"address": "127.0.0.1", "port": 8080},
        {"address": "::1", "port": 443},
    ]

    assert analyze_listening_ports(ports) == []


def test_returns_empty_list_without_listening_ports():
    assert analyze_listening_ports([]) == []
