from system_inspector.security_analyzer import analyze_listening_ports, analyze_unquoted_service_paths


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


def test_detects_unquoted_service_executable_path():
    services = [{
        "name": "vgc",
        "display_name": "Riot Vanguard",
        "binary_path": "C:\\Program Files\\Riot Vanguard\\vgc.exe",
        "username": "LocalSystem",
        "start_type": "manual",
        "status": "stopped",
    }]

    findings = analyze_unquoted_service_paths(services)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SSI-002"
    assert findings[0]["severity"] == "low"
    assert findings[0]["evidence"]["executable_path"] == (
        "C:\\Program Files\\Riot Vanguard\\vgc.exe"
    )
    assert findings[0]["evidence"]["exploitability_confirmed"] is False


def test_ignores_quoted_service_executable_path():
    services = [{
        "name": "ExampleService",
        "binary_path": '"C:\\Program Files\\Example\\service.exe"',
    }]

    assert analyze_unquoted_service_paths(services) == []


def test_ignores_spaces_only_in_service_arguments():
    services = [{
        "name": "ExampleService",
        "binary_path": "C:\\Windows\\System32\\svchost.exe -k netsvcs",
    }]

    assert analyze_unquoted_service_paths(services) == []


def test_ignores_executable_paths_without_spaces():
    services = [{
        "name": "ExampleService",
        "binary_path": "C:\\Windows\\System32\\service.exe",
    }]

    assert analyze_unquoted_service_paths(services) == []


def test_ignores_empty_or_invalid_service_paths():
    services = [
        {"name": "EmptyService", "binary_path": ""},
        {"name": "MissingService"},
        {"name": "InvalidService", "binary_path": None},
        {"name": "NonExecutableService", "binary_path": "C:\\Program Files\\service"},
    ]

    assert analyze_unquoted_service_paths(services) == []


def test_analyzes_multiple_services_independently():
    services = [
        {
            "name": "UnsafeService",
            "binary_path": "C:\\Program Files\\Example\\service.exe",
        },
        {
            "name": "SafeService",
            "binary_path": '"C:\\Program Files\\Example\\service.exe"',
        },
        {
            "name": "SystemService",
            "binary_path": "C:\\Windows\\System32\\service.exe",
        },
    ]

    findings = analyze_unquoted_service_paths(services)

    assert len(findings) == 1
    assert findings[0]["evidence"]["service_name"] == "UnsafeService"


def test_detects_uppercase_executable_extension():
    services = [{
        "name": "UppercaseService",
        "binary_path": "C:\\Program Files\\Example\\SERVICE.EXE",
    }]

    findings = analyze_unquoted_service_paths(services)

    assert len(findings) == 1
    assert findings[0]["evidence"]["executable_path"].endswith("SERVICE.EXE")


def test_detects_unquoted_path_with_quoted_arguments():
    services = [{
        "name": "ArgumentService",
        "binary_path": 'C:\\Program Files\\Example\\service.exe --config "C:\\App Data\\config.json"',
    }]

    findings = analyze_unquoted_service_paths(services)

    assert len(findings) == 1
    assert findings[0]["evidence"]["executable_path"] == (
        "C:\\Program Files\\Example\\service.exe"
    )


def test_ignores_quoted_executable_with_arguments():
    services = [{
        "name": "QuotedService",
        "binary_path": '"C:\\Program Files\\Example\\service.exe" --config "C:\\App Data\\config.json"',
    }]

    assert analyze_unquoted_service_paths(services) == []
