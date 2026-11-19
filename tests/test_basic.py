import psutil

from system_inspector.network_inspector import (
    _get_process_name,
    get_listening_ports,
)
from system_inspector.process_inspector import get_running_processes
from system_inspector.system_info import get_system_info


def test_system_info_returns_expected_fields():
    info = get_system_info()

    assert set(info) == {
        "hostname",
        "operating_system",
        "os_release",
        "architecture",
        "python_version",
    }


def test_system_info_values_are_not_empty():
    info = get_system_info()

    assert all(isinstance(value, str) and value.strip() for value in info.values())


def test_process_inspector_returns_process_information(monkeypatch):
    class FakeProcess:
        info = {
            "pid": 123,
            "name": "example.exe",
            "username": "user",
        }

    monkeypatch.setattr(psutil, "process_iter", lambda attrs: [FakeProcess()])

    assert get_running_processes() == [{
        "pid": 123,
        "name": "example.exe",
        "username": "user",
    }]


def test_process_inspector_handles_inaccessible_processes(monkeypatch):
    class FakeProcess:
        @property
        def info(self):
            raise psutil.AccessDenied(pid=123)

    monkeypatch.setattr(psutil, "process_iter", lambda attrs: [FakeProcess()])

    assert get_running_processes() == []


def test_network_inspector_returns_listening_ports(monkeypatch):
    class FakeAddress:
        ip = "127.0.0.1"
        port = 8080

    class FakeConnection:
        status = psutil.CONN_LISTEN
        laddr = FakeAddress()
        pid = 123

    class FakeProcess:
        def name(self):
            return "example.exe"

    monkeypatch.setattr(psutil, "net_connections", lambda kind: [FakeConnection()])
    monkeypatch.setattr(psutil, "Process", lambda pid: FakeProcess())

    assert get_listening_ports() == [{
        "address": "127.0.0.1",
        "port": 8080,
        "pid": 123,
        "process_name": "example.exe",
    }]


def test_network_inspector_ignores_non_listening_connections(monkeypatch):
    class FakeAddress:
        ip = "127.0.0.1"
        port = 8080

    class FakeConnection:
        status = psutil.CONN_ESTABLISHED
        laddr = FakeAddress()
        pid = 123

    monkeypatch.setattr(psutil, "net_connections", lambda kind: [FakeConnection()])

    assert get_listening_ports() == []


def test_network_inspector_sorts_ports(monkeypatch):
    class FakeAddress:
        def __init__(self, port):
            self.ip = "127.0.0.1"
            self.port = port

    class FakeConnection:
        status = psutil.CONN_LISTEN
        pid = None

        def __init__(self, port):
            self.laddr = FakeAddress(port)

    monkeypatch.setattr(
        psutil,
        "net_connections",
        lambda kind: [FakeConnection(9000), FakeConnection(443)],
    )

    ports = get_listening_ports()

    assert [item["port"] for item in ports] == [443, 9000]


def test_process_name_returns_unknown_without_pid():
    assert _get_process_name(None) == "Unknown"


def test_process_name_handles_inaccessible_process(monkeypatch):
    def inaccessible_process(pid):
        raise psutil.AccessDenied(pid=pid)

    monkeypatch.setattr(psutil, "Process", inaccessible_process)

    assert _get_process_name(123) == "Unknown"
