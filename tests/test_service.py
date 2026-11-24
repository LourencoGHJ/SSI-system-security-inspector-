import psutil

from system_inspector.service_inspector import get_windows_services


class FakeService:
    def __init__(self, name="ExampleService"):
        self.service_name = name

    def name(self):
        return self.service_name

    def display_name(self):
        return "Example Service"

    def status(self):
        return "running"

    def start_type(self):
        return "automatic"

    def username(self):
        return "LocalSystem"

    def pid(self):
        return 123

    def binpath(self):
        return "C:\\Example\\service.exe"


def test_service_inspector_returns_service_information(monkeypatch):
    monkeypatch.setattr(
        psutil,
        "win_service_iter",
        lambda: [FakeService()],
        raising=False,
    )

    assert get_windows_services() == [{
        "name": "ExampleService",
        "display_name": "Example Service",
        "status": "running",
        "start_type": "automatic",
        "username": "LocalSystem",
        "pid": 123,
        "binary_path": "C:\\Example\\service.exe",
    }]


def test_service_inspector_sorts_services(monkeypatch):
    monkeypatch.setattr(
        psutil,
        "win_service_iter",
        lambda: [
            FakeService("ZuluService"),
            FakeService("AlphaService"),
        ],
        raising=False,
    )

    services = get_windows_services()

    assert [service["name"] for service in services] == [
        "AlphaService",
        "ZuluService",
    ]


def test_service_inspector_skips_inaccessible_services(monkeypatch):
    class InaccessibleService:
        def name(self):
            raise psutil.AccessDenied()

    monkeypatch.setattr(
        psutil,
        "win_service_iter",
        lambda: [InaccessibleService()],
        raising=False,
    )

    assert get_windows_services() == []


def test_service_inspector_skips_missing_services(monkeypatch):
    class MissingService:
        def name(self):
            raise FileNotFoundError()

    monkeypatch.setattr(
        psutil,
        "win_service_iter",
        lambda: [MissingService()],
        raising=False,
    )

    assert get_windows_services() == []



def test_service_inspector_handles_unsupported_platform(monkeypatch):
    monkeypatch.delattr(psutil, "win_service_iter", raising=False)

    assert get_windows_services() == []
