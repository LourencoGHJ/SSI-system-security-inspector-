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

    def pid(self):
        return 123

    def binpath(self):
        return "C:\\Example\\service.exe"


def test_service_inspector_returns_service_information(monkeypatch):
    monkeypatch.setattr(
        psutil,
        "win_service_iter",
        lambda: [FakeService()],
    )

    assert get_windows_services() == [{
        "name": "ExampleService",
        "display_name": "Example Service",
        "status": "running",
        "start_type": "automatic",
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
    )

    assert get_windows_services() == []
