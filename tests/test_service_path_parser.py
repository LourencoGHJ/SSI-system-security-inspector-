import pytest

from system_inspector.service_path_parser import (
    get_service_executable_directory,
    get_service_executable_path,
)


@pytest.mark.parametrize(
    ("binary_path", "expected"),
    [
        (
            '"C:\\Program Files\\Vendor\\service.exe" --service',
            r"C:\Program Files\Vendor",
        ),
        (
            r"C:\Windows\System32\service.exe",
            r"C:\Windows\System32",
        ),
        (
            r"C:\Windows\System32\service.exe --service",
            r"C:\Windows\System32",
        ),
    ],
)
def test_extracts_unambiguous_executable_directory(binary_path, expected):
    assert get_service_executable_directory(binary_path) == expected


@pytest.mark.parametrize(
    "binary_path",
    [
        r"C:\Program Files\Vendor\service.exe --service",
        r"relative\service.exe",
        "",
        "   ",
        None,
        '"C:\\Program Files\\Vendor\\service.exe --service',
    ],
)
def test_rejects_ambiguous_or_invalid_paths(binary_path):
    assert get_service_executable_directory(binary_path) is None


def test_rejects_non_executable_path():
    assert get_service_executable_directory(
        r"C:\Windows\System32\service.dll"
    ) is None


def test_rejects_environment_variable_paths():
    assert get_service_executable_directory(
        r"%SystemRoot%\System32\service.exe"
    ) is None


@pytest.mark.parametrize(
    ("binary_path", "expected"),
    [
        (
            '"C:\\Program Files\\Vendor\\service.exe" --service',
            r"C:\Program Files\Vendor\service.exe",
        ),
        (
            r"C:\Windows\System32\service.exe",
            r"C:\Windows\System32\service.exe",
        ),
    ],
)
def test_extracts_unambiguous_executable_path(binary_path, expected):
    assert get_service_executable_path(binary_path) == expected


@pytest.mark.parametrize(
    "binary_path",
    [
        r"C:\Program Files\Vendor\service.exe --service",
        r"relative\service.exe",
        "",
        None,
        r"%SystemRoot%\System32\service.exe",
    ],
)
def test_rejects_ambiguous_executable_path(binary_path):
    assert get_service_executable_path(binary_path) is None
