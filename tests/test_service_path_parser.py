import pytest

from system_inspector.service_path_parser import (
    get_service_executable_directory,
)


@pytest.mark.parametrize(
    ("binary_path", "expected"),
    [
        (
            '"C:\\Program Files\\Vendor\\service.exe" --service',
            "C:\\Program Files\\Vendor",
        ),
        (
            'C:\\Windows\\System32\\service.exe',
            "C:\\Windows\\System32",
        ),
        (
            'C:\\Windows\\System32\\service.exe --service',
            "C:\\Windows\\System32",
        ),
    ],
)
def test_extracts_unambiguous_executable_directory(binary_path, expected):
    assert get_service_executable_directory(binary_path) == expected


@pytest.mark.parametrize(
    "binary_path",
    [
        "C:\\Program Files\\Vendor\\service.exe --service",
        "relative\\service.exe",
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
        "C:\\Windows\\System32\\service.dll"
    ) is None

def test_rejects_environment_variable_paths():
    assert get_service_executable_directory(
        "%SystemRoot%\\System32\\service.exe"
    ) is None

