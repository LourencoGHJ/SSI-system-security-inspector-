"""Conservative Windows service executable path extraction."""

import ntpath
import re


QUOTED_EXECUTABLE_PATTERN = re.compile(
    r'^\s*"(?P<executable>[^"]+\.exe)"(?:\s|$)',
    re.IGNORECASE,
)

UNQUOTED_EXECUTABLE_PATTERN = re.compile(
    r"^\s*(?P<executable>\S+\.exe)(?:\s|$)",
    re.IGNORECASE,
)


def get_service_executable_path(binary_path: str) -> str | None:
    """Return an absolute executable path only when it is unambiguous."""

    if not isinstance(binary_path, str):
        return None

    value = binary_path.strip()

    if not value or "%" in value:
        return None

    quoted_match = QUOTED_EXECUTABLE_PATTERN.match(value)

    if quoted_match:
        executable_path = quoted_match.group("executable")
    else:
        unquoted_match = UNQUOTED_EXECUTABLE_PATTERN.match(value)

        if not unquoted_match:
            return None

        executable_path = unquoted_match.group("executable")

    if not ntpath.isabs(executable_path):
        return None

    return executable_path


def get_service_executable_directory(binary_path: str) -> str | None:
    """Return the executable directory only when its path is unambiguous."""

    executable_path = get_service_executable_path(binary_path)

    if executable_path is None:
        return None

    directory = ntpath.dirname(executable_path)

    return directory or None
