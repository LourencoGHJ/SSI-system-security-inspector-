
import platform
import socket
import sys


def get_system_info() -> dict[str, str]:
    """Collect basic information about the local system."""
    return {
        "hostname": socket.gethostname(),
        "operating_system": platform.system(),
        "os_release": platform.release(),
        "architecture": platform.machine(),
        "python_version": sys.version.split()[0],
    }
