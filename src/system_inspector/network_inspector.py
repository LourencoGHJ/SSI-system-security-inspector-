import psutil


def _get_process_name(pid: int | None) -> str:
    """Return a process name when its PID is available."""
    if pid is None:
        return "Unknown"

    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return "Unknown"


def get_listening_ports() -> list[dict[str, str | int | None]]:
    """Return basic information about TCP listening ports."""
    ports = []

    for connection in psutil.net_connections(kind="inet"):
        if connection.status != psutil.CONN_LISTEN:
            continue

        pid = connection.pid

        ports.append({
            "address": connection.laddr.ip,
            "port": connection.laddr.port,
            "pid": pid,
            "process_name": _get_process_name(pid),
        })

    return sorted(ports, key=lambda item: item["port"])
