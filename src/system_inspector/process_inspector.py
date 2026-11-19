import psutil


def get_running_processes() -> list[dict[str, str | int]]:
    """Return basic information about running processes."""
    processes = []

    for process in psutil.process_iter(["pid", "name", "username"]):
        try:
            info = process.info

            processes.append({
                "pid": info["pid"],
                "name": info["name"] or "Unknown",
                "username": info["username"] or "Unknown",
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return processes
