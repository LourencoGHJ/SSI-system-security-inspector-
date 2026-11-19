import psutil


def get_windows_services() -> list[dict[str, str | int | None]]:
    """Return basic information about Windows services."""
    services = []

    for service in psutil.win_service_iter():
        try:
            services.append({
                "name": service.name(),
                "display_name": service.display_name(),
                "status": service.status(),
                "start_type": service.start_type(),
                "pid": service.pid(),
                "binary_path": service.binpath(),
            })

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            FileNotFoundError,
        ):
            continue

    return sorted(services, key=lambda item: item["name"].lower())
