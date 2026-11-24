import psutil


def get_windows_services() -> list[dict[str, str | int | None]]:
    """Return basic information about Windows services."""
    services = []
    service_iterator = getattr(psutil, "win_service_iter", None)

    if not callable(service_iterator):
        return services

    for service in service_iterator():
        try:
            services.append({
                "name": service.name(),
                "display_name": service.display_name(),
                "status": service.status(),
                "start_type": service.start_type(),
                "username": service.username(),
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
