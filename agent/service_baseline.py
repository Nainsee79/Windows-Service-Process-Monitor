import json
import os
from datetime import datetime

from service_audit import get_services, extract_executable_path


BASELINE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "config",
    "service_baseline.json"
)


def create_service_baseline():
    """Create a baseline of the current Windows service configuration."""

    services = get_services()

    baseline_services = []

    for service in services:
        path_name = service.get("PathName") or "Unknown"

        baseline_services.append({
            "name": service.get("Name") or "Unknown",
            "display_name": service.get("DisplayName") or "Unknown",
            "state": service.get("State") or "Unknown",
            "start_mode": service.get("StartMode") or "Unknown",
            "start_account": service.get("StartName") or "Unknown",
            "path": extract_executable_path(path_name)
        })

    baseline_data = {
        "created_at": datetime.now().isoformat(),
        "services": baseline_services
    }

    with open(BASELINE_FILE, "w", encoding="utf-8") as file:
        json.dump(
            baseline_data,
            file,
            indent=4
        )

    return len(baseline_services)


if __name__ == "__main__":

    print("=" * 70)
    print("WINDOWS SERVICE BASELINE MANAGER")
    print("=" * 70)
    print()

    count = create_service_baseline()

    print("Service baseline created successfully.")
    print(f"Services recorded: {count}")
    print(f"Baseline file: {BASELINE_FILE}")