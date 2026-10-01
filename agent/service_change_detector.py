import json
import os
from datetime import datetime

from service_audit import get_services, extract_executable_path


BASELINE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "config",
    "service_baseline.json"
)


def normalize(value):
    """Normalize values for reliable comparison."""

    if value is None:
        return ""

    value = str(value).strip().lower()

    if value in ["none", "unknown", "null"]:
        return ""

    return value


def get_field(service, field):
    """
    Read service fields from either the raw PowerShell format
    or the normalized baseline format.
    """

    mapping = {
        "name": ["name", "Name"],
        "display_name": ["display_name", "DisplayName"],
        "state": ["state", "State"],
        "start_mode": ["start_mode", "StartMode"],
        "start_account": ["start_account", "StartName"],
        "path": ["path", "PathName"]
    }

    for key in mapping.get(field, [field]):

        if key in service:
            value = service.get(key)

            if value is not None:
                return value

    return ""


def get_executable(service):
    """Get normalized executable path from a service."""

    path = get_field(service, "path")

    if not path:
        return ""

    return normalize(
        extract_executable_path(str(path))
    )


def load_baseline():

    if not os.path.exists(BASELINE_FILE):

        print("[ERROR] Service baseline not found.")
        print(f"Expected file: {BASELINE_FILE}")

        return []

    try:

        with open(
            BASELINE_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)

        return data.get("services", [])

    except Exception as error:

        print(
            f"[ERROR] Unable to read service baseline: {error}"
        )

        return []


def build_service_map(services):

    service_map = {}

    for service in services:

        name = normalize(
            get_field(service, "name")
        )

        if name:

            service_map[name] = service

    return service_map


def compare_services(baseline, current):

    baseline_map = build_service_map(baseline)
    current_map = build_service_map(current)

    new_services = []
    removed_services = []
    modified_services = []

    # ---------------------------------------------------------
    # NEW SERVICES
    # ---------------------------------------------------------

    for name, service in current_map.items():

        if name not in baseline_map:

            new_services.append(service)

    # ---------------------------------------------------------
    # REMOVED SERVICES
    # ---------------------------------------------------------

    for name, service in baseline_map.items():

        if name not in current_map:

            removed_services.append(service)

    # ---------------------------------------------------------
    # MODIFIED SERVICES
    # ---------------------------------------------------------

    for name, current_service in current_map.items():

        if name not in baseline_map:

            continue

        old_service = baseline_map[name]

        changes = []

        # -----------------------------------------------------
        # EXECUTABLE PATH
        # -----------------------------------------------------

        old_executable = get_executable(old_service)
        new_executable = get_executable(current_service)

        if old_executable != new_executable:

            changes.append({
                "field": "executable_path",
                "old": get_field(old_service, "path"),
                "new": get_field(current_service, "path")
            })

        # -----------------------------------------------------
        # START MODE
        # -----------------------------------------------------

        old_start_mode = normalize(
            get_field(old_service, "start_mode")
        )

        new_start_mode = normalize(
            get_field(current_service, "start_mode")
        )

        if old_start_mode != new_start_mode:

            changes.append({
                "field": "start_mode",
                "old": get_field(old_service, "start_mode"),
                "new": get_field(current_service, "start_mode")
            })

        # -----------------------------------------------------
        # START ACCOUNT
        # -----------------------------------------------------

        old_start_account = normalize(
            get_field(old_service, "start_account")
        )

        new_start_account = normalize(
            get_field(current_service, "start_account")
        )

        if old_start_account != new_start_account:

            changes.append({
                "field": "start_account",
                "old": get_field(old_service, "start_account"),
                "new": get_field(current_service, "start_account")
            })

        if changes:

            modified_services.append({
                "service": current_service,
                "changes": changes
            })

    return (
        new_services,
        removed_services,
        modified_services
    )


def print_service(service):

    print(
        f"Service      : "
        f"{get_field(service, 'name')}"
    )

    print(
        f"Display Name : "
        f"{get_field(service, 'display_name')}"
    )

    print(
        f"State        : "
        f"{get_field(service, 'state')}"
    )

    print(
        f"Start Mode   : "
        f"{get_field(service, 'start_mode')}"
    )

    print(
        f"Start Account: "
        f"{get_field(service, 'start_account')}"
    )

    print(
        f"Path         : "
        f"{get_field(service, 'path')}"
    )


def main():

    print("=" * 70)
    print("WINDOWS SERVICE CHANGE DETECTOR")
    print("=" * 70)

    print(
        f"Timestamp: "
        f"{datetime.now().isoformat()}"
    )

    print()

    # ---------------------------------------------------------
    # LOAD BASELINE
    # ---------------------------------------------------------

    baseline = load_baseline()

    if not baseline:

        print(
            "[ERROR] Baseline is empty or unavailable."
        )

        return

    # ---------------------------------------------------------
    # GET CURRENT SERVICES
    # ---------------------------------------------------------

    try:

        current = get_services()

    except Exception as error:

        print(
            f"[ERROR] Unable to enumerate services: {error}"
        )

        return

    print(
        f"Baseline services : {len(baseline)}"
    )

    print(
        f"Current services  : {len(current)}"
    )

    print()

    # ---------------------------------------------------------
    # COMPARE
    # ---------------------------------------------------------

    (
        new_services,
        removed_services,
        modified_services
    ) = compare_services(
        baseline,
        current
    )

    total_changes = (
        len(new_services)
        + len(removed_services)
        + len(modified_services)
    )

    # ---------------------------------------------------------
    # NEW SERVICES
    # ---------------------------------------------------------

    if new_services:

        print("=" * 70)
        print("NEW SERVICES")
        print("=" * 70)

        for service in new_services:

            print()
            print("[HIGH] New service detected")

            print_service(service)

    # ---------------------------------------------------------
    # REMOVED SERVICES
    # ---------------------------------------------------------

    if removed_services:

        print()
        print("=" * 70)
        print("REMOVED SERVICES")
        print("=" * 70)

        for service in removed_services:

            print()
            print("[MEDIUM] Service removed")

            print_service(service)

    # ---------------------------------------------------------
    # MODIFIED SERVICES
    # ---------------------------------------------------------

    if modified_services:

        print()
        print("=" * 70)
        print("MODIFIED SERVICES")
        print("=" * 70)

        for finding in modified_services:

            service = finding["service"]

            print()
            print(
                "[MEDIUM] Service configuration changed"
            )

            print(
                f"Service      : "
                f"{get_field(service, 'name')}"
            )

            print(
                f"Display Name : "
                f"{get_field(service, 'display_name')}"
            )

            for change in finding["changes"]:

                print(
                    f"Changed Field: "
                    f"{change['field']}"
                )

                print(
                    f"Old Value    : "
                    f"{change['old']}"
                )

                print(
                    f"New Value    : "
                    f"{change['new']}"
                )

    # ---------------------------------------------------------
    # FINAL RESULT
    # ---------------------------------------------------------

    print()
    print("=" * 70)

    if total_changes == 0:

        print(
            "No service changes detected."
        )

    else:

        print(
            f"Service changes detected: "
            f"{total_changes}"
        )

        print(
            f"New services       : "
            f"{len(new_services)}"
        )

        print(
            f"Removed services   : "
            f"{len(removed_services)}"
        )

        print(
            f"Modified services  : "
            f"{len(modified_services)}"
        )

    print("=" * 70)


if __name__ == "__main__":
    main()