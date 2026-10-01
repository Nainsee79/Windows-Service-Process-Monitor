import json
import os
import psutil
from datetime import datetime


BASELINE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "config",
    "baseline.json"
)


def collect_current_processes():
    """Collect the current process baseline."""

    processes = {}

    for process in psutil.process_iter(
        ["pid", "name", "exe"]
    ):
        try:
            info = process.info

            name = info["name"] or "Unknown"
            executable = info["exe"] or "Unknown"

            # Use process name + executable path as the identity.
            process_key = f"{name.lower()}|{executable.lower()}"

            processes[process_key] = {
                "name": name,
                "path": executable
            }

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):
            continue

    return processes


def save_baseline(processes):
    """Save the process baseline to baseline.json."""

    baseline_data = {
        "created_at": datetime.now().isoformat(),
        "processes": list(processes.values())
    }

    with open(BASELINE_FILE, "w", encoding="utf-8") as file:
        json.dump(
            baseline_data,
            file,
            indent=4
        )


def create_baseline():
    """Create and save a baseline of current processes."""

    processes = collect_current_processes()

    save_baseline(processes)

    return len(processes)


if __name__ == "__main__":

    print("=" * 70)
    print("PROCESS BASELINE MANAGER")
    print("=" * 70)
    print()

    count = create_baseline()

    print(f"Baseline created successfully.")
    print(f"Processes recorded: {count}")
    print(f"Baseline file: {BASELINE_FILE}")