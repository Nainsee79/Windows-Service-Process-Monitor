import json
import os
import psutil
from datetime import datetime


BASELINE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "config",
    "baseline.json"
)


def load_baseline():
    """Load the approved process baseline."""

    if not os.path.exists(BASELINE_FILE):
        return {}

    with open(BASELINE_FILE, "r", encoding="utf-8") as file:
        data = json.load(file)

    baseline_processes = {}

    for process in data.get("processes", []):
        name = process.get("name", "Unknown")
        path = process.get("path", "Unknown")

        key = f"{name.lower()}|{path.lower()}"

        baseline_processes[key] = process

    return baseline_processes


def collect_current_processes():
    """Collect currently running processes."""

    processes = []

    for process in psutil.process_iter(
        ["pid", "ppid", "name", "exe", "username", "create_time"]
    ):
        try:
            info = process.info

            name = info["name"] or "Unknown"
            path = info["exe"] or "Unknown"

            processes.append({
                "pid": info["pid"],
                "ppid": info["ppid"],
                "name": name,
                "path": path,
                "username": info["username"] or "Unknown",
                "created_at": (
                    datetime.fromtimestamp(
                        info["create_time"]
                    ).isoformat()
                    if info["create_time"]
                    else "Unknown"
                )
            })

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):
            continue

    return processes


def is_suspicious_path(path):
    """Check for execution from commonly abused directories."""

    if not path or path == "Unknown":
        return False

    normalized_path = path.lower().replace("/", "\\")

    suspicious_locations = [
        "\\appdata\\local\\temp\\",
        "\\appdata\\roaming\\",
        "\\windows\\temp\\",
        "\\users\\public\\"
    ]

    return any(
        location in normalized_path
        for location in suspicious_locations
    )


def detect_new_processes():
    """Compare current processes against the baseline."""

    baseline = load_baseline()
    current_processes = collect_current_processes()

    alerts = []

    for process in current_processes:

        key = (
            f"{process['name'].lower()}|"
            f"{process['path'].lower()}"
        )

        if key in baseline:
            continue

        if is_suspicious_path(process["path"]):
            severity = "HIGH"
            reason = (
                "New process is running from a "
                "temporary or user-writable directory."
            )
        else:
            severity = "MEDIUM"
            reason = (
                "Process was not present in the "
                "established process baseline."
            )

        alerts.append({
            "timestamp": datetime.now().isoformat(),
            "severity": severity,
            "type": "New Process Detected",
            "pid": process["pid"],
            "ppid": process["ppid"],
            "process": process["name"],
            "path": process["path"],
            "username": process["username"],
            "reason": reason
        })

    return alerts


if __name__ == "__main__":

    print("=" * 70)
    print("NEW PROCESS DETECTION")
    print("=" * 70)
    print()

    alerts = detect_new_processes()

    if not alerts:
        print("No new processes detected.")
    else:
        print(f"New processes detected: {len(alerts)}")
        print()

        for alert in alerts:
            print(
                f"[{alert['severity']}] "
                f"{alert['type']}"
            )

            print(
                f"Process : {alert['process']} "
                f"(PID: {alert['pid']})"
            )

            print(
                f"Parent  : PID {alert['ppid']}"
            )

            print(
                f"Path    : {alert['path']}"
            )

            print(
                f"User    : {alert['username']}"
            )

            print(
                f"Reason  : {alert['reason']}"
            )

            print("-" * 70)