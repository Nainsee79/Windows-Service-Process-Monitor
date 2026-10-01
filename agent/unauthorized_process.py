import json
import os
import psutil


RULES_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "config",
    "process_rules.json"
)


def load_rules():
    """Load process detection rules from configuration."""

    with open(RULES_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def is_suspicious_path(executable_path, suspicious_directories):
    """Check whether a process is running from a suspicious location."""

    if not executable_path or executable_path == "Unknown":
        return False

    normalized_path = executable_path.lower().replace("/", "\\")

    for directory in suspicious_directories:
        if directory.lower() in normalized_path:
            return True

    return False


def analyze_processes():
    """Analyze running processes against configured detection rules."""

    rules = load_rules()

    whitelist = {
        process.lower()
        for process in rules.get("whitelist", [])
    }

    blacklist = {
        process.lower()
        for process in rules.get("blacklist", [])
    }

    suspicious_directories = rules.get(
        "suspicious_directories", []
    )

    alerts = []

    for process in psutil.process_iter(
        ["pid", "ppid", "name", "exe", "username"]
    ):
        try:
            info = process.info

            pid = info["pid"]
            ppid = info["ppid"]
            name = info["name"] or "Unknown"
            executable = info["exe"] or "Unknown"
            username = info["username"] or "Unknown"

            process_name = name.lower()

            # Blacklist detection
            if process_name in blacklist:
                alerts.append({
                    "severity": "CRITICAL",
                    "type": "Blacklisted Process",
                    "pid": pid,
                    "ppid": ppid,
                    "process": name,
                    "path": executable,
                    "username": username,
                    "reason": (
                        "Process name matches a configured "
                        "high-risk blacklist entry."
                    )
                })

            # Suspicious execution path detection
            if is_suspicious_path(
                executable,
                suspicious_directories
            ):
                alerts.append({
                    "severity": "HIGH",
                    "type": "Suspicious Execution Path",
                    "pid": pid,
                    "ppid": ppid,
                    "process": name,
                    "path": executable,
                    "username": username,
                    "reason": (
                        "Process is running from a temporary "
                        "or user-writable directory."
                    )
                })

            # Unknown process detection
            if (
                process_name not in whitelist
                and process_name not in blacklist
            ):
                alerts.append({
                    "severity": "MEDIUM",
                    "type": "Unknown Process",
                    "pid": pid,
                    "ppid": ppid,
                    "process": name,
                    "path": executable,
                    "username": username,
                    "reason": (
                        "Process is not present in the configured "
                        "process whitelist."
                    )
                })

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):
            continue

    return alerts


if __name__ == "__main__":

    print("=" * 70)
    print("UNAUTHORIZED PROCESS DETECTION")
    print("=" * 70)
    print()

    alerts = analyze_processes()

    if not alerts:
        print("No suspicious processes detected.")
    else:
        print(f"Total alerts generated: {len(alerts)}")
        print()

        for alert in alerts:
            print(f"[{alert['severity']}] {alert['type']}")
            print(
                f"Process : {alert['process']} "
                f"(PID: {alert['pid']})"
            )
            print(f"Parent  : PID {alert['ppid']}")
            print(f"Path    : {alert['path']}")
            print(f"User    : {alert['username']}")
            print(f"Reason  : {alert['reason']}")
            print("-" * 70)