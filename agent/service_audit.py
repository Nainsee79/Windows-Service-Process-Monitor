import subprocess
import json
import re
from datetime import datetime


def get_services():
    """Collect Windows service information using PowerShell."""

    command = [
        "powershell",
        "-NoProfile",
        "-Command",
        """
        Get-CimInstance Win32_Service |
        Select-Object Name, DisplayName, State, StartMode,
        StartName, PathName, Description |
        ConvertTo-Json -Depth 3
        """
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace"
        )

        if result.returncode != 0:
            print("Failed to query Windows services.")
            print(result.stderr)
            return []

        if not result.stdout.strip():
            return []

        data = json.loads(result.stdout)

        if isinstance(data, dict):
            data = [data]

        return data

    except json.JSONDecodeError:
        print("Unable to parse Windows service data.")
        return []

    except Exception as error:
        print(f"Service enumeration error: {error}")
        return []


def extract_executable_path(path_name):
    """Extract a likely executable path from a service ImagePath."""

    if not path_name:
        return "Unknown"

    path_name = path_name.strip()

    # Quoted executable path
    if path_name.startswith('"'):
        match = re.match(r'"([^"]+)"', path_name)

        if match:
            return match.group(1)

    # Unquoted executable path
    match = re.match(
        r"(.+?\.exe)(?:\s|$)",
        path_name,
        re.IGNORECASE
    )

    if match:
        return match.group(1)

    return path_name.split()[0]


def is_suspicious_path(path):
    """Identify commonly abused service executable locations."""

    if not path or path == "Unknown":
        return False

    normalized = path.lower().replace("/", "\\")

    suspicious_locations = [
        "\\appdata\\local\\temp\\",
        "\\appdata\\roaming\\",
        "\\windows\\temp\\",
        "\\users\\public\\"
    ]

    return any(
        location in normalized
        for location in suspicious_locations
    )


def analyze_services(services):
    """Analyze services for suspicious executable locations."""

    alerts = []

    for service in services:

        name = service.get("Name") or "Unknown"
        display_name = service.get("DisplayName") or "Unknown"
        state = service.get("State") or "Unknown"
        start_mode = service.get("StartMode") or "Unknown"
        start_name = service.get("StartName") or "Unknown"
        path_name = service.get("PathName") or "Unknown"
        description = service.get("Description") or ""

        executable = extract_executable_path(path_name)

        if is_suspicious_path(executable):

            alerts.append({
                "timestamp": datetime.now().isoformat(),
                "severity": "HIGH",
                "type": "Suspicious Service Executable Path",
                "service_name": name,
                "display_name": display_name,
                "state": state,
                "start_mode": start_mode,
                "start_account": start_name,
                "path": executable,
                "reason": (
                    "Service executable is located in a "
                    "temporary or user-writable directory."
                )
            })

    return alerts


if __name__ == "__main__":

    print("=" * 70)
    print("WINDOWS SERVICE AUDIT")
    print("=" * 70)
    print()

    services = get_services()

    print(f"Services discovered: {len(services)}")
    print()

    print("SERVICE INVENTORY")
    print("-" * 70)

    for service in services:

        executable = extract_executable_path(
            service.get("PathName") or "Unknown"
        )

        print(
            f"Service      : {service.get('Name') or 'Unknown'}"
        )

        print(
            f"Display Name : "
            f"{service.get('DisplayName') or 'Unknown'}"
        )

        print(
            f"State        : "
            f"{service.get('State') or 'Unknown'}"
        )

        print(
            f"Start Mode   : "
            f"{service.get('StartMode') or 'Unknown'}"
        )

        print(
            f"Start Account: "
            f"{service.get('StartName') or 'Unknown'}"
        )

        print(f"Executable   : {executable}")

        print("-" * 70)

    print()
    print("SUSPICIOUS SERVICE ANALYSIS")
    print("-" * 70)

    alerts = analyze_services(services)

    if not alerts:
        print("No suspicious service executable paths detected.")
    else:

        print(
            f"Suspicious services detected: {len(alerts)}"
        )
        print()

        for alert in alerts:

            print(
                f"[{alert['severity']}] "
                f"{alert['type']}"
            )

            print(
                f"Service      : "
                f"{alert['service_name']}"
            )

            print(
                f"Display Name : "
                f"{alert['display_name']}"
            )

            print(
                f"State        : "
                f"{alert['state']}"
            )

            print(
                f"Start Mode   : "
                f"{alert['start_mode']}"
            )

            print(
                f"Start Account: "
                f"{alert['start_account']}"
            )

            print(
                f"Path         : "
                f"{alert['path']}"
            )

            print(
                f"Reason       : "
                f"{alert['reason']}"
            )

            print("-" * 70)