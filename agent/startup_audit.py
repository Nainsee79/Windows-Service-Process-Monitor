import json
import os
import subprocess
from datetime import datetime


SUSPICIOUS_DIRECTORIES = [
    r"\AppData\Local\Temp",
    r"\AppData\Roaming",
    r"\Windows\Temp",
    r"\Users\Public",
]


def run_powershell(command):
    result = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())

    return result.stdout


def get_startup_services():
    command = """
    Get-CimInstance Win32_Service |
    Where-Object {
        $_.StartMode -eq 'Auto' -or
        $_.StartMode -eq 'Boot' -or
        $_.StartMode -eq 'System'
    } |
    Select-Object Name, DisplayName, State, StartMode, StartName, PathName |
    ConvertTo-Json -Depth 3
    """

    output = run_powershell(command)

    if not output.strip():
        return []

    data = json.loads(output)

    if isinstance(data, dict):
        data = [data]

    return data


def extract_executable_path(path_name):
    if not path_name:
        return ""

    path = path_name.strip()

    # Remove surrounding quotes
    if path.startswith('"'):
        end_quote = path.find('"', 1)
        if end_quote != -1:
            return path[1:end_quote]

    # Handle normal executable paths
    extensions = [".exe", ".com", ".bat", ".cmd"]

    lower_path = path.lower()

    for extension in extensions:
        index = lower_path.find(extension)

        if index != -1:
            return path[: index + len(extension)].strip()

    return path


def is_suspicious_path(path):
    if not path:
        return False

    normalized = path.lower().replace("/", "\\")

    for directory in SUSPICIOUS_DIRECTORIES:
        if directory.lower() in normalized:
            return True

    return False


def is_user_writable_location(path):
    if not path:
        return False

    normalized = path.lower().replace("/", "\\")

    user_writable_locations = [
        r"\users\public",
        r"\appdata\local\temp",
        r"\appdata\roaming",
        r"\downloads",
        r"\desktop",
    ]

    return any(location in normalized for location in user_writable_locations)


def analyze_service(service):
    name = service.get("Name", "Unknown")
    display_name = service.get("DisplayName", "Unknown")
    state = service.get("State", "Unknown")
    start_mode = service.get("StartMode", "Unknown")
    start_account = service.get("StartName", "Unknown")
    raw_path = service.get("PathName", "")

    executable = extract_executable_path(raw_path)

    findings = []

    if is_suspicious_path(executable):
        findings.append(
            {
                "severity": "HIGH",
                "reason": "Startup service executable is located in a suspicious directory.",
            }
        )

    if is_user_writable_location(executable):
        findings.append(
            {
                "severity": "HIGH",
                "reason": "Startup service executable appears to be located in a user-writable location.",
            }
        )

    if start_mode in ["Auto", "Boot", "System"]:
        if start_account and start_account.lower() in [
            "localsystem",
            "nt authority\\system",
            "local system",
        ]:
            if is_user_writable_location(executable):
                findings.append(
                    {
                        "severity": "CRITICAL",
                        "reason": (
                            "A privileged startup service appears to execute "
                            "from a user-writable location."
                        ),
                    }
                )

    return {
        "name": name,
        "display_name": display_name,
        "state": state,
        "start_mode": start_mode,
        "start_account": start_account,
        "path": raw_path,
        "executable": executable,
        "findings": findings,
    }


def main():
    print("=" * 70)
    print("WINDOWS STARTUP SERVICE AUDIT")
    print("=" * 70)
    print(f"Timestamp: {datetime.now().isoformat()}")
    print()

    try:
        services = get_startup_services()
    except Exception as error:
        print(f"[ERROR] Unable to enumerate startup services: {error}")
        return

    print(f"Startup services analyzed: {len(services)}")
    print()

    suspicious_count = 0

    for service in services:
        result = analyze_service(service)

        if result["findings"]:
            suspicious_count += 1

            print("-" * 70)
            print("[SUSPICIOUS STARTUP SERVICE]")
            print(f"Service      : {result['name']}")
            print(f"Display Name : {result['display_name']}")
            print(f"State        : {result['state']}")
            print(f"Start Mode   : {result['start_mode']}")
            print(f"Start Account: {result['start_account']}")
            print(f"Executable   : {result['executable']}")

            for finding in result["findings"]:
                print(f"[{finding['severity']}] {finding['reason']}")

    print()
    print("=" * 70)

    if suspicious_count == 0:
        print("No suspicious startup service configurations detected.")
    else:
        print(f"Potentially suspicious startup services: {suspicious_count}")

    print("=" * 70)


if __name__ == "__main__":
    main()