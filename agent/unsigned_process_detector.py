import os
import json
import psutil
import subprocess
from datetime import datetime


SUSPICIOUS_DIRECTORIES = [
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\windows\\temp\\",
    "\\users\\public\\",
]


HIGH_RISK_PROCESS_NAMES = {
    "mimikatz.exe",
    "psexec.exe",
    "procdump.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe",
    "certutil.exe",
    "bitsadmin.exe",
}


def normalize_path(path):
    if not path:
        return ""

    return path.lower().replace("/", "\\")


def get_process_path(process):
    try:
        return process.exe()

    except (
        psutil.AccessDenied,
        psutil.NoSuchProcess,
        psutil.ZombieProcess
    ):
        return ""


def get_signature_statuses(paths):
    """
    Check Authenticode signatures for all executable paths
    in one PowerShell invocation.
    """

    unique_paths = []

    for path in paths:
        if not path:
            continue

        if not os.path.exists(path):
            continue

        if path not in unique_paths:
            unique_paths.append(path)

    if not unique_paths:
        return {}

    # Pass paths to PowerShell through a temporary JSON file.
    temp_file = os.path.join(
        os.environ.get("TEMP", "."),
        "process_signature_paths.json"
    )

    try:
        with open(
            temp_file,
            "w",
            encoding="utf-8"
        ) as file:
            json.dump(
                unique_paths,
                file
            )

        powershell_script = f"""
$paths = Get-Content -LiteralPath '{temp_file}' -Raw | ConvertFrom-Json

foreach ($path in $paths) {{
    try {{
        $signature = Get-AuthenticodeSignature -LiteralPath $path

        [PSCustomObject]@{{
            Path = $path
            Status = [string]$signature.Status
        }}
    }}
    catch {{
        [PSCustomObject]@{{
            Path = $path
            Status = "Unknown"
        }}
    }}
}}

"""

        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                powershell_script
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120
        )

        if result.returncode != 0:
            return {}

        output = result.stdout.strip()

        if not output:
            return {}

        data = json.loads(output)

        if isinstance(data, dict):
            data = [data]

        signature_map = {}

        for item in data:
            path = item.get("Path")
            status = (
                item.get("Status")
                or "Unknown"
            )

            if status.lower() == "valid":
                normalized_status = "Signed"

            elif status.lower() in {
                "notsigned",
                "hashmismatch",
                "nottrusted",
                "unknownerror"
            }:
                normalized_status = "Unsigned"

            else:
                normalized_status = "Unknown"

            signature_map[path] = normalized_status

        return signature_map

    except (
        subprocess.TimeoutExpired,
        json.JSONDecodeError,
        OSError,
        Exception
    ):
        return {}

    finally:
        try:
            if os.path.exists(temp_file):
                os.remove(temp_file)
        except OSError:
            pass


def is_suspicious_directory(path):
    normalized = normalize_path(path)

    return any(
        directory in normalized
        for directory in SUSPICIOUS_DIRECTORIES
    )


def analyze_processes():
    processes = []
    executable_paths = []

    for process in psutil.process_iter(
        [
            "pid",
            "ppid",
            "name",
            "username"
        ]
    ):

        try:
            executable = get_process_path(
                process
            )

            if not executable:
                continue

            process_data = {
                "pid": process.info["pid"],
                "ppid": process.info["ppid"],
                "name": (
                    process.info["name"]
                    or "Unknown"
                ),
                "username": (
                    process.info["username"]
                    or "Unknown"
                ),
                "executable": executable
            }

            processes.append(
                process_data
            )

            executable_paths.append(
                executable
            )

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):
            continue

    signature_map = get_signature_statuses(
        executable_paths
    )

    findings = []

    for process in processes:

        name = process["name"]
        executable = process["executable"]

        signature = signature_map.get(
            executable,
            "Unknown"
        )

        suspicious_path = (
            is_suspicious_directory(
                executable
            )
        )

        high_risk_name = (
            name.lower()
            in HIGH_RISK_PROCESS_NAMES
        )

        reasons = []

        if signature == "Unsigned":
            reasons.append(
                "Executable has no valid "
                "Authenticode signature."
            )

        if suspicious_path:
            reasons.append(
                "Executable is running from "
                "a commonly user-writable "
                "directory."
            )

        if high_risk_name:
            reasons.append(
                "Process name matches a "
                "configured high-risk tool."
            )

        if not reasons:
            continue

        if high_risk_name:
            severity = "CRITICAL"

        elif (
            signature == "Unsigned"
            and suspicious_path
        ):
            severity = "HIGH"

        elif signature == "Unsigned":
            severity = "MEDIUM"

        else:
            severity = "MEDIUM"

        findings.append({
            "severity": severity,
            "type": "Unsigned / High-Risk Process",
            "process": name,
            "pid": process["pid"],
            "ppid": process["ppid"],
            "username": process["username"],
            "executable": executable,
            "signature": signature,
            "suspicious_path": suspicious_path,
            "reasons": reasons
        })

    return len(processes), findings


def print_finding(finding):

    print(
        f"[{finding['severity']}] "
        f"{finding['type']}"
    )

    print(
        f"Process          : "
        f"{finding['process']}"
    )

    print(
        f"PID              : "
        f"{finding['pid']}"
    )

    print(
        f"PPID             : "
        f"{finding['ppid']}"
    )

    print(
        f"Username         : "
        f"{finding['username']}"
    )

    print(
        f"Executable       : "
        f"{finding['executable']}"
    )

    print(
        f"Signature        : "
        f"{finding['signature']}"
    )

    print(
        f"Suspicious Path  : "
        f"{finding['suspicious_path']}"
    )

    print("Reason           :")

    for reason in finding["reasons"]:
        print(
            f"  - {reason}"
        )

    print("-" * 70)


if __name__ == "__main__":

    print("=" * 70)
    print("WINDOWS UNSIGNED / HIGH-RISK PROCESS DETECTOR")
    print("=" * 70)

    print(
        f"Timestamp: "
        f"{datetime.now().isoformat()}"
    )

    print()

    print(
        "Authenticode signature verification "
        "is performed using PowerShell."
    )

    print(
        "Signature checks are batched to "
        "reduce execution overhead."
    )

    print()

    process_count, findings = (
        analyze_processes()
    )

    print(
        f"Processes analyzed: "
        f"{process_count}"
    )

    print()

    print(
        "UNSIGNED / HIGH-RISK PROCESS ANALYSIS"
    )

    print("-" * 70)

    if not findings:

        print(
            "No unsigned or high-risk "
            "process indicators detected."
        )

    else:

        print(
            f"Findings detected: "
            f"{len(findings)}"
        )

        print()

        for finding in findings:
            print_finding(finding)

    print()

    print("=" * 70)

    critical = sum(
        1
        for finding in findings
        if finding["severity"] == "CRITICAL"
    )

    high = sum(
        1
        for finding in findings
        if finding["severity"] == "HIGH"
    )

    medium = sum(
        1
        for finding in findings
        if finding["severity"] == "MEDIUM"
    )

    print(
        f"CRITICAL : {critical}"
    )

    print(
        f"HIGH     : {high}"
    )

    print(
        f"MEDIUM   : {medium}"
    )

    print("=" * 70)