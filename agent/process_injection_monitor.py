import os
import re
import psutil
from datetime import datetime


SUSPICIOUS_TARGETS = {
    "lsass.exe",
    "winlogon.exe",
    "csrss.exe",
    "services.exe",
    "smss.exe",
    "explorer.exe",
}

SCRIPTING_PROCESSES = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
}

SUSPICIOUS_PATHS = [
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\windows\\temp\\",
    "\\users\\public\\",
]


def normalize_path(path):
    if not path:
        return ""

    return path.lower().replace("/", "\\")


def get_process_command_line(process):
    try:
        return " ".join(
            process.cmdline()
        ).strip()

    except (
        psutil.AccessDenied,
        psutil.NoSuchProcess,
        psutil.ZombieProcess
    ):
        return ""


def get_process_path(process):
    try:
        return process.exe()

    except (
        psutil.AccessDenied,
        psutil.NoSuchProcess,
        psutil.ZombieProcess
    ):
        return ""


def detect_suspicious_path(path):
    normalized = normalize_path(path)

    for suspicious_path in SUSPICIOUS_PATHS:
        if suspicious_path in normalized:
            return True

    return False


def detect_suspicious_command_line(command_line):
    if not command_line:
        return []

    command = command_line.lower()

    indicators = []

    patterns = {
        "VirtualAlloc": r"\bvirtualalloc\b",
        "VirtualProtect": r"\bvirtualprotect\b",
        "WriteProcessMemory": r"\bwriteprocessmemory\b",
        "CreateRemoteThread": r"\bcreateremotethread\b",
        "NtWriteVirtualMemory": r"\bntwritevirtualmemory\b",
        "NtCreateThreadEx": r"\bntcreatethreadex\b",
        "QueueUserAPC": r"\bqueueuserapc\b",
        "OpenProcess": r"\bopenprocess\b",
    }

    for name, pattern in patterns.items():

        if re.search(pattern, command):
            indicators.append(name)

    return indicators


def analyze_processes():
    findings = []

    for process in psutil.process_iter(
        [
            "pid",
            "ppid",
            "name",
            "username",
            "create_time"
        ]
    ):

        try:
            pid = process.info["pid"]
            ppid = process.info["ppid"]
            name = (
                process.info["name"]
                or "Unknown"
            )

            username = (
                process.info["username"]
                or "Unknown"
            )

            executable = get_process_path(
                process
            )

            command_line = (
                get_process_command_line(
                    process
                )
            )

            process_name = name.lower()

            suspicious_path = (
                detect_suspicious_path(
                    executable
                )
            )

            injection_api_indicators = (
                detect_suspicious_command_line(
                    command_line
                )
            )

            parent_name = "Unknown"

            try:
                parent = psutil.Process(
                    ppid
                )

                parent_name = (
                    parent.name()
                    or "Unknown"
                ).lower()

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied
            ):
                pass

            parent_child_indicator = False

            if (
                process_name
                in SCRIPTING_PROCESSES
                and parent_name
                in SUSPICIOUS_TARGETS
            ):
                parent_child_indicator = True

            if suspicious_path:

                findings.append({
                    "severity": "HIGH",
                    "type": (
                        "Suspicious Process "
                        "Execution Path"
                    ),
                    "pid": pid,
                    "ppid": ppid,
                    "process": name,
                    "parent": parent_name,
                    "username": username,
                    "executable": executable,
                    "reason": (
                        "Process executable is "
                        "running from a commonly "
                        "user-writable directory."
                    )
                })

            if injection_api_indicators:

                findings.append({
                    "severity": "HIGH",
                    "type": (
                        "Process Injection API "
                        "Indicator"
                    ),
                    "pid": pid,
                    "ppid": ppid,
                    "process": name,
                    "parent": parent_name,
                    "username": username,
                    "executable": executable,
                    "indicators": (
                        injection_api_indicators
                    ),
                    "reason": (
                        "Command line contains "
                        "process-memory or "
                        "remote-thread API "
                        "indicators commonly "
                        "associated with injection "
                        "techniques."
                    )
                })

            if parent_child_indicator:

                findings.append({
                    "severity": "MEDIUM",
                    "type": (
                        "Suspicious Process "
                        "Relationship"
                    ),
                    "pid": pid,
                    "ppid": ppid,
                    "process": name,
                    "parent": parent_name,
                    "username": username,
                    "executable": executable,
                    "reason": (
                        "A scripting interpreter "
                        "was observed as a child "
                        "of a sensitive Windows "
                        "process."
                    )
                })

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):
            continue

    return findings


def print_finding(finding):

    print(
        f"[{finding['severity']}] "
        f"{finding['type']}"
    )

    print(
        f"Process    : "
        f"{finding['process']}"
    )

    print(
        f"PID        : "
        f"{finding['pid']}"
    )

    print(
        f"Parent     : "
        f"{finding['parent']}"
    )

    print(
        f"PPID       : "
        f"{finding['ppid']}"
    )

    print(
        f"Username   : "
        f"{finding['username']}"
    )

    print(
        f"Executable : "
        f"{finding['executable'] or 'Unknown'}"
    )

    if "indicators" in finding:

        print(
            "Indicators  : "
            + ", ".join(
                finding["indicators"]
            )
        )

    print(
        f"Reason     : "
        f"{finding['reason']}"
    )

    print("-" * 70)


if __name__ == "__main__":

    print("=" * 70)
    print("WINDOWS PROCESS INJECTION INDICATOR MONITOR")
    print("=" * 70)
    print(
        f"Timestamp: "
        f"{datetime.now().isoformat()}"
    )
    print()

    print(
        "Note: This module detects "
        "behavioral indicators only."
    )

    print(
        "It does not claim confirmed "
        "process injection without "
        "memory-level evidence."
    )

    print()

    findings = analyze_processes()

    print(
        f"Processes analyzed: "
        f"{len(list(psutil.process_iter()))}"
    )

    print()

    print(
        "INJECTION INDICATOR ANALYSIS"
    )

    print("-" * 70)

    if not findings:

        print(
            "No process injection indicators "
            "detected."
        )

    else:

        print(
            f"Indicators detected: "
            f"{len(findings)}"
        )

        print()

        for finding in findings:
            print_finding(finding)

    print()

    print("=" * 70)

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
        f"HIGH   : {high}"
    )

    print(
        f"MEDIUM : {medium}"
    )

    print("=" * 70)