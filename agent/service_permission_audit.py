import os
import re
import subprocess
from datetime import datetime


PRIVILEGED_PRINCIPALS = {
    "SY",
    "BA",
    "SU",
    "LS",
    "NS",
}


DANGEROUS_SERVICE_PERMISSIONS = {
    "DC": "SERVICE_CHANGE_CONFIG",
    "WD": "WRITE_DAC",
    "WO": "WRITE_OWNER",
}


REVIEW_PRINCIPALS = {
    "BU",
    "AU",
    "WD",
    "AN",
}


LOW_PRIVILEGE_IDENTITIES = {
    "BU",
    "AU",
    "WD",
    "AN",
    "US",
    "WD",
}

USER_WRITABLE_DIRECTORIES = [
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\windows\\temp\\",
    "\\users\\public\\",
]


def run_command(command):
    """Run a command safely and return stdout."""

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace"
        )

        if result.returncode != 0:
            return ""

        return result.stdout.strip()

    except Exception:
        return ""


def get_service_security_info(service_name):
    """Retrieve the service security descriptor."""

    return run_command(
        ["sc", "sdshow", service_name]
    )


def parse_access_control_entries(security_descriptor):
    """Parse basic ACE information from an SDDL security descriptor."""

    if not security_descriptor:
        return []

    ace_pattern = r"\(([^()]*)\)"
    matches = re.findall(
        ace_pattern,
        security_descriptor
    )

    entries = []

    for ace in matches:

        parts = ace.split(";")

        if len(parts) < 6:
            continue

        entries.append({
            "type": parts[0].strip(),
            "flags": parts[1].strip(),
            "permissions": parts[2].strip(),
            "principal": parts[5].strip()
        })

    return entries


def classify_principal(principal):
    """Classify the Windows security principal."""

    principal = principal.upper().strip()

    if principal in PRIVILEGED_PRINCIPALS:
        return "PRIVILEGED"

    if principal in REVIEW_PRINCIPALS:
        return "REVIEW"

    if principal.startswith("S-1-5-80-"):
        return "SERVICE_SID"

    if principal.startswith("S-1-5-"):
        return "WINDOWS_SID"

    return "OTHER"


def find_dangerous_service_permissions(entries):
    """Find dangerous service-control permissions."""

    findings = []

    for entry in entries:

        ace_type = entry["type"].upper().strip()

        if ace_type != "A":
            continue

        principal = entry["principal"].upper().strip()
        permissions = entry["permissions"].upper().strip()

        principal_class = classify_principal(
            principal
        )

        if principal_class == "PRIVILEGED":
            continue

        matched_permissions = []

        for code, permission_name in (
            DANGEROUS_SERVICE_PERMISSIONS.items()
        ):

            if code in permissions:
                matched_permissions.append({
                    "code": code,
                    "name": permission_name
                })

        if not matched_permissions:
            continue

        if principal_class == "SERVICE_SID":

            severity = "INFO"
            classification = (
                "Service SID permission"
            )

        elif principal_class == "WINDOWS_SID":

            severity = "REVIEW"
            classification = (
                "Windows SID requires review"
            )

        elif principal_class == "REVIEW":

            severity = "HIGH"
            classification = (
                "Broad or potentially low-privilege principal"
            )

        else:

            severity = "HIGH"
            classification = (
                "Non-privileged principal"
            )

        findings.append({
            "principal": principal,
            "principal_class": principal_class,
            "severity": severity,
            "classification": classification,
            "permissions": matched_permissions
        })

    return findings


def get_service_info(service_name):
    """Retrieve service configuration."""

    command = [
        "powershell",
        "-NoProfile",
        "-Command",
        (
            f"Get-CimInstance Win32_Service "
            f"-Filter \"Name='{service_name}'\" | "
            f"Select-Object Name,DisplayName,State,"
            f"StartMode,StartName,PathName | "
            f"ConvertTo-Json -Depth 3"
        )
    ]

    output = run_command(command)

    if not output:
        return None

    try:
        import json

        data = json.loads(output)

        if isinstance(data, list):
            return data[0] if data else None

        return data

    except Exception:
        return None


def extract_executable_path(path_name):
    """Extract executable path from a Windows service ImagePath."""

    if not path_name:
        return ""

    path_name = str(path_name).strip()

    if path_name.startswith('"'):

        match = re.match(
            r'"([^"]+)"',
            path_name
        )

        if match:
            return match.group(1)

    match = re.match(
        r"(.+?\.exe)(?:\s|$)",
        path_name,
        re.IGNORECASE
    )

    if match:
        return match.group(1)

    return path_name.split()[0]


def is_user_writable_location(path):
    """Check whether the executable is in a commonly writable location."""

    if not path:
        return False

    normalized = (
        path.lower()
        .replace("/", "\\")
    )

    return any(
        directory in normalized
        for directory in USER_WRITABLE_DIRECTORIES
    )


def get_file_acl(path):
    """Retrieve Windows file ACL information using icacls."""

    if not path:
        return ""

    if not os.path.exists(path):
        return ""

    return run_command(
        ["icacls", path]
    )


def parse_icacls_write_access(acl_output):
    """
    Identify potentially dangerous write permissions
    granted to broad or low-privileged principals.
    """

    if not acl_output:
        return []

    findings = []

    for line in acl_output.splitlines():

        line = line.strip()

        if not line:
            continue

        if line.startswith(
            "Successfully processed"
        ):
            continue

        match = re.match(
            r"(.+?):(.*)",
            line
        )

        if not match:
            continue

        principal = match.group(1).strip()
        permissions = match.group(2).strip()

        principal_upper = principal.upper()

        if principal_upper in {
            "BUILTIN\\USERS",
            "USERS",
            "EVERYONE",
            "NT AUTHORITY\\AUTHENTICATED USERS",
            "AUTHENTICATED USERS",
            "NT AUTHORITY\\INTERACTIVE",
            "INTERACTIVE",
        }:

            write_indicators = [
                "(F)",
                "(M)",
                "(W)",
                "(WD)",
                "(AD)",
                "(WA)",
                "(WEA)",
                "(DC)",
            ]

            if any(
                indicator in permissions.upper()
                for indicator in write_indicators
            ):

                findings.append({
                    "principal": principal,
                    "permissions": permissions
                })

    return findings


def audit_executable_acl(executable):
    """Audit the executable ACL for low-privilege write access."""

    if not executable:
        return {
            "exists": False,
            "writable_by_low_privilege": False,
            "findings": []
        }

    if not os.path.exists(executable):
        return {
            "exists": False,
            "writable_by_low_privilege": False,
            "findings": []
        }

    acl_output = get_file_acl(
        executable
    )

    findings = parse_icacls_write_access(
        acl_output
    )

    return {
        "exists": True,
        "writable_by_low_privilege": bool(findings),
        "findings": findings,
        "acl": acl_output
    }


def determine_final_severity(
    service_permission_finding,
    executable,
    executable_acl
):
    """
    Correlate service ACL and executable ACL
    to determine final risk.
    """

    service_severity = (
        service_permission_finding["severity"]
    )

    principal_class = (
        service_permission_finding["principal_class"]
    )

    service_permission_codes = {
        permission["code"]
        for permission
        in service_permission_finding["permissions"]
    }

    dangerous_service_control = bool(
        service_permission_codes
        & {"DC", "WD", "WO"}
    )

    low_privilege_file_write = (
        executable_acl.get(
            "writable_by_low_privilege",
            False
        )
    )

    suspicious_location = is_user_writable_location(
        executable
    )

    if (
        dangerous_service_control
        and low_privilege_file_write
    ):

        return (
            "CRITICAL",
            "Service-control permission and "
            "low-privilege executable write access "
            "were both identified."
        )

    if (
        dangerous_service_control
        and suspicious_location
    ):

        return (
            "CRITICAL",
            "Service-control permission is combined "
            "with execution from a commonly "
            "user-writable location."
        )

    if service_severity == "HIGH":

        return (
            "HIGH",
            "Potentially dangerous service-control "
            "permission requires security review."
        )

    if service_severity == "REVIEW":

        return (
            "REVIEW",
            "Windows SID has a potentially sensitive "
            "service-control permission."
        )

    return (
        "INFO",
        "Permission is associated with a service SID "
        "or otherwise requires contextual review."
    )


def audit_service_permissions(service_names):
    """Perform complete service permission correlation."""

    alerts = []

    for service_name in service_names:

        security_descriptor = (
            get_service_security_info(
                service_name
            )
        )

        if not security_descriptor:
            continue

        entries = parse_access_control_entries(
            security_descriptor
        )

        permission_findings = (
            find_dangerous_service_permissions(
                entries
            )
        )

        if not permission_findings:
            continue

        service_info = get_service_info(
            service_name
        )

        executable = ""

        if service_info:

            executable = extract_executable_path(
                service_info.get("PathName")
                or ""
            )

        executable_acl = audit_executable_acl(
            executable
        )

        for finding in permission_findings:

            permission_names = ", ".join(
                permission["name"]
                for permission
                in finding["permissions"]
            )

            permission_codes = ", ".join(
                permission["code"]
                for permission
                in finding["permissions"]
            )

            final_severity, final_reason = (
                determine_final_severity(
                    finding,
                    executable,
                    executable_acl
                )
            )

            alerts.append({
                "timestamp": datetime.now().isoformat(),
                "service": service_name,
                "principal": finding["principal"],
                "principal_class": finding[
                    "principal_class"
                ],
                "service_permissions": permission_names,
                "permission_codes": permission_codes,
                "executable": executable,
                "executable_exists": executable_acl[
                    "exists"
                ],
                "low_privilege_file_write": (
                    executable_acl[
                        "writable_by_low_privilege"
                    ]
                ),
                "file_acl_findings": (
                    executable_acl.get(
                        "findings",
                        []
                    )
                ),
                "severity": final_severity,
                "classification": finding[
                    "classification"
                ],
                "reason": final_reason,
                "security_descriptor": (
                    security_descriptor
                )
            })

    return alerts


def get_all_service_names():
    """Enumerate all Windows service names."""

    output = run_command(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            "(Get-CimInstance Win32_Service).Name"
        ]
    )

    if not output:
        return []

    return [
        line.strip()
        for line in output.splitlines()
        if line.strip()
    ]


def print_alert(alert):
    """Print one permission finding."""

    print(
        f"[{alert['severity']}] "
        f"Service Permission Finding"
    )

    print(
        f"Service              : "
        f"{alert['service']}"
    )

    print(
        f"Principal            : "
        f"{alert['principal']}"
    )

    print(
        f"Principal Type       : "
        f"{alert['principal_class']}"
    )

    print(
        f"Service Permissions  : "
        f"{alert['service_permissions']}"
    )

    print(
        f"Permission Codes     : "
        f"{alert['permission_codes']}"
    )

    print(
        f"Executable           : "
        f"{alert['executable'] or 'Unknown'}"
    )

    print(
        f"Executable Exists    : "
        f"{alert['executable_exists']}"
    )

    print(
        f"Low-Privilege Write  : "
        f"{alert['low_privilege_file_write']}"
    )

    print(
        f"Classification       : "
        f"{alert['classification']}"
    )

    print(
        f"Reason               : "
        f"{alert['reason']}"
    )

    if alert["file_acl_findings"]:

        print(
            "File ACL Findings    :"
        )

        for finding in (
            alert["file_acl_findings"]
        ):

            print(
                f"  {finding['principal']} "
                f"-> {finding['permissions']}"
            )

    print("-" * 70)


if __name__ == "__main__":

    print("=" * 70)
    print("WINDOWS SERVICE PERMISSION AUDIT")
    print("=" * 70)
    print()

    services = get_all_service_names()

    print(
        f"Services analyzed: "
        f"{len(services)}"
    )

    print()

    alerts = audit_service_permissions(
        services
    )

    print(
        "PERMISSION ANALYSIS"
    )

    print("-" * 70)

    if not alerts:

        print(
            "No potentially risky service "
            "permissions identified."
        )

    else:

        print(
            f"Permission findings: "
            f"{len(alerts)}"
        )

        print()

        for alert in alerts:
            print_alert(alert)

    print()

    print("=" * 70)

    critical = sum(
        1
        for alert in alerts
        if alert["severity"] == "CRITICAL"
    )

    high = sum(
        1
        for alert in alerts
        if alert["severity"] == "HIGH"
    )

    review = sum(
        1
        for alert in alerts
        if alert["severity"] == "REVIEW"
    )

    info = sum(
        1
        for alert in alerts
        if alert["severity"] == "INFO"
    )

    print(
        f"CRITICAL : {critical}"
    )

    print(
        f"HIGH     : {high}"
    )

    print(
        f"REVIEW   : {review}"
    )

    print(
        f"INFO     : {info}"
    )

    print("=" * 70)