import subprocess
import re
import sys
from pathlib import Path
from datetime import datetime


BASE_DIR = Path(__file__).resolve().parent.parent
PYTHON_EXE = sys.executable

DETECTORS = [
    ("Unauthorized Process", BASE_DIR / "agent" / "unauthorized_process.py"),
    ("Process Injection Indicators", BASE_DIR / "agent" / "process_injection_monitor.py"),
    ("Unsigned / High-Risk Process", BASE_DIR / "agent" / "unsigned_process_detector.py"),
    ("Service Audit", BASE_DIR / "agent" / "service_audit.py"),
    ("Startup Service Audit", BASE_DIR / "agent" / "startup_audit.py"),
]

SEVERITY_SCORE = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "REVIEW": 3,
    "LOW": 2,
    "INFO": 0
}


def run_detector(name, script):
    print(f"\n{'=' * 70}")
    print(f"RUNNING: {name}")
    print(f"{'=' * 70}")

    try:
        result = subprocess.run(
            [PYTHON_EXE, str(script)],
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            timeout=180
        )

        output = result.stdout + result.stderr

        findings = []

        for line in output.splitlines():
            match = re.match(
                r"\[(CRITICAL|HIGH|MEDIUM|REVIEW|LOW|INFO)\]\s+(.+)",
                line.strip()
            )

            if match:
                findings.append({
                    "severity": match.group(1),
                    "message": match.group(2).strip()
                })

        if result.returncode != 0:
            print("ERROR:")
            print(output[-3000:])

        return {
            "name": name,
            "success": result.returncode == 0,
            "findings": findings,
            "output": output
        }

    except subprocess.TimeoutExpired:
        return {
            "name": name,
            "success": False,
            "findings": [],
            "output": "Detector timed out after 180 seconds."
        }

    except Exception as e:
        return {
            "name": name,
            "success": False,
            "findings": [],
            "output": str(e)
        }


def main():
    print("\nWINDOWS SERVICE & PROCESS MONITOR")
    print("CENTRAL DETECTION ENGINE")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Python   : {PYTHON_EXE}")

    results = []

    for name, script in DETECTORS:
        results.append(run_detector(name, script))

    print("\n")
    print("=" * 70)
    print("CENTRAL DETECTION SUMMARY")
    print("=" * 70)

    total_score = 0

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "REVIEW": 0,
        "LOW": 0
    }

    for result in results:

        unique_findings = set()

        for finding in result["findings"]:
            severity = finding["severity"]
            message = finding["message"]

            if severity == "INFO":
                continue

            # Ignore generic unknown-process noise.
            if (
                severity == "MEDIUM"
                and message.lower() == "unknown process"
            ):
                continue

            key = (severity, message)

            if key in unique_findings:
                continue

            unique_findings.add(key)

            severity_counts[severity] += 1
            total_score += SEVERITY_SCORE.get(severity, 0)

        print(
            f"{result['name']:<35} "
            f"{'SUCCESS' if result['success'] else 'FAILED':<10} "
            f"Raw Findings: {len(result['findings']):<5} "
            f"Unique Risk Findings: {len(unique_findings)}"
        )

    if severity_counts["CRITICAL"] > 0:
        risk_level = "CRITICAL"
    elif severity_counts["HIGH"] > 0:
        risk_level = "HIGH"
    elif severity_counts["MEDIUM"] > 0:
        risk_level = "MEDIUM"
    elif severity_counts["REVIEW"] > 0:
        risk_level = "REVIEW"
    else:
        risk_level = "LOW"

    print("\n" + "=" * 70)
    print("RISK ASSESSMENT")
    print("=" * 70)

    print(f"Risk Score : {total_score}")
    print(f"Risk Level : {risk_level}")

    print("\nSeverity Summary:")
    print(f"CRITICAL : {severity_counts['CRITICAL']}")
    print(f"HIGH     : {severity_counts['HIGH']}")
    print(f"MEDIUM   : {severity_counts['MEDIUM']}")
    print(f"REVIEW   : {severity_counts['REVIEW']}")
    print(f"LOW      : {severity_counts['LOW']}")

    print("\n" + "=" * 70)
    print("DETECTION MODULE STATUS")
    print("=" * 70)

    for result in results:
        status = "SUCCESS" if result["success"] else "FAILED"
        print(f"{result['name']:<35}: {status}")

    print("\nDetection engine execution completed.")


if __name__ == "__main__":
    main()