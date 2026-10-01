import psutil
from collections import defaultdict


def get_process_tree():
    """
    Build a parent-child process tree from currently
    running Windows processes.
    """

    processes = {}
    children = defaultdict(list)

    for process in psutil.process_iter(
        ["pid", "ppid", "name", "exe", "username"]
    ):
        try:
            info = process.info

            pid = info["pid"]
            ppid = info["ppid"]

            processes[pid] = {
                "pid": pid,
                "ppid": ppid,
                "name": info["name"] or "Unknown",
                "exe": info["exe"] or "Unknown",
                "username": info["username"] or "Unknown",
            }

            children[ppid].append(pid)

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
        ):
            continue

    return processes, children


def print_tree(processes, children, parent_pid=0, level=0, visited=None):
    """
    Recursively print the process hierarchy.
    """

    if visited is None:
        visited = set()

    if parent_pid in visited:
        return

    visited.add(parent_pid)

    for pid in sorted(children.get(parent_pid, [])):
        process = processes.get(pid)

        if not process:
            continue

        indentation = "    " * level

        print(
            f"{indentation}|-- "
            f"{process['name']} "
            f"(PID: {process['pid']}, "
            f"PPID: {process['ppid']})"
        )

        print_tree(
            processes,
            children,
            parent_pid=pid,
            level=level + 1,
            visited=visited,
        )


def find_suspicious_parent_child_relationships(processes):
    """
    Detect potentially suspicious parent-child relationships.
    """

    suspicious_pairs = {
        "winword.exe": {
            "powershell.exe",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
        },
        "excel.exe": {
            "powershell.exe",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
        },
        "outlook.exe": {
            "powershell.exe",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
        },
        "powerpnt.exe": {
            "powershell.exe",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
        },
    }

    alerts = []

    for child in processes.values():
        parent_pid = child["ppid"]
        parent = processes.get(parent_pid)

        if not parent:
            continue

        parent_name = parent["name"].lower()
        child_name = child["name"].lower()

        if child_name in suspicious_pairs.get(parent_name, set()):
            alerts.append(
                {
                    "severity": "HIGH",
                    "type": "Suspicious Parent-Child Relationship",
                    "parent_name": parent["name"],
                    "parent_pid": parent["pid"],
                    "child_name": child["name"],
                    "child_pid": child["pid"],
                    "reason": (
                        f"{parent['name']} spawned {child['name']}, "
                        "which is an unusual process relationship "
                        "and may indicate malicious script execution."
                    ),
                }
            )

    return alerts


if __name__ == "__main__":

    print("=" * 70)
    print("WINDOWS PROCESS TREE MONITOR")
    print("=" * 70)
    print()

    processes, children = get_process_tree()

    print(f"Processes analyzed: {len(processes)}")
    print()

    print("PROCESS HIERARCHY")
    print("-" * 70)

    print_tree(processes, children)

    print()
    print("SUSPICIOUS RELATIONSHIP ANALYSIS")
    print("-" * 70)

    alerts = find_suspicious_parent_child_relationships(processes)

    if alerts:
        for alert in alerts:
            print(f"[{alert['severity']}] {alert['type']}")
            print(
                f"Parent: {alert['parent_name']} "
                f"(PID: {alert['parent_pid']})"
            )
            print(
                f"Child : {alert['child_name']} "
                f"(PID: {alert['child_pid']})"
            )
            print(f"Reason: {alert['reason']}")
            print("-" * 70)
    else:
        print("No suspicious parent-child relationships detected.")