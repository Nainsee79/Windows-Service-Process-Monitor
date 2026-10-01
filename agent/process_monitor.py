import psutil
from datetime import datetime


def get_process_details(process):
    """Collect useful metadata for a running process."""

    try:
        with process.oneshot():
            return {
                "pid": process.pid,
                "ppid": process.ppid(),
                "name": process.name(),
                "exe": process.exe(),
                "username": process.username(),
                "create_time": datetime.fromtimestamp(
                    process.create_time()
                ).isoformat(),
                "status": process.status(),
            }

    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


def enumerate_processes():
    """Enumerate all currently running processes."""

    processes = []

    for process in psutil.process_iter():
        details = get_process_details(process)

        if details:
            processes.append(details)

    return processes


if __name__ == "__main__":
    process_list = enumerate_processes()

    print("=" * 70)
    print("WINDOWS PROCESS MONITOR")
    print("=" * 70)
    print(f"Total processes detected: {len(process_list)}")
    print()

    for process in process_list:
        print(
            f"PID: {process['pid']} | "
            f"PPID: {process['ppid']} | "
            f"Name: {process['name']} | "
            f"Path: {process['exe']}"
        )