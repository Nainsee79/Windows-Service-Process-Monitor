import time
import psutil
from datetime import datetime


CHECK_INTERVAL = 3


def get_process_snapshot():
    snapshot = {}

    for process in psutil.process_iter(
        ["pid", "ppid", "name", "username"]
    ):
        try:
            pid = process.info["pid"]

            snapshot[pid] = {
                "pid": pid,
                "ppid": process.info["ppid"],
                "name": process.info["name"] or "Unknown",
                "username": (
                    process.info["username"]
                    or "Unknown"
                )
            }

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):
            continue

    return snapshot


def print_process_start(process):
    print()
    print("=" * 70)
    print("[PROCESS STARTED]")
    print("=" * 70)
    print(
        f"Timestamp : "
        f"{datetime.now().isoformat()}"
    )
    print(
        f"Process   : "
        f"{process['name']}"
    )
    print(
        f"PID       : "
        f"{process['pid']}"
    )
    print(
        f"PPID      : "
        f"{process['ppid']}"
    )
    print(
        f"Username  : "
        f"{process['username']}"
    )
    print("=" * 70)


def print_process_exit(process):
    print()
    print("=" * 70)
    print("[PROCESS EXITED]")
    print("=" * 70)
    print(
        f"Timestamp : "
        f"{datetime.now().isoformat()}"
    )
    print(
        f"Process   : "
        f"{process['name']}"
    )
    print(
        f"PID       : "
        f"{process['pid']}"
    )
    print(
        f"PPID      : "
        f"{process['ppid']}"
    )
    print("=" * 70)


def monitor_processes():
    print("=" * 70)
    print("WINDOWS REAL-TIME PROCESS MONITOR")
    print("=" * 70)
    print(
        f"Started   : "
        f"{datetime.now().isoformat()}"
    )
    print(
        f"Interval  : "
        f"{CHECK_INTERVAL} seconds"
    )
    print()
    print(
        "Monitoring process creation and "
        "termination events..."
    )
    print(
        "Press Ctrl+C to stop."
    )
    print("=" * 70)

    previous = get_process_snapshot()

    print(
        f"Initial processes: "
        f"{len(previous)}"
    )

    try:

        while True:

            time.sleep(
                CHECK_INTERVAL
            )

            current = get_process_snapshot()

            previous_pids = set(
                previous.keys()
            )

            current_pids = set(
                current.keys()
            )

            new_pids = (
                current_pids
                - previous_pids
            )

            exited_pids = (
                previous_pids
                - current_pids
            )

            for pid in sorted(new_pids):

                process = current[pid]

                print_process_start(
                    process
                )

            for pid in sorted(exited_pids):

                process = previous[pid]

                print_process_exit(
                    process
                )

            previous = current

    except KeyboardInterrupt:

        print()
        print("=" * 70)
        print("REAL-TIME MONITOR STOPPED")
        print("=" * 70)
        print(
            f"Stopped   : "
            f"{datetime.now().isoformat()}"
        )


if __name__ == "__main__":
    monitor_processes()