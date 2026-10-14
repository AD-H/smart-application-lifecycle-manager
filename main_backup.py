import psutil
import time
import os


# Stores how long each process has remained inactive
idle_times = {}

# Demo threshold
IDLE_THRESHOLD = 30


def clear_screen():
    os.system("clear")


def get_process_data():
    data = []

    for process in psutil.process_iter(
        ["pid", "name", "status", "memory_info"]
    ):
        try:
            # Initialize CPU measurement
            process.cpu_percent(None)

            # Wait for CPU measurement
            time.sleep(0.1)

            cpu = process.cpu_percent(None)

            memory = (
                process.info["memory_info"].rss
                / (1024 * 1024)
            )

            data.append({
                "pid": process.info["pid"],
                "name": process.info["name"],
                "cpu": cpu,
                "memory": memory,
                "status": process.info["status"]
            })

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):
            pass

    return data


def update_idle_time(processes):
    current_pids = set()

    for process in processes:

        pid = process["pid"]
        cpu = process["cpu"]

        current_pids.add(pid)

        # Consider process inactive if CPU usage is very low
        if cpu < 1.0:

            if pid not in idle_times:
                idle_times[pid] = 2
            else:
                idle_times[pid] += 2
        else:
            # Process became active again
            idle_times[pid] = 0

    # Remove processes that no longer exist
    for pid in list(idle_times.keys()):
        if pid not in current_pids:
            del idle_times[pid]


while True:

    clear_screen()

    print("SMART APPLICATION LIFECYCLE MANAGER")
    print("=" * 90)

    print(
        f"{'PID':<8}"
        f"{'PROCESS':<25}"
        f"{'CPU %':<10}"
        f"{'RAM(MB)':<12}"
        f"{'STATUS':<12}"
        f"{'IDLE':<10}"
        f"{'CLASS':<15}"
    )

    print("-" * 90)

    processes = get_process_data()

    update_idle_time(processes)

    # Sort according to CPU usage
    processes.sort(
        key=lambda x: x["cpu"],
        reverse=True
    )

    for process in processes[:20]:

        pid = process["pid"]
        idle = idle_times.get(pid, 0)

        if idle >= IDLE_THRESHOLD:
            classification = "IDLE"

        elif process["cpu"] > 50:
            classification = "HIGH USAGE"

        else:
            classification = "ACTIVE"

        print(
            f"{pid:<8}"
            f"{process['name'][:23]:<25}"
            f"{process['cpu']:<10.1f}"
            f"{process['memory']:<12.1f}"
            f"{process['status']:<12}"
            f"{idle:<10}s"
            f"{classification:<15}"
        )

    print()
    print(f"Idle threshold: {IDLE_THRESHOLD} seconds")
    print("Updating every 2 seconds...")
    print("Press Ctrl+C to exit.")

    time.sleep(2)
