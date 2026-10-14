import psutil
import time

from resource_analyzer import calculate_resource_score
from classifier import classify_process
from decision_engine import make_decision
from activity_tracker import ActivityTracker
from process_protection import is_protected

# Time between monitoring cycles
INTERVAL = 2

def monitor_processes():
    tracker = ActivityTracker();

    print("\nSMART APPLICATION LIFECYCLE MANAGER")
    print("=" * 100)

    while True:

        print("\nPID    PROCESS              CPU %    RAM(MB)   IDLE(s)   SCORE   CLASSIFICATION              ACTION")
        print("-" * 115)

        active_pids = set()

        for process in psutil.process_iter(
            ['pid', 'name', 'cpu_percent', 'memory_info', 'status']
        ):

            try:

                pid = process.info['pid']
                name = process.info['name']
                cpu = process.info['cpu_percent']

                if process.info['memory_info']:
                    memory = process.info['memory_info'].rss / (1024 * 1024)
                else:
                    memory = 0

                status = process.info['status']

                active_pids.add(pid)

                # Update idle time
                idle_time = tracker.update(pid, cpu)

                # Calculate resource score
                score = calculate_resource_score(
                    cpu,
                    memory,
                    idle_time
                )

                # Classify process
                classification = classify_process(
                    cpu,
                    memory,
                    idle_time,
                    score
                )

                # Make decision
                action, reason = make_decision(
                    cpu,
                    memory,
                    idle_time,
                    score,
                    classification
                )
                if is_protected(pid, name):
                    action = "PROTECTED"
                    reason = "Critical process - lifecycle action blocked"
                    
                print(
                    f"{pid:<6}"
                    f"{name[:20]:<21}"
                    f"{cpu:<9.1f}"
                    f"{memory:<10.1f}"
                    f"{idle_time:<10}"
                    f"{score:<8}"
                    f"{classification:<28}"
                    f"{action}"
                )

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess
            ):
                continue

        # Remove processes that no longer exist
        dead_pids = set(tracker.idle_since.keys()) - active_pids

        for pid in dead_pids:
            tracker.remove_process(pid)

        print("\nUpdating every 2 seconds...")
        print("Press Ctrl+C to exit.")

        time.sleep(INTERVAL)


try:
    monitor_processes()

except KeyboardInterrupt:
    print("\n\nSmart Application Lifecycle Manager stopped.")