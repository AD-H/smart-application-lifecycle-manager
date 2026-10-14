import time

from activity_tracker import ActivityTracker


tracker = ActivityTracker()

pid = 1234

print("Process becomes idle...")

idle_time = tracker.update(pid, 0.2)
print("Idle time:", idle_time)

time.sleep(3)

idle_time = tracker.update(pid, 0.2)
print("Idle time:", idle_time)

time.sleep(2)

idle_time = tracker.update(pid, 0.2)
print("Idle time:", idle_time)

print("\nProcess becomes active...")

idle_time = tracker.update(pid, 10.0)

print("Idle time after activity:", idle_time)
