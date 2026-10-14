
import time
from activity_tracker import ActivityTracker

tracker = ActivityTracker(idle_threshold=1.0)
pid = 99999

print("First idle observation:")
print(tracker.update(pid, 0.0))

time.sleep(2)

print("After 2 seconds:")
print(tracker.update(pid, 0.0))

print("After activity:")
print(tracker.update(pid, 5.0))

print("Idle timer restarted:")
print(tracker.update(pid, 0.0))

time.sleep(1)

print("After another second:")
print(tracker.update(pid, 0.0))

