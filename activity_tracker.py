
import time


class ActivityTracker:
    def __init__(self, idle_threshold=1.0):
        self.idle_threshold = idle_threshold

        # Stores when each process first became idle
        self.idle_since = {}

        # Stores when each process was last active
        self.last_active = {}

    def update(self, pid, cpu):
        current_time = time.monotonic()

        # A process is considered active when CPU usage
        # reaches the configured threshold.
        if cpu >= self.idle_threshold:
            self.last_active[pid] = current_time
            self.idle_since.pop(pid, None)
            return 0.0

        # Start the idle timer on the first idle observation
        if pid not in self.idle_since:
            self.idle_since[pid] = current_time
            return 0.0

        # Calculate how long the process has remained idle
        return current_time - self.idle_since[pid]

    def remove_process(self, pid):
        self.idle_since.pop(pid, None)
        self.last_active.pop(pid, None)

