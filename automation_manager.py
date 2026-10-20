
import os
import time
import threading
from datetime import datetime
from collections import deque

import psutil

from decision_engine import make_decision


# ============================================================
# CONFIGURATION
# ============================================================

SCAN_INTERVAL = 3                 # Seconds between scans
REQUIRED_IDLE_SCANS = 3            # Must qualify for 3 scans
MAX_SUSPEND_SECONDS = 30           # Automatically resume after 30 sec
FAILED_ACTION_COOLDOWN = 300       # Don't retry failed actions for 5 min
MAX_SIMULTANEOUS_SUSPENSIONS = 1

# Empty by default: no process can be automatically suspended.
# Only add a disposable test-process name after testing manually.
AUTO_SUSPEND_ALLOWLIST = set()

# Processes that automation must never suspend.
PROTECTED_PROCESSES = {
    "system",
    "system idle process",
    "registry",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "memcompression.exe",
    "explorer.exe",
    "dwm.exe",
    "python.exe",
    "pythonw.exe",
    "python3.exe",
    "uvicorn.exe",
}


class AutomationManager:
    """
    Safely manages optional automatic process suspension and resumption.

    Features:
    - Automation is OFF by default.
    - Automatic suspension requires an explicit allowlist.
    - A process must qualify across multiple scans.
    - PID creation time is checked to guard against PID reuse.
    - Suspended processes are automatically resumed after a time limit.
    - Failed actions have a cooldown.
    - Recent actions are available through get_history().
    """

    def __init__(self,interval = 3):
        self.enabled = False
        self._stop_event = threading.Event()
        self._thread = None
        self._lock = threading.RLock()

        self._history = deque(maxlen=200)
        self._suspended = {}
        self._candidate_scans = {}
        self._failed_until = {}

        self._last_scan = None
        self._last_error = None
        self._scans_completed = 0

    # --------------------------------------------------------
    # GENERAL HELPERS
    # --------------------------------------------------------

    @staticmethod
    def _timestamp():
        return datetime.now().isoformat(timespec="seconds")

    def _log(self, action, pid=None, name=None, message=""):
        entry = {
            "timestamp": self._timestamp(),
            "action": action,
            "pid": pid,
            "process": name,
            "message": message,
        }

        with self._lock:
            self._history.appendleft(entry)

        print(
            f"[AUTOMATION] {action} | "
            f"PID={pid} | Process={name} | {message}"
        )

    @staticmethod
    def _process_identity(proc):
        """
        Returns a process identity including creation time.
        Creation time helps avoid acting on a reused PID.
        """
        try:
            return {
                "pid": proc.pid,
                "name": proc.name(),
                "create_time": proc.create_time(),
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    @staticmethod
    def _is_protected(name):
        name = (name or "").lower().strip()

        if name in PROTECTED_PROCESSES:
            return True

        # Protect the process running this application.
        current_pid = os.getpid()
        return False

    def _is_our_process(self, pid):
        return pid == os.getpid()

    def _is_allowed(self, name):
        return name.lower().strip() in {
            item.lower().strip()
            for item in AUTO_SUSPEND_ALLOWLIST
        }

    # --------------------------------------------------------
    # PROCESS CLASSIFICATION AND DECISION
    # --------------------------------------------------------

    @staticmethod
    def _calculate_score(cpu, memory, idle_time):
        """
        Produces a simple 0-100 candidate score.
        This score is a heuristic, not an operating-system metric.
        """
        score = 0

        if idle_time >= 60:
            score += 30
        if idle_time >= 180:
            score += 20
        if cpu >= 5:
            score += 20
        if cpu >= 15:
            score += 10
        if memory >= 200:
            score += 10
        if memory >= 500:
            score += 10

        return min(score, 100)

    @staticmethod
    def _classify(cpu, memory, idle_time):
        """
        Basic classification used by the automation manager.
        """
        if cpu >= 50:
            return "HIGH USAGE"

        if idle_time >= 60 and (cpu >= 5 or memory >= 200):
            return "IDLE RESOURCE CONSUMER"

        if idle_time >= 30:
            return "LOW ACTIVITY"

        return "ACTIVE"

    def _evaluate_process(self, proc, idle_time):
        """
        Collects metrics and calls the project's decision engine.
        """
        try:
            cpu = proc.cpu_percent(interval=None)
            memory = proc.memory_info().rss / (1024 * 1024)

            classification = self._classify(
                cpu=cpu,
                memory=memory,
                idle_time=idle_time,
            )

            score = self._calculate_score(
                cpu=cpu,
                memory=memory,
                idle_time=idle_time,
            )

            decision, reason = make_decision(
                cpu,
                memory,
                idle_time,
                score,
                classification,
            )

            return {
                "pid": proc.pid,
                "name": proc.name(),
                "cpu": round(cpu, 2),
                "memory_mb": round(memory, 2),
                "idle_time": round(idle_time, 1),
                "score": score,
                "classification": classification,
                "decision": decision,
                "reason": reason,
            }

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
        ):
            return None

    # --------------------------------------------------------
    # RESUME HANDLING
    # --------------------------------------------------------

    def _resume_one(self, pid, expected_create_time=None, reason=""):
        """
        Resumes a process only if its identity still matches.
        """
        with self._lock:
            record = self._suspended.get(pid)

        if not record:
            return False

        try:
            proc = psutil.Process(pid)

            if expected_create_time is None:
                expected_create_time = record["create_time"]

            if abs(proc.create_time() - expected_create_time) > 0.01:
                self._log(
                    "RESUME_SKIPPED",
                    pid,
                    record.get("name"),
                    "Process identity changed; refusing to act on reused PID.",
                )
                with self._lock:
                    self._suspended.pop(pid, None)
                return False

            proc.resume()

            with self._lock:
                self._suspended.pop(pid, None)

            self._log(
                "AUTO_RESUMED",
                pid,
                record.get("name"),
                reason or "Process resumed.",
            )
            return True

        except psutil.NoSuchProcess:
            with self._lock:
                self._suspended.pop(pid, None)

            self._log(
                "RESUME_SKIPPED",
                pid,
                record.get("name"),
                "Process no longer exists.",
            )
            return False

        except (psutil.AccessDenied, psutil.Error) as exc:
            self._log(
                "RESUME_FAILED",
                pid,
                record.get("name"),
                str(exc),
            )
            return False

    def _resume_expired_processes(self):
        now = time.time()

        with self._lock:
            expired = [
                (pid, record["create_time"])
                for pid, record in self._suspended.items()
                if now - record["suspended_at"] >= MAX_SUSPEND_SECONDS
            ]

        for pid, create_time in expired:
            self._resume_one(
                pid,
                create_time,
                "Maximum suspension time reached.",
            )

    def _resume_all(self, reason="Automation stopped."):
        with self._lock:
            items = [
                (pid, record["create_time"])
                for pid, record in self._suspended.items()
            ]

        for pid, create_time in items:
            self._resume_one(pid, create_time, reason)

    # --------------------------------------------------------
    # AUTOMATIC SUSPENSION
    # --------------------------------------------------------

    def _try_suspend(self, proc, metrics):
        pid = proc.pid
        name = metrics["name"]
        now = time.time()

        if self._is_protected(name) or self._is_our_process(pid):
            return

        # Automatic suspension is opt-in.
        if not self._is_allowed(name):
            return

        with self._lock:
            if pid in self._suspended:
                return

            if len(self._suspended) >= MAX_SIMULTANEOUS_SUSPENSIONS:
                return

            if self._failed_until.get(pid, 0) > now:
                return

        # Only act on the decision engine's explicit SUSPEND decision.
        if metrics["decision"] != "SUSPEND":
            with self._lock:
                self._candidate_scans.pop(pid, None)
            return

        with self._lock:
            self._candidate_scans[pid] = (
                self._candidate_scans.get(pid, 0) + 1
            )
            qualifying_scans = self._candidate_scans[pid]

        if qualifying_scans < REQUIRED_IDLE_SCANS:
            return

        try:
            identity = self._process_identity(proc)

            if identity is None:
                return

            # Verify process identity again immediately before suspension.
            check_proc = psutil.Process(pid)

            if abs(
                check_proc.create_time() - identity["create_time"]
            ) > 0.01:
                return

            check_proc.suspend()

            with self._lock:
                self._suspended[pid] = {
                    "name": name,
                    "create_time": identity["create_time"],
                    "suspended_at": time.time(),
                }
                self._candidate_scans.pop(pid, None)

            self._log(
                "AUTO_SUSPENDED",
                pid,
                name,
                (
                    f"Score={metrics['score']}; "
                    f"CPU={metrics['cpu']}%; "
                    f"RAM={metrics['memory_mb']} MB; "
                    f"Idle={metrics['idle_time']} sec."
                ),
            )

        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.Error) as exc:
            with self._lock:
                self._failed_until[pid] = now + FAILED_ACTION_COOLDOWN
                self._candidate_scans.pop(pid, None)

            self._log("SUSPEND_FAILED", pid, name, str(exc))

    # --------------------------------------------------------
    # SCAN LOOP
    # --------------------------------------------------------

    def _scan_once(self):
        now = time.time()
        self._last_scan = self._timestamp()
        self._scans_completed += 1

        self._resume_expired_processes()

        # Remove expired retry cooldown entries.
        with self._lock:
            self._failed_until = {
                pid: until
                for pid, until in self._failed_until.items()
                if until > now
            }

        try:
            processes = list(
                psutil.process_iter(
                    attrs=["pid", "name", "create_time"]
                )
            )

            for proc in processes:
                if self._stop_event.is_set():
                    break

                try:
                    pid = proc.pid
                    name = proc.info.get("name") or ""

                    if self._is_protected(name) or self._is_our_process(pid):
                        continue

                    # Suspended processes should not be evaluated for
                    # another suspension.
                    with self._lock:
                        if pid in self._suspended:
                            continue

                    # Use CPU activity as a practical inactivity estimate.
                    # The first CPU sample is a baseline and may be zero.
                    cpu = proc.cpu_percent(interval=None)
                    memory = proc.memory_info().rss / (1024 * 1024)

                    # Keep an activity timestamp for each PID.
                    last_active = getattr(self, "_last_active", None)
                    if last_active is None:
                        self._last_active = {}
                        last_active = self._last_active

                    if cpu > 1:
                        last_active[pid] = now
                    else:
                        last_active.setdefault(pid, now)

                    idle_time = max(0, now - last_active[pid])

                    metrics = self._evaluate_process(proc, idle_time)

                    if metrics is None:
                        continue

                    self._try_suspend(proc, metrics)

                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied,
                    psutil.ZombieProcess,
                ):
                    continue

        except Exception as exc:
            self._last_error = str(exc)
            self._log("SCAN_ERROR", message=str(exc))

    def _worker(self):
        self._log("AUTOMATION_STARTED", message="Background monitoring enabled.")

        while not self._stop_event.is_set():
            try:
                self._scan_once()
            except Exception as exc:
                self._last_error = str(exc)
                self._log("WORKER_ERROR", message=str(exc))

            self._stop_event.wait(self.interval)

        # Restore processes suspended by this manager on shutdown.
        self._resume_all("Automation stopped; restoring managed processes.")
        self._log("AUTOMATION_STOPPED", message="Background monitoring disabled.")

    # --------------------------------------------------------
    # PUBLIC API
    # --------------------------------------------------------

    def start(self):
        with self._lock:
            if self.enabled and self._thread and self._thread.is_alive():
                return self.get_status()

            self._stop_event.clear()
            self.enabled = True
            self._thread = threading.Thread(
                target=self._worker,
                name="SALM-Automation",
                daemon=True,
            )
            self._thread.start()

        return self.get_status()

    def stop(self):
        with self._lock:
            self.enabled = False
            self._stop_event.set()
            thread = self._thread

        if thread and thread.is_alive():
            thread.join(timeout=5)

        # Try to restore managed processes even if the worker took too long.
        self._resume_all("Automation stop requested.")
        return self.get_status()

    def get_status(self):
        with self._lock:
            return {
                "enabled": self.enabled,
                "suspended_count": len(self._suspended),
                "suspended_processes": [
                    {
                        "pid": pid,
                        "name": record["name"],
                        "suspended_at": datetime.fromtimestamp(
                            record["suspended_at"]
                        ).isoformat(timespec="seconds"),
                    }
                    for pid, record in self._suspended.items()
                ],
                "scans_completed": self._scans_completed,
                "last_scan": self._last_scan,
                "last_error": self._last_error,
                "allowlist": sorted(AUTO_SUSPEND_ALLOWLIST),
                "automatic_suspension_configured": bool(
                    AUTO_SUSPEND_ALLOWLIST
                ),
            }

    def get_history(self, limit=50):
        limit = max(1, min(int(limit), 200))

        with self._lock:
            return list(self._history)[:limit]
    def status(self):
        return self.get_status()
    def history(self):
        return self.get_history()