
import os
import threading
import time
from collections import deque

import psutil

from activity_tracker import ActivityTracker
from resource_analyzer import calculate_resource_score
from classifier import classify_process
from decision_engine import make_decision
from process_protection import is_protected
from lifecycle_controller import suspend_process, resume_process


class AutomationManager:
    def __init__(self, interval=3):
        self.interval = interval
        self.enabled = False
        self.lock = threading.RLock()
        self.thread = None
        self.tracker = ActivityTracker()
        self.action_retry_after = {}
        # Only processes suspended by this manager are tracked here.
        self.suspended = {}
        self.logs = deque(maxlen=200)
        self.resume_cooldown = {}
        # Require repeated eligible readings before suspending.
        self.eligible_counts = {}
        self.last_scan_time = None
        self.scans_completed = 0
        self.last_scan_results = {}

    def log(self, pid, name, action, message):
        with self.lock:
            self.logs.appendleft({
                "time": time.strftime("%H:%M:%S"),
                "pid": pid,
                "name": name,
                "action": action,
                "message": message,
            })

    def start(self):
        with self.lock:
            if self.enabled:
                return

            self.enabled = True
            self.thread = threading.Thread(
                target=self._run,
                daemon=True,
                name="SALM-Automation",
            )
            self.thread.start()

        self.log("-", "SALM", "AUTOMATION ON",
                 "Automatic lifecycle management enabled")

    def stop(self):
        with self.lock:
            self.enabled = False

        # Resume processes suspended by SALM when automation is disabled.
        self._resume_all()

        self.log("-", "SALM", "AUTOMATION OFF",
                 "Automation disabled; SALM-suspended processes resumed")

    def status(self):
        with self.lock:
            return {
            "enabled": self.enabled,
            "suspended_count": len(self.suspended),
            "last_scan_time": self.last_scan_time,
            "scans_completed": self.scans_completed,
            "last_scan_results": dict(self.last_scan_results),
        }

    def history(self):
        with self.lock:
            return list(self.logs)

    def _run(self):
        while self.enabled:
            try:
                self._scan()
            except Exception as error:
                self.log("-", "SALM", "ERROR", str(error))

            time.sleep(self.interval)

    def _scan(self):
        seen = set()
        classification_counts = {}
        decision_counts = {}
        scanned_count = 0
        suspend_candidates = 0
        for proc in psutil.process_iter(
            ["pid", "name", "status", "memory_info"]
        ):
            if not self.enabled:
                break

            try:
                pid = proc.info["pid"]
                name = proc.info["name"] or "Unknown"
                seen.add(pid)
                scanned_count += 1
                if is_protected(pid, name):
                    self.eligible_counts.pop(pid, None)
                    continue

                # Do not evaluate or suspend a process already managed by SALM.
                if pid in self.suspended:
                    continue

                memory_info = proc.info["memory_info"]
                if memory_info is None:
                    continue

                memory_mb = memory_info.rss / (1024 * 1024)
                cpu = proc.cpu_percent(interval=None)
                idle = self.tracker.update(pid, cpu)

                score = calculate_resource_score(cpu, memory_mb, idle)
                
                classification = classify_process(cpu, memory_mb, idle, score)
                idle = self.tracker.update(pid, cpu)
                score = calculate_resource_score(cpu, memory_mb, idle)
                classification = classify_process(cpu, memory_mb, idle, score)
                action, reason = make_decision(cpu, memory_mb, idle, score, classification)
                if name == "ProtonVPN.Client.exe":
                    self.log(
                    pid,
                    name,
                    "DECISION TEST",
                    f"CPU={cpu:.2f}% | RAM={memory_mb:.1f} MB | "
                    f"Idle={idle:.1f}s | Score={score} | "
                    f"Class={classification} | Action={action}"
                )           

# TEMPORARY DIAGNOSTIC
                if len(self.logs) < 10:
                    self.log(
                        pid,
                        name,
                        "DIAGNOSTIC",
                        f"CPU={cpu:.1f}% | RAM={memory_mb:.1f} MB | "
                        f"Idle={idle:.1f}s | Score={score} | "
                        f"Class={classification}"
                    )

                action, reason = make_decision(
                    cpu, memory_mb, idle, score, classification
                )


# Count classifications for debugging
                if "classification_counts" not in locals():
                    classification_counts = {}

                classification_counts[classification] = (
                    classification_counts.get(classification, 0) + 1
                )

                action, reason = make_decision(
                    cpu, memory_mb, idle, score, classification
                )


                decision_counts[action] = decision_counts.get(action, 0) + 1
                if action == "SUSPEND":
    # Give a resumed app time to respond before considering it again.
                    if time.monotonic() < self.resume_cooldown.get(pid, 0):
                        continue
                    if time.monotonic() < self.action_retry_after.get(pid, 0):
                        continue
                    count = self.eligible_counts.get(pid, 0) + 1
                    self.eligible_counts[pid] = count

                    # Require repeated eligibility before acting.
                    if count >= 3 and self.enabled:
                        success, message = suspend_process(pid)

                        if success:
                            with self.lock:
                                self.suspended[pid] = {
                                    "name": name,
                                    "process": proc,
                                }
                            self.log(pid, name, "SUSPEND", reason)
                        else:
                            self.log(pid, name, "FAILED", message)
                            self.action_retry_after[pid] = time.monotonic() + 300
                            self.eligible_counts.pop(pid, None)
                else:
                    self.eligible_counts.pop(pid, None)

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess,
            ):
                continue

        # Forget exited processes and their counters.
        for pid in list(self.eligible_counts):
            if pid not in seen:
                self.eligible_counts.pop(pid, None)

        # Resume processes that no longer exist or have become foreground apps.
        self._resume_foreground_windows()
        with self.lock:
            self.last_scan_time = time.strftime("%H:%M:%S")
            self.scans_completed += 1
            self.last_scan_results = {
            "processes_scanned": scanned_count,
            "suspend_candidates": suspend_candidates,
            "decisions": decision_counts,
            "classifications": classification_counts,
        }
    
    def _resume_foreground_windows(self):
        """Resume a SALM-suspended app when its window is selected."""
        if os.name != "nt":
            return

        try:
            import ctypes

            foreground = ctypes.windll.user32.GetForegroundWindow()
            if not foreground:
                return

            foreground_pid = ctypes.c_ulong()
            ctypes.windll.user32.GetWindowThreadProcessId(
                foreground, ctypes.byref(foreground_pid)
            )

            pid = foreground_pid.value

            with self.lock:
                is_managed = pid in self.suspended

            if is_managed:
                self._resume_one(pid)

        except Exception as error:
            self.log(
                "-", "SALM", "ERROR",
                f"Foreground detection failed: {error}"
            )
            
            
    def _resume_one(self, pid):
        with self.lock:
            entry = self.suspended.get(pid)

        if entry is None:
            return

        success, message = resume_process(pid)

        if success:
            with self.lock:
                self.suspended.pop(pid, None)
                self.resume_cooldown[pid] = time.monotonic() + 60
                self.eligible_counts.pop(pid, None)

            self.log(
                pid, entry["name"], "RESUME",
                "Process resumed by SALM"
            )
        else:
            self.log(pid, entry["name"], "RESUME FAILED", message)

    def _resume_all(self):
        with self.lock:
            pids = list(self.suspended)

        for pid in pids:
            self._resume_one(pid)