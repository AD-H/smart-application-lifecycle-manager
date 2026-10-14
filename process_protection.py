
import os

# Critical process names, stored in lowercase for Windows compatibility.
PROTECTED_NAMES = {
    # Linux / WSL
    "systemd",
    "init",
    "kthreadd",
    "ksoftirqd",
    "migration",
    "rcu_sched",

        # Windows system and memory-management processes
    "system",
    "registry",
    "memcompression",
    "memcompression.exe",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "dwm.exe",
    "explorer.exe",
}


def is_protected(pid, name):
    """Prevent lifecycle actions on critical or self processes."""

    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return True

    # Invalid/system-reserved Windows PIDs and Linux PID 1.
    if pid in (0, 1, 4):
        return True

    # Never allow lifecycle actions against the SALM server itself.
    if pid == os.getpid():
        return True

    # Windows executable names are case-insensitive.
    normalized_name = os.path.basename(str(name or "")).lower()

    if normalized_name in PROTECTED_NAMES:
        return True

    return False