
import psutil


def suspend_process(pid):
    """Suspend a process on Windows or Linux/WSL."""
    try:
        process = psutil.Process(pid)
        process.suspend()
        return True, f"Process {pid} suspended successfully"

    except psutil.NoSuchProcess:
        return False, "Process no longer exists"

    except psutil.AccessDenied:
        return False, "Permission denied"

    except psutil.ZombieProcess:
        return False, "Cannot suspend a zombie process"

    except (OSError, ValueError) as e:
        return False, f"Unable to suspend process: {e}"


def resume_process(pid):
    """Resume a suspended process on Windows or Linux/WSL."""
    try:
        process = psutil.Process(pid)
        process.resume()
        return True, f"Process {pid} resumed successfully"

    except psutil.NoSuchProcess:
        return False, "Process no longer exists"

    except psutil.AccessDenied:
        return False, "Permission denied"

    except psutil.ZombieProcess:
        return False, "Cannot resume a zombie process"

    except (OSError, ValueError) as e:
        return False, f"Unable to resume process: {e}"


def terminate_process(pid):
    """Request process termination using the platform's process API."""
    try:
        process = psutil.Process(pid)
        process.terminate()
        return True, f"Termination requested for process {pid}"

    except psutil.NoSuchProcess:
        return False, "Process no longer exists"

    except psutil.AccessDenied:
        return False, "Permission denied"

    except psutil.ZombieProcess:
        return False, "Cannot terminate a zombie process"

    except (OSError, ValueError) as e:
        return False, f"Unable to terminate process: {e}"