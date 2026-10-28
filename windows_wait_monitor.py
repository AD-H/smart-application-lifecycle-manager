from collections import Counter
import ctypes
import os
import psutil


if os.name != "nt":
    raise OSError("Windows Wait Chain Traversal requires Windows.")

DWORD = ctypes.c_uint32
BOOL = ctypes.c_int32
WCT_MAX_NODE_COUNT = 16
WCT_OBJNAME_LENGTH = 128

# Windows WCT object types
OBJECT_TYPES = {
    1: "Critical Section",
    2: "Send Message",
    3: "Mutex",
    4: "ALPC",
    5: "COM",
    6: "Thread Wait",
    7: "Process Wait",
    8: "Thread",
    9: "COM Activation",
    10: "Unknown",
    11: "Socket I/O",
    12: "SMB I/O",
}

OBJECT_STATUSES = {
    1: "No Access",
    2: "Running",
    3: "Blocked",
    4: "PID Only",
    5: "PID Only (RPCSS)",
    6: "Owned",
    7: "Not Owned",
    8: "Abandoned",
    9: "Unknown",
    10: "Error",
}


class LockObject(ctypes.Structure):
    _fields_ = [
        ("ObjectName", ctypes.c_wchar * WCT_OBJNAME_LENGTH),
        ("Timeout", ctypes.c_int64),
        ("Alertable", BOOL),
    ]


class ThreadObject(ctypes.Structure):
    _fields_ = [
        ("ProcessId", DWORD),
        ("ThreadId", DWORD),
        ("WaitTime", DWORD),
        ("ContextSwitches", DWORD),
    ]


class NodeUnion(ctypes.Union):
    _fields_ = [
        ("LockObject", LockObject),
        ("ThreadObject", ThreadObject),
    ]


class WaitChainNode(ctypes.Structure):
    _fields_ = [
        ("ObjectType", ctypes.c_int),
        ("ObjectStatus", ctypes.c_int),
        ("Object", NodeUnion),
    ]


advapi32 = ctypes.WinDLL("Advapi32.dll", use_last_error=True)

open_session = advapi32.OpenThreadWaitChainSession
open_session.argtypes = [DWORD, ctypes.c_void_p]
open_session.restype = ctypes.c_void_p

get_wait_chain = advapi32.GetThreadWaitChain
get_wait_chain.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    DWORD,
    DWORD,
    ctypes.POINTER(DWORD),
    ctypes.POINTER(WaitChainNode),
    ctypes.POINTER(BOOL),
]
get_wait_chain.restype = BOOL

close_session = advapi32.CloseThreadWaitChainSession
close_session.argtypes = [ctypes.c_void_p]
close_session.restype = None


def get_windows_processes():
    """Return real Windows process and thread counts."""
    processes = []

    for proc in psutil.process_iter(
        ["pid", "name", "status", "username"]
    ):
        try:
            info = proc.info
            processes.append({
                "pid": info["pid"],
                "name": info["name"] or "Unknown",
                "status": info["status"],
                "username": info["username"],
                "thread_count": proc.num_threads(),
            })
        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
        ):
            continue

    return processes


def inspect_process_wait_chains(pid, max_threads=50):
    """
    Inspect WCT chains for threads belonging to one process.
    WCT's IsCycle flag is reported separately from ordinary waits.
    """
    try:
        proc = psutil.Process(pid)
        process_name = proc.name()
        thread_ids = [thread.id for thread in proc.threads()]
    except psutil.NoSuchProcess:
        return {
            "status": "ERROR",
            "message": f"Process {pid} no longer exists.",
            "pid": pid,
            "chains": [],
        }
    except psutil.AccessDenied:
        return {
            "status": "ERROR",
            "message": f"Access denied while inspecting process {pid}.",
            "pid": pid,
            "chains": [],
        }

    session = open_session(0, None)
    if not session:
        return {
            "status": "ERROR",
            "message": (
                "Could not open a WCT session. "
                f"Windows error: {ctypes.get_last_error()}"
            ),
            "pid": pid,
            "chains": [],
        }

    chains = []
    checked = 0

    try:
        for thread_id in thread_ids[:max_threads]:
            count = DWORD(WCT_MAX_NODE_COUNT)
            nodes = (WaitChainNode * WCT_MAX_NODE_COUNT)()
            is_cycle = BOOL(0)

            success = get_wait_chain(
                session,
                None,
                0x7,  # WCTP_GETINFO_ALL_FLAGS,  
                thread_id,
                ctypes.byref(count),
                nodes,
                ctypes.byref(is_cycle),
            )

            checked += 1

            if not success:
                chains.append({
                    "thread_id": thread_id,
                    "status": "QUERY_FAILED",
                    "windows_error": ctypes.get_last_error(),
                    "cycle_detected": False,
                    "nodes": [],
                })
                continue

            chain_nodes = []

            for node in nodes[:min(count.value, WCT_MAX_NODE_COUNT)]:
                item = {
                    "object_type": OBJECT_TYPES.get(
                        node.ObjectType, "Unknown"
                    ),
                    "object_status": OBJECT_STATUSES.get(
                        node.ObjectStatus, "Unknown"
                    ),
                }

                if node.ObjectType == 8:
                    thread = node.Object.ThreadObject
                    item.update({
                        "pid": thread.ProcessId,
                        "thread_id": thread.ThreadId,
                        "wait_time_raw": thread.WaitTime,
                    })
                else:
    # WCT only provides meaningful names for certain object types.
    # Do not interpret arbitrary union memory as an object name.
                    if node.ObjectType in (1, 3):
                        name = node.Object.LockObject.ObjectName
                        item["object_name"] = name if name else None
                    else:
                        item["object_name"] = None

                chain_nodes.append(item)

            chains.append({
                "thread_id": thread_id,
                "status": (
                    "CYCLE_DETECTED_BY_WCT"
                    if is_cycle.value
                    else "NO_CYCLE_REPORTED"
                ),
                "cycle_detected": bool(is_cycle.value),
                "nodes": chain_nodes,
            })

    finally:
        close_session(session)

    detected_cycles = [
        chain for chain in chains if chain["cycle_detected"]
    ]

    return {
        "status": (
            "CYCLE_DETECTED_BY_WCT"
            if detected_cycles
            else "NO_CYCLE_REPORTED"
        ),
        "pid": pid,
        "process_name": process_name,
        "threads_found": len(thread_ids),
        "threads_checked": checked,
        "threads_skipped_by_limit": max(
            0, len(thread_ids) - max_threads
        ),
        "chains": chains,
        "detected_cycles": len(detected_cycles),
        "note": (
            "WCT covers supported synchronization waits only. "
            "A missing cycle does not prove that no deadlock exists."
        ),
    }

def scan_system_deadlocks(max_threads_per_process=50):
    """
    Inspect real Windows process threads using WCT.
    Reports confirmed WCT cycles separately from incomplete scans.
    Does not terminate or suspend processes.
    """
    process_list = get_windows_processes()

    results = []
    errors = []
    total_threads = 0
    checked_threads = 0
    skipped_threads = 0

    for process in process_list:
        pid = process["pid"]

        try:
            result = inspect_process_wait_chains(
                pid,
                max_threads=max_threads_per_process
            )

            results.append({
                "pid": pid,
                "process_name": process["name"],
                "status": result["status"],
                "threads_found": result.get("threads_found", 0),
                "threads_checked": result.get("threads_checked", 0),
                "threads_skipped_by_limit": result.get(
                    "threads_skipped_by_limit", 0
                ),
                "detected_cycles": result.get("detected_cycles", 0),
                "chains": result.get("chains", []),
            })

            total_threads += result.get("threads_found", 0)
            checked_threads += result.get("threads_checked", 0)
            skipped_threads += result.get(
                "threads_skipped_by_limit", 0
            )

            if result["status"] == "ERROR":
    # PID 0 is a special Windows process that cannot
    # be inspected through normal process APIs.
                if pid == 0:
                    continue

                message = result.get("message", "WCT inspection failed")

    # A process may disappear while the scan is running.
                if "no longer exists" in message.lower():
                    continue

                errors.append({
                    "pid": pid,
                    "process_name": process["name"],
                    "message": message,
                })

        except Exception as exc:
            message = str(exc)

            # PID 0 is a special Windows process; skip it.
            if pid == 0:
                continue

            # Processes can exit during a live scan.
            if "no longer exists" in message.lower():
                continue

            errors.append({
                "pid": pid,
                "process_name": process["name"],
                "message": message
            })
    cycles = [
        {
            "pid": process["pid"],
            "process_name": process["process_name"],
            "thread_id": chain["thread_id"],
            "nodes": chain.get("nodes", []),
        }
        for process in results
        for chain in process["chains"]
        if chain.get("cycle_detected")
    ]

    query_failures = sum(
        1
        for process in results
        for chain in process["chains"]
        if chain.get("status") == "QUERY_FAILED"
    )

    if cycles:
        status = "DEADLOCK_DETECTED"
    elif errors or query_failures or skipped_threads:
        status = "SCAN_INCOMPLETE"
    else:
        status = "NO_CYCLE_DETECTED_IN_INSPECTED_CHAINS"

    return {
        "status": status,
        "deadlock_detected": bool(cycles),
        "processes_found": len(process_list),
        "processes_inspected": len(results),
        "threads_found": total_threads,
        "threads_checked": checked_threads,
        "threads_skipped_by_limit": skipped_threads,
        "query_failures": query_failures,
        "errors": errors,
        "cycles": cycles,
        "process_results": results,
        "note": (
            "This scan reports cycles explicitly detected by Windows WCT. "
            "It cannot prove that no deadlock exists outside the inspected "
            "or supported wait chains."
        ),
    }


if __name__ == "__main__":
    print("Windows process monitor loaded successfully.")
    print("Sample processes:")
    for process in get_windows_processes()[:10]:
        print(process)
