
import time

import psutil
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from activity_tracker import ActivityTracker
from resource_analyzer import calculate_resource_score
from classifier import classify_process
from decision_engine import make_decision
from process_protection import is_protected
from lifecycle_controller import suspend_process, resume_process
from automation_manager import AutomationManager


app = FastAPI(title="Smart Application Lifecycle Manager")

tracker = ActivityTracker()

BASELINE_CPU = 0.0
automation = AutomationManager(interval=3)

class ProcessAction(BaseModel):
    pid: int
    action: str


@app.get("/api/health")
def health():
    return {
        "status": "running",
        "application": "Smart Application Lifecycle Manager"
    }


@app.get("/api/system")
def get_system_stats():
    return {
        "cpu_percent": psutil.cpu_percent(interval=0.2),
        "memory_percent": psutil.virtual_memory().percent,
        "memory_used_mb": round(
            psutil.virtual_memory().used / (1024 * 1024), 2
        ),
        "memory_total_mb": round(
            psutil.virtual_memory().total / (1024 * 1024), 2
        ),
        "process_count": len(psutil.pids())
    }


@app.get("/api/processes")
def get_processes():
    processes = []
    active_pids = set()

    for proc in psutil.process_iter(
        ["pid", "name", "status", "memory_info"]
    ):
        try:
            pid = proc.info["pid"]
            name = proc.info["name"] or "Unknown"
            status = proc.info["status"] or "unknown"
            memory_info = proc.info["memory_info"]

            # Ignore processes that disappear or cannot be inspected.
            if memory_info is None:
                continue

            memory_mb = round(
                memory_info.rss / (1024 * 1024), 2
            )

            # First CPU reading may be zero because psutil needs
            # a previous measurement for comparison.
            cpu = proc.cpu_percent(interval=None)

            active_pids.add(pid)

            idle_time = tracker.update(pid, cpu)

            score = calculate_resource_score(
                cpu, memory_mb, idle_time
            )

            classification = classify_process(
                cpu, memory_mb, idle_time, score
            )

            action, reason = make_decision(
                cpu, memory_mb, idle_time, score, classification
            )

            protected = is_protected(pid, name)

            if protected:
                action = "PROTECTED"
                reason = "Critical process - lifecycle action blocked"

            processes.append({
                "pid": pid,
                "name": name,
                "cpu_percent": round(cpu, 2),
                "memory_mb": memory_mb,
                "status": status,
                "idle_seconds": round(idle_time, 1),
                "score": score,
                "classification": classification,
                "action": action,
                "reason": reason,
                "protected": protected
            })

        except (psutil.NoSuchProcess, psutil.AccessDenied,
                psutil.ZombieProcess):
            continue

    # Remove tracking data for processes that have exited.
    for pid in list(tracker.idle_since):
        if pid not in active_pids:
            tracker.remove_process(pid)

    processes.sort(
        key=lambda item: item["cpu_percent"],
        reverse=True
    )

    return {"processes": processes}


@app.get("/api/applications")
def get_applications():
    grouped = {}

    for proc in psutil.process_iter(["pid", "name", "memory_info"]):
        try:
            pid = proc.info["pid"]
            name = proc.info["name"] or "Unknown"
            memory_info = proc.info["memory_info"]

            if memory_info is None:
                continue

            memory_mb = memory_info.rss / (1024 * 1024)
            cpu = proc.cpu_percent(interval=None)

            # Group processes with the same executable name.
            key = name.lower()

            if key not in grouped:
                grouped[key] = {
                    "name": name,
                    "process_count": 0,
                    "memory_mb": 0.0,
                    "cpu_percent": 0.0,
                    "pids": []
                }

            grouped[key]["process_count"] += 1
            grouped[key]["memory_mb"] += memory_mb
            grouped[key]["cpu_percent"] += cpu
            grouped[key]["pids"].append(pid)

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):
            continue

    applications = list(grouped.values())

    for application in applications:
        application["memory_mb"] = round(
            application["memory_mb"], 2
        )
        application["cpu_percent"] = round(
            application["cpu_percent"], 2
        )
        application["pids"].sort()

    applications.sort(
        key=lambda application: application["memory_mb"],
        reverse=True
    )

    return {"applications": applications}

@app.post("/api/process-action")
def process_action(request: ProcessAction):
    if request.action not in {"suspend", "resume"}:
        raise HTTPException(
            status_code=400,
            detail="Supported actions are suspend and resume"
        )

    try:
        proc = psutil.Process(request.pid)
        name = proc.name()

        if is_protected(request.pid, name):
            raise HTTPException(
                status_code=403,
                detail="This process is protected"
            )

        if request.action == "suspend":
            success, message = suspend_process(request.pid)
        else:
            success, message = resume_process(request.pid)

        if not success:
            raise HTTPException(status_code=400, detail=message)

        return {
            "success": True,
            "pid": request.pid,
            "action": request.action,
            "message": message
        }

    except psutil.NoSuchProcess:
        raise HTTPException(
            status_code=404,
            detail="Process no longer exists"
        )


@app.get("/api/automation/status")
def get_automation_status():
    return automation.status()


@app.post("/api/automation/start")
def start_automation():
    automation.start()
    return {
        "success": True,
        "message": "Automatic lifecycle management enabled",
        **automation.status(),
    }


@app.post("/api/automation/stop")
def stop_automation():
    automation.stop()
    return {
        "success": True,
        "message": "Automation disabled; managed processes resumed",
        **automation.status(),
    }


@app.get("/api/automation/history")
def get_automation_history():
    return {"history": automation.history()}

@app.get("/api/relationship-graph")
def get_relationship_graph(limit: int = 150):
    """
    Returns process nodes and verified parent-child relationships.
    The limit keeps the graph manageable on busy systems.
    """
    if limit < 20 or limit > 300:
        raise HTTPException(
            status_code=400,
            detail="limit must be between 20 and 300"
        )

    processes = []
    process_by_pid = {}

    # Collect process information safely.
    for proc in psutil.process_iter(
        ["pid", "ppid", "name", "memory_info", "status"]
    ):
        try:
            info = proc.info
            pid = info["pid"]
            name = info.get("name") or "Unknown"
            ppid = info.get("ppid")

            memory_info = info.get("memory_info")
            memory_mb = (
                round(memory_info.rss / (1024 * 1024), 2)
                if memory_info is not None
                else 0
            )

            cpu = proc.cpu_percent(interval=None)

            item = {
                "pid": pid,
                "ppid": ppid,
                "name": name,
                "cpu_percent": round(cpu, 2),
                "memory_mb": memory_mb,
                "status": info.get("status") or "unknown",
            }

            processes.append(item)
            process_by_pid[pid] = item

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
        ):
            continue

    # Prioritize higher-memory processes if the graph is too large.
    processes.sort(
        key=lambda item: item["memory_mb"],
        reverse=True
    )

    selected = processes[:limit]
    selected_pids = {item["pid"] for item in selected}

    nodes = []

    for item in selected:
        pid = item["pid"]

        nodes.append({
            "data": {
                "id": str(pid),
                "label": f'{item["name"]}\nPID {pid}',
                "pid": pid,
                "name": item["name"],
                "cpu_percent": item["cpu_percent"],
                "memory_mb": item["memory_mb"],
                "status": item["status"],
                "parent_pid": item["ppid"],
                "protected": is_protected(pid, item["name"]),
            }
        })

    edges = []

    for item in selected:
        pid = item["pid"]
        ppid = item["ppid"]

        # Only create an edge when both processes are present.
        if ppid is not None and ppid in selected_pids:
            edges.append({
                "data": {
                    "id": f"parent-{ppid}-{pid}",
                    "source": str(ppid),
                    "target": str(pid),
                    "relationship": "parent-child",
                }
            })

    return {
        "nodes": nodes,
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "relationship_type": "parent-child",
        "limit": limit,
    }

from pathlib import Path

STATIC_DIR = Path(__file__).parent / "static"

app.mount(
    "/static",
    StaticFiles(directory=str(STATIC_DIR)),
    name="static"
)


@app.get("/")
def home():
    return FileResponse(STATIC_DIR / "index.html")