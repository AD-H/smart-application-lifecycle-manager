
def detect_deadlock(graph):
    """
    Detect cycles in a wait-for graph.

    graph format:
    {
        "Process A": ["Process B"],
        "Process B": ["Process A"]
    }

    An edge A -> B means A is waiting for B.
    """

    visited = set()
    active_path = set()
    path = []
    deadlocks = []

    def dfs(process):
        visited.add(process)
        active_path.add(process)
        path.append(process)

        for neighbor in graph.get(process, []):
            if neighbor not in visited:
                if dfs(neighbor):
                    return True

            elif neighbor in active_path:
                start = path.index(neighbor)
                deadlocks.append(path[start:] + [neighbor])
                return True

        path.pop()
        active_path.remove(process)
        return False

    for process in graph:
        if process not in visited:
            if dfs(process):
                break

    return deadlocks


def get_demo_data():
    """Return a sample scenario for testing."""

    graph = {
        "Process A": ["Process B"],
        "Process B": ["Process C"],
        "Process C": ["Process A"],
        "Process D": []
    }

    deadlocks = detect_deadlock(graph)

    return {
        "status": "DEADLOCK DETECTED" if deadlocks else "NO DEADLOCK",
        "deadlocks": deadlocks,
        "wait_for_graph": graph
    }


if __name__ == "__main__":
    result = get_demo_data()
    print("Status:", result["status"])
    print("Deadlock cycles:", result["deadlocks"])


def analyze_deadlock():
    """
    Analyze the current demo wait-for graph.
    Later, we can replace this with dynamic input.
    """
    return get_demo_data()



def simulate_recovery(process_to_remove):
    data = get_demo_data()
    graph = data["wait_for_graph"]

    # Normalize the input
    process_to_remove = process_to_remove.strip()

    # Find the matching process name, ignoring case
    matched_process = next(
        (
            name for name in graph
            if name.lower() == process_to_remove.lower()
        ),
        None
    )

    if matched_process is None:
        return {
            "status": "ERROR",
            "message": f"Process '{process_to_remove}' not found",
            "available_processes": list(graph.keys()),
            "wait_for_graph": graph,
            "deadlocks": data["deadlocks"]
        }

    # Simulate removing the selected process
    graph.pop(matched_process)

    # Remove incoming waiting relationships
    for process in graph:
        graph[process] = [
            target for target in graph[process]
            if target != matched_process
        ]

    deadlocks = detect_deadlock(graph)

    return {
        "status": (
            "DEADLOCK DETECTED" if deadlocks
            else "NO DEADLOCK"
        ),
        "recovered_process": matched_process,
        "deadlocks": deadlocks,
        "wait_for_graph": graph
    }
