
def classify_process(cpu, memory, idle_time, score):
    # Very high CPU usage
    if cpu > 50:
        return "HIGH USAGE"

    # Long inactivity with significant memory consumption
    if idle_time > 60 and memory > 200:
        return "IDLE RESOURCE CONSUMER"

    # Low CPU activity
    if cpu < 5:
        return "LOW ACTIVITY"

    return "ACTIVE"

