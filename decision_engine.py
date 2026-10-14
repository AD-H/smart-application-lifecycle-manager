def make_decision(cpu, memory, idle_time, score, classification):

    # High CPU usage needs investigation
    if classification == "HIGH USAGE":
        return "INVESTIGATE", "Process is consuming high CPU"

    # Idle process using significant resources
    if classification == "IDLE RESOURCE CONSUMER":

        if score >= 60:
            return "SUSPEND", "High resource usage with prolonged inactivity"

        elif score >= 40:
            return "LOWER PRIORITY", "Moderate resource usage with prolonged inactivity"

        else:
            return "MONITOR", "Process is idle but resource usage is limited"

    # Low activity process
    if classification == "LOW ACTIVITY":
        return "MONITOR", "Low activity detected"

    # Normal active process
    return "KEEP RUNNING", "Process is actively being used"
