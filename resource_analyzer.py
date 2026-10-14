
def calculate_resource_score(cpu, memory, idle_time):
    score = 0

    # CPU contribution
    if cpu > 50:
        score += 40
    elif cpu > 20:
        score += 25
    elif cpu > 5:
        score += 10

    # Memory contribution
    if memory > 1000:
        score += 40
    elif memory > 500:
        score += 30
    elif memory > 200:
        score += 20
    elif memory > 100:
        score += 10

    # Inactivity contribution
    if idle_time > 300:
        score += 30
    elif idle_time > 120:
        score += 25
    elif idle_time > 60:
        score += 20
    elif idle_time > 30:
        score += 10

    return min(score, 100)

