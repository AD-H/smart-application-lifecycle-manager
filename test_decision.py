from decision_engine import make_decision


cpu = 90
memory = 100
idle_time = 0
score = 40
classification = "HIGH USAGE"

action, reason = make_decision(
    cpu,
    memory,
    idle_time,
    score,
    classification
)

print("Action:", action)
print("Reason:", reason)
