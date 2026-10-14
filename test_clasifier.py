from classifier import classify_process


cpu = 2
memory = 800
idle_time = 70
score = 45

result = classify_process(cpu, memory, idle_time, score)

print("Classification:", result)
