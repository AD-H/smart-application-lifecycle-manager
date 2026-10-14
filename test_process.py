
import time

print("SALM test process started.")
print("PID:", __import__("os").getpid())

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("SALM test process stopped.")
