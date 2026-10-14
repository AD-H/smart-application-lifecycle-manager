
import time
import psutil

# Start a harmless application for testing
process = psutil.Popen(["notepad.exe"])

try:
    print("Started Notepad. PID:", process.pid)
    time.sleep(2)

    print("Suspending Notepad...")
    process.suspend()
    time.sleep(2)
    print("Status while suspended:", process.status())

    print("Resuming Notepad...")
    process.resume()
    time.sleep(1)
    print("Status after resume:", process.status())

    print("Test complete. Notepad should respond again.")

except psutil.Error as error:
    print("Process test failed:", error)