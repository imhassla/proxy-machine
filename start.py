import subprocess
import time
import signal
import os

commands = [
    "python3 proxy.py -type http -db -api -w 20",
    "python3 proxy.py -type socks4 -db -api -w 20",
    "python3 proxy.py -type socks5 -db -api -w 20",
    "python3 http-proxy-relay.py",
    "uvicorn api:app --host 127.0.0.1 --port 8000 --reload"
]

processes = []

try:
    for command in commands[:-1]:
        process = subprocess.Popen(command.split(), stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        processes.append(process)
        time.sleep(2)

    process = subprocess.Popen(commands[-1].split())
    processes.append(process)

    while True:
        time.sleep(1)

except KeyboardInterrupt:
    print("Exit...")
    for process in processes:
        os.kill(process.pid, signal.SIGKILL)
