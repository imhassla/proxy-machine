import subprocess
import time
import signal
import os
import sqlite3

choices=['http','https', 'socks4', 'socks5']
for choice in choices:
    conn = sqlite3.connect('data.db',timeout = 30)
    c = conn.cursor()
    c.execute(f'''CREATE TABLE IF NOT EXISTS {choice} (proxy TEXT PRIMARY KEY, response_time REAL, last_checked TEXT)''')
    c.execute('BEGIN')
    c.execute('COMMIT')
    conn.close()

commands = [
    "python3 proxy.py -type http -db -api -w 25 -t 5",
    "python3 proxy.py -type https -db -api -w 25 -t 5",
    "python3 proxy.py -type socks4 -db -api -w 25 -t 8",
    "python3 proxy.py -type socks5 -db -api -w 25 -t 8",
    "python3 checker.py -list",
    "python3 http-proxy-relay.py",
    "uvicorn api:app --host 0.0.0.0 --port 8000 --reload"
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