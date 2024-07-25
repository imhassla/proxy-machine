import subprocess
import time
import signal
import os
import sqlite3
import logging
import configparser

# Setup logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Load configuration
config = configparser.ConfigParser()
config.read('config.ini')

# List of proxy types
proxy_types = ['http', 'https', 'socks4', 'socks5']
for proxy_type in proxy_types:
    try:
        # Connect to SQLite database with a timeout of 30 seconds
        conn = sqlite3.connect(config['database']['path'], timeout=30)
        c = conn.cursor()
        # Create table for each proxy type if it doesn't already exist
        c.execute(f'''CREATE TABLE IF NOT EXISTS {proxy_type} (proxy TEXT PRIMARY KEY, response_time REAL, last_checked TEXT)''')
        c.execute('BEGIN')  # Begin transaction
        c.execute('COMMIT')  # Commit transaction
        conn.close()  # Close the database connection
    except Exception as e:
        logging.error(f"Error setting up database for {proxy_type}: {e}")

# List of commands to run different scripts
commands = [
    config['commands']['proxy_http'],
    config['commands']['proxy_https'],
    config['commands']['proxy_socks4'],
    config['commands']['proxy_socks5'],
    config['commands']['checker'],
    config['commands']['relay'],
    config['commands']['api']
]

processes = []

def start_process(command):
    try:
        process = subprocess.Popen(command.split(), stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        return process
    except Exception as e:
        logging.error(f"Error starting command '{command}': {e}")
        return None

def stop_process(process):
    if process is not None:
        try:
            os.kill(process.pid, signal.SIGTERM)
            process.wait()
        except Exception as e:
            logging.error(f"Error stopping process {process.pid}: {e}")

try:
    # Start each command as a subprocess, except the last two
    for command in commands:
        process = start_process(command)
        if process:
            processes.append(process)
            logging.info(f"Process {process.args} started...")
            time.sleep(1)  # Sleep for 2 seconds between starting each process
    logging.info(f"PROXY MACHINE READY! \nAPI: http://0.0.0.0:8000 \nhttp-proxy: http://0.0.0.0:3333 ")

    # Monitor processes and restart if they exit unexpectedly
    while True:
        for i, process in enumerate(processes):
            if process.poll() is not None:  # Process has terminated
                logging.warning(f"Process {process.args} terminated. Restarting...")
                processes[i] = start_process(commands[i])
        time.sleep(5)

except KeyboardInterrupt:
    logging.info("Exit...")

finally:
    # On exit, gracefully stop all running subprocesses
    for process in processes:
        stop_process(process)
