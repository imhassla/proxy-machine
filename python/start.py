import subprocess
import time
import signal
import os
import sqlite3
import logging
import configparser
import requests
import string

# Setup logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Load configuration
config = configparser.ConfigParser()
config.read('config.ini')

default_checker_workers = config["defaults"].get("checker_workers", "25")
default_checker_timeout = config["defaults"].get("checker_timeout", "4")
default_api_workers = config["defaults"].get("api_workers", "200")

CHECKER_WORKERS = os.getenv("CHECKER_WORKERS", default_checker_workers)
CHECKER_TIMEOUT = os.getenv("CHECKER_TIMEOUT", default_checker_timeout)
API_WORKERS = os.getenv("API_WORKERS", default_api_workers)

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

template = string.Template
commands_map = {}
for key, value in config["commands"].items():
    value = template(value).safe_substitute({
        "CHECKER_WORKERS": CHECKER_WORKERS,
        "CHECKER_TIMEOUT": CHECKER_TIMEOUT,
				"API_WORKERS": API_WORKERS
    })
    commands_map[key] = value

# List of commands to run different scripts
commands = [
    commands_map['proxy_http'],
    commands_map['proxy_https'],
    commands_map['proxy_socks4'],
    commands_map['proxy_socks5'],
    commands_map['checker'],
    commands_map['api'],
    commands_map['relay']
]

processes = []

def start_process(command):
    try:
        # Redirect stdout and stderr to a log file for uvicorn
        if 'uvicorn' in command:
            with open('uvicorn.log', 'w') as log_file:
                process = subprocess.Popen(command.split(), stdout=log_file, stderr=log_file)
        else:
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

def check_api_status(url, retries=50, delay=10):
    for attempt in range(retries):
        try:
            response = requests.get(url)
            if response.status_code == 200:
                logging.info("API is running successfully.")
                return True
        except requests.ConnectionError:
            logging.warning(f"API not reachable, attempt {attempt + 1} of {retries}. Retrying in {delay} seconds...")
        time.sleep(delay * 2)  # Increase delay to give more time for the server to start
    logging.error("API failed to start after multiple attempts.")
    return False

def check_proxy_relay(url, retries=50, delay=10):
    for attempt in range(retries):
        try:
            response = requests.get(url, proxies={"http": "http://127.0.0.1:3333"})
            if response.status_code == 200 and "origin" in response.json():
                logging.info("Proxy relay is running successfully.")
                return True
        except requests.RequestException as e:
            logging.warning(f"Proxy relay not reachable, attempt {attempt + 1} of {retries}. Retrying in {delay} seconds... Error: {e}")
        time.sleep(delay)
    logging.error("Proxy relay failed to start after multiple attempts.")
    return False

try:
    # Start each command as a subprocess
    for command in commands:
        process = start_process(command)
        if process:
            processes.append(process)
            logging.info(f"Process {process.args} started...")
            time.sleep(1)  # Sleep for 1 second between starting each process

    # Check if the API is running
    api_url = "http://0.0.0.0:8000"
    if not check_api_status(api_url):
        raise RuntimeError("API failed to start.")

    # Check if the proxy relay is running
    test_url = "http://httpbin.org/ip"
    if not check_proxy_relay(test_url):
        raise RuntimeError("Proxy relay failed to start.")

    logging.info(f"PROXY MACHINE READY! \nAPI: {api_url} \nhttp-proxy: http://0.0.0.0:3333 ")

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
