import subprocess
import threading
import requests
import queue
import sqlite3
import random
import urllib3
import time
import os
import re
import argparse
import json
import socks
import socket
import configparser
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from socks import set_default_proxy, SOCKS4, SOCKS5, socksocket
from urllib3.exceptions import ProxyError, SSLError, ConnectTimeoutError, ReadTimeoutError, NewConnectionError
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load configuration
config = configparser.ConfigParser()
config.read('config.ini')

# Parse command-line arguments
parser = argparse.ArgumentParser(description='Script for retrieving and checking http, https, socks4, and socks5 proxies')
parser.add_argument('-p', type=int, default=5000, help='ping (ms) of the proxy server (default providers only)')
parser.add_argument('-t', type=int, default=5, help='timeout (s) for checker')
parser.add_argument('-w', type=int, default=200, help='number of worker threads for proxy checking')
parser.add_argument('-type', type=str, default='socks4', choices=['http', 'https', 'socks4', 'socks5'], help='type of proxies to retrieve and check')
parser.add_argument('-api', action='store_true', help='skip tracking proxies if specified')
parser.add_argument('-scan', action='store_true', help='run scan.py for checked proxy IP ranges if specified')
parser.add_argument('-sw', type=int, default=3, help='number of scanner worker threads')
parser.add_argument('-db', action='store_true', help='store checked proxies in database')
parser.add_argument('-url', type=str, help='URL of the API to retrieve proxies from')
args = parser.parse_args()

# Clear the screen
os.system('ulimit -n 50000')

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize a set to store the proxies and other variables for tracking proxy statistics and availability
proxy_type = args.type
proxies = set()
alive_proxies_set = set()
semaphore = threading.Semaphore(args.sw) 
proxy_stats = {}

t = args.t
workers = args.w
if args.scan:
    proxy_type = 'socks4'
proxy_absence_count = {}
process = None

# Set the API URL for retrieving proxies based on the command line arguments or use the default URL if not specified
if args.url:
    api_url = args.url
else:
    api_url = f"https://api.proxyscrape.com/v2/?request=displayproxies&protocol={proxy_type}&timeout={args.p}&country=all&ssl=all&anonymity=all"

# Get the user's IP address 
while True:
    try:
        ip_url = 'https://httpbin.org/ip'
        response = requests.get(ip_url)
        data = response.json()
        sip = data.get('origin')
        break
    except Exception as e:
        logging.warning(f'Connection error: {e}. Retrying in 5 seconds...')
        time.sleep(5)

# Create a global connection pool for HTTP/HTTPS proxies
http_pool = urllib3.PoolManager(maxsize=10)

# Function to check proxies
def check_proxy(proxy, proxy_type):
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    try:
        proxy_host, proxy_port = proxy.split(':')
        url = 'https://httpbin.org/ip'
        
        if proxy_type in ['http', 'https']:
            # Use a ProxyManager for HTTP/HTTPS proxies
            proxy_url = f"{proxy_type}://{proxy_host}:{proxy_port}"
            http = urllib3.ProxyManager(
                proxy_url,
                timeout=urllib3.Timeout(connect=args.t, read=args.t),
                retries=False,
                cert_reqs='CERT_NONE',
                assert_hostname=False
            )
            start_time = time.time()
            response = http.request('GET', url, preload_content=False)
            response_time = time.time() - start_time
            data = json.loads(response.data.decode('utf-8'))
            response.release_conn()  # Ensure the connection is released
            
            if any(origin == sip for origin in data.get('origin').split(', ')):
                return None
            else:
                logging.info(f"Successful proxy: {proxy_host}:{proxy_port} with response time {response_time:.2f}s")
                return f'{proxy_host}:{proxy_port}', response_time, current_time
        
        elif proxy_type in ['socks4', 'socks5']:
            # Use socks for SOCKS proxies
            socks.set_default_proxy(SOCKS4 if proxy_type == 'socks4' else SOCKS5, proxy_host, int(proxy_port))
            socket.socket = socks.socksocket
            headers = {'X-Forwarded-For': proxy_host}
            r = requests.get(url, timeout=args.t, verify=False, headers=headers)
            
            if r.status_code == 200:
                response_time = r.elapsed.total_seconds()
                data = r.json()
                
                if any(origin == sip for origin in data.get('origin').split(', ')):
                    return None
                else:
                    logging.info(f"Successful proxy: {proxy_host}:{proxy_port} with response time {response_time:.2f}s")
                    return f'{proxy_host}:{proxy_port}', response_time, current_time
    
    except (NewConnectionError, SSLError, ProxyError, ConnectTimeoutError, ReadTimeoutError) as e:
        if isinstance(e, NewConnectionError) and "Too many open files" in str(e):
            logging.warning("Too many open files error encountered.")
        return None
    except Exception as e:
        logging.debug(f"Unexpected error checking proxy {proxy}: {e}")
        return None
    finally:
        socks.set_default_proxy()
        socket.socket = socket.socket
    
    return None

# Function to retrieve proxies from API and additional sources
def get_proxies():
    try:
        socks.set_default_proxy()
        try:
            response = requests.get(api_url)
            new_proxies = set(response.text.splitlines())
            proxies.update(new_proxies - proxies)
        except Exception as e:
            logging.debug(f"Error fetching proxies from API: {e}")

        additional_sources = [
            f"https://www.proxy-list.download/api/v1/get?type={proxy_type}",
            f"https://github.com/mmpx12/proxy-list/blob/master/{proxy_type}.txt",
            f"https://github.com/ErcinDedeoglu/proxies/blob/main/proxies/{proxy_type}.txt",
            f"http://pubproxy.com/api/proxy?limit=5&format=txt?type={proxy_type}",
            f"https://github.com/Anonym0usWork1221/Free-Proxies/blob/main/proxy_files/{proxy_type}_proxies.txt",
        ]

        ip_port_pattern = re.compile(r'^\d{1,3}(\.\d{1,3}){3}:\d+$')

        for source in additional_sources:
            try:
                response = requests.get(source)
                new_proxies = set(line.strip() for line in response.text.splitlines() if ip_port_pattern.match(line.strip()))
                proxies.update(new_proxies - proxies)
            except Exception as e:
                logging.debug(f"Error fetching proxies from source {source}: {e}")
    except Exception as e:
        logging.error(f"Unexpected error in get_proxies: {e}")

# Function to save proxy details to the queue
def save_proxy_to_queue(proxy, rounded_resp_time, current_time):
    db_queue.put((proxy, rounded_resp_time, current_time))

# Function to periodically write queue data to database
def db_writer():
    conn = sqlite3.connect(config['database']['path'], timeout=30, check_same_thread=False)
    c = conn.cursor()
    c.execute(f'''CREATE TABLE IF NOT EXISTS {proxy_type} (proxy TEXT PRIMARY KEY, response_time REAL, last_checked TEXT)''')
    conn.close()

    while True:
        try:
            conn = sqlite3.connect(config['database']['path'], timeout=30)
            c = conn.cursor()
            while not db_queue.empty():
                proxy, rounded_resp_time, current_time = db_queue.get()
                c.execute(f'''INSERT OR REPLACE INTO {proxy_type} (proxy, response_time, last_checked) VALUES (?, ?, ?)''', (proxy, rounded_resp_time, current_time))
                db_queue.task_done()
            conn.commit()
        except Exception as e:
            logging.error(f"Database write error: {e}")
            conn.rollback()
        finally:
            conn.close()
            time.sleep(3)

# Function to check proxies in memory
def check_proxies():
    while True:
        try:
            if not proxies:
                time.sleep(3)
                continue
            with ThreadPoolExecutor(max_workers=workers // 2) as executor:
                futures = {executor.submit(check_proxy, proxy, proxy_type): proxy for proxy in random.sample(list(proxies), len(proxies))}
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        proxy, rounded_resp_time, current_time = result
                        rounded_resp_time = round(rounded_resp_time, 2)
                        alive_proxies_set.add(proxy)
                        save_proxy_to_queue(proxy, rounded_resp_time, current_time)
                    else:
                        proxies.discard(futures[future])
        except Exception as e:
            logging.error(f"Error in check_proxies: {e}")

# Function to recheck alive proxies periodically
def recheck_alive_proxies():
    while True:
        try:
            alive_proxies = set(alive_proxies_set)
            with ThreadPoolExecutor(max_workers=workers // 2) as executor:
                futures = {executor.submit(check_proxy, proxy, proxy_type): proxy for proxy in alive_proxies}
                for future in as_completed(futures):
                    if future.result() is None:
                        alive_proxies_set.discard(futures[future])
            time.sleep(10)
        except Exception as e:
            logging.error(f"Error in recheck_alive_proxies: {e}")

# Function to track proxy statistics
def track_proxies():
    checked_proxies = alive_proxies_set.copy()
    for proxy in checked_proxies:
        proxy_stats[proxy] = proxy_stats.get(proxy, 0) + 1
        proxy_absence_count.pop(proxy, None)
    
    absent_proxies = set(proxy_stats) - checked_proxies
    for proxy in absent_proxies:
        proxy_absence_count[proxy] = proxy_absence_count.get(proxy, 0) + 1
        if proxy_absence_count[proxy] > 0:
            del proxy_stats[proxy]
            del proxy_absence_count[proxy]
    
    top_10_proxies = sorted(proxy_stats.items(), key=lambda x: x[1], reverse=True)[:10]
    output_strs = [f"\033[1;36mTop {proxy_type} proxies by availability time:\033[0m\n"]
    for i, (proxy, count) in enumerate(top_10_proxies):
        output_strs.append(f"\033[1;33m{i+1}.\033[0m {proxy} \033[32malive for {round(count/6, 2)} min.\033[0m")
    output_strs.append("")
    output_str = "\n".join(output_strs)
    
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"proxies in memory:\033[1m\033[31m {len(proxies)}\033[0m")
    print(output_str)

def get_ip_ranges():
    data = list(alive_proxies_set)
    ip_ranges = set()
    ports = set()
    for line in data:
        ip, port = line.split(':')
        ip_range = '.'.join(ip.split('.')[:-1]) + '.0/24'
        ip_ranges.add(ip_range)
        ports.add(port)
    return ip_ranges, ports

def run_scan(ip_range, ports):
    # Acquire the semaphore before starting the scan
    semaphore.acquire()
    try:
        # Convert the list of ports to a list of strings
        ports_str = [str(port) for port in ports]
        # Start the scan.py script as a subprocess

        process = subprocess.Popen(
            ['python3', 'scan.py', '-ping', '-machine', '-range', ip_range, '-port', *ports_str],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        try:
            # Wait for the subprocess to finish
            process.wait()
        except KeyboardInterrupt:
            # Terminate the subprocess if Ctrl-C is pressed
            process.terminate()
            # Wait for the subprocess to terminate
            process.wait()
            # Re-raise the KeyboardInterrupt exception
            raise
    finally:
        # Release the semaphore when the scan is finished
        semaphore.release()

def scan_ip_ranges():
    # Keep running indefinitely
    while True:
        # Get the list of IP ranges and ports
        ip_ranges, ports = get_ip_ranges()
        # Convert the set of ports to a list
        ports = list(ports)
        # Keep track of the scanned IP ranges
        scanned_ip_ranges = set()
        # Check if ip_ranges or ports are empty
        while not ip_ranges or not ports:
            # Retry getting the list of IP ranges and ports
            ip_ranges, ports = get_ip_ranges()
            time.sleep(3)
        with ThreadPoolExecutor() as executor:
            while ip_ranges:
                # Submit a task to the executor for each IP range
                for ip_range in ip_ranges:
                    if ip_range not in scanned_ip_ranges:
                        executor.submit(run_scan, ip_range, ports)
                        scanned_ip_ranges.add(ip_range)
                # Get the updated list of IP ranges
                ip_ranges, ports = get_ip_ranges()

def run_thread(func, interval):
    # Run the given function at the specified interval
    while True:
        try:
            func()   
            time.sleep(interval)
        except Exception as e:
            logging.error(f"Error in run_thread: {e}")

# Main execution
if __name__ == "__main__":
    
    if args.db:
        conn = sqlite3.connect(config['database']['path'], timeout=30, check_same_thread=False)
        c = conn.cursor()
        c.execute(f"SELECT proxy FROM {proxy_type} WHERE response_time <= {t}")
        new_proxies = set([row[0] for row in c.fetchall()])
        proxies.update(new_proxies - proxies)
        conn.close()

    db_queue = queue.Queue()  
    db_writer_thread = threading.Thread(target=db_writer, daemon=True)
    db_writer_thread.start()
    
    if args.scan:
        scan_thread = threading.Thread(target=scan_ip_ranges)
        scan_thread.start()
        
    t1 = threading.Thread(target=run_thread, args=(get_proxies, 15))
    t2 = threading.Thread(target=check_proxies)
    if not args.api:
        t3 = threading.Thread(target=run_thread, args=(track_proxies, 10))
    t4 = threading.Thread(target=recheck_alive_proxies)
    
    t1.start()
    t2.start()
    if not args.api:
        t3.start()
    t4.start()
    
    t2.join()
    t4.join()
