import subprocess
import requests
import sys
import threading
import random
import time
import sqlite3
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
import ipaddress

# Global counters and storage
successful_proxies = 0
active_checker_threads = 0
total_zmap_addresses = 0
lock = threading.Lock()
checked_set = set()  # To store unique IP:port combinations
scanned_ranges_ports = set()  # Store unique /24 ranges and ports to avoid re-scanning

# Queue to hold IP addresses to check
checker_queue = Queue()

# Get own IP
while True:
    try:
        url = 'https://httpbin.org/ip'
        response = requests.get(url)
        data = response.json()
        sip = data.get('origin')
        break
    except Exception as e:
        print(f'Connection error: {e}. Retrying in 5 seconds...', end="\r")
        time.sleep(5)

# Retrieve proxies from the database
def get_proxies_from_db(proxy_type):
    proxies = []
    conn = sqlite3.connect('data.db')
    cursor = conn.cursor()
    try:
        cursor.execute(f"SELECT proxy FROM {proxy_type}")
        proxies = [row[0] for row in cursor.fetchall()]
        random.shuffle(proxies)
    except Exception as e:
        print(f"Error fetching proxies from database: {e}")
    finally:
        conn.close()
    return proxies

# Updated get_all_ranges_ports_from_db to get unique ranges and ports
def get_all_ranges_ports_from_db(proxy_type):
    ranges_ports = []
    conn = sqlite3.connect('data.db')
    cursor = conn.cursor()
    try:
        cursor.execute(f"SELECT DISTINCT proxy FROM {proxy_type}")
        all_ports = set()
        all_ranges = set()

        for row in cursor.fetchall():
            ip, port = row[0].split(":")
            network = str(ipaddress.ip_network(f"{ip}/24", strict=False))
            all_ranges.add(network)
            all_ports.add(int(port))

        # Now generate combinations of each range with all available ports
        for network in all_ranges:
            for port in all_ports:
                ranges_ports.append((network, port))

    except Exception as e:
        print(f"Error fetching ranges and ports from database: {e}")
    finally:
        conn.close()
    return ranges_ports

def run_checker(proxy_type):
    global successful_proxies, active_checker_threads
    while True:
        ip, port = checker_queue.get()
        
        checker_cmd = ["python", "checker.py", "-sip", sip, "-type", proxy_type, "-t", "3", "-s", f"{ip}:{port}"]

        with lock:
            active_checker_threads += 1

        process = subprocess.Popen(checker_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            output, _ = process.communicate(timeout=5)
            if output.decode().strip().endswith("s."):
                with lock:
                    successful_proxies += 1
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait()  # Ensure subprocess termination
            #print(f"Checker timeout for {ip}:{port}")
        except Exception as e:
            print(f"Error in checker for {ip}:{port}: {e}")
        finally:
            with lock:
                active_checker_threads -= 1

        checker_queue.task_done()

def run_zmap(ip, port):
    global total_zmap_addresses
    network = str(ipaddress.ip_network(f"{ip}/24", strict=False))

    with lock:
        if (network, port) in scanned_ranges_ports:
            return  # Skip if already scanned
        else:
            scanned_ranges_ports.add((network, port))  # Add unique combination

    zmap_cmd = ["zmap", "-B", "5M", "-p", str(port), network]
    zmap_process = subprocess.Popen(zmap_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        stdout, stderr = zmap_process.communicate(timeout=9999)  # Use communicate() for bulk read
        for line in stdout.decode().splitlines():
            ip_address = line.strip()
            with lock:
                total_zmap_addresses += 1

            if (ip_address, port) not in checked_set:
                with lock:
                    checked_set.add((ip_address, port))  # Add to unique set
                checker_queue.put((ip_address, port))  # Add to check queue
    except subprocess.TimeoutExpired:
        zmap_process.terminate()
        zmap_process.wait()  # Ensure subprocess termination
        #print(f"ZMap timeout for {network}:{port}")
    except Exception as e:
        print(f"Error in ZMap for {network}:{port}: {e}")

def print_status():
    while True:
        with lock:
            print(f"Active checker threads: {active_checker_threads} | Queue size: {checker_queue.qsize()} | Total ZMap addresses: {total_zmap_addresses} | Successful proxies: {successful_proxies}")
        time.sleep(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <proxy_type>")
        sys.exit(1)
    threading.Thread(target=print_status, daemon=True).start()

    while True:
        try:
            proxy_type = sys.argv[1]
            proxies = get_proxies_from_db(proxy_type)
            all_ranges_ports = get_all_ranges_ports_from_db(proxy_type)
            
            if not proxies:
                print("No proxies found in the database.")
                sys.exit(1)

            

            with ThreadPoolExecutor(max_workers=100) as checker_executor:
                for _ in range(100):  # Start 100 threads for processing the queue
                    checker_executor.submit(run_checker, proxy_type)

                with ThreadPoolExecutor(max_workers=10) as executor:
                    future_to_proxy = {executor.submit(run_zmap, ip, port): proxy 
                                    for proxy in proxies for ip, port in [proxy.split(":")]}
                    
                    for future in as_completed(future_to_proxy):
                        proxy = future_to_proxy[future]
                        try:
                            future.result()
                        except Exception as exc:
                            print(f"Proxy {proxy} generated an exception: {exc}")

            checker_queue.join()
        except Exception as e:
            print(e)
        finally:
            time.sleep(5)