import os
import sys
import time
import socks
import atexit
import random
import socket
import argparse
import datetime
import ipaddress
import threading
import ipaddress
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed


# Check for correct number of arguments
parser = argparse.ArgumentParser(description='Scan open ports socks4 proxies')
parser.add_argument('-w', type=int, default=25, help='number of worker threads to use when checking proxies')
parser.add_argument('-port', nargs='+', type=int, help='list of ports to use')
parser.add_argument('-range', nargs='+', type=str, help='list of IP address ranges in the format 1.1.1.1-2.2.2.2 or CIDR 1.1.1.0/24')
parser.add_argument('-machine', action='store_true', help='when runs from proxy-machine scrypt (or proxy.py subprocess already running)')
args = parser.parse_args()
num_threads = args.w

if not args.machine:
    # Start proxy.py script in the background
    proxy_process = subprocess.Popen(["python3", "proxy.py", "-type", "socks4", "-l 35", "-p 1500"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def cleanup():
    if not args.machine:
        proxy_process.terminate()

atexit.register(cleanup) 
os.system('cls' if os.name == 'nt' else 'clear')

ip_ranges = args.range
ports = args.port
socks.set_default_proxy()
time.sleep(5)

os.makedirs("scan_results", exist_ok=True)
timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
filename = f"scan_results/{timestamp}.txt"
with open(filename, "w+") as f:
    f.close()

def get_random_proxy():
    with open('checked_proxies.txt', 'r') as f:
        proxies = f.readlines()
    if proxies:
        return random.choice(proxies).strip()
    time.sleep(3)
    return None
    

def get_ip_ranges():
    ips = []
    if ip_ranges:
        for ip_range in ip_ranges:
            if '/' in ip_range:
                # CIDR format
                net = ipaddress.ip_network(ip_range)
                for ip in net:
                    ips.append(str(ip))
            else:
                # Range format
                start, end = ip_range.strip().split('-')
                start = ipaddress.IPv4Address(start)
                end = ipaddress.IPv4Address(end)
                for ip_int in range(int(start), int(end)+1):
                    ips.append(str(ipaddress.IPv4Address(ip_int)))
    else:
        with open('range.txt', 'r') as f:
            ranges = f.readlines()
        for r in ranges:
            if '/' in r:
                # CIDR format
                net = ipaddress.ip_network(r.strip())
                for ip in net:
                    ips.append(str(ip))
            else:
                # Range format
                start, end = r.strip().split('-')
                start = ipaddress.IPv4Address(start)
                end = ipaddress.IPv4Address(end)
                for ip_int in range(int(start), int(end)+1):
                    ips.append(str(ipaddress.IPv4Address(ip_int)))
    return ips

def scan(host, port):
    while True:
        try:           
            proxy = get_random_proxy()
            if proxy is None:
                print(" Waiting for proxies...", end="\r")
                time.sleep(7)
                print(" " * 40, end="\r")
                continue
            ip_pool = ["8.8.8.8", "1.1.1.1", "8.8.4.4"]
            random_ip = random.choice(ip_pool)
            response = subprocess.run(["ping", "-c", "1", random_ip], stdout=subprocess.DEVNULL)
            if response.returncode != 0:
                print(" No internet connection, waiting...", end="\r")
                time.sleep(8)
                print(" " * 40, end="\r")
                continue
            print(" Scan in progress...", end="\r")
            proxy_host, proxy_port = proxy.split(':')
            sock = socks.socksocket()
            socks.set_default_proxy(socks.SOCKS4, proxy_host, int(proxy_port))
            sock.settimeout(5)
            try:
                sock.connect((host, port))
                sock.shutdown(2)
                sock.close()
                return ((proxy, host, port, True))
            except (socket.timeout, ConnectionRefusedError, OSError):
                return (proxy, host, port, False)
        except ValueError:
            continue

def scan_ips(max_threads=num_threads):
    try:
        ips = get_ip_ranges()
        scanned = set()
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = []
            for ip in ips:
                for port in ports:
                    if (ip, port) not in scanned:
                        futures.append(executor.submit(scan, ip, port))
                        scanned.add((ip, port))
            for future in as_completed(futures):
                proxy, host, port, result = future.result()
                if result == True:
                    print(f'{host}:{port} is open. Scaned with Proxy {proxy}')
                    with open(filename, "a") as f:
                        f.write(f"{host}:{port}\n")
                sys.stdout.flush()           
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)

try:
    scan_ips()
except KeyboardInterrupt:
    print("\nExiting...")
    sys.exit(0)
