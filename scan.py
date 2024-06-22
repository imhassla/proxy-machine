import os
import sys
import time
import socks
import atexit
import random
import sqlite3
import socket
import argparse
import datetime
import ipaddress
import threading
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

# Check for correct number of arguments
parser = argparse.ArgumentParser(description='Scan open ports socks4 proxies')
parser.add_argument('-w', type=int, default=25, help='number of worker threads to use when checking proxies')
parser.add_argument('-t', type=int, default=5, help='timeout (s.) of socket')
parser.add_argument('-port', nargs='+', type=int, help='list of ports to use')
parser.add_argument('-ping', action='store_true', help='ping "1.1.1.1" before every connetcion try to enshure that network connection is availble )')
parser.add_argument('-range', nargs='+', type=str, help='list of IP address ranges in the format 1.1.1.1-2.2.2.2 or CIDR 1.1.1.0/24')
parser.add_argument('-machine', action='store_true', help='when runs from proxy-machine scrypt(or proxy.py subprocess already running)')
args = parser.parse_args()

num_threads = args.w

if not args.machine:
    # Start proxy.py script in the background
    proxy_process = subprocess.Popen(["python3", "proxy.py", "-type", "socks4", "-p 1500"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def cleanup():
    if not args.machine:
        proxy_process.terminate()

atexit.register(cleanup) 
os.system('cls' if os.name == 'nt' else 'clear')

ip_ranges = args.range
ports = args.port
socks.set_default_proxy()
time.sleep(5)

def get_random_proxy():
    with open('last_checked.txt', 'r') as f:
        proxies = f.readlines()
    if len(proxies) >= 3:
        top_third = proxies[:len(proxies)//3]
        return random.choice(top_third).strip()
    time.sleep(3)
    return None

class Ping:
    def __init__(self, host):
        self.host = host
        self.response_time = None
        self.is_running = True
        thread = threading.Thread(target=self.run, args=())
        thread.daemon = True
        thread.start()

    def run(self):
        while self.is_running:
            try:
                output = subprocess.check_output(['ping', '-c', '1', self.host])
                lines = output.splitlines()
                for line in lines:
                    if 'time=' in line.decode('utf-8'):
                        resptime = float(line.decode('utf-8').split('time=')[1].split(' ')[0])

                        self.response_time = resptime
            except subprocess.CalledProcessError:
                self.response_time = False
            time.sleep(1)

    def get_response_time(self):
        return self.response_time

    def stop(self):
        self.is_running = None

if args.ping:
    pinger = Ping('1.1.1.1')

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
            if args.ping:
                response_time = pinger.get_response_time()
                if response_time == None:
                    print(" Weak internet connection, waiting...", end="\r")
                    time.sleep(5)
                    print(" " * 40, end="\r")
                    continue
            proxy_host, proxy_port = proxy.split(':')
            sock = socks.socksocket()
            socks.set_default_proxy(socks.SOCKS4, proxy_host, int(proxy_port))
            sock.settimeout(args.t)
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
            data_to_write = []
            for ip in ips:
                for port in ports:
                    if (ip, port) not in scanned:
                        futures.append(executor.submit(scan, ip, port))
                        scanned.add((ip, port))
            for future in as_completed(futures):
                proxy, host, port, result = future.result()
                if result == True:
                    data_to_write.append((f"{host}:{port}",))
                    print(f'{host}:{port} is open. Scanned with Proxy {proxy}')
             
                sys.stdout.flush()    
        if data_to_write:
            conn = sqlite3.connect('data.db',timeout = 10)
            c = conn.cursor()
            c.execute(f'''CREATE TABLE IF NOT EXISTS {'_scan_results'} (ip_port TEXT PRIMARY KEY)''')
            c.execute('BEGIN')
            c.executemany(f'''INSERT OR REPLACE INTO _scan_results (ip_port) VALUES (?)''', data_to_write)
            c.execute('COMMIT')
            data_to_write = []
            conn.close()

    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)

try:
    scan_ips()
except KeyboardInterrupt:
    print("\nExiting...")
    sys.exit(0)

