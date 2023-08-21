import os
import time
import socks
import socket
import re
import json
import sqlite3
import requests
import argparse
import threading
import subprocess
import urllib.request
import concurrent.futures
from datetime import datetime
from contextlib import closing
import xml.etree.ElementTree as ET

# Set up command line argument parsing
parser = argparse.ArgumentParser(description='The script checks uniq ip:port combinations from scan_results/ directory as http, https, socks4, socks5 proxies. ')
parser.add_argument('-url', type=str, help='"URL" of the API to retrieve proxies from. Only ip:port format supported')
parser.add_argument('-ping', action='store_true', help='ping "1.1.1.1" before check to enshure that network connection is availble )')
parser.add_argument('-db', action='store_true', help='recheck all proxies in db')
parser.add_argument('-clean', action='store_true', help='clean old unavailible proxies in db')
parser.add_argument('-scan', action='store_true', help='check scan results and clear "scan_results" table in db')
parser.add_argument('-type', type=str, default= None, choices=['http', 'https', 'socks4', 'socks5'], help='type of proxies to retrieve and check')
parser.add_argument('-mass', type=str, help='Absolute path to the masscan XML file')
parser.add_argument('-list', action='store_true', help='use targets.txt as source')

parser.add_argument('-w', type=int, default=50, help='number of worker threads to use when checking proxies')
parser.add_argument('-t', type=int, default=5, help='timeout (s.) of checker')
args = parser.parse_args()

os.system('ulimit -n 4000')
os.system('cls' if os.name == 'nt' else 'clear')

if args.type:
    proxy_types = args.type
else:
    proxy_types = ['http', 'https', 'socks4', 'socks5']

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
                    if 'time' in line.decode('utf-8'):
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

# Get the user's IP address 
while True:
    try:
        # Get the user's IP address 
        url = 'https://httpbin.org/ip'
        opener = urllib.request.build_opener()
        urllib.request.install_opener(opener)
        response = urllib.request.urlopen(url)
        data = response.read().decode('utf-8')
        data = json.loads(data)
        sip = data.get('origin')
        break
    except Exception as e:
        print(f' Connection error: {e}. Retrying in 5 seconds...',end="\r")
        time.sleep(5)

def check_proxy(proxy, proxy_type):

    while True:
        # Initialize an empty dictionary to store the proxy settings for HTTP and HTTPS requests.
        proxies = {}
        try:
            # Check for internet connectivity
            if args.ping:
                response_time = pinger.get_response_time()
                if response_time == None:
                    print(" Weak internet connection, waiting...", end="\r")
                    time.sleep(5)
                    continue

            proxy_host, proxy_port = proxy.split(':')

            if proxy_type == 'http':
                proxy = urllib.request.ProxyHandler({
                    'http': f'http://{proxy_host}:{proxy_port}'
                })
                url = 'http://httpbin.org/ip'
            elif proxy_type == 'https':
                proxy = urllib.request.ProxyHandler({
                    'https': f'https://{proxy_host}:{proxy_port}'
                })
                url = 'https://httpbin.org/ip'
            elif proxy_type == 'socks4':
                socks.set_default_proxy(socks.SOCKS4, proxy_host, int(proxy_port))
                socket.socket = socks.socksocket
            elif proxy_type == 'socks5':
                socks.set_default_proxy(socks.SOCKS5, proxy_host, int(proxy_port))
                socket.socket = socks.socksocket

            if proxy_type == 'http' or proxy_type == 'https':
                opener = urllib.request.build_opener(proxy)
                urllib.request.install_opener(opener)
                start_time = time.time()
                response = urllib.request.urlopen(url, timeout=args.t)
                end_time = time.time()
                response_time = end_time - start_time
                rounded_resp_time = round(response_time,2)
                data = response.read().decode('utf-8')
                data = json.loads(data)
  
                if any(origin == sip for origin in data.get('origin').split(', ')):
                    return None
                else:
                    return (f'{proxy_host}:{proxy_port}', rounded_resp_time)               

            if proxy_type == 'socks4' or proxy_type == 'socks5':
                # Make a request to https://httpbin.org/ip using the specified proxy settings and measure the response time.
                url = 'https://httpbin.org/ip'
                r = requests.get(url, timeout=args.t)
            
                # If the request was successful and the returned IP address is different from the user's IP address, return the proxy and response time.
                if r.status_code == 200:
                    response_time = r.elapsed.total_seconds()
                    rounded_resp_time = round(response_time,2)
                    data = r.json()
                    if any(origin == sip for origin in data.get('origin').split(', ')):
                        return None
                    else:
                        return (f'{proxy_host}:{proxy_port}', rounded_resp_time) 
                    
        except (Exception) as e:
            #print(f'Error checking {proxy} as {proxy_type}: {e}')
            if args.ping:
                print(" Proxy Checks in progress... ping:",response_time, 'ms.', end="\r")
            else:
                print(" Proxy Checks in progress... (use '-ping' agrument to check connetction latency)",end="\r")
            socks.set_default_proxy()
            pass
        return None


def get_db_connection():
    conn = sqlite3.connect('data.db', timeout=10)
    return conn

if __name__ == '__main__':
    data_written = False
    if args.type:
        with closing(get_db_connection()) as conn:
            c = conn.cursor()
            c.execute(f'''CREATE TABLE IF NOT EXISTS {args.type} (proxy TEXT PRIMARY KEY, response_time REAL, last_checked TEXT)''')
            conn.commit()
    else:
        for proxy_type in proxy_types:
            with closing(get_db_connection()) as conn:
                c = conn.cursor()
                c.execute(f'''CREATE TABLE IF NOT EXISTS {proxy_type} (proxy TEXT PRIMARY KEY, response_time REAL, last_checked TEXT)''')
                conn.commit()

    ip_ports = set()
    if args.url:
        response = requests.get(args.url)
        new_proxies = set(response.text.splitlines())
        ip_ports.update(new_proxies)
    if args.mass:
        tree = ET.parse(args.mass)
        root = tree.getroot()
        for host in root.findall('host'):
            address = host.find('address').get('addr')
            port = host.find('ports').find('port').get('portid')
            ip_port = f"{address}:{port}"
            ip_ports.add(ip_port)
    if args.list:

        urls = [
            "https://github.com/TheSpeedX/PROXY-List/blob/master/socks5.txt",
            "https://github.com/TheSpeedX/PROXY-List/blob/master/socks4.txt",
            "https://github.com/TheSpeedX/PROXY-List/blob/master/http.txt",
            "https://github.com/monosans/proxy-list/blob/main/proxies/http.txt",
            "https://github.com/monosans/proxy-list/blob/main/proxies/socks4.txt",
            "https://github.com/monosans/proxy-list/blob/main/proxies/socks5.txt",
            "https://github.com/hookzof/socks5_list/blob/master/proxy.txt",
            "https://github.com/mmpx12/proxy-list/blob/master/http.txt",
            "https://github.com/mmpx12/proxy-list/blob/master/https.txt",
            "https://github.com/mmpx12/proxy-list/blob/master/socks4.txt",
            "https://github.com/mmpx12/proxy-list/blob/master/socks5.txt",
            "https://github.com/zevtyardt/proxy-list/blob/main/all.txt",
            "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/http.txt",
            "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks4.txt",
            "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks5.txt",
            "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/http/http.txt",
            "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/http/https.txt",
            "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/http/socks4.txt",
            "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/http/socks5.txt",
            "https://github.com/proxy4parsing/proxy-list/blob/main/http.txt",
            "https://github.com/roosterkid/openproxylist/blob/main/HTTPS_RAW.txt",
            "https://github.com/roosterkid/openproxylist/blob/main/SOCKS4_RAW.txt",
            "https://github.com/roosterkid/openproxylist/blob/main/SOCKS5_RAW.txt",
            "https://github.com/ALIILAPRO/Proxy/blob/main/http.txt",
            "https://github.com/ALIILAPRO/Proxy/blob/main/socks4.txt",
            "https://github.com/ALIILAPRO/Proxy/blob/main/socks5.txt"
        ]

        proxies = set()
        pattern = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+\b")

        for url in urls:
            response = requests.get(url)
            if response.status_code == 200:
                proxies.update(response.text.splitlines())

        with open("targets.txt", "w") as f:
            for proxy in proxies:
                for match in pattern.findall(proxy):
                    f.write(match + "\n")
        

        with open('targets.txt', 'r') as f:
            for line in f:
                address, port = line.strip().split(':')
                ip_port = f"{address}:{port}"
                ip_ports.add(ip_port)

    if args.db:
        if args.type:
            proxy_types = [args.type]
        else:
            proxy_types = ['http', 'https', 'socks4', 'socks5']
        for proxy_type in proxy_types:
            with closing(get_db_connection()) as conn:
                c = conn.cursor()
                c.execute(f'''SELECT proxy FROM {proxy_type}''')
                rows = c.fetchall()
                for row in rows:
                    ip_ports.add(row[0])
                conn.commit()
    if args.scan:
        with closing(get_db_connection()) as conn:
            c = conn.cursor()
            c.execute(f'''SELECT ip_port FROM {'_scan_results'}''')
            rows = c.fetchall()
            for row in rows:
                ip_ports.add(row[0])
            conn.commit()

    all_checked_proxies = {}
    if args.type:
        proxy_types = [args.type]
    else:
        proxy_types = ['http', 'https', 'socks4', 'socks5']

    for proxy_type in proxy_types:
        checked_proxies = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.w) as executor:
            futures = [executor.submit(check_proxy, p, proxy_type) for p in ip_ports]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result is not None:
                    checked_proxies.append(result)
                else:
                    if args.clean:
                        for p in ip_ports:
                            with closing(get_db_connection()) as conn:
                                c = conn.cursor()
                                c.execute(f'''DELETE FROM {proxy_type} WHERE ip_port = ?''', (p,))
                                conn.commit()
                    if args.scan:
                        for p in ip_ports:
                            with closing(get_db_connection()) as conn:
                                c = conn.cursor()
                                c.execute(f'''DELETE FROM {'_scan_results'} WHERE ip_port = ?''', (p,))
                                conn.commit()
        all_checked_proxies[proxy_type] = sorted(checked_proxies, key=lambda x: x[1])

        for proxy_type, checked_proxies in all_checked_proxies.items():
            for checked_proxy in checked_proxies:
                rounded_resp_time = round(checked_proxy[1], 2)
                current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                with closing(get_db_connection()) as conn:
                    c = conn.cursor()
                    c.execute(f'''INSERT OR REPLACE INTO {proxy_type} (proxy, response_time, last_checked) VALUES (?, ?, ?)''', (checked_proxy[0], rounded_resp_time, current_time))
                    print(f"{proxy_type} {checked_proxy[0]} {rounded_resp_time} s.")
                    data_written = True
                    conn.commit()                         
    if not data_written:
        print('No proxy found')

