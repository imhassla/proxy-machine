import os
import re
import time
import socks
import socket
import sqlite3
import requests
import urllib3
import argparse
import json
import threading
import subprocess
import configparser
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from contextlib import closing
import xml.etree.ElementTree as ET
from urllib3.exceptions import ProxyError, SSLError, ConnectTimeoutError, ReadTimeoutError, NewConnectionError
import logging
from urllib3 import PoolManager

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load configuration
config = configparser.ConfigParser()
config.read('config.ini')

parser = argparse.ArgumentParser(description='The script checks uniq ip:port combinations from scan_results/ directory as http, https, socks4, socks5 proxies.')
parser.add_argument('-url', type=str, help='"URL" of the API to retrieve proxies from. Only ip:port format supported')
parser.add_argument('-sip', type=str, help='"Self ip')
parser.add_argument('-ping', action='store_true', help='ping "1.1.1.1" before check to ensure that network connection is available')
parser.add_argument('-db', action='store_true', help='recheck all proxies in db')
parser.add_argument('-clean', action='store_true', help='clean old unavailable proxies in db')
parser.add_argument('-txt', action='store_true', help='save results in txt/proxy_type.txt')
parser.add_argument('-scan', action='store_true', help='check scan results and clear "scan_results" table in db')
parser.add_argument('-type', nargs='+', type=str, default=None, choices=['http', 'https', 'socks4', 'socks5'], help='type of proxies to retrieve and check')
parser.add_argument('-mass', type=str, help='Absolute path to the masscan XML file')
parser.add_argument('-list', action='store_true', help='check proxy from open sources')
parser.add_argument('-targets', action='store_true', help='check proxy from targets.txt')
parser.add_argument('-s', nargs='+', help='check multiple server:port')
parser.add_argument('-w', type=int, default=100, help='number of worker threads to use when checking proxies')
parser.add_argument('-t', type=int, default=4, help='timeout (s.) of checker')
args = parser.parse_args()

os.system('ulimit -n 80000')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
all_checked_proxies = {}

if args.type:
    proxy_types = list(args.type) if isinstance(args.type, list) else [args.type]
else:
    proxy_types = ['http', 'https', 'socks4', 'socks5']

class Ping:
    def __init__(self, host):
        self.host = host
        self.response_time = None
        self.is_running = True
        thread = threading.Thread(target=self.run)
        thread.daemon = True
        thread.start()

    def run(self):
        while self.is_running:
            try:
                output = subprocess.check_output(['ping', '-c', '1', self.host])
                lines = output.decode().splitlines()
                for line in lines:
                    if 'time=' in line:
                        self.response_time = float(line.split('time=')[1].split(' ')[0])
            except subprocess.CalledProcessError:
                self.response_time = None
            time.sleep(1)

    def get_response_time(self):
        return self.response_time

    def stop(self):
        self.is_running = False

if args.ping:
    pinger = Ping('1.1.1.1')

if not args.sip:
    while True:
        try:
            url = 'https://httpbin.org/ip'
            response = requests.get(url)
            data = response.json()
            sip = data.get('origin')
            break
        except Exception as e:
            logging.warning(f'Connection error: {e}. Retrying in 5 seconds...')
            time.sleep(5)
else:
    sip = args.sip

def process_page(page, ip_port_pattern):
    try:
        response = requests.get(f"https://www.freeproxy.world/?page={page}")
        if response.status_code != 200:
            return []
        content = response.text
        results = []
        ip = None
        for line in content.splitlines():
            if 'port=' in line:
                port_match = re.search(r'port=([0-9]+)', line)
                if port_match:
                    port = port_match.group(1)
                    if ip:
                        results.append(f"{ip}:{port}")
                        ip = None
            elif ip_port_pattern.search(line):
                ip_match = re.search(r'(([0-9]{1,3}\.){3}[0-9]{1,3})', line)
                if ip_match:
                    ip = ip_match.group(1)
        return results
    except Exception as e:
        logging.error(f"Error processing page {page}: {e}")
        return []

# Create a global connection pool
http_pool = PoolManager(maxsize=10)  # Adjust maxsize as needed

def check_proxy(proxy, proxy_type):
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    try:
        proxy_host, proxy_port = proxy.split(':')
        url = 'https://httpbin.org/ip'
        
        if proxy_type in ['http', 'https']:
            # Use a ProxyManager for HTTP/HTTPS proxies
            http = urllib3.ProxyManager(
                f"{proxy_type}://{proxy_host}:{proxy_port}",
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
            socks.set_default_proxy(socks.SOCKS4 if proxy_type == 'socks4' else socks.SOCKS5, proxy_host, int(proxy_port))
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

def get_db_connection():
    return sqlite3.connect(config['database']['path'], timeout=30)

def load_urls_from_file(file_path):
    with open(file_path, 'r') as file:
        return file.read().splitlines()

def add_sources(start_page=1, end_page=200, num_threads=10):
    ip_port_pattern = re.compile(r'(([0-9]{1,3}\.){3}[0-9]{1,3}|port=[0-9]+)')
    all_results = set()
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        future_to_page = {executor.submit(process_page, page, ip_port_pattern): page for page in range(start_page, end_page + 1)}
        for future in as_completed(future_to_page):
            try:
                results = future.result()
                all_results.update(results)
            except Exception as e:
                logging.error(f"Error in future for page {future_to_page[future]}: {e}")
    return all_results

if __name__ == '__main__':
    data_written = False
    ip_ports = set()
    
    if args.url:
        try:
            response = requests.get(args.url)
            new_proxies = set(response.text.splitlines())
            ip_ports.update(new_proxies)
        except Exception as e:
            logging.error(f"Error fetching proxies from URL {args.url}: {e}")
    
    if args.s:
        ip_ports.update(args.s)
    
    if args.targets:
        try:
            with open('targets.txt', 'r') as file:
                ip_ports.update(file.read().splitlines())
        except Exception as e:
            logging.error(f"Error reading targets.txt: {e}")
    
    if args.list:
        logging.info('Getting targets...')
        ip_ports.update(add_sources())
        try:
            urls = load_urls_from_file('urls.txt')
            for url in urls:
                try:
                    response = requests.get(url)
                    if response.status_code == 200:
                        new_proxies = set(response.text.splitlines())
                        ip_ports.update(new_proxies)
                except Exception as e:
                    logging.error(f"Error fetching proxies from URL {url}: {e}")
        except Exception as e:
            logging.error(f"Error loading URLs from urls.txt: {e}")

    if args.mass:
        try:
            tree = ET.parse(args.mass)
            root = tree.getroot()
            for host in root.findall('host'):
                ip_address = host.find('address').get('addr')
                for port in host.findall('ports/port'):
                    portid = port.get('portid')
                    if ip_address and portid:
                        ip_ports.add(f"{ip_address}:{portid}")
        except Exception as e:
            logging.error(f"Error parsing masscan XML file {args.mass}: {e}")
    
    if args.db:
        with closing(get_db_connection()) as conn:
            c = conn.cursor()
            for proxy_type in proxy_types:
                c.execute(f'''CREATE TABLE IF NOT EXISTS {proxy_type} (proxy TEXT PRIMARY KEY, response_time REAL, last_checked TEXT)''')
                c.execute(f'''SELECT proxy FROM {proxy_type}''')
                proxies = c.fetchall()
                for proxy in proxies:
                    ip_ports.add(proxy[0])

    logging.info(f'Total proxies to check: {len(ip_ports)}')
    
    for proxy_type in proxy_types:
        logging.info(f'Checking {proxy_type} proxies...')
        
        with closing(get_db_connection()) as conn:
            c = conn.cursor()
            c.execute(f'''CREATE TABLE IF NOT EXISTS {proxy_type} (proxy TEXT PRIMARY KEY, response_time REAL, last_checked TEXT)''')
            conn.commit()
        
        checked_proxies = []
        failed_proxies = []

        with ThreadPoolExecutor(max_workers=args.w) as executor:
            futures = {executor.submit(check_proxy, p, proxy_type): p for p in ip_ports}
            for future in as_completed(futures):
                result = future.result()
                p = futures[future]
                if result is not None:
                    checked_proxies.append(result)
                else:
                    failed_proxies.append(p)

        if args.clean:
            with closing(get_db_connection()) as conn:
                c = conn.cursor()
                for p in failed_proxies:
                    c.execute(f'''DELETE FROM {proxy_type} WHERE proxy = ?''', (p,))
                conn.commit()

        if args.scan:
            with closing(get_db_connection()) as conn:
                c = conn.cursor()
                for p in ip_ports:
                    c.execute(f'''DELETE FROM {'_scan_results'} WHERE ip_port = ?''', (p,))
                conn.commit()

        all_checked_proxies[proxy_type] = sorted(checked_proxies, key=lambda x: x[1])
 
    if args.txt:
        if not os.path.exists('txt'):
            os.makedirs('txt')

    for proxy_type, checked_proxies in all_checked_proxies.items():
        proxy_list = []  

        for checked_proxy in checked_proxies:
            rounded_resp_time = round(checked_proxy[1], 2)
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            with closing(get_db_connection()) as conn:
                c = conn.cursor()
                c.execute(f'''INSERT OR REPLACE INTO {proxy_type} (proxy, response_time, last_checked) VALUES (?, ?, ?)''', (checked_proxy[0], rounded_resp_time, current_time))
                logging.info(f"{proxy_type} {checked_proxy[0]} {rounded_resp_time} s.")
                data_written = True
                conn.commit()

            proxy_list.append(checked_proxy[0])

        if args.txt:
            with open(f'txt/{proxy_type}.txt', 'w') as file:
                file.write('\n'.join(proxy_list))
                
    if not data_written:
        logging.info('No proxy found')
