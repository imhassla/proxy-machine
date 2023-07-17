import os
import bs4
import time
import socks
import socket
import random
import logging
import requests
import argparse
import threading
import subprocess
import concurrent.futures
from datetime import datetime

ip_ports = set()


colors = {
    'http': '\033[94m',  # Blue
    'https': '\033[92m', # Green
    'socks4': '\033[93m', # Yellow
    'socks5': '\033[91m' # Red
}
reset_color = '\033[0m'

# Set up command line argument parsing
parser = argparse.ArgumentParser(description='The script checks uniq ip:port combinations from scan_results/ directory as http, https, socks4, socks5 proxies. ')
parser.add_argument('-url', type=str, help='"URL" of the API to retrieve proxies from. Only ip:port format supported')
parser.add_argument('-ping', action='store_true', help='ping "1.1.1.1" before check to enshure that network connection is availble )')
parser.add_argument('-type', type=str, default= None, choices=['http', 'https', 'socks4', 'socks5'], help='type of proxies to retrieve and check')
parser.add_argument('-w', type=int, default=15, help='number of worker threads to use when checking proxies')
parser.add_argument('-t', type=int, default=5, help='timeout (s.) of checker')
args = parser.parse_args()

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

# Get the user's IP address by making a request to 2ip.ua and parsing the response using Beautiful Soup
while True:
    try:
        selfip = requests.get('https://2ip.ua/ru/')
        b = bs4.BeautifulSoup(selfip.text, "html.parser")
        sip = b.select(" .ipblockgradient .ip")[0].getText()
        sip = sip.strip()
        break
    except Exception as e:
        print(f' Connection error: {e}. Retrying in 5 seconds...',end="\r")
        time.sleep(5)

os.system('cls' if os.name == 'nt' else 'clear')

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
                    print(" " * 40, end="\r")
                    continue

            proxy_host, proxy_port = proxy.split(':')

            if proxy_type == 'http':
                proxies = {
                    'http': f'http://{proxy_host}:{proxy_port}',
                    'https': f'http://{proxy_host}:{proxy_port}'
                }
            elif proxy_type == 'https':
                proxies = {
                    'http': f'https://{proxy_host}:{proxy_port}',
                    'https': f'https://{proxy_host}:{proxy_port}'
                }
            elif proxy_type == 'socks4':
                socks.set_default_proxy(socks.SOCKS4, proxy_host, int(proxy_port))
                socket.socket = socks.socksocket
            elif proxy_type == 'socks5':
                socks.set_default_proxy(socks.SOCKS5, proxy_host, int(proxy_port))
                socket.socket = socks.socksocket

            # Make a request to https://httpbin.org/ip using the specified proxy settings and measure the response time.
            url = 'https://httpbin.org/ip'
            r = requests.get(url, proxies=proxies, timeout=args.t)

            # If the request was successful and the returned IP address is different from the user's IP address, return the proxy and response time.
            if r.status_code == 200:
                data = r.json()
                if data.get('origin') != sip:
                    response_time = r.elapsed.total_seconds()
                    return (proxy, response_time)
        except (Exception) as e:
            #print(f'Error checking {proxy} as {proxy_type}: {e}')
            if args.ping:
                print(" Proxy Checks in progress... ping:",response_time, 'ms.', end="\r")
            else:
                print(" Proxy Checks in progress... (use '-ping' agrument to check connetction latency)",end="\r")
            socks.set_default_proxy()
            pass
        return None

if __name__ == '__main__':

    start_time = datetime.now().strftime('%Y%m%d%H%M%S')
    checker_results_dir = 'checker_results'
    os.makedirs(checker_results_dir, exist_ok=True)
    result_file_path = os.path.join(checker_results_dir, f'{start_time}.txt')
    if args.url:
        response = requests.get(args.url)
        new_proxies = set(response.text.splitlines())
        ip_ports.update(new_proxies)
    else:
        for filename in os.listdir('scan_results/'):
            if filename.endswith('.txt'):
                with open(os.path.join('scan_results/', filename), 'r') as f:
                    for line in f:
                        ip_ports.add(line.strip())
    try:
        data_written = False
        all_checked_proxies = {}
        for proxy_type in proxy_types:
            checked_proxies = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.w) as executor:
                futures = [executor.submit(check_proxy, p, proxy_type) for p in ip_ports]
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result is not None:
                        checked_proxies.append(result)
            all_checked_proxies[proxy_type] = sorted(checked_proxies, key=lambda x: x[1])

        with open(result_file_path, 'w') as f:
            os.system('cls' if os.name == 'nt' else 'clear')
            for proxy_type, checked_proxies in all_checked_proxies.items():
                for checked_proxy in checked_proxies:
                    rounded_resp_time = round(checked_proxy[1], 2)

                    f.write(f"{proxy_type} {checked_proxy[0]} {rounded_resp_time} s.\n")
                    color = colors.get(proxy_type, reset_color)
                    proxy_color = colors.get(proxy_type, reset_color)
                    print(f"{proxy_color}{proxy_type}{reset_color} {checked_proxy[0]} {rounded_resp_time} s.")
                    data_written = True               
    
                # Check if any data was written to the file
        if not data_written:
                # Delete the file if no data was written
            os.remove(result_file_path)
            print('No proxy found')
            
    except KeyboardInterrupt:
        logging.info('Exiting...')
