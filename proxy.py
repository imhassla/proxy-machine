import imp
import requests
import schedule
import time
import os
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import argparse
import json
import socks
import socket
import http.client
from http.client import HTTPSConnection, HTTPConnection
from urllib.parse import urlparse
import python_socks 
import urllib
from socks import set_default_proxy, SOCKS4, SOCKS5, HTTP, socksocket

parser = argparse.ArgumentParser(description='The script retrieve and check http, https, socks4 and socks5 proxies')
parser.add_argument('-l', type=int, default=50, help='limit of proxies stored in checked_proxies.txt')
parser.add_argument('-p', type=int, default=800, help='ping (ms.) of the proxy server. (for default providers only)')
parser.add_argument('-t', type=int, default=5, help='timeout (s.) of checker')
parser.add_argument('-w', type=int, default=50, help='number of worker threads to use when checking proxies')
parser.add_argument('-type', type=str, default='http', choices=['http', 'https', 'socks4', 'socks5'], help='type of proxies to retrieve and check')
parser.add_argument('--top', action='store_true', help='If specified, store top 10 proxies in file')
parser.add_argument('-url', type=str, help='"URL" of the API to retrieve proxies from')
args = parser.parse_args()

logging.basicConfig(level=logging.INFO)
os.system('cls' if os.name == 'nt' else 'clear')
os.system('ulimit -n 4000')

if args.url:
    api_url = args.url
else:
    api_url = f"https://api.proxyscrape.com/v2/?request=displayproxies&protocol={args.type}&timeout={args.p}&country=all&ssl=all&anonymity=all"

max = args.l*6 #max proxies in memory
t = args.t
workers = args.w
proxies = set()
checked_filename = "checked_proxies.txt"
top10_filename = "top10.txt"
file_lock = Lock()
proxy_stats = {}
proxy_type = args.type
proxy_absence_count = {}

open(checked_filename, "w+").close()

txt = '\033[1;36mGetting data from sources and primary proxy checks. \nStatistics will be displayed soon...\033[0m'
for i in txt:  
    time.sleep(0.01)
    print(i, end='', flush=True)
# Create the checked proxies and top 10 files if they do not exist.

def check_proxy(proxy):
    # Check if a proxy is available by sending a GET request to https://httpbin.org/ip.
    try:
        start_time = time.time()
        proxy_host, proxy_port = proxy.split(':')       
        proxies = None
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
        
        url = 'https://httpbin.org/ip'
        r = requests.get(url, proxies=proxies, timeout=args.t)
        
        if r.status_code == 200:
            # If the proxy is available, check if the response contains the proxy IP.
            data = r.json()
            if proxy.split(':')[0] in data.get('origin').split(', '):
                # If one of the IP addresses in the response matches the proxy IP, return its response time.
                response_time = time.time() - start_time
                return (proxy, response_time)
    except (Exception) as e:
        #print(f'Error: {e}')  #for debug
        pass
    return None

#old checker - faster but not 100% true checks
""" def check_proxy(proxy):
    # Check if a proxy is available by sending a HEAD request to https://httpbin.org/ip.
    try:
        start_time = time.time()
        session = requests.Session()
        session.proxies = {args.type: f'{args.type}://{proxy}'}
        r = session.head('https://httpbin.org/ip', timeout=args.t)
        if r.ok:
            # If the proxy is available, return its response time.
            response_time = time.time() - start_time
            return (proxy, response_time)
        else:
            proxies.discard(proxy)
    except requests.exceptions.RequestException:
        pass
    return None
 """

def get_proxies():
    # Check if the number of records in the checked_filename file exceeds 100
    with open(checked_filename, 'r') as f:
        if len(f.readlines()) > args.l:
            return
    try:
        response = requests.get(api_url)
        new_proxies = set(response.text.splitlines())
        with file_lock:
            # Update the set of proxies with any new proxies that were retrieved.
            proxies.update(new_proxies - proxies)
    except requests.exceptions.RequestException as e:
        # Log any errors that occur while retrieving proxies from the API.
        logging.error(f"An error occurred while getting proxies: {e}")

    # Retrieve a list of proxies from the additional sources.
    additional_sources = [
        f"https://www.proxyscan.io/api/proxy?format=txt&limit=100&type={args.type}&uptime=20&ping={args.p}",
        f"https://www.proxy-list.download/api/v1/get?type={args.type}"
    ]
    for source in additional_sources:
        try:
            response = requests.get(source)
            new_proxies = set(response.text.splitlines()[:args.l*3])
            with file_lock:
                # Update the set of proxies with any new proxies that were retrieved.
                proxies.update(new_proxies - proxies)
        except requests.exceptions.RequestException as e:
            # Log any errors that occur while retrieving proxies from the additional sources.
            logging.error(f"An error occurred while getting proxies from {source}: {e}")

def check_proxies():
    # Check all known proxies for availability.
    with open(checked_filename, "r") as f:
        checked_proxies = set(f.read().splitlines())
        all_proxies = proxies | checked_proxies

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {}
        for proxy in all_proxies:
            future = executor.submit(check_proxy, proxy)
            futures[future] = proxy
        results = []
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                results.append(result)
            else:
                # If the check_proxy function returns None, remove the proxy from the collection of proxies.
                proxy = futures[future]
                proxies.discard(proxy)

    # Sort the available proxies by response time.
    alive_proxies = sorted(results, key=lambda x: x[1])
    alive_proxies = [proxy[0] for proxy in alive_proxies]

    # Update the checked proxies file with the list of available proxies.
    with file_lock, open(checked_filename, "w") as f:
        for proxy in alive_proxies:
            f.write(proxy + "\n")

    # Clear the set of retrieved proxies if it has reached the maximum size.
    if len(proxies) >= max:
        with file_lock:
            proxies.clear()

def track_proxies():
    # Track the top 10 proxies by continuous availability time.
    with open(checked_filename, "r") as f:
        checked_proxies = set(f.read().splitlines())

    for proxy in checked_proxies:
        if proxy not in proxy_stats:
            proxy_stats[proxy] = 1
        else:
            proxy_stats[proxy] += 1

        if proxy in proxy_absence_count:
            del proxy_absence_count[proxy]

    absent_proxies = set(proxy_stats.keys()) - checked_proxies
    for proxy in absent_proxies:
        if proxy not in proxy_absence_count:
            proxy_absence_count[proxy] = 1
        else:
            proxy_absence_count[proxy] += 1

        if proxy_absence_count[proxy] > 1:
            del proxy_stats[proxy]
            del proxy_absence_count[proxy]

    # Sort the proxies by continuous availability time and select the top 10.
    top_10_proxies = sorted(proxy_stats.items(), key=lambda x: x[1], reverse=True)[:10]
    
    # Generate the output strings for the console.
    output_strs = [f"\033[1;36mTop {args.type} proxies by availability time:\033[0m\n"]
    for i, (proxy, count) in enumerate(top_10_proxies):
        output_strs.append(f"\033[1;33m{i+1}.\033[0m {proxy} \033[32malive for {round(count/6, 2)} min.\033[0m")
    
    output_strs.append("")
    output_str = "\n".join(output_strs)
    os.system('cls' if os.name == 'nt' else 'clear')

    # Display the number of proxies in checked_filename and in the proxies set.
    #print(f"proxies in memory:\033[1m\033[31m {len(proxies)}\033[0m")        #for debug
    print(f"proxies in {checked_filename}: \033[1m\033[32m {len(checked_proxies)}\033[0m\n")

    # Print the top 10 proxies to the console.
    print(output_str)

    if args.top:
        if not os.path.exists(top10_filename):
            open(top10_filename, "w").close()

        # Generate the output string for the top 10 file.
        file_output_str = "\n".join([proxy[0] for proxy in top_10_proxies])
        
        # Update the top 10 file with the list of top 10 proxies.
        with open(top10_filename, "w") as f:
            f.write(file_output_str)

if __name__ == "__main__":
    # Schedule the get_proxies and check_proxies functions to run periodically.
    schedule.every(14).seconds.do(get_proxies)
    schedule.every(20).seconds.do(check_proxies)
    schedule.every(10).seconds.do(track_proxies)

    try:
        while True:
            schedule.run_pending()
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info('Exiting...')
