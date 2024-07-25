import subprocess
import threading
import requests
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
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import ThreadPoolExecutor
from socks import set_default_proxy, SOCKS4, SOCKS5, HTTP, socksocket
from urllib3.exceptions import ProxyError, SSLError, ConnectTimeoutError, ReadTimeoutError

# Set up command line argument parsing
parser = argparse.ArgumentParser(description='The script retrieves and checks http, https, socks4 and socks5 proxies')
parser.add_argument('-p', type=int, default=5000, help='ping (ms.) of the proxy server. (for default providers only)')
parser.add_argument('-t', type=int, default=5, help='timeout (s.) of checker')
parser.add_argument('-w', type=int, default=200, help='number of worker threads to use when checking proxies')
parser.add_argument('-type', type=str, default='socks4', choices=['http', 'https', 'socks4', 'socks5'], help='type of proxies to retrieve and check')
parser.add_argument('-api', action='store_true', help='If specified, dont track proxies ')
parser.add_argument('-scan', action='store_true', help='If specified, perform scan.py for checked proxies ip ranges.')
parser.add_argument('-sw', type=int, default=3, help='number of scanner workers threads')
parser.add_argument('-db', action='store_true', help='store checked proxies in db')
parser.add_argument('-url', type=str, help='"URL" of the API to retrieve proxies from')
args = parser.parse_args()

# Clear the screen
os.system('cls' if os.name == 'nt' else 'clear')
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

# Print a message indicating that data is being retrieved from sources and primary proxy checks are being performed
txt = '\033[1;36mGetting data from sources and primary proxy checks. \nStatistics will be displayed soon...\033[0m'
for i in txt:  
    time.sleep(0.01)
    print(i, end='', flush=True)

# Get the user's IP address 
while True:
    try:
        ip_url = 'https://httpbin.org/ip'
        response = requests.get(ip_url)
        data = response.json()
        sip = data.get('origin')
        break
    except Exception as e:
        print(f' Connection error: {e}. Retrying in 5 seconds...',end="\r")
        time.sleep(5)

def check_proxy(proxy, proxy_type):
    # Record the current time in the format YYYY-MM-DD HH:MM:SS
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    try:
        # Split the proxy string into host and port
        proxy_host, proxy_port = proxy.split(':')
        # Define the URL for checking the proxy
        url = 'https://httpbin.org/ip'
        
        # Check if the proxy type is 'http' or 'https'
        if proxy_type in ['http', 'https']:
            # Create a ProxyManager instance for the given proxy
            http = urllib3.ProxyManager(
                f"{proxy_type}://{proxy_host}:{proxy_port}",
                timeout=urllib3.Timeout(connect=args.t, read=args.t),  # Set connection and read timeouts
                retries=False,  # Disable retries in urllib3
                cert_reqs='CERT_NONE',  # Do not verify SSL certificates
                assert_hostname=False  # Do not verify hostname in SSL certificate
            )
            
            # Record the start time for measuring response time
            start_time = time.time()
            # Make a GET request through the proxy
            response = http.request('GET', url, preload_content=False)
            # Record the end time for measuring response time
            end_time = time.time()
            # Calculate the response time
            response_time = end_time - start_time
            # Decode the response data from bytes to string and parse it as JSON
            data = json.loads(response.data.decode('utf-8'))
            
            # Check if the IP address returned by the proxy matches the user's IP address
            if any(origin == sip for origin in data.get('origin').split(', ')):
                return None  # If the IP matches, the proxy is valid but no need to return any data
            else:
                # If the IP does not match, return a tuple with the proxy details and response time
                return (f'{proxy_host}:{proxy_port}', response_time, current_time)
        
        # Check if the proxy type is 'socks4' or 'socks5'
        elif proxy_type in ['socks4', 'socks5']:
            # Configure the SOCKS proxy based on the type
            if proxy_type == 'socks4':
                socks.set_default_proxy(socks.SOCKS4, proxy_host, int(proxy_port))
                socket.socket = socks.socksocket
            elif proxy_type == 'socks5':
                socks.set_default_proxy(socks.SOCKS5, proxy_host, int(proxy_port))
                socket.socket = socks.socksocket
            
            # Make a GET request through the SOCKS proxy
            r = requests.get(url, timeout=args.t, verify=False)
            
            # Check if the response status code is 200 (OK)
            if r.status_code == 200:
                # Calculate the response time
                response_time = r.elapsed.total_seconds()
                # Parse the response as JSON
                data = r.json()
                
                # Check if the IP address returned by the proxy matches the user's IP address
                if any(origin == sip for origin in data.get('origin').split(', ')):
                    return None  # If the IP matches, the proxy is valid but no need to return any data
                else:
                    # If the IP does not match, return a tuple with the proxy details and response time
                    return (f'{proxy_host}:{proxy_port}', response_time, current_time)
    
    except (Exception, SSLError, ProxyError, ConnectTimeoutError, ReadTimeoutError) as e:
        # Handle exceptions related to the proxy check
        # Uncomment the line below to print the error message for debugging
        # print(f"General Error for proxy {proxy}: {e}")
        return None  # Return None if any exception occurs
    
    finally:
        # Reset the SOCKS proxy to the default state
        socks.set_default_proxy()
        # Reset the socket to the default socket
        socket.socket = socket.socket
    
    # Return None if no valid response was obtained
    return None


def get_proxies():
    try:
        # Reset the default proxy settings.
        socks.set_default_proxy()
        # Try to retrieve proxies from the API URL specified by the command line arguments or the default API URL.
        try:
            response = requests.get(api_url)
            new_proxies = set(response.text.splitlines())
            proxies.update(new_proxies - proxies)
        except:
            pass
        # Define additional sources for retrieving proxies.
        additional_sources = [
            f"https://www.proxy-list.download/api/v1/get?type={proxy_type}",
            f"https://github.com/mmpx12/proxy-list/blob/master/{proxy_type}.txt",
            f"https://github.com/ErcinDedeoglu/proxies/blob/main/proxies/{proxy_type}.txt",
            f"https://github.com/Anonym0usWork1221/Free-Proxies/blob/main/proxy_files/{proxy_type}_proxies.txt",
        ]

        ip_port_pattern = re.compile(r'^\d{1,3}(\.\d{1,3}){3}:\d+$')

        # Try to retrieve proxies from each additional source.
        for source in additional_sources:
            try:
                response = requests.get(source)
                new_proxies = set(line.strip() for line in response.text.splitlines() if ip_port_pattern.match(line.strip()))
                proxies.update(new_proxies - proxies)
            except:
                pass

        # If the args.db argument is specified, retrieve proxies from the database.
        if args.db:
            conn = sqlite3.connect('data.db', timeout=10)
            c = conn.cursor()
            c.execute(f"SELECT proxy FROM {proxy_type} WHERE response_time <= {t}")
            new_proxies = set([row[0] for row in c.fetchall()])
            proxies.update(new_proxies - proxies)
            conn.close()
    except:
        pass

def check_proxies():
    # Infinite loop to check proxies stored in memory
    while True:
        try:
            # If the proxies list is empty, wait for 1 second and continue the loop
            if not proxies:
                time.sleep(1)
                continue
            # Use ThreadPoolExecutor for parallel proxy checking
            with ThreadPoolExecutor(max_workers=workers/2) as executor:
                futures = {}
                # Check each proxy in the proxies list
                for proxy in random.sample(list(proxies), len(proxies)):
                    # Submit the task of checking the proxy to the thread pool
                    future = executor.submit(check_proxy, proxy, proxy_type)
                    futures[future] = proxy
                # Iterate over completed futures
                for future in as_completed(futures):
                    result = future.result()
                    # If the result is not None, the proxy is alive
                    if result is not None:
                        proxy, rounded_resp_time, current_time = result
                        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        rounded_resp_time = round(rounded_resp_time, 2)
                        alive_proxies_set.add(proxy)
                        # If the database option is enabled, store the proxy information in the database
                        if args.db:
                            conn = sqlite3.connect('data.db',timeout = 30)
                            c = conn.cursor()
                            c.execute(f'''CREATE TABLE IF NOT EXISTS {proxy_type} (proxy TEXT PRIMARY KEY, response_time REAL, last_checked TEXT)''')
                            c.execute('BEGIN')
                            c.execute(f'''INSERT OR REPLACE INTO {proxy_type} (proxy, response_time, last_checked) VALUES (?, ?, ?)''', (proxy, rounded_resp_time, current_time))
                            c.execute('COMMIT')
                            conn.close()
                    # If the result is None, the proxy is dead and should be removed from the proxies list
                    else:
                        proxy = futures[future]
                        proxies.discard(proxy)
        except:
            pass
                
def recheck_alive_proxies():
    while True:
        try:
            # Create a copy of the set of alive proxies
            alive_proxies = set(alive_proxies_set)
            # Use a ThreadPoolExecutor to check all of the alive proxies concurrently using multiple worker threads.
            with ThreadPoolExecutor(max_workers=workers/2) as executor:
                futures = {}
                for proxy in alive_proxies:
                    future = executor.submit(check_proxy, proxy, proxy_type)
                    futures[future] = proxy
                for future in as_completed(futures):
                    result = future.result()
                    if result is None:
                        proxy = futures[future]
                        # If a proxy check was not successful, remove it from the set of alive proxies in memory.
                        alive_proxies_set.discard(proxy)
            # Sleep for 10 seconds before rechecking the proxies again.
            time.sleep(10)
        except:
            pass

def track_proxies():
    checked_proxies = alive_proxies_set.copy()
    # For each checked proxy, increment its count in the proxy_stats dictionary. If it is not already present in the dictionary, add it with an initial count of 1.
    for proxy in checked_proxies:
        if proxy not in proxy_stats:
            proxy_stats[proxy] = 1
        else:
            proxy_stats[proxy] += 1
        # If the proxy was previously absent, remove it from the proxy_absence_count dictionary.
        if proxy in proxy_absence_count:
            del proxy_absence_count[proxy]
    # Find any proxies that were previously present in the proxy_stats dictionary but are no longer available (checked).
    absent_proxies = set(proxy_stats.keys()) - checked_proxies
    # For each absent proxy, increment its count in the proxy_absence_count dictionary. If it is not already present in the dictionary, add it with an initial count of 1.
    for proxy in absent_proxies:
        if proxy not in proxy_absence_count:
            proxy_absence_count[proxy] = 1
        else:
            proxy_absence_count[proxy] += 1
        # If a proxy has been absent for more than one iteration, remove it from both the proxy_stats and proxy_absence_count dictionaries.
        if proxy_absence_count[proxy] > 0:
            del proxy_stats[proxy]
            del proxy_absence_count[proxy]
    # Sort the list of proxies by their uptime (count) and get the top 10 proxies.
    top_10_proxies = sorted(proxy_stats.items(), key=lambda x: x[1], reverse=True)[:10]
    # Create a list of strings to display information about the top 10 proxies by uptime.
    output_strs = [f"\033[1;36mTop {proxy_type} proxies by availability time:\033[0m\n"]
    for i, (proxy, count) in enumerate(top_10_proxies):
        output_strs.append(f"\033[1;33m{i+1}.\033[0m {proxy} \033[32malive for {round(count/6, 2)} min.\033[0m")
    output_strs.append("")
    output_str = "\n".join(output_strs)
    
    # Clear the screen and print information about the number of proxies in memory and in the last_checked.txt file as well as information about the top 10 proxies by uptime.
    os.system('cls' if os.name == 'nt' else 'clear')

    print(f"proxies in memory:\033[1m\033[31m {len(proxies)}\033[0m")
    print(output_str)
    with open('last_checked.txt', 'w') as f:
        for proxy in absent_proxies:
            f.write(proxy + '\n')

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
        except:
            pass

if __name__ == "__main__":
    if args.scan:
        scan_thread = threading.Thread(target=scan_ip_ranges)
        scan_thread.start()
        
    # Create and start threads for each of the functions
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
    
    t1.join()
    t2.join()
    t3.join()
    t4.join()
