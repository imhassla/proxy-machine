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
import concurrent.futures
from datetime import datetime
from contextlib import closing
import xml.etree.ElementTree as ET
from urllib3.exceptions import ProxyError, SSLError, ConnectTimeoutError, ReadTimeoutError

# Load configuration
config = configparser.ConfigParser()
config.read('config.ini')

parser = argparse.ArgumentParser(description='The script checks uniq ip:port combinations from scan_results/ directory as http, https, socks4, socks5 proxies. ')
parser.add_argument('-url', type=str, help='"URL" of the API to retrieve proxies from. Only ip:port format supported')
parser.add_argument('-sip', type=str, help='"Self ip')
parser.add_argument('-ping', action='store_true', help='ping "1.1.1.1" before check to enshure that network connection is availble )')
parser.add_argument('-db', action='store_true', help='recheck all proxies in db')
parser.add_argument('-clean', action='store_true', help='clean old unavailible proxies in db')
parser.add_argument('-txt', action='store_true', help='save results in txt/proxy_type.txt')
parser.add_argument('-scan', action='store_true', help='check scan results and clear "scan_results" table in db')
parser.add_argument('-type', nargs='+', type=str, default= None, choices=['http', 'https', 'socks4', 'socks5'], help='type of proxies to retrieve and check')
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
    if isinstance(args.type, str):
        proxy_types = [args.type]
    else:
        proxy_types = list(args.type)
else:
    proxy_types = ['http', 'https', 'socks4', 'socks5']

class Ping:
    def __init__(self, host):
        # Initialize the Ping class with the host to ping
        self.host = host
        # Variable to store the response time from the ping
        self.response_time = None
        # Flag to indicate whether the ping thread should keep running
        self.is_running = True
        # Create and start a new thread that runs the `run` method
        thread = threading.Thread(target=self.run)
        # Set the thread as a daemon so it will exit when the main program exits
        thread.daemon = True
        thread.start()

    def run(self):
        # Continuously ping the host while the `is_running` flag is True
        while self.is_running:
            try:
                # Execute the ping command and capture the output
                output = subprocess.check_output(['ping', '-c', '1', self.host])
                # Decode the output from bytes to string and split into lines
                lines = output.decode().splitlines()
                # Iterate over each line to find the response time
                for line in lines:
                    if 'time=' in line:
                        # Extract the response time from the line
                        self.response_time = float(line.split('time=')[1].split(' ')[0])
            except subprocess.CalledProcessError:
                # Handle the case where the ping command fails
                self.response_time = None
            # Sleep for 1 second before the next ping
            time.sleep(1)

    def get_response_time(self):
        # Return the last recorded response time
        return self.response_time

    def stop(self):
        # Set the `is_running` flag to False to stop the ping thread
        self.is_running = False

# If the -ping argument is provided, create an instance of the Ping class
if args.ping:
    pinger = Ping('1.1.1.1')

if not args.sip:
# Retrieve the user's IP address by making a request to httpbin.org
    while True:
        try:
            url = 'https://httpbin.org/ip'
            # Make a GET request to retrieve the IP address
            response = requests.get(url)
            # Parse the response JSON data
            data = response.json()
            # Extract the IP address from the response data
            sip = data.get('origin')
            break  # Exit the loop if the request is successful
        except Exception as e:
            # Handle connection errors and retry after a short delay
            print(f' Connection error: {e}. Retrying in 5 seconds...', end="\r")
            time.sleep(5)
else:
    sip = args.sip

def process_page(page, ip_port_pattern):
    # Fetch the content of the page from freeproxy.world
    response = requests.get(f"https://www.freeproxy.world/?page={page}")
    # If the response status code is not 200 (OK), return an empty list
    if response.status_code != 200:
        return []
    content = response.text
    # Initialize an empty list to store results
    results = []
    # Initialize a variable to store the current IP address being processed
    ip = None

    # Split the page content into lines and process each line
    for line in content.splitlines():
        # Check if the line contains 'port=' to extract port information
        if 'port=' in line:
            # Use regex to find the port number
            port_match = re.search(r'port=([0-9]+)', line)
            if port_match:
                # Extract the port number from the match
                port = port_match.group(1)
                # If an IP address was previously found, add it to the results with the port
                if ip:
                    results.append(f"{ip}:{port}")
                    ip = None
        # Check if the line matches the IP pattern
        elif ip_port_pattern.search(line):
            # Use regex to find the IP address
            ip_match = re.search(r'(([0-9]{1,3}\.){3}[0-9]{1,3})', line)
            if ip_match:
                # Extract the IP address from the match
                ip = ip_match.group(1)
    return results

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
            # Headers including 'X-Forwarded-For'
            headers = {
                'X-Forwarded-For': proxy_host  # This will explicitly set the proxy forwarding IP
            }

            r = requests.get(url, timeout=args.t, verify=False, headers=headers)
            
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

def get_db_connection():
    # Establish a connection to the SQLite database with a timeout of 30 seconds
    conn = sqlite3.connect(config['database']['path'], timeout=30)
    return conn

def load_urls_from_file(file_path):
    # Open the file specified by 'file_path' in read mode
    with open(file_path, 'r') as file:
        # Read the content of the file and split it into lines
        urls = file.read().splitlines()
    return urls

def add_sources(start_page=1, end_page=200, num_threads=10):
    # Compile a regular expression pattern to match IP addresses and ports
    ip_port_pattern = re.compile(r'(([0-9]{1,3}\.){3}[0-9]{1,3}|port=[0-9]+)')
    # Initialize a set to store all unique proxy addresses
    all_results = set()
    
    # Use a ThreadPoolExecutor to manage concurrent execution of page processing
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        # Submit tasks to process each page and associate each future with its page number
        future_to_page = {executor.submit(process_page, page, ip_port_pattern): page for page in range(start_page, end_page + 1)}
        
        # Process completed futures as they finish
        for future in as_completed(future_to_page):
            try:
                # Retrieve the results from the future and update the set of all results
                results = future.result()
                all_results.update(results)
            except:
                # Ignore any exceptions raised during future processing
                pass
    
    return all_results

if __name__ == '__main__':
    # Flag to track if any data has been written to the database
    data_written = False
    # Initialize a set to store proxy addresses
    ip_ports = set()
    
    # If a URL is provided via command line arguments, fetch and add proxies from it
    if args.url:
        response = requests.get(args.url)
        new_proxies = set(response.text.splitlines())
        ip_ports.update(new_proxies)
    
    # If server addresses are provided via command line arguments, add them to the set
    if args.s:
        ip_ports.update(args.s)
    
    # If 'targets.txt' file is specified, read and add proxies from it
    if args.targets:
        with open('targets.txt', 'r') as file:
            ip_ports.update(file.read().splitlines())
    
    # If the -list argument is provided, fetch additional proxies from sources
    if args.list:
        print('Getting targets...')
        ip_ports.update(add_sources())
        # Load URLs from 'urls.txt' file
        urls = load_urls_from_file('urls.txt')
        for url in urls:
            try:
                # Fetch and add proxies from each URL
                response = requests.get(url)
                if response.status_code == 200:
                    new_proxies = set(response.text.splitlines())
                    ip_ports.update(new_proxies)
            except:
                # Ignore any exceptions raised during URL fetching
                pass

    # If a masscan XML file is specified, parse and add targets from it
    if args.mass:
        tree = ET.parse(args.mass)
        root = tree.getroot()
        for host in root.findall('host'):
            ip_address = host.find('address').get('addr')
            for port in host.findall('ports/port'):
                portid = port.get('portid')
                if ip_address and portid:
                    ip_ports.add(f"{ip_address}:{portid}")
    
    # If the -db argument is provided, fetch and add proxies from the database
    if args.db:
        with closing(get_db_connection()) as conn:
            c = conn.cursor()
            # Create tables for each proxy type if they don't already exist
            for proxy_type in proxy_types:
                c.execute(f'''CREATE TABLE IF NOT EXISTS {proxy_type} (proxy TEXT PRIMARY KEY, response_time REAL, last_checked TEXT)''')
                c.execute(f'''SELECT proxy FROM {proxy_type}''')
                proxies = c.fetchall()
                for proxy in proxies:
                    ip_ports.add(proxy[0])

    # Print the total number of proxies to check
    print(f'Total proxies to check: {len(ip_ports)}')
    
    # For each proxy type, check the proxies and process results
    for proxy_type in proxy_types:
        print(f'Checks {proxy_type} in progress...')
        
        # Create table for proxy type if not already created
        with closing(get_db_connection()) as conn:
            c = conn.cursor()
            c.execute(f'''CREATE TABLE IF NOT EXISTS {proxy_type} (proxy TEXT PRIMARY KEY, response_time REAL, last_checked TEXT)''')
            conn.commit()
        
        # Initialize lists to keep track of checked and failed proxies
        checked_proxies = []
        failed_proxies = []

        # Use ThreadPoolExecutor to manage concurrent proxy checks
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.w) as executor:
            # Submit tasks to check each proxy and associate each future with its proxy address
            futures = {executor.submit(check_proxy, p, proxy_type): p for p in ip_ports}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                p = futures[future]
                if result is not None:
                    # If the proxy check succeeds, add the result to checked_proxies
                    checked_proxies.append(result)
                else:
                    # If the proxy check fails, add the proxy to failed_proxies
                    failed_proxies.append(p)

        # If the -clean argument is provided, remove failed proxies from the database
        if args.clean:
            for p in failed_proxies:
                with closing(get_db_connection()) as conn:
                    c = conn.cursor()
                    c.execute(f'''DELETE FROM {proxy_type} WHERE proxy = ?''', (p,))
                    conn.commit()

        # If the -scan argument is provided, remove scanned proxies from the database
        if args.scan:
            for p in ip_ports:
                with closing(get_db_connection()) as conn:
                    c = conn.cursor()
                    c.execute(f'''DELETE FROM {'_scan_results'} WHERE ip_port = ?''', (p,))
                    conn.commit()

        # Store the checked proxies, sorted by response time
        all_checked_proxies[proxy_type] = sorted(checked_proxies, key=lambda x: x[1])
 
    # For each proxy type, insert or replace the checked proxies into the database
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
                # Print the proxy details and response time
                print(f"{proxy_type} {checked_proxy[0]} {rounded_resp_time} s.")
                data_written = True
                conn.commit()

            proxy_list.append(checked_proxy[0])

        if args.txt:
            with open(f'txt/{proxy_type}.txt', 'w') as file:
                file.write('\n'.join(proxy_list))
                
    # Print a message if no proxies were found
    if not data_written:
        print('No proxy found')
