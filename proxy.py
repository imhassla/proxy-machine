import requests
import schedule
import time
import os
import bs4
import logging
import argparse
import json
import socks
import socket
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed
from socks import set_default_proxy, SOCKS4, SOCKS5, HTTP, socksocket

# Set up command line argument parsing
parser = argparse.ArgumentParser(description='The script retrieves and checks http, https, socks4 and socks5 proxies')
parser.add_argument('-l', type=int, default=50, help='limit of proxies stored in checked_proxies.txt')
parser.add_argument('-p', type=int, default=800, help='ping (ms.) of the proxy server. (for default providers only)')
parser.add_argument('-t', type=int, default=5, help='timeout (s.) of checker')
parser.add_argument('-w', type=int, default=50, help='number of worker threads to use when checking proxies')
parser.add_argument('-type', type=str, default='http', choices=['http', 'https', 'socks4', 'socks5'], help='type of proxies to retrieve and check')
parser.add_argument('--top', action='store_true', help='If specified, store top 10 proxies in file')
parser.add_argument('-url', type=str, help='"URL" of the API to retrieve proxies from')
args = parser.parse_args()

# Set up logging
logging.basicConfig(level=logging.INFO)

# Clear the screen
os.system('cls' if os.name == 'nt' else 'clear')

# Set the maximum number of open file descriptors to 4000
os.system('ulimit -n 4000')

# Set the API URL for retrieving proxies based on the command line arguments or use the default URL if not specified
if args.url:
    api_url = args.url
else:
    api_url = f"https://api.proxyscrape.com/v2/?request=displayproxies&protocol={args.type}&timeout={args.p}&country=all&ssl=all&anonymity=all"

# Set the maximum number of proxies to store in memory and other variables based on the command line arguments
max = args.l*6 
t = args.t
workers = args.w

# Initialize a set to store the proxies and other variables for tracking proxy statistics and availability
proxies = set()
checked_filename = "checked_proxies.txt"
top10_filename = "top10.txt"
file_lock = Lock()
proxy_stats = {}
proxy_type = args.type
proxy_absence_count = {}

# Get the user's IP address by making a request to 2ip.ua and parsing the response using Beautiful Soup
selfip = requests.get('https://2ip.ua/ru/')
b = bs4.BeautifulSoup(selfip.text, "html.parser")
sip = b.select(" .ipblockgradient .ip")[0].getText()
sip = sip.strip()

# Create or clear the checked_proxies.txt file
open(checked_filename, "w+").close()

# Print a message indicating that data is being retrieved from sources and primary proxy checks are being performed
txt = '\033[1;36mGetting data from sources and primary proxy checks. \nStatistics will be displayed soon...\033[0m'
for i in txt:  
    time.sleep(0.01)
    print(i, end='', flush=True)

# Define a function to check a single proxy by making a request to https://httpbin.org/ip using the proxy and measuring the response time.
def check_proxy(proxy):
    # Initialize an empty dictionary to store the proxy settings for HTTP and HTTPS requests.
    proxies = {} 
    try:
        # Split the proxy string into host and port components.
        proxy_host, proxy_port = proxy.split(':')       
        # Set up the proxy settings based on the type of proxy specified by the command line arguments.
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
        # If an error occurs, reset the default proxy settings and continue.
        #print(f'Error: {e}') #for debug
        socks.set_default_proxy()
        pass
    # If the proxy check was not successful, return None.
    return None

# Define a function to retrieve proxies from various sources and update the set of proxies in memory.
def get_proxies():
    # Reset the default proxy settings.
    socks.set_default_proxy()
    # If the number of proxies in memory has reached the maximum limit, clear the set of proxies.
    if len(proxies) >= max:
        with file_lock:
            proxies.clear()
    # If the number of checked proxies in the checked_proxies.txt file has reached the limit specified by the command line arguments, return without retrieving any new proxies.
    with open(checked_filename, 'r') as f:
        if len(f.readlines()) > args.l:
            return
    # Try to retrieve proxies from the API URL specified by the command line arguments or the default API URL.
    try:
        response = requests.get(api_url)
        new_proxies = set(response.text.splitlines())
        with file_lock:
            # Update the set of proxies in memory with any new proxies that were not already in the set.
            proxies.update(new_proxies - proxies)
    except requests.exceptions.RequestException as e:
        logging.error(f"An error occurred while getting proxies: {e}")
        pass

    # Define additional sources for retrieving proxies.
    additional_sources = [
        f"https://www.proxyscan.io/api/proxy?format=txt&limit=100&type={args.type}&uptime=20&ping={args.p}",
        f"https://www.proxy-list.download/api/v1/get?type={args.type}"
    ]
    # Try to retrieve proxies from each additional source.
    for source in additional_sources:
        try:
            response = requests.get(source)
            new_proxies = set(response.text.splitlines()[:args.l*3])
            with file_lock:
                # Update the set of proxies in memory with any new proxies that were not already in the set.
                proxies.update(new_proxies - proxies)
        except requests.exceptions.RequestException as e:
            logging.error(f"An error occurred while getting proxies from {source}: {e}")
            pass

# Define a function to check all of the proxies in memory and in the checked_proxies.txt file using multiple worker threads.
def check_proxies():
    # Read the checked_proxies.txt file and combine its contents with the set of proxies in memory to create a set of all known proxies.
    with open(checked_filename, "r") as f:
        checked_proxies = set(f.read().splitlines())
        all_proxies = proxies | checked_proxies

    # Use a ThreadPoolExecutor to check all of the known proxies concurrently using multiple worker threads.
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
                proxy = futures[future]
                # If a proxy check was not successful, remove it from the set of proxies in memory.
                proxies.discard(proxy)

    # Sort the list of alive proxies by response time and extract only the proxy strings from each tuple.
    alive_proxies = sorted(results, key=lambda x: x[1])
    alive_proxies = [proxy[0] for proxy in alive_proxies]

    # Write the list of alive proxies to the checked_proxies.txt file.
    with file_lock, open(checked_filename, "w") as f:
        for proxy in alive_proxies:
            f.write(proxy + "\n")

# Define a function to track the availability of checked proxies over time and display statistics about their uptime.
def track_proxies():
    # Read the checked_proxies.txt file to get a list of currently available (checked) proxies.
    with open(checked_filename, "r") as f:
        checked_proxies = set(f.read().splitlines())

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
        if proxy_absence_count[proxy] > 1:
            del proxy_stats[proxy]
            del proxy_absence_count[proxy]

    # Sort the list of proxies by their uptime (count) and get the top 10 proxies.
    top_10_proxies = sorted(proxy_stats.items(), key=lambda x: x[1], reverse=True)[:10]
    
    # Create a list of strings to display information about the top 10 proxies by uptime.
    output_strs = [f"\033[1;36mTop {args.type} proxies by availability time:\033[0m\n"]
    for i, (proxy, count) in enumerate(top_10_proxies):
        output_strs.append(f"\033[1;33m{i+1}.\033[0m {proxy} \033[32malive for {round(count/6, 2)} min.\033[0m")
    
    output_strs.append("")
    output_str = "\n".join(output_strs)
    
    # Clear the screen and print information about the number of proxies in memory and in the checked_proxies.txt file as well as information about the top 10 proxies by uptime.
    os.system('cls' if os.name == 'nt' else 'clear')

    print(f"proxies in memory:\033[1m\033[31m {len(proxies)}\033[0m")
    print(f"proxies in {checked_filename}: \033[1m\033[32m {len(checked_proxies)}\033[0m\n")

    print(output_str)

    # If the --top command line argument was specified, write the top 10 proxies to a file (top10.txt).
    if args.top:
        if not os.path.exists(top10_filename):
            open(top10_filename, "w").close()

        file_output_str = "\n".join([proxy[0] for proxy in top_10_proxies])
        
        with open(top10_filename, "w") as f:
            f.write(file_output_str)

# Define the main function to run when the script is executed.
if __name__ == "__main__":
    # Schedule the get_proxies, check_proxies, and track_proxies functions to run at regular intervals using the schedule library.
    schedule.every(14).seconds.do(get_proxies)
    schedule.every(20).seconds.do(check_proxies)
    schedule.every(10).seconds.do(track_proxies)

    try:
        # Continuously run scheduled tasks until interrupted by a keyboard interrupt (Ctrl-C).
        while True:
            schedule.run_pending()
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info('Exiting...')
