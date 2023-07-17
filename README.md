# Proxy Machine

- proxy.py - retrieves and checks HTTP, HTTPS, SOCKS4, and SOCKS5 proxies.

- scan.py - performs port scaning with socks4 socket using founded proxies.

- checker.py - checks all types of proxies from scan_results or custom API '-url'


The availability of all proxies is checked using a GET request to https://httpbin.org/ip. 

Only those proxies that do not reveal the current external address of the system where the proxy checker is running are marked as available and alive.

Every script can be run from the command line with several optional arguments to specify the requred ping of the proxy server, the timeout of the checker, the number of worker threads to use when checking proxies, the type of proxies to retrieve and check, URL of the API to retrieve proxies from 
- use '-h' or '-help' argumets to see all options of every script
  

## Install
Install python3 and python3-pip:
- `sudo apt update`
- `sudo apt install python3`
- `sudo apt install python3-pip`
  
Clone repo and install dependencies:
- `git clone https://github.com/imhassla/proxy-machine.git`
- `cd proxy-machine`
- `pip install -r requirements.txt`

## Usage
- `python3 proxy.py -type http` to retrieve and check http proxy

The script will continue to run until interrupted by the user (e.g., by pressing Ctrl-C). 

While running, it will periodically retrieve, check, and track proxies, updating the `checked_proxies.txt` 

main options:
- `  -h, --help `           show help message 
- `  -l `                   limit of proxies stored in checked_proxies.txt                       
- `  -t `                   timeout (s.) of checker  
- `  -w `                   number of worker threads to use when checking proxies                  
- `  -url 'URL' `           custom "URL" of the API to retrieve proxies from
- ` -type {http,https,socks4,socks5}`
type of proxies to retrieve and check (default=http)  

![alt text](https://github.com/imhassla/proxy-machine/blob/main/img/demo_machine.png)

- `python3 scan.py -range 1.1.1.0/24 1.2.3.0/24 -port 53 80 8080` runs proxy.py in background to retrieve socks4 proxies and perform port scan ower founded proxies for all ip-range with every selected port

![alt text](https://github.com/imhassla/proxy-machine/blob/main/img/demo_scan.png)

- `python3 checker.py -ping` chech all uniq scan results ip:port combinations as HTTP, HTTPS, SOCKS4, and SOCKS5 proxy, print results and store log in checher_results folder.
- `python3 checker.py -ping -url 'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=all&timeout=300'` check API source list as all types of proxies, print results and store log in checher_results folder.

![alt text](https://github.com/imhassla/proxy-machine/blob/main/img/demo_checker.png)

## Troubleshooting

If you encounter any issues while running this script, try checking the following:

- Make sure that all dependencies are installed and up-to-date.
- Check that you have specified valid values for any command-line arguments.
- If you are using a custom API URL to retrieve proxies, make sure that it is correctly formatted and returns a valid list of proxies.

## Limitations

The accuracy of the proxy availability checks may vary depending on network conditions and other factors. Proxies that are reported as available may not always be accessible or reliable.

## License

This script is distributed under the MIT license. 
