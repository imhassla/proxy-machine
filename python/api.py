from fastapi import FastAPI
from sqlalchemy import create_engine, Table, MetaData, select
from sqlalchemy.orm import sessionmaker
from starlette.responses import JSONResponse, Response, HTMLResponse
from threading import Thread
from datetime import datetime, timedelta
from typing import Optional
import configparser
import time

# Load configuration
config = configparser.ConfigParser()
config.read('config.ini')

app = FastAPI()

# Create a connection to the SQLite database with connection pooling
engine = create_engine(
    f"sqlite:///{config['database']['path']}",
    connect_args={'timeout': 30},  # Set a timeout for the database connection
    pool_size=5,  # Set pool size for connection pooling
    max_overflow=10  # Allow some overflow connections
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

metadata = MetaData()

# Define tables in the database
http_table = Table('http', metadata, autoload_with=engine)
https_table = Table('https', metadata, autoload_with=engine)
socks4_table = Table('socks4', metadata, autoload_with=engine)
socks5_table = Table('socks5', metadata, autoload_with=engine)

# Global cache for proxies
proxy_cache = {
    "http": {},
    "https": {},
    "socks4": {},
    "socks5": {}
}

# Function to load proxies into memory
def load_proxies_into_cache():
    global proxy_cache
    with engine.connect() as connection:
        for proxy_type, table in [("http", http_table), ("https", https_table), ("socks4", socks4_table), ("socks5", socks5_table)]:
            last_checked = proxy_cache.get(f"last_updated_{proxy_type}", datetime.min)
            query = select(table.c.proxy, table.c.response_time, table.c.last_checked).where(
                table.c.last_checked > last_checked
            )
            result = connection.execute(query).fetchall()
            for row in result:
                proxy = {column.name: value for column, value in zip(table.columns, row)}
                proxy_cache[proxy_type][proxy['proxy']] = proxy
            proxy_cache[f"last_updated_{proxy_type}"] = datetime.now()

# Background thread to update proxy cache every 10 seconds
def update_cache_periodically():
    while True:
        load_proxies_into_cache()
        time.sleep(10)  # Sleep for 10 seconds before the next update

# Start the cache updater in a separate thread
Thread(target=update_cache_periodically, daemon=True).start()

# Route to display API documentation
@app.get("/", response_class=HTMLResponse)
async def get_documentation():
    return """
    <html>
        <head>
            <title>Proxy-Machine API Documentation</title>
            <script>
                function getServerUrl() {
                    return window.location.protocol + "//" + window.location.hostname + ":" + window.location.port;
                }
            </script>
        </head>
        <body>
            <h1>Proxy-Machine API Documentation</h1>
            <p>This API provides a list of proxies filtered based on their response time and the last time they were checked.</p>
            <h2>Supported Proxy Types</h2>
            <ul>
                <li><b>HTTP</b> </li>
                <li><b>HTTPS</b> </li>
                <li><b>SOCKS4</b> </li>
                <li><b>SOCKS5</b> </li>
            </ul>
            <h2>GET /proxy/{proxy_type}</h2>
            <p>Returns a list of proxies of the specified type.</p>
            <ul>
                <li><b>proxy_type</b>: The type of proxy. </li>
                <p>This can be either 'http', 'https', 'socks4' or 'socks5'. For example, <a href="#" onclick="window.location.href = getServerUrl() + '/proxy/http'">/proxy/http</a> will return HTTP proxies.</p>
                <li><b>time</b>: The maximum response time of the proxies in seconds. </li>
                <p>For example, <a href="#" onclick="window.location.href = getServerUrl() + '/proxy/http?time=1.5'">/proxy/http?time=1.5</a> will return proxies with a response time of 1.5 seconds or less.</p>
                <li><b>minutes</b>: The maximum number of minutes since the last check of the proxies. </li>
                <p>For example, <a href="#" onclick="window.location.href = getServerUrl() + '/proxy/http?time=3&minutes=5'">/proxy/http?time=3&minutes=5</a> will return proxies with a response time of 3 seconds or less that were checked within the last 5 minutes.</p>
                <li><b>format</b>: The format of the response. </li>
                <p>This can be either 'json' or 'text'. For example, <a href="#" onclick="window.location.href = getServerUrl() + '/proxy/http?time=3&minutes=5&format=text'">/proxy/http?time=3&minutes=5&format=text</a> will return the proxies as a plain text list.</p>
            </ul>
        </body>
    </html>
    """

# Route to get proxies based on their type and filters
@app.get("/proxy/{proxy_type}")
async def get_proxy(proxy_type: str, time: Optional[float] = None, minutes: int = 30, format: str = 'json'):
    # Check if the provided proxy type is valid
    if proxy_type not in ["http", "https", "socks4", "socks5"]:
        return JSONResponse(status_code=400, content={"message": "Invalid proxy type"})

    # Calculate the time threshold for filtering proxies
    time_threshold = datetime.now() - timedelta(minutes=minutes)

    # Filter proxies from cache based on response time and last checked time
    proxies = [
        proxy for proxy in proxy_cache[proxy_type].values()
        if (time is None or proxy['response_time'] <= time) and
           datetime.strptime(proxy['last_checked'], '%Y-%m-%d %H:%M:%S') >= time_threshold
    ]

    # Return the proxies in the requested format
    if format == 'text':
        return Response("\n".join([proxy['proxy'] for proxy in proxies]), media_type='text/plain')
    else:
        return proxies