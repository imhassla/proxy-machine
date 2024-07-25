from fastapi import FastAPI
from sqlalchemy import create_engine, Table, MetaData, select
from starlette.responses import JSONResponse, Response, HTMLResponse
from datetime import datetime, timedelta
from typing import Optional
import configparser

# Load configuration
config = configparser.ConfigParser()
config.read('config.ini')

app = FastAPI()

# Create a connection to the SQLite database
engine = create_engine(
    f"sqlite:///{config['database']['path']}",
    connect_args={'timeout': 30}  # Set a timeout for the database connection
)

metadata = MetaData()

# Define tables in the database
http_table = Table('http', metadata, autoload_with=engine)
https_table = Table('https', metadata, autoload_with=engine)
socks4_table = Table('socks4', metadata, autoload_with=engine)
socks5_table = Table('socks5', metadata, autoload_with=engine)

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
                <li><b>SOCKS4</b> </li>
                <li><b>SOCKS5</b> </li>
            </ul>
            <h2>GET /proxy/{proxy_type}</h2>
            <p>Returns a list of proxies of the specified type.</p>
            <ul>
                <li><b>proxy_type</b>: The type of proxy. </li>
                <p>This can be either 'http', 'socks4' or 'socks5'. For example, <a href="#" onclick="window.location.href = getServerUrl() + '/proxy/http'">/proxy/http</a> will return HTTP proxies.</p>
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

    # Select the appropriate table based on the proxy type
    if proxy_type == "http":
        table = http_table
    elif proxy_type == "https":
        table = https_table
    elif proxy_type == "socks4":
        table = socks4_table
    else:
        table = socks5_table

    # Calculate the time threshold for filtering proxies
    time_threshold = datetime.now() - timedelta(minutes=minutes)

    # Create a query to fetch proxies based on response time
    if time is not None:
        query = select(table.c.proxy, table.c.response_time, table.c.last_checked).where(
            table.c.response_time <= time
        ).order_by(table.c.response_time)
    else:
        query = select(table.c.proxy, table.c.response_time, table.c.last_checked).order_by(table.c.response_time)

    # Execute the query and fetch results
    with engine.connect() as connection:
        result = connection.execute(query).fetchall()

    # Filter proxies based on the last checked time
    proxies = [
        {column.name: value for column, value in zip(table.columns, row)}
        for row in result
        if datetime.strptime(row[2], '%Y-%m-%d %H:%M:%S') >= time_threshold
    ]

    # Return the proxies in the requested format
    if format == 'text':
        return Response("\n".join([proxy['proxy'] for proxy in proxies]), media_type='text/plain')
    else:
        return proxies
