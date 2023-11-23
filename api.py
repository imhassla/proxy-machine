from fastapi import FastAPI
from sqlalchemy import create_engine, Table, MetaData, select, and_
from starlette.responses import JSONResponse, Response, HTMLResponse
from datetime import datetime, timedelta

app = FastAPI()

engine = create_engine(
    "sqlite:///data.db",
    connect_args={'timeout': 10} 
)

metadata = MetaData()
http_table = Table('http', metadata, autoload_with=engine)
socks4_table = Table('socks4', metadata, autoload_with=engine)
socks5_table = Table('socks5', metadata, autoload_with=engine)

@app.get("/", response_class=HTMLResponse)
async def get_documentation():
    return """
    <html>
        <head>
            <title>Proxy-Machine API Documentation</title>
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
                <li><b>proxy_type</b>: The type of proxy. This can be either 'http' or 'socks4'. For example, '/proxy/http' will return HTTP proxies.</li>
                <li><b>time</b>: The maximum response time of the proxies in seconds. For example, '/proxy/http?time=1.5' will return proxies with a response time of 1.5 seconds or less.</li>
                <li><b>minutes</b>: The maximum number of minutes since the last check of the proxies. For example, '/proxy/http?time=1.5&minutes=30' will return proxies that were checked within the last 30 minutes.</li>
                <li><b>format</b>: The format of the response. This can be either 'json' or 'text'. For example, '/proxy/http?time=1.5&minutes=30&format=text' will return the proxies as a plain text list.</li>
            </ul>
        </body>
    </html>
    """

# Define a new endpoint for the FastAPI application. This is a GET request at the path "/proxy/{proxy_type}".
@app.get("/proxy/{proxy_type}")
# The function get_proxy is an asynchronous function that handles requests to the endpoint.
# It accepts four parameters: proxy_type, time, minutes, and format.
async def get_proxy(proxy_type: str, time: float, minutes: int = 30, format: str = 'json'):
    # Check if the proxy_type is valid. If not, return a 400 status code with an error message.
    if proxy_type not in ["http", "socks4","socks5"]:
        return JSONResponse(status_code=400, content={"message": "Invalid proxy type"})

    # Select the appropriate table based on the proxy_type.
    if proxy_type == "http":
        table = http_table
    elif proxy_type == "socks4":
        table = socks4_table
    else:
        table = socks5_table

    # Calculate the time threshold for filtering proxies based on the current time and the minutes parameter.
    time_threshold = datetime.now() - timedelta(minutes=minutes)

    # Create a SQL query that selects proxies from the table where the response time is less than or equal to the time parameter.
    # The results are ordered by response time.
    query = select(table.c.proxy, table.c.response_time, table.c.last_checked).where(
        table.c.response_time <= time
    ).order_by(table.c.response_time)

    # Connect to the database and execute the query.
    with engine.connect() as connection:
        result = connection.execute(query).fetchall()

    # Filter the results based on the time threshold and convert them into a list of dictionaries.
    proxies = [
        {column.name: value for column, value in zip(table.columns, row)}
        for row in result
        if datetime.strptime(row[2], '%Y-%m-%d %H:%M:%S') >= time_threshold
    ]

    # If the format parameter is 'text', join the proxies into a string with each proxy on a new line and return the string as plain text.
    # Otherwise, return the list of dictionaries as JSON.
    if format == 'text':
        return Response("\n".join([proxy['proxy'] for proxy in proxies]), media_type='text/plain')
    else:
        return proxies
