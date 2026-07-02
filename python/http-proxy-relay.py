import aiohttp
from aiohttp import web
import random
import asyncio
import time

proxies = []
last_update = None

# Function to update proxies periodically
async def update_proxies():
    global proxies
    global last_update
    while True:
        # Check if it's time to update the proxies
        if last_update is None or (time.time() - last_update) > 10:
            proxy_api = "http://127.0.0.1:8000/proxy/http?time=3&minutes=5&format=text"
            async with aiohttp.ClientSession() as session:
                try:
                    # Fetch the list of proxies from the API
                    resp = await session.get(proxy_api)
                    proxies = (await resp.text()).split('\n')
                    last_update = time.time()
                except Exception as e:
                    print(f"Error getting proxies: {e}")
                    await asyncio.sleep(5)
        await asyncio.sleep(5)

# Function to fetch a URL using a given proxy
async def fetch(session, url, proxy=None):
    try:
        async with session.get(url, proxy=proxy, timeout=5) as response:
            return await response.text()
    except Exception as e:
        print(f"Error fetching URL with proxy {proxy}: {e}")
        return None

# HTTP request handler
async def handle(request):
    url = str(request.url)
    if not proxies:
        return web.Response(text="No active proxies", status=503)  # Return 503 Service Unavailable

    # Proxies are available, attempt to use them
    async with aiohttp.ClientSession() as session:
        for _ in range(15):
            proxy = 'http://' + random.choice(proxies)
            resp = await fetch(session, url, proxy)
            if resp:
                return web.Response(text=resp)
    
    return web.Response(text="Failed to get a response from the server after 15 attempts", status=502)  # Return 502 Bad Gateway

# Create the web application
app = web.Application()
app.router.add_get('/{url:.*}', handle)

# On startup, start updating the proxies
async def on_startup(app):
    app['update_proxies'] = asyncio.create_task(update_proxies())

app.on_startup.append(on_startup)

# Run the web application
web.run_app(app, host='0.0.0.0', port=3333)
