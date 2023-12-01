import aiohttp
from aiohttp import web
import random
import asyncio
import time

proxies = []
last_update = None

async def update_proxies():
    global proxies
    global last_update
    while True:
        if last_update is None or (time.time() - last_update) > 10:
            proxy_api = "http://127.0.0.1:8000/proxy/http?time=2&minutes=2&format=text"
            async with aiohttp.ClientSession() as session:
                try:
                    resp = await session.get(proxy_api)
                    proxies = (await resp.text()).split('\n')
                    last_update = time.time()
                except Exception as e:
                    print(f"Error getting proxies: {e}")
                    await asyncio.sleep(5)
        await asyncio.sleep(1)

async def fetch(session, url, proxy=None):
    async with session.get(url, proxy=proxy) as response:
        return await response.text()

async def handle(request):
    url = str(request.url)
    if not proxies:
        return web.Response(text="No active proxies")
    for _ in range(5):
        proxy = 'http://' + random.choice(proxies)
        async with aiohttp.ClientSession() as session:
            try:
                resp = await asyncio.wait_for(fetch(session, url, proxy), timeout=3)
                return web.Response(text=resp)
            except asyncio.TimeoutError:
                continue
            except:
                continue
    return web.Response(text="Failed to get a response from the server after 5 attempts")

app = web.Application()
app.router.add_get('/{url:.*}', handle)

async def on_startup(app):
    app['update_proxies'] = asyncio.create_task(update_proxies())

app.on_startup.append(on_startup)

web.run_app(app, host='127.0.0.1', port=3333)
