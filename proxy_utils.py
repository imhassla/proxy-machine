import time
import json
import socks
import socket
import urllib3
import requests
import ssl
import logging
from datetime import datetime
from typing import Optional, Tuple
from urllib3.exceptions import (
    ProxyError,
    SSLError,
    ConnectTimeoutError,
    ReadTimeoutError,
    NewConnectionError,
)


def check_proxy(
    proxy: str,
    proxy_type: str,
    sip: str,
    timeout_seconds: int,
    target_url: str,
) -> Optional[Tuple[str, float, str]]:
    """
    Validate a proxy by requesting target_url and verifying that the response origin
    differs from the caller's self IP (sip). Returns (proxy, response_time, current_time)
    on success, or None on failure.
    """
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    original_socket = socket.socket

    try:
        proxy_host, proxy_port = proxy.split(':')

        if proxy_type in ['http', 'https']:
            # Strict by default: for 'http' use HTTP CONNECT; for 'https' require TLS to proxy
            schemes_to_try = ['http'] if proxy_type == 'http' else ['https']

            for proxy_scheme in schemes_to_try:
                try:
                    proxy_url = f"{proxy_scheme}://{proxy_host}:{proxy_port}"

                    ssl_ctx = None
                    if proxy_scheme == 'https':
                        ssl_ctx = ssl.create_default_context()
                        ssl_ctx.check_hostname = False
                        ssl_ctx.verify_mode = ssl.CERT_NONE
                        # Relax legacy servers when supported
                        try:
                            ssl_ctx.options &= ~getattr(ssl, 'OP_NO_TLSv1', 0)
                            ssl_ctx.options &= ~getattr(ssl, 'OP_NO_TLSv1_1', 0)
                            legacy_flag = getattr(ssl, 'OP_LEGACY_SERVER_CONNECT', 0)
                            if legacy_flag:
                                ssl_ctx.options |= legacy_flag
                        except Exception:
                            pass

                    http = urllib3.ProxyManager(
                        proxy_url,
                        timeout=urllib3.Timeout(connect=timeout_seconds, read=timeout_seconds),
                        retries=False,
                        cert_reqs='CERT_NONE',
                        assert_hostname=False,
                        ssl_context=ssl_ctx,
                    )
                    start_time = time.time()
                    response = http.request('GET', target_url)
                    response_time = time.time() - start_time
                    data = json.loads(response.data.decode('utf-8'))
                    response.release_conn()

                    sip_ips = [ip.strip() for ip in str(sip).split(',') if ip.strip()]
                    origin_ips = [ip.strip() for ip in str(data.get('origin', '')).split(',') if ip.strip()]
                    is_masking = any(ip not in sip_ips for ip in origin_ips)
                    if not is_masking:
                        continue

                    logging.info(
                        f"Successful proxy via scheme={proxy_scheme}: {proxy_host}:{proxy_port} with response time {response_time:.2f}s"
                    )
                    return f'{proxy_host}:{proxy_port}', response_time, current_time
                except (NewConnectionError, SSLError, ProxyError, ConnectTimeoutError, ReadTimeoutError):
                    continue
            return None

        elif proxy_type in ['socks4', 'socks5']:
            # Use PySocks to dial through SOCKS proxy and validate via requests
            socks.set_default_proxy(
                socks.SOCKS4 if proxy_type == 'socks4' else socks.SOCKS5,
                proxy_host,
                int(proxy_port),
            )
            socket.socket = socks.socksocket
            headers = {'X-Forwarded-For': proxy_host}
            r = requests.get(target_url, timeout=timeout_seconds, verify=False, headers=headers)

            if r.status_code == 200:
                response_time = r.elapsed.total_seconds()
                data = r.json()

                sip_ips = [ip.strip() for ip in str(sip).split(',') if ip.strip()]
                origin_ips = [ip.strip() for ip in str(data.get('origin', '')).split(',') if ip.strip()]
                is_masking = any(ip not in sip_ips for ip in origin_ips)
                if not is_masking:
                    return None
                logging.info(
                    f"Successful proxy: {proxy_host}:{proxy_port} with response time {response_time:.2f}s"
                )
                return f'{proxy_host}:{proxy_port}', response_time, current_time

    except (NewConnectionError, SSLError, ProxyError, ConnectTimeoutError, ReadTimeoutError) as e:
        if isinstance(e, NewConnectionError) and "Too many open files" in str(e):
            logging.warning("Too many open files error encountered.")
        return None
    except Exception as e:
        logging.debug(f"Unexpected error checking proxy {proxy}: {e}")
        return None
    finally:
        socks.set_default_proxy()
        socket.socket = original_socket

    return None


