import sqlite3
import configparser
from contextlib import contextmanager
from typing import Iterable, List


def get_db_path(config_path: str = 'config.ini') -> str:
    config = configparser.ConfigParser()
    config.read(config_path)
    return config['database']['path']


def get_connection(db_path: str, timeout: int = 30, check_same_thread: bool = False) -> sqlite3.Connection:
    return sqlite3.connect(db_path, timeout=timeout, check_same_thread=check_same_thread)


@contextmanager
def transaction(db_path: str, timeout: int = 30):
    conn = get_connection(db_path, timeout=timeout)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def ensure_proxy_table(conn: sqlite3.Connection, proxy_type: str) -> None:
    cursor = conn.cursor()
    cursor.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {proxy_type} (
            proxy TEXT PRIMARY KEY,
            response_time REAL,
            last_checked TEXT
        )
        """
    )


def ensure_proxy_tables(conn: sqlite3.Connection, proxy_types: Iterable[str]) -> None:
    for proxy_type in proxy_types:
        ensure_proxy_table(conn, proxy_type)


def select_all_proxies(conn: sqlite3.Connection, proxy_type: str) -> List[str]:
    cursor = conn.cursor()
    cursor.execute(f"SELECT proxy FROM {proxy_type}")
    return [row[0] for row in cursor.fetchall()]


def select_proxies_by_response_time(
    conn: sqlite3.Connection, proxy_type: str, max_response_time: float
) -> List[str]:
    cursor = conn.cursor()
    cursor.execute(
        f"SELECT proxy FROM {proxy_type} WHERE response_time <= ?",
        (max_response_time,),
    )
    return [row[0] for row in cursor.fetchall()]


def upsert_proxy(
    conn: sqlite3.Connection,
    proxy_type: str,
    proxy: str,
    response_time: float,
    last_checked: str,
) -> None:
    cursor = conn.cursor()
    cursor.execute(
        f"""
        INSERT OR REPLACE INTO {proxy_type} (proxy, response_time, last_checked)
        VALUES (?, ?, ?)
        """,
        (proxy, response_time, last_checked),
    )


def delete_proxies(conn: sqlite3.Connection, proxy_type: str, proxies: Iterable[str]) -> None:
    cursor = conn.cursor()
    cursor.executemany(
        f"DELETE FROM {proxy_type} WHERE proxy = ?",
        [(p,) for p in proxies],
    )


def ensure_scan_results_table(conn: sqlite3.Connection) -> None:
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS _scan_results (
            ip_port TEXT PRIMARY KEY
        )
        """
    )


def bulk_insert_scan_results(conn: sqlite3.Connection, ip_ports: Iterable[str]) -> None:
    cursor = conn.cursor()
    cursor.executemany(
        "INSERT OR REPLACE INTO _scan_results (ip_port) VALUES (?)",
        [(ip_port,) for ip_port in ip_ports],
    )


def delete_scan_results(conn: sqlite3.Connection, ip_ports: Iterable[str]) -> None:
    cursor = conn.cursor()
    cursor.executemany(
        "DELETE FROM _scan_results WHERE ip_port = ?",
        [(ip_port,) for ip_port in ip_ports],
    )


