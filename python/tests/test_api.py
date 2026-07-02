import sqlite3
from pathlib import Path
import importlib
import sys

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    project_root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(project_root))
    db_path = project_root / "data.db"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    for table in ("http", "https", "socks4", "socks5"):
        cursor.execute(
            f"CREATE TABLE IF NOT EXISTS {table} (" \
            "proxy TEXT, response_time REAL, last_checked TEXT)"
        )
    conn.commit()
    conn.close()

    api = importlib.import_module("api")
    with TestClient(api.app) as client:
        yield client

    db_path.unlink(missing_ok=True)


def test_invalid_proxy_type(client):
    response = client.get("/proxy/invalid")
    assert response.status_code == 400


def test_http_format_text_content_type(client):
    response = client.get("/proxy/http?format=text")
    assert response.headers["content-type"] == "text/plain; charset=utf-8"
