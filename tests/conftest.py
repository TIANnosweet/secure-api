import os
import sys

import pytest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

# Configure the application before it is imported.
os.environ.setdefault("SECRET_KEY", "test-only-secret-key-0123456789abcdef")
_TMP_DB = os.path.join(BASE_DIR, ".pytest-test.db")
os.environ["DB_PATH"] = _TMP_DB

import app as app_module  # noqa: E402


@pytest.fixture()
def client():
    if os.path.exists(_TMP_DB):
        os.remove(_TMP_DB)
    app_module.init_db()
    app_module.app.config.update(TESTING=True)
    with app_module.app.test_client() as test_client:
        yield test_client


@pytest.fixture()
def token(client):
    client.post("/api/register", json={"username": "alice", "password": "Passw0rd!"})
    response = client.post(
        "/auth/login", json={"username": "alice", "password": "Passw0rd!"}
    )
    return response.get_json()["token"]
