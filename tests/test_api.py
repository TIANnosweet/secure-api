"""Functional and security regression tests for the secure API."""


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_register_and_duplicate(client):
    payload = {"username": "bob", "password": "Passw0rd!"}
    assert client.post("/api/register", json=payload).status_code == 201
    assert client.post("/api/register", json=payload).status_code == 409


def test_register_rejects_weak_input(client):
    assert client.post("/api/register", json={"username": "x", "password": "short"}).status_code == 400
    assert client.post("/api/register", json={"username": "<script>", "password": "Passw0rd!"}).status_code == 400


def test_login_success_and_failure(client):
    client.post("/api/register", json={"username": "carol", "password": "Passw0rd!"})
    ok = client.post("/auth/login", json={"username": "carol", "password": "Passw0rd!"})
    assert ok.status_code == 200
    body = ok.get_json()
    assert body["expires_in"] == 3600
    assert body["token"].count(".") == 2

    bad = client.post("/auth/login", json={"username": "carol", "password": "wrong-pass"})
    assert bad.status_code == 401


def test_sql_injection_does_not_bypass_login(client):
    client.post("/api/register", json={"username": "dave", "password": "Passw0rd!"})
    attack = client.post(
        "/auth/login", json={"username": "dave' OR '1'='1' --", "password": "x"}
    )
    assert attack.status_code == 401


def test_protected_endpoint_requires_token(client):
    assert client.get("/api/data").status_code == 401
    assert client.get("/api/data", headers={"Authorization": "Bearer not.a.token"}).status_code == 401


def test_protected_endpoint_with_token(client, token):
    response = client.get("/api/data", headers={"Authorization": "Bearer " + token})
    assert response.status_code == 200
    usernames = [row["username"] for row in response.get_json()["data"]]
    assert "alice" in usernames


def test_stored_xss_is_escaped_in_response(client, token):
    headers = {"Authorization": "Bearer " + token}
    payload = "<script>alert('xss')</script>"
    assert client.post("/api/messages", json={"body": payload}, headers=headers).status_code == 201

    response = client.get("/api/messages", headers=headers)
    assert response.status_code == 200
    body = response.get_json()["messages"][0]["body"]
    assert "<script>" not in body
    assert "&lt;script&gt;" in body


def test_security_headers_present(client):
    response = client.get("/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
