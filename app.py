"""Secure REST API - Information Security Lab, Work 1.

Endpoints
---------
POST /api/register    register a new user (bcrypt password hashing)
POST /auth/login      authenticate and receive a JWT
GET  /api/data        list registered users          (JWT required)
POST /api/messages    create a message               (JWT required)
GET  /api/messages    list messages                  (JWT required)
GET  /health          liveness probe

Security notes
--------------
* every SQL statement is parameterised (no string formatting of user input);
* passwords are hashed with bcrypt, never stored or returned in plaintext;
* authentication uses short-lived HS256 JWT signed with a server secret which is
  read from the environment (a random key is generated for local development);
* user supplied text is HTML-escaped before it is put into a JSON response, so a
  client that renders it cannot execute injected markup (defence in depth
  against XSS, OWASP A03:2021);
* the JWT secret and the debug flag are never hard-coded.
"""

import os
import re
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from functools import wraps

import bcrypt
import jwt
from flask import Flask, jsonify, request
from markupsafe import escape

DB_PATH = os.environ.get("DB_PATH", "app.db")
JWT_ALGORITHM = "HS256"
TOKEN_TTL = timedelta(hours=1)
BCRYPT_ROUNDS = 12
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
MIN_PASSWORD_LEN = 8
# bcrypt silently truncates everything after 72 bytes, so reject longer input.
MAX_PASSWORD_BYTES = 72
MAX_BODY_LEN = 500

app = Flask(__name__)


def load_secret_key():
    """Return the signing key from the environment, or an ephemeral one."""
    key = os.environ.get("SECRET_KEY")
    if key:
        return key
    app.logger.warning(
        "SECRET_KEY is not set - generating an ephemeral key (development only)"
    )
    return secrets.token_hex(32)


app.config["SECRET_KEY"] = load_secret_key()


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    with db() as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS users ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " username TEXT UNIQUE NOT NULL,"
            " password_hash TEXT NOT NULL,"
            " created_at TEXT NOT NULL)"
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS messages ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " author TEXT NOT NULL,"
            " body TEXT NOT NULL,"
            " created_at TEXT NOT NULL)"
        )
        conn.commit()


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def json_body():
    """Return the request body if it is a JSON object, otherwise None."""
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else None


def validate_credentials(username, password):
    """Return an error message or None when the input is acceptable."""
    if not USERNAME_RE.match(username):
        return "username must be 3-32 characters: letters, digits, '_', '.', '-'"
    if len(password) < MIN_PASSWORD_LEN:
        return "password must be at least %d characters" % MIN_PASSWORD_LEN
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        return "password must not exceed %d bytes" % MAX_PASSWORD_BYTES
    return None


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


@app.route("/api/register", methods=["POST"])
def register():
    data = json_body() or {}
    username = str(data.get("username", "")).strip()
    password = data.get("password", "")
    if not isinstance(password, str):
        return jsonify({"error": "invalid payload"}), 400

    error = validate_credentials(username, password)
    if error:
        return jsonify({"error": error}), 400

    password_hash = bcrypt.hashpw(
        password.encode("utf-8"), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    ).decode("ascii")

    with db() as conn:
        try:
            # Parameterised query: user input never becomes SQL syntax.
            conn.execute(
                "INSERT INTO users (username, password_hash, created_at)"
                " VALUES (?, ?, ?)",
                (username, password_hash, now_iso()),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            return jsonify({"error": "username already exists"}), 409

    return jsonify({"message": "user created", "username": username}), 201


@app.route("/auth/login", methods=["POST"])
def login():
    data = json_body() or {}
    username = str(data.get("username", "")).strip()
    password = data.get("password", "")
    if not username or not isinstance(password, str) or not password:
        return jsonify({"error": "username and password required"}), 400

    with db() as conn:
        # Parameterised query: "' OR '1'='1" is treated as a literal username.
        row = conn.execute(
            "SELECT username, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    # The same generic answer is returned for an unknown user and a wrong
    # password, so the endpoint cannot be used to enumerate accounts.
    if row is None or not bcrypt.checkpw(
        password.encode("utf-8"), row["password_hash"].encode("ascii")
    ):
        return jsonify({"error": "invalid credentials"}), 401

    issued_at = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "sub": row["username"],
            "iat": issued_at,
            "exp": issued_at + TOKEN_TTL,
            "jti": secrets.token_hex(8),
        },
        app.config["SECRET_KEY"],
        algorithm=JWT_ALGORITHM,
    )
    response_payload = {
        "token": token,
        "expires_in": int(TOKEN_TTL.total_seconds()),
    }
    return jsonify(response_payload), 200


def token_required(view):
    """Reject requests that do not carry a valid, unexpired Bearer token."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token:
            return jsonify({"error": "missing or invalid token"}), 401
        try:
            payload = jwt.decode(
                token, app.config["SECRET_KEY"], algorithms=[JWT_ALGORITHM]
            )
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "invalid token"}), 401
        request.user = payload.get("sub")
        return view(*args, **kwargs)

    return wrapper


@app.route("/api/data", methods=["GET"])
@token_required
def get_data():
    with db() as conn:
        rows = conn.execute(
            "SELECT username, created_at FROM users ORDER BY id"
        ).fetchall()

    # Escape user controlled fields before they are embedded in a response.
    users = [
        {
            "username": str(escape(row["username"])),
            "created_at": row["created_at"],
        }
        for row in rows
    ]
    return jsonify({"data": users}), 200


@app.route("/api/messages", methods=["POST"])
@token_required
def create_message():
    data = json_body() or {}
    body = str(data.get("body", "")).strip()
    if not body:
        return jsonify({"error": "body required"}), 400
    if len(body) > MAX_BODY_LEN:
        return jsonify({"error": "body too long"}), 400

    with db() as conn:
        conn.execute(
            "INSERT INTO messages (author, body, created_at) VALUES (?, ?, ?)",
            (request.user, body, now_iso()),
        )
        conn.commit()
    return jsonify({"message": "created"}), 201


@app.route("/api/messages", methods=["GET"])
@token_required
def list_messages():
    with db() as conn:
        rows = conn.execute(
            "SELECT author, body, created_at FROM messages ORDER BY id DESC"
        ).fetchall()

    messages = [
        {
            "author": str(escape(row["author"])),
            "body": str(escape(row["body"])),
            "created_at": row["created_at"],
        }
        for row in rows
    ]
    return jsonify({"messages": messages}), 200


init_db()


if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="127.0.0.1", port=5000, debug=debug)
