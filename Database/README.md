# acm-db (secure)

User storage for "Build the Internet". The acm-db OpenAPI contract is unchanged; security is added on top.
Only acm-server may call /db/*. Everyone else gets a uniform `403 {"error":"Forbidden"}`.

## Install
    pip install -r requirements.txt

## Start (on the DB laptop)
    export DB_API_KEY=$(python -c "import secrets;print(secrets.token_urlsafe(32))")   # share this ONLY with the acm-server teammate
    export DNS_URL=http://<DNS_IP>:<DNS_PORT>
    export ALLOWED_IPS=<SERVER_IP>        # acm-server laptop (also auto-learned via DNS)
    python main.py                        # listens on 0.0.0.0:8002

## acm-server teammate must send
    X-ACM-Key: <DB_API_KEY>               # on every request to acm-db
    (find acm-db through acm-dns, never by hardcoded IP)

## Test
    python -m pytest -q                                   # 25 contract + security tests
    DB_API_KEY=<key> python security_tests.py             # live attacker simulation (server running with ALLOWED_IPS=127.0.0.1)
    DB_API_KEY=<key> python bench.py                      # speed

Dashboard: open http://localhost:8002/dashboard ON THE DB LAPTOP (localhost only; remote needs the key header, so it is not browsable remotely).

## Defenses
| Layer | What |
|---|---|
| Caller auth | secret header (constant-time compare), IP allowlist (ALLOWED_IPS + acm-server IP via DNS), fails closed |
| Replay (optional) | `REQUIRE_SIGNATURE=true`: HMAC-SHA256 over method+path+timestamp+body hash, 30 s window, replay cache. Headers `X-ACM-Timestamp`, `X-ACM-Signature` |
| Abuse | per-IP rate limit, auto-ban after 10 failures (real server exempt), 2 KB body cap, JSON-only POST, 405 on odd methods |
| Input | username `[A-Za-z0-9_.@+-]{1,64}`, hash printable ASCII <=512, parameterized SQL, UNIQUE constraint (race-safe) |
| Leakage | hashes/keys never logged, no stack traces, /docs off, /health minimal, server/date headers removed, security headers |
| At rest | DB file chmod 600 |

## Emergency switches
- `AUTH_REQUIRED=false`: turns off key+IP checks (rate limits and validation stay). Use only if organizer scripts hit the DB directly.
- `IP_CHECK=false`: keep the key check, skip the IP check (if DNS lookup/IPs misbehave).
- `USERNAME_REGEX=...`: loosen username rules if tests use other characters.
- `DNS_URL` register/lookup calls are ASSUMPTIONS until the acm-dns YAML is known (see `register_loop`, `allowlist_loop` in main.py).
