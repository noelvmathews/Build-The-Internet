#!/usr/bin/env python3
"""
acm-db  -  secure user-storage microservice for "Build the Internet"   (SINGLE FILE)
=========================================================================================
Contract: acm-db OpenAPI 3.0.3, UNCHANGED (201/400/200/404 shapes exactly as specified).
Security: fail-closed. Only acm-server may use /db/*; everyone else gets 403 {"error":"Forbidden"}.

INSTALL (once)      pip install fastapi uvicorn

COMMANDS
  python acm_db.py                 start the service            (same as: python acm_db.py serve)
  python acm_db.py genkey          print a strong DB_API_KEY
  python acm_db.py selftest        start a throw-away server, run ~30 attack/contract checks + speed test
  python acm_db.py attack          run the attack checks against YOUR running server (needs DB_API_KEY)
  python acm_db.py bench           speed test against your running server (needs DB_API_KEY)

QUICK START (DB laptop)
  export DB_API_KEY=$(python acm_db.py genkey)     # give this secret ONLY to the acm-server teammate
  export DNS_URL=http://<DNS_IP>:<DNS_PORT>
  export ALLOWED_IPS=<SERVER_IP>                   # acm-server laptop (also learned via DNS)
  python acm_db.py                                 # listens on 0.0.0.0:8002
  Dashboard: http://localhost:8002/dashboard  (open on THIS laptop; localhost-only on purpose)

acm-server teammate must send  X-ACM-Key: <DB_API_KEY>  on every call, and find acm-db via acm-dns.

ENV VARS
  DB_API_KEY         shared secret, >= 32 chars (required unless AUTH_REQUIRED=false)
  DNS_URL            acm-dns base URL                      ALLOWED_IPS   comma list of allowed caller IPs
  ACM_SERVER_NAME    DNS name of auth server (acm-server)  SERVICE_NAME   name registered in DNS (acm-db)
  SERVICE_HOST       address to advertise (auto)           PORT (8002)   DB_PATH (acm.db)
  AUTH_REQUIRED=true IP_CHECK=true REQUIRE_SIGNATURE=false ENABLE_DOCS=false
  MAX_BODY=2048  RATE_LIMIT=3000 (req/s/IP)  FAIL_LIMIT=10  BAN_SECONDS=60  USERNAME_REGEX

EMERGENCY SWITCHES (demo day)
  AUTH_REQUIRED=false   key+IP checks OFF (rate limit + validation stay) - if organizer scripts hit the DB directly
  IP_CHECK=false        keep the key check, skip the IP check          - if IPs/DNS misbehave
  USERNAME_REGEX=...    loosen username rules if tests use other characters

OPTIONAL SIGNED MODE  (REQUIRE_SIGNATURE=true): replay-proof requests. acm-server adds headers
  X-ACM-Timestamp: <unix seconds>   X-ACM-Signature: hex(HMAC_SHA256(DB_API_KEY,
      METHOD + "\\n" + PATH + "\\n" + TIMESTAMP + "\\n" + sha256hex(BODY)))      (30 s window, one-time use)

KNOWN ASSUMPTIONS: the acm-dns register / lookup calls (register_loop, allowlist_loop) are guesses
until the acm-dns YAML is known. ALLOWED_IPS is the safe fallback for the allowlist.
"""
import hashlib, hmac, ipaddress, json, os, re, secrets, socket, sqlite3, subprocess, sys, tempfile, threading, time
import urllib.request
from collections import deque
from contextlib import asynccontextmanager
from urllib.parse import urlparse


def _bool(name, default):
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


SERVICE_NAME = os.getenv("SERVICE_NAME", "acm-db")
PORT = int(os.getenv("PORT", "8002"))
DNS_URL = os.getenv("DNS_URL", "").rstrip("/")
DB_PATH = os.getenv("DB_PATH", "acm.db")
DB_API_KEY = os.getenv("DB_API_KEY", "")
AUTH_REQUIRED = _bool("AUTH_REQUIRED", True)
IP_CHECK = _bool("IP_CHECK", True)
REQUIRE_SIGNATURE = _bool("REQUIRE_SIGNATURE", False)
ENABLE_DOCS = _bool("ENABLE_DOCS", False)
ACM_SERVER_NAME = os.getenv("ACM_SERVER_NAME", "acm-server")
MAX_BODY = int(os.getenv("MAX_BODY", "2048"))
RATE_LIMIT = int(os.getenv("RATE_LIMIT", "3000"))
FAIL_LIMIT = int(os.getenv("FAIL_LIMIT", "10"))
BAN_SECONDS = int(os.getenv("BAN_SECONDS", "60"))
SIG_WINDOW = 30
USERNAME_RE = re.compile(os.getenv("USERNAME_REGEX", r"[A-Za-z0-9_.@+\-]{1,64}"))
HASH_RE = re.compile(r"[\x21-\x7e]{1,512}")  # printable ASCII, no spaces/control chars
START = time.time()


# =====================================================================================
# TOOLS: genkey / attack / bench / selftest   (stdlib only; run BEFORE the server loads)
# =====================================================================================
def _tool_attacks(host, port, key):
    import http.client
    ok = bad = skip = 0
    try:
        s = socket.socket(); s.bind(("127.0.0.2", 0)); s.close()
        alias = host.startswith("127.")
    except OSError:
        alias = False

    def req(method, path, body=None, headers=None, src=None, raw=None):
        c = http.client.HTTPConnection(host, port, timeout=5, source_address=(src, 0) if src else None)
        h = dict(headers or {})
        if raw is None and body is not None:
            raw = json.dumps(body).encode(); h.setdefault("Content-Type", "application/json")
        c.request(method, path, raw, h)
        r = c.getresponse(); data = r.read(); c.close()
        return r.status, data, r

    def check(name, cond, extra="", needs_alias=False):
        nonlocal ok, bad, skip
        if needs_alias and not alias:
            skip += 1; print("SKIP " + name + "  (needs Linux loopback aliases)"); return
        ok += bool(cond); bad += (not cond)
        print(("PASS " if cond else "FAIL ") + name + (f"   <- got {extra}" if not cond else ""))

    A = {"X-ACM-Key": key}
    u = os.urandom(3).hex()
    check("no key -> 403", req("GET", "/db/users/x")[0] == 403)
    check("wrong key -> 403", req("GET", "/db/users/x", headers={"X-ACM-Key": "nope"})[0] == 403)
    check("right key from a wrong IP -> 403", req("GET", "/db/users/x", headers=A, src="127.0.0.2")[0] == 403, needs_alias=True)
    s, d, _ = req("POST", "/db/users", {"username": "u" + u, "password_hash": "HASHSECRET" + u}, A)
    check("register -> 201 {status,user_id}", s == 201 and json.loads(d).get("status") == "ok" and "user_id" in json.loads(d), (s, d))
    s, d, _ = req("POST", "/db/users", {"username": "u" + u, "password_hash": "h"}, A)
    check('duplicate -> 400 {"error":"Username already exists"}', s == 400 and json.loads(d) == {"error": "Username already exists"}, (s, d))
    s, d, _ = req("GET", "/db/users/u" + u, headers=A)
    check("fetch -> 200 with user_id/username/hash", s == 200 and set(json.loads(d)) == {"user_id", "username", "password_hash"}, (s, d))
    s, d, _ = req("GET", "/db/users/nobody" + u, headers=A)
    check('unknown -> 404 {"error":"User not found"}', s == 404 and json.loads(d) == {"error": "User not found"}, (s, d))
    for p in ("/db/users/'%20OR%20'1'='1", "/db/users/..%2f..%2fetc%2fpasswd", "/db/users/%00",
              "/db/users/a%0d%0aSet-Cookie:x=1", "/db/users/%E2%82%AC"):
        s, d, r = req("GET", p, headers=A)
        check(f"hostile path {p[:34]} -> 404, no header injection", s == 404 and r.getheader("Set-Cookie") is None, s)
    check("SQL injection in POST username -> 400", req("POST", "/db/users", {"username": "a';DROP TABLE users;--", "password_hash": "h"}, A)[0] == 400)
    check("empty/missing fields -> 400", req("POST", "/db/users", {"username": ""}, A)[0] == 400)
    check("oversize body -> 413", req("POST", "/db/users", raw=b'{"username":"a","password_hash":"' + b"x" * 9000 + b'"}', headers={**A, "Content-Type": "application/json"})[0] == 413)
    check("wrong content-type -> 415", req("POST", "/db/users", raw=b"a=b", headers={**A, "Content-Type": "text/plain"})[0] == 415)
    check("malformed JSON -> 400", req("POST", "/db/users", raw=b"{bad", headers={**A, "Content-Type": "application/json"})[0] == 400)
    for m in ("PUT", "DELETE", "PATCH", "TRACE"):
        check(f"{m} refused (405/403)", req(m, "/db/users/x", headers=A)[0] in (405, 403))
    check("/docs and /openapi.json hidden", req("GET", "/docs", headers=A)[0] == 404 and req("GET", "/openapi.json", headers=A)[0] == 404)
    check("/health minimal", json.loads(req("GET", "/health")[1]) == {"status": "ok"})
    check("dashboard data not public from remote", req("GET", "/events", src="127.0.0.2")[0] == 403, needs_alias=True)
    res = []
    def race(i):
        res.append(req("POST", "/db/users", {"username": "race" + u, "password_hash": "h%d" % i}, A)[0])
    ts = [threading.Thread(target=race, args=(i,)) for i in range(40)]
    [t.start() for t in ts]; [t.join() for t in ts]
    check("40 parallel registrations -> exactly one 201", res.count(201) == 1 and res.count(400) == 39, (res.count(201), res.count(400)))
    codes = [req("GET", "/db/users/x", headers={"X-ACM-Key": "g%d" % i}, src="127.0.0.3")[0] for i in range(30)] if alias else []
    check("brute force gets banned (429)", 429 in codes, set(codes), needs_alias=True)
    check("banned IP blocked even with the right key", req("GET", "/db/users/x", headers=A, src="127.0.0.3")[0] == 429, needs_alias=True)
    check("real server unaffected by attacker's ban", req("GET", "/db/users/u" + u, headers=A)[0] == 200)
    dump = req("GET", "/events", headers=A)[1].decode()
    check("no password hash / key in dashboard feed", "HASHSECRET" not in dump and key not in dump)
    print(f"\n{ok} passed, {bad} failed, {skip} skipped")
    return bad


def _tool_bench(host, port, key, n=2000):
    import http.client
    c = http.client.HTTPConnection(host, port, timeout=10)
    h = {"Content-Type": "application/json", "X-ACM-Key": key}
    tag = os.urandom(2).hex()
    t = time.time()
    for i in range(n):
        c.request("POST", "/db/users", json.dumps({"username": f"b{tag}{i}", "password_hash": "x"}), h); c.getresponse().read()
    post = n / (time.time() - t)
    t = time.time()
    for i in range(n):
        c.request("GET", f"/db/users/b{tag}{i}", headers=h); c.getresponse().read()
    get = n / (time.time() - t)
    print(f"SPEED: POST {post:,.0f} req/s | GET {get:,.0f} req/s | avg {1000/post:.2f} ms / {1000/get:.2f} ms")


def _tool_selftest():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    key, tmp = secrets.token_urlsafe(32), tempfile.mkdtemp()
    env = {**os.environ, "PORT": str(port), "DB_API_KEY": key, "ALLOWED_IPS": "127.0.0.1",
           "DB_PATH": os.path.join(tmp, "selftest.db"), "DNS_URL": "", "AUTH_REQUIRED": "true", "IP_CHECK": "true",
           "REQUIRE_SIGNATURE": "false", "ENABLE_DOCS": "false"}
    p = subprocess.Popen([sys.executable, os.path.abspath(__file__), "serve"], env=env,
                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        for _ in range(60):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1).read(); break
            except Exception:
                if p.poll() is not None:
                    print("server failed to start:\n" + p.stderr.read().decode()[-1500:]); return 1
                time.sleep(0.25)
        print(f"== acm-db self-test (temporary server on port {port}) ==")
        bad = _tool_attacks("127.0.0.1", port, key)
        _tool_bench("127.0.0.1", port, key)
        print("RESULT:", "ALL GOOD" if bad == 0 else f"{bad} FAILURES")
        return 1 if bad else 0
    finally:
        p.terminate()
        try: p.wait(5)
        except Exception: p.kill()


if __name__ == "__main__":
    _cmd = sys.argv[1] if len(sys.argv) > 1 else "serve"
    if _cmd == "genkey":
        print(secrets.token_urlsafe(32)); sys.exit(0)
    if _cmd == "selftest":
        sys.exit(_tool_selftest())
    if _cmd in ("attack", "bench"):
        _h = os.getenv("HOST", "127.0.0.1")
        if not DB_API_KEY: sys.exit("set DB_API_KEY first")
        if _cmd == "attack": sys.exit(1 if _tool_attacks(_h, PORT, DB_API_KEY) else 0)
        _tool_bench(_h, PORT, DB_API_KEY); sys.exit(0)
    if _cmd != "serve":
        sys.exit(__doc__.split("QUICK START")[0])
    if AUTH_REQUIRED and len(DB_API_KEY) < 32:  # fail closed BEFORE touching the database
        sys.exit("REFUSING TO START: set DB_API_KEY (>= 32 chars).  Make one:  python acm_db.py genkey")

# =====================================================================================
# SERVER
# =====================================================================================
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

os.umask(0o077)  # new files (the DB) are owner-only


def norm_ip(s):
    try:
        ip = ipaddress.ip_address(s)
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        return str(ip)
    except ValueError:
        return s


static_allowed = {norm_ip(x.strip()) for x in os.getenv("ALLOWED_IPS", "").split(",") if x.strip()}
dns_allowed = set()


def is_allowed(ip):
    return ip in static_allowed or ip in dns_allowed


KEY_HASH = hashlib.sha256(DB_API_KEY.encode()).digest()


def key_ok(raw):  # constant-time, length-independent
    return hmac.compare_digest(hashlib.sha256(raw).digest(), KEY_HASH)


# ---------- storage ----------
db = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
db.execute("PRAGMA journal_mode=WAL")
db.execute("PRAGMA synchronous=NORMAL")
db.execute("CREATE TABLE IF NOT EXISTS users ("
           "user_id INTEGER PRIMARY KEY AUTOINCREMENT,"
           "username TEXT NOT NULL UNIQUE,"
           "password_hash TEXT NOT NULL)")
for _sfx in ("", "-wal", "-shm"):
    try: os.chmod(DB_PATH + _sfx, 0o600)
    except OSError: pass

# ---------- event log (dashboard). Never stores hashes or keys. ----------
events = deque(maxlen=500)
_seq = 0
stats = {"requests": 0, "created": 0, "duplicates": 0, "found": 0, "not_found": 0, "bad_request": 0, "blocked": 0}


def clean(s, n=80):
    return re.sub(r"[^\x20-\x7e]", "?", str(s))[:n]


def log(kind, msg, ms=None):
    global _seq
    _seq += 1
    events.append({"id": _seq, "t": time.strftime("%H:%M:%S"), "kind": kind, "msg": clean(msg, 160), "ms": ms})


# ---------- abuse state ----------
rate, fails, banned, seen_sigs = {}, {}, {}, {}


def note_fail(ip, now):
    if is_allowed(ip):  # never lock out the real acm-server
        return
    f = fails.get(ip)
    if not f or f[0] < now:
        fails[ip] = [now + 60, 1]
    else:
        f[1] += 1
        if f[1] >= FAIL_LIMIT:
            banned[ip] = now + BAN_SECONDS
            fails.pop(ip, None)
            log("sec", f"BANNED {ip} for {BAN_SECONDS}s (repeated failures)")
    if len(fails) > 10000: fails.clear()
    if len(banned) > 10000: banned.clear()


def sig_ok(method, path, hdrs, body, now):
    try:
        t = int(hdrs.get(b"x-acm-timestamp", b""))
    except ValueError:
        return False
    sg = hdrs.get(b"x-acm-signature", b"").lower()
    if abs(now - t) > SIG_WINDOW:
        return False
    msg = f"{method}\n{path}\n{t}\n{hashlib.sha256(body).hexdigest()}".encode()
    if not hmac.compare_digest(sg, hmac.new(DB_API_KEY.encode(), msg, hashlib.sha256).hexdigest().encode()):
        return False
    if seen_sigs.get(sg, 0) > now:  # replay
        return False
    seen_sigs[sg] = now + 2 * SIG_WINDOW
    if len(seen_sigs) > 10000:
        for k in [k for k, v in seen_sigs.items() if v < now]:
            del seen_sigs[k]
    return True


SEC_HEADERS = [
    (b"x-content-type-options", b"nosniff"), (b"cache-control", b"no-store"), (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"), (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
]


async def reply(send, status, msg):
    body = json.dumps({"error": msg}).encode()
    await send({"type": "http.response.start", "status": status, "headers": [
        (b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()), *SEC_HEADERS]})
    await send({"type": "http.response.body", "body": body})


async def read_body(receive, limit):
    chunks, total = [], 0
    while True:
        m = await receive()
        if m["type"] == "http.disconnect":
            return None
        b = m.get("body", b"")
        total += len(b)
        if total > limit:
            return False
        chunks.append(b)
        if not m.get("more_body"):
            return b"".join(chunks)


class Guard:
    """Pure-ASGI gatekeeper (fast): runs before any route code."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            return await self.app(scope, receive, send)
        if scope["type"] != "http":
            return await send({"type": "websocket.close"})
        now = time.time()
        ip = norm_ip((scope.get("client") or ("?", 0))[0])
        path, method = scope["path"], scope["method"]
        hdrs = dict(scope["headers"])

        async def deny(status, msg, why, fail=False):
            stats["blocked"] += 1
            if fail:
                note_fail(ip, now)
            log("sec", f"BLOCKED {ip} {method} {clean(path, 40)}: {why}")
            await reply(send, status, msg)

        # 1. ban + rate limit
        if banned.get(ip, 0) > now:
            return await deny(429, "Too many requests", "banned")
        sec = int(now)
        w = rate.get(ip)
        if w is None or w[0] != sec:
            rate[ip] = [sec, 1]
            if len(rate) > 10000: rate.clear()
        else:
            w[1] += 1
            if w[1] > RATE_LIMIT:
                return await deny(429, "Too many requests", "rate limit")

        # 2. authentication (everything except GET /health; dashboard is open on localhost only)
        public = path == "/health" and method == "GET"
        dash_local = method == "GET" and path in ("/dashboard", "/events") and ip in ("127.0.0.1", "::1")
        if AUTH_REQUIRED and not public and not dash_local:
            k_ok = key_ok(hdrs.get(b"x-acm-key", b""))
            i_ok = (not IP_CHECK) or is_allowed(ip)
            if not (k_ok and i_ok):
                return await deny(403, "Forbidden", "bad key" if not k_ok else "ip not allowed", fail=True)

        # 3. body rules
        body = b""
        receive_replay = receive
        if method == "POST":
            if hdrs.get(b"content-type", b"").split(b";")[0].strip().lower() != b"application/json":
                return await deny(415, "Content-Type must be application/json", "content-type")
            try:
                if int(hdrs.get(b"content-length", b"0")) > MAX_BODY:
                    return await deny(413, "Request body too large", "body too large")
            except ValueError:
                return await deny(400, "Invalid request", "bad content-length")
            body = await read_body(receive, MAX_BODY)
            if body is False:
                return await deny(413, "Request body too large", "body too large")
            if body is None:
                return
            sent = False

            async def receive_replay():
                nonlocal sent
                if not sent:
                    sent = True
                    return {"type": "http.request", "body": body, "more_body": False}
                return await receive()

        # 4. optional signature / replay protection
        if AUTH_REQUIRED and REQUIRE_SIGNATURE and path.startswith("/db/"):
            if not sig_ok(method, path, hdrs, body, now):
                return await deny(403, "Forbidden", "bad signature/replay", fail=True)

        async def send_wrapped(message):
            if message["type"] == "http.response.start":
                h = list(message.get("headers", []))
                names = {k.lower() for k, _ in h}
                h += [(k, v) for k, v in SEC_HEADERS if k not in names]
                message = {**message, "headers": h}
            await send(message)

        await self.app(scope, receive_replay, send_wrapped)


# ---------- DNS: register ourselves + learn acm-server's IP for the allowlist ----------
dns_state = {"registered": False, "last": "not started", "allowed": 0}


def local_ip_towards(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((host, port))
        return s.getsockname()[0]
    finally:
        s.close()


def register_loop():
    # ASSUMPTION: adjust path/payload to the real acm-dns contract.
    u = urlparse(DNS_URL)
    delay = 1
    while True:
        try:
            host = os.getenv("SERVICE_HOST") or local_ip_towards(u.hostname, u.port or 80)
            payload = json.dumps({"domain": SERVICE_NAME}).encode()
            r = urllib.request.Request(f"{DNS_URL}/register", data=payload,
                                       headers={"Content-Type": "application/json"}, method="POST")
            urllib.request.urlopen(r, timeout=3).read()
            if not dns_state["registered"]:
                log("info", f"registered with acm-dns as {SERVICE_NAME} @ {host}:{PORT}")
            dns_state.update(registered=True, last="ok")
            delay = 1
            time.sleep(15)  # heartbeat: re-register if DNS restarted
        except Exception as e:
            dns_state.update(registered=False, last=clean(e, 60))
            log("warn", f"DNS registration failed ({clean(e, 60)}); retry in {delay}s")
            time.sleep(delay)
            delay = min(delay * 2, 5)


def _extract_host(data):
    if isinstance(data, dict):
        for k in ("ip", "host", "address", "addr"):
            if isinstance(data.get(k), str):
                return data[k]
        data = list(data.values())
    if isinstance(data, list):
        for v in data:
            r = _extract_host(v) if isinstance(v, (dict, list)) else None
            if r:
                return r
    return None


def allowlist_loop():
    # ASSUMPTION: lookup path is a guess (several common shapes tried). ALLOWED_IPS is the sure fallback.
    while True:
        for p in (f"/lookup/{ACM_SERVER_NAME}", f"/resolve/{ACM_SERVER_NAME}", f"/services/{ACM_SERVER_NAME}",
                  f"/dns/{ACM_SERVER_NAME}"):
            try:
                h = _extract_host(json.loads(urllib.request.urlopen(DNS_URL + p, timeout=2).read()))
                if h:
                    try: ipaddress.ip_address(h)
                    except ValueError: h = socket.gethostbyname(h)
                    new = {norm_ip(h)}
                    if new != dns_allowed:
                        dns_allowed.clear(); dns_allowed.update(new)
                        log("info", f"allowlist: acm-server resolved via DNS to {h}")
                    break
            except Exception:
                continue
        time.sleep(3)


def check_config():
    if AUTH_REQUIRED and len(DB_API_KEY) < 32:
        raise SystemExit("REFUSING TO START: set DB_API_KEY (>= 32 chars).  Make one:  python acm_db.py genkey")


@asynccontextmanager
async def lifespan(app):
    check_config()
    if not AUTH_REQUIRED:
        log("sec", "WARNING: AUTH_REQUIRED=false -> key/IP checks are OFF")
    if AUTH_REQUIRED and IP_CHECK and not static_allowed and not DNS_URL:
        log("sec", "WARNING: no ALLOWED_IPS and no DNS_URL: every /db request will be denied")
    if DNS_URL:
        threading.Thread(target=register_loop, daemon=True).start()
        if AUTH_REQUIRED and IP_CHECK:
            threading.Thread(target=allowlist_loop, daemon=True).start()
    else:
        dns_state["last"] = "DNS_URL not set"
        log("warn", "DNS_URL not set: running without DNS registration")
    yield


app = FastAPI(title="acm-db", version="2.1.0", lifespan=lifespan,
              docs_url="/docs" if ENABLE_DOCS else None, redoc_url=None,
              openapi_url="/openapi.json" if ENABLE_DOCS else None)
app.add_middleware(Guard)


def err(status, message):
    return JSONResponse({"error": message}, status_code=status)


@app.exception_handler(StarletteHTTPException)
async def http_err(request, exc):
    return err(exc.status_code, {404: "Not found", 405: "Method not allowed"}.get(exc.status_code, "Error"))


@app.exception_handler(Exception)
async def any_err(request, exc):
    log("warn", f"internal error {type(exc).__name__}")
    return err(500, "Internal server error")  # never leak traces


# ---------- contract endpoints ----------
@app.post("/db/users")
async def create_user(request: Request):
    t0 = time.perf_counter()
    stats["requests"] += 1
    try:
        body = json.loads(await request.body())
        username, ph = body.get("username"), body.get("password_hash")
    except Exception:
        username = ph = None
    if (not isinstance(username, str) or not isinstance(ph, str)
            or not USERNAME_RE.fullmatch(username) or not HASH_RE.fullmatch(ph)):
        stats["bad_request"] += 1
        log("warn", "POST /db/users -> 400 invalid body")
        return err(400, "Invalid request: username and password_hash are required valid strings")
    try:
        cur = db.execute("INSERT INTO users(username, password_hash) VALUES (?, ?)", (username, ph))
    except sqlite3.IntegrityError:
        stats["duplicates"] += 1
        log("warn", f"POST /db/users '{username}' -> 400 already exists", round((time.perf_counter() - t0) * 1000, 2))
        return err(400, "Username already exists")
    stats["created"] += 1
    log("ok", f"POST /db/users '{username}' -> 201 user_id={cur.lastrowid}", round((time.perf_counter() - t0) * 1000, 2))
    return JSONResponse({"status": "ok", "user_id": cur.lastrowid}, status_code=201)


@app.get("/db/users/{username}")
async def get_user(username: str):
    t0 = time.perf_counter()
    stats["requests"] += 1
    row = None
    if USERNAME_RE.fullmatch(username):
        row = db.execute("SELECT user_id, username, password_hash FROM users WHERE username = ?", (username,)).fetchone()
    ms = round((time.perf_counter() - t0) * 1000, 2)
    if row is None:
        stats["not_found"] += 1
        log("warn", f"GET /db/users/{clean(username, 40)} -> 404", ms)
        return err(404, "User not found")
    stats["found"] += 1
    log("ok", f"GET /db/users/{username} -> 200 user_id={row[0]}", ms)
    return {"user_id": row[0], "username": row[1], "password_hash": row[2]}


# ---------- extras (additive; contract untouched) ----------
@app.get("/health")
async def health():
    return {"status": "ok"}  # minimal on purpose


@app.get("/events")
async def get_events(since: int = 0):
    users = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    dns_state["allowed"] = len(static_allowed | dns_allowed)
    return {"events": [e for e in list(events) if e["id"] > since], "stats": {**stats, "users": users}, "dns": dns_state}


DASH = """<!doctype html><meta charset=utf-8><title>acm-db dashboard</title>
<style>body{font:14px system-ui;background:#0b1020;color:#e6e9f5;margin:0;padding:20px}
h1{margin:0 0 12px}.cards{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px}
.c{background:#161d36;border-radius:8px;padding:10px 16px}.c b{display:block;font-size:22px}
#log{background:#060a16;border-radius:8px;padding:10px;height:60vh;overflow:auto;font:13px ui-monospace,monospace}
.ok{color:#5be28b}.warn{color:#ffb347}.info{color:#7cb7ff}.sec{color:#ff6b6b}.ms{color:#888}</style>
<h1>&#128274; acm-db <span id=dns style="font-size:14px"></span></h1><div class=cards id=cards></div><div id=log></div>
<script>let last=0;const L=document.getElementById('log');
const esc=s=>String(s).replace(/[&<>"']/g,c=>'&#'+c.charCodeAt(0)+';');
async function tick(){try{const r=await (await fetch('/events?since='+last)).json();
document.getElementById('cards').innerHTML=Object.entries(r.stats).map(([k,v])=>`<div class=c>${esc(k)}<b>${esc(v)}</b></div>`).join('');
document.getElementById('dns').textContent=(r.dns.registered?'\\u{1F7E2} DNS registered':'\\u{1F534} DNS not registered')+' | allowed callers: '+r.dns.allowed;
for(const e of r.events){last=e.id;L.insertAdjacentHTML('beforeend',`<div class="${esc(e.kind)}">[${esc(e.t)}] ${esc(e.msg)} <span class=ms>${e.ms!=null?esc(e.ms)+' ms':''}</span></div>`);}
if(r.events.length)L.scrollTop=L.scrollHeight}catch(e){}}
setInterval(tick,1000);tick()</script>"""


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    return HTMLResponse(DASH, headers={
        "Content-Security-Policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'"})


if __name__ == "__main__":
    import uvicorn
    check_config()
    print(f"acm-db v2.1 | port {PORT} | auth={'ON' if AUTH_REQUIRED else 'OFF'} ip_check={'ON' if IP_CHECK else 'OFF'} "
          f"signed={'ON' if REQUIRE_SIGNATURE else 'off'} | allowed={sorted(static_allowed) or 'via DNS only'} | "
          f"dns={DNS_URL or 'not set'} | dashboard: http://localhost:{PORT}/dashboard", flush=True)
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="warning", access_log=False, server_header=False,
                date_header=False, timeout_keep_alive=5, h11_max_incomplete_event_size=16384)
