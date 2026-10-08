"""acm-db v2 (secure): user storage service. Contract: acm-db OpenAPI 3.0.3 (unchanged).

Security model: fail closed. Only acm-server may use /db/*:
  1. shared secret header  X-ACM-Key  (constant-time compare)
  2. source-IP allowlist   (ALLOWED_IPS and/or acm-server's IP looked up through acm-dns)
  3. optional HMAC signing + timestamp + replay cache (REQUIRE_SIGNATURE=true)
  4. per-IP rate limit, auto-ban after repeated failures, body size/type limits, strict validation

Env vars (nothing is hardcoded):
  DB_API_KEY        shared secret, >= 32 chars (required unless AUTH_REQUIRED=false)
  DNS_URL           acm-dns base URL, e.g. http://<DNS_IP>:<port>
  ALLOWED_IPS       comma list of caller IPs allowed (e.g. <SERVER_IP>); also resolved via DNS
  ACM_SERVER_NAME   DNS name of the auth server           (default acm-server)
  SERVICE_NAME / SERVICE_HOST / PORT (8002) / DB_PATH (acm.db)
  AUTH_REQUIRED=true  IP_CHECK=true  REQUIRE_SIGNATURE=false  ENABLE_DOCS=false
  MAX_BODY=2048  RATE_LIMIT=3000(req/s/IP)  FAIL_LIMIT=10  BAN_SECONDS=60  USERNAME_REGEX
"""
import hashlib, hmac, ipaddress, json, os, re, socket, sqlite3, sys, threading, time, urllib.request
from collections import deque
from urllib.parse import urlparse

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

os.umask(0o077)  # new files (the DB) are owner-only


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


def key_ok(raw):
    return hmac.compare_digest(hashlib.sha256(raw).digest(), KEY_HASH)


# ---------- storage ----------
db = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
db.execute("PRAGMA journal_mode=WAL")
db.execute("PRAGMA synchronous=NORMAL")
db.execute(
    "CREATE TABLE IF NOT EXISTS users ("
    "user_id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "username TEXT NOT NULL UNIQUE,"
    "password_hash TEXT NOT NULL)"
)
for _suffix in ("", "-wal", "-shm"):
    try:
        os.chmod(DB_PATH + _suffix, 0o600)
    except OSError:
        pass

# ---------- event log (dashboard). Never stores hashes or keys. ----------
events = deque(maxlen=500)
_seq = 0
stats = {"requests": 0, "created": 0, "duplicates": 0, "found": 0, "not_found": 0,
         "bad_request": 0, "blocked": 0}


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
    if len(fails) > 10000:
        fails.clear()
    if len(banned) > 10000:
        banned.clear()


def sig_ok(method, path, hdrs, body, now):
    try:
        t = int(hdrs.get(b"x-acm-timestamp", b""))
    except ValueError:
        return False
    sg = hdrs.get(b"x-acm-signature", b"").lower()
    if abs(now - t) > SIG_WINDOW:
        return False
    msg = f"{method}\n{path}\n{t}\n{hashlib.sha256(body).hexdigest()}".encode()
    exp = hmac.new(DB_API_KEY.encode(), msg, hashlib.sha256).hexdigest().encode()
    if not hmac.compare_digest(sg, exp):
        return False
    if seen_sigs.get(sg, 0) > now:  # replay
        return False
    seen_sigs[sg] = now + 2 * SIG_WINDOW
    if len(seen_sigs) > 10000:
        for k in [k for k, v in seen_sigs.items() if v < now]:
            del seen_sigs[k]
    return True


SEC_HEADERS = [
    (b"x-content-type-options", b"nosniff"),
    (b"cache-control", b"no-store"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
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
            if len(rate) > 10000:
                rate.clear()
        else:
            w[1] += 1
            if w[1] > RATE_LIMIT:
                return await deny(429, "Too many requests", "rate limit")

        # 2. authentication (everything except GET /health)
        public = path == "/health" and method == "GET"
        dash_local = method == "GET" and path in ("/dashboard", "/events") and ip in ("127.0.0.1", "::1")
        if AUTH_REQUIRED and not public and not dash_local:
            k_ok = key_ok(hdrs.get(b"x-acm-key", b""))
            i_ok = (not IP_CHECK) or is_allowed(ip)
            if not (k_ok and i_ok):
                return await deny(403, "Forbidden", "bad key" if not k_ok else "ip not allowed", fail=True)

        # 3. body rules
        body = b""
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
        else:
            receive_replay = receive

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


app = FastAPI(title="acm-db", version="2.0.0",
              docs_url="/docs" if ENABLE_DOCS else None, redoc_url=None,
              openapi_url="/openapi.json" if ENABLE_DOCS else None)
app.add_middleware(Guard)


def err(status, message):
    return JSONResponse({"error": message}, status_code=status)


@app.exception_handler(StarletteHTTPException)
async def http_err(request, exc):
    msg = {404: "Not found", 405: "Method not allowed"}.get(exc.status_code, "Error")
    return err(exc.status_code, msg)


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
        row = db.execute("SELECT user_id, username, password_hash FROM users WHERE username = ?",
                         (username,)).fetchone()
    ms = round((time.perf_counter() - t0) * 1000, 2)
    if row is None:
        stats["not_found"] += 1
        log("warn", f"GET /db/users/{clean(username, 40)} -> 404", ms)
        return err(404, "User not found")
    stats["found"] += 1
    log("ok", f"GET /db/users/{username} -> 200 user_id={row[0]}", ms)
    return {"user_id": row[0], "username": row[1], "password_hash": row[2]}


# ---------- extras ----------
@app.get("/health")
async def health():
    return {"status": "ok"}  # minimal on purpose


dns_state = {"registered": False, "last": "not started", "allowed": 0}


@app.get("/events")
async def get_events(since: int = 0):
    users = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    dns_state["allowed"] = len(static_allowed | dns_allowed)
    return {"events": [e for e in list(events) if e["id"] > since], "stats": {**stats, "users": users},
            "dns": dns_state}


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


# ---------- DNS: register ourselves + learn acm-server's IP for the allowlist ----------
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
            payload = json.dumps({"name": SERVICE_NAME, "host": host, "ip": host, "port": PORT}).encode()
            req = urllib.request.Request(f"{DNS_URL}/register", data=payload,
                                         headers={"Content-Type": "application/json"}, method="POST")
            urllib.request.urlopen(req, timeout=3).read()
            if not dns_state["registered"]:
                log("info", f"registered with acm-dns as {SERVICE_NAME} @ {host}:{PORT}")
            dns_state.update(registered=True, last="ok")
            delay = 1
            time.sleep(15)
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
        for v in data.values():
            r = _extract_host(v)
            if r:
                return r
    elif isinstance(data, list):
        for v in data:
            r = _extract_host(v)
            if r:
                return r
    return None


def allowlist_loop():
    # ASSUMPTION: lookup path is a guess; several common shapes are tried. ALLOWED_IPS is the sure fallback.
    while True:
        for p in (f"/lookup/{ACM_SERVER_NAME}", f"/resolve/{ACM_SERVER_NAME}", f"/services/{ACM_SERVER_NAME}",
                  f"/dns/{ACM_SERVER_NAME}"):
            try:
                data = json.loads(urllib.request.urlopen(DNS_URL + p, timeout=2).read())
                h = _extract_host(data)
                if h:
                    try:
                        ipaddress.ip_address(h)
                    except ValueError:
                        h = socket.gethostbyname(h)
                    new = {norm_ip(h)}
                    if new != dns_allowed:
                        dns_allowed.clear()
                        dns_allowed.update(new)
                        log("info", f"allowlist: acm-server resolved via DNS to {h}")
                    break
            except Exception:
                continue
        time.sleep(3)


def check_config():
    if AUTH_REQUIRED and len(DB_API_KEY) < 32:
        raise SystemExit("REFUSING TO START: set DB_API_KEY to a secret of at least 32 chars.\n"
                         "  python -c \"import secrets;print(secrets.token_urlsafe(32))\"")


@app.on_event("startup")
async def startup():
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


if __name__ == "__main__":
    import uvicorn
    check_config()
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="warning", access_log=False,
                server_header=False, date_header=False, timeout_keep_alive=5,
                h11_max_incomplete_event_size=16384)
