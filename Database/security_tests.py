"""Live attacker simulation. Start the server first, e.g.:
  DB_API_KEY=<key> ALLOWED_IPS=127.0.0.1 python main.py
Run:  DB_API_KEY=<key> python security_tests.py   (HOST/PORT optional)
Uses 127.0.0.2 / 127.0.0.3 as 'attacker' source IPs (Linux loopback)."""
import http.client, json, os, sys, threading
HOST, PORT, KEY = os.getenv("HOST", "127.0.0.1"), int(os.getenv("PORT", "8002")), os.getenv("DB_API_KEY", "")
ok = bad = 0


def req(method, path, body=None, headers=None, src="127.0.0.1", raw=None):
    c = http.client.HTTPConnection(HOST, PORT, timeout=5, source_address=(src, 0))
    h = dict(headers or {})
    if raw is None and body is not None:
        raw = json.dumps(body).encode(); h.setdefault("Content-Type", "application/json")
    c.request(method, path, raw, h)
    r = c.getresponse(); data = r.read(); c.close()
    return r.status, data, r


def check(name, cond, extra=""):
    global ok, bad
    ok += cond; bad += (not cond)
    print(("PASS " if cond else "FAIL ") + name + (f"  {extra}" if not cond else ""))


A = {"X-ACM-Key": KEY}
uniq = os.urandom(3).hex()
check("no key -> 403", req("GET", "/db/users/x")[0] == 403)
check("wrong key -> 403", req("GET", "/db/users/x", headers={"X-ACM-Key": "nope"})[0] == 403)
check("right key, wrong IP -> 403", req("GET", "/db/users/x", headers=A, src="127.0.0.2")[0] == 403)
s, d, _ = req("POST", "/db/users", {"username": "u" + uniq, "password_hash": "HASHSECRET" + uniq}, A)
check("register -> 201", s == 201, d)
check("duplicate -> 400", req("POST", "/db/users", {"username": "u" + uniq, "password_hash": "h"}, A)[0] == 400)
s, d, _ = req("GET", "/db/users/u" + uniq, headers=A)
check("fetch -> 200 with hash", s == 200 and b"HASHSECRET" in d)
check("unknown -> 404", req("GET", "/db/users/nobody" + uniq, headers=A)[0] == 404)
for p in ("/db/users/'%20OR%20'1'='1", "/db/users/..%2f..%2fetc%2fpasswd", "/db/users/%00", "/db/users/a%0d%0aSet-Cookie:x=1", "/db/users/%E2%82%AC"):
    s, d, r = req("GET", p, headers=A)
    check(f"payload {p[:30]} -> 404, no header injection", s == 404 and r.getheader("Set-Cookie") is None, s)
check("SQLi in POST username -> 400", req("POST", "/db/users", {"username": "a';DROP TABLE users;--", "password_hash": "h"}, A)[0] == 400)
check("oversize body -> 413", req("POST", "/db/users", raw=b'{"username":"a","password_hash":"' + b"x" * 9000 + b'"}', headers={**A, "Content-Type": "application/json"})[0] == 413)
check("wrong content-type -> 415", req("POST", "/db/users", raw=b"a=b", headers={**A, "Content-Type": "text/plain"})[0] == 415)
check("malformed JSON -> 400", req("POST", "/db/users", raw=b"{bad", headers={**A, "Content-Type": "application/json"})[0] == 400)
for m in ("PUT", "DELETE", "PATCH", "TRACE"):
    check(f"{m} -> 405/403", req(m, "/db/users/x", headers=A)[0] in (405, 403))
check("/docs hidden", req("GET", "/docs", headers=A)[0] == 404)
check("/health minimal", json.loads(req("GET", "/health")[1]) == {"status": "ok"})
check("dashboard data not public (remote)", req("GET", "/events", src="127.0.0.2")[0] == 403)

res = []
def race(i):
    res.append(req("POST", "/db/users", {"username": "race" + uniq, "password_hash": "h%d" % i}, A)[0])
ts = [threading.Thread(target=race, args=(i,)) for i in range(40)]
[t.start() for t in ts]; [t.join() for t in ts]
check("race: exactly one 201", res.count(201) == 1 and res.count(400) == 39, (res.count(201), res.count(400)))

codes = [req("GET", "/db/users/x", headers={"X-ACM-Key": "g%d" % i}, src="127.0.0.3")[0] for i in range(30)]
check("brute force gets banned (429)", 429 in codes, set(codes))
check("banned IP blocked even with right key", req("GET", "/db/users/x", headers=A, src="127.0.0.3")[0] == 429)
check("real server unaffected by attacker ban", req("GET", "/db/users/u" + uniq, headers=A)[0] == 200)

dump = req("GET", "/events")[1].decode()
check("no hash / key in dashboard feed", "HASHSECRET" not in dump and KEY not in dump)
print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)
