import hashlib, hmac, os, tempfile, time
KEY = "k" * 40
os.environ.update(DB_PATH=tempfile.mktemp(suffix=".db"), DB_API_KEY=KEY, ALLOWED_IPS="testclient")
import pytest
from fastapi.testclient import TestClient
import main

c = TestClient(main.app)                                   # allowed caller
evil = lambda ip="10.9.9.9": TestClient(main.app, client=(ip, 1))
H = {"X-ACM-Key": KEY}
GOOD = {"username": "alice", "password_hash": "$2b$12$abcdefghijklmnopqrstuv"}


def test_contract_flow():
    r = c.post("/db/users", json=GOOD, headers=H)
    assert r.status_code == 201 and r.json()["status"] == "ok" and isinstance(r.json()["user_id"], int)
    r = c.post("/db/users", json=GOOD, headers=H)
    assert r.status_code == 400 and r.json() == {"error": "Username already exists"}
    r = c.get("/db/users/alice", headers=H)
    assert r.status_code == 200 and r.json()["password_hash"] == GOOD["password_hash"] and r.json()["username"] == "alice"
    r = c.get("/db/users/nobody", headers=H)
    assert r.status_code == 404 and r.json() == {"error": "User not found"}


def test_no_or_wrong_key_forbidden():
    assert c.get("/db/users/alice").status_code == 403
    assert c.get("/db/users/alice", headers={"X-ACM-Key": "wrong"}).status_code == 403
    assert c.post("/db/users", json=GOOD).status_code == 403
    assert c.get("/db/users/alice").json() == {"error": "Forbidden"}


def test_wrong_ip_forbidden_even_with_key():
    assert evil("10.1.1.1").get("/db/users/alice", headers=H).status_code == 403


def test_ban_after_repeated_failures():
    e = evil("10.7.7.7")
    codes = [e.get("/db/users/alice", headers={"X-ACM-Key": "x"}).status_code for _ in range(main.FAIL_LIMIT + 2)]
    assert codes[0] == 403 and codes[-1] == 429
    assert e.get("/db/users/alice", headers=H).status_code == 429   # banned even with a valid key


def test_real_server_never_banned():
    for _ in range(main.FAIL_LIMIT + 5):
        c.get("/db/users/alice", headers={"X-ACM-Key": "x"})
    assert c.get("/db/users/alice", headers=H).status_code == 200


@pytest.mark.parametrize("body", [{}, {"username": "x"}, {"username": "", "password_hash": "h"},
                                  {"username": 1, "password_hash": "h"}, {"username": "a b", "password_hash": "h"},
                                  {"username": "a'; DROP TABLE users;--", "password_hash": "h"},
                                  {"username": "u\x00x", "password_hash": "h"}, {"username": "ok", "password_hash": "has space"},
                                  {"username": "ok", "password_hash": "x" * 600}, {"username": "x" * 65, "password_hash": "h"},
                                  [1, 2], "str"])
def test_invalid_bodies_400(body):
    assert c.post("/db/users", json=body, headers=H).status_code == 400


def test_malformed_json_and_types():
    assert c.post("/db/users", content=b"notjson", headers={**H, "Content-Type": "application/json"}).status_code == 400
    assert c.post("/db/users", content=b"a=b", headers={**H, "Content-Type": "text/plain"}).status_code == 415
    assert c.post("/db/users", headers=H).status_code == 415            # no content-type at all


def test_oversize_body_413():
    r = c.post("/db/users", content=b'{"username":"a","password_hash":"' + b"x" * 5000 + b'"}',
               headers={**H, "Content-Type": "application/json"})
    assert r.status_code == 413


def test_methods_405():
    for m in ("put", "delete", "patch"):
        assert getattr(c, m)("/db/users/alice", headers=H).status_code == 405
    assert c.get("/db/users", headers=H).status_code == 405


def test_injection_and_traversal_paths():
    for p in ("/db/users/' OR '1'='1", "/db/users/..%2f..%2fetc", "/db/users/%00", "/db/users/a%0d%0aX-Evil:1",
              "/db/users/%E2%82%AC", "/etc/passwd"):
        r = c.get(p, headers=H)
        assert r.status_code in (404,), (p, r.status_code)
        assert "x-evil" not in {k.lower() for k in r.headers}
    assert c.get("/db/users/alice", headers=H).status_code == 200      # table intact


def test_attack_surface_closed():
    assert c.get("/docs", headers=H).status_code == 404 and c.get("/openapi.json", headers=H).status_code == 404
    assert c.get("/health").json() == {"status": "ok"}
    assert c.get("/events").status_code == 403            # not localhost, no key


def test_security_headers():
    r = c.get("/db/users/alice", headers=H)
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["cache-control"] == "no-store"
    assert r.headers["x-frame-options"] == "DENY"


def test_secrets_not_in_logs():
    c.post("/db/users", json={"username": "leaky", "password_hash": "SUPERSECRETHASH12345"}, headers=H)
    c.get("/db/users/leaky", headers=H)
    dump = str(list(main.events)) + str(main.stats) + c.get("/events", headers=H).text
    assert "SUPERSECRETHASH12345" not in dump and KEY not in dump


def _sign(method, path, body=b"", ts=None):
    ts = int(ts or time.time())
    msg = f"{method}\n{path}\n{ts}\n{hashlib.sha256(body).hexdigest()}".encode()
    return {**H, "X-ACM-Timestamp": str(ts), "X-ACM-Signature": hmac.new(KEY.encode(), msg, hashlib.sha256).hexdigest()}


def test_signature_and_replay(monkeypatch):
    monkeypatch.setattr(main, "REQUIRE_SIGNATURE", True)
    assert c.get("/db/users/alice", headers=H).status_code == 403            # unsigned
    h = _sign("GET", "/db/users/alice")
    assert c.get("/db/users/alice", headers=h).status_code == 200
    assert c.get("/db/users/alice", headers=h).status_code == 403            # replay
    assert c.get("/db/users/alice", headers=_sign("GET", "/db/users/alice", ts=time.time() - 120)).status_code == 403
    assert c.get("/db/users/bob", headers=_sign("GET", "/db/users/alice")).status_code == 403  # sig for other path
