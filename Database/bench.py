import os; KEY = os.getenv("DB_API_KEY", "")
import time, http.client, json
c = http.client.HTTPConnection("127.0.0.1", 8002)
t = time.time(); n = 2000
for i in range(n):
    c.request("POST", "/db/users", json.dumps({"username": f"u{i}", "password_hash": "x"}), {"Content-Type": "application/json", "X-ACM-Key": KEY}); c.getresponse().read()
print("POST/s", int(n / (time.time() - t)))
t = time.time()
for i in range(n):
    c.request("GET", f"/db/users/u{i}", headers={"X-ACM-Key": KEY}); c.getresponse().read()
print("GET/s", int(n / (time.time() - t)))
