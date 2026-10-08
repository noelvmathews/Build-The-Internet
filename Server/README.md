# acm-server

Authentication and session management API for the acm microservices project.

## Run

The service requires Node.js 20+ and reads its configuration from environment variables.

```powershell
$env:DNS_URL = "http://<DNS_IP>:<DNS_PORT>"
$env:SERVICE_ADVERTISE_ADDRESS = "<SERVER_IP>:3000"
$env:DB_PORT = "<DB_PORT>"
npm start
```

At startup, the service posts `{ "domain": "acm-server", "address": "<SERVER_IP>:<PORT>" }` to `POST {DNS_URL}/register` so the client can discover it. On first database access, it queries `GET {DNS_URL}/lookup?domain=acm-db`. The response must contain `destination`. If it is an IP/host, `DB_PORT` is appended; if it is a full HTTP URL, it is used as-is. DNS results are cached for the process lifetime.

`DNS_URL` is the DNS laptop's reachable address and port. `SERVICE_ADVERTISE_ADDRESS` must be this laptop's LAN IP and listening port, reachable by the client. Database paths and timeout are configurable with the `DB_*` environment variables shown in `.env.example`.

## acm-db integration contract

The OpenAPI contract supplied for acm-server does not specify the database API. The adapter currently expects:

- `POST /db/users` with `{ "username": "...", "password_hash": "scrypt$..." }`, returning `{ "status": "ok", "user_id": 101 }` or HTTP 400 for a duplicate.
- `GET /db/users/{username}` returning `{ "user_id": 101, "username": "...", "password_hash": "scrypt$..." }`.

The supplied DNS contract's `/register` schema lists only `domain`, and says it captures the request source IP. This implementation also sends an `address` field so DNS can register the server's reachable LAN address and port. **The DNS service must honor that field** (or the DNS contract must be extended to include an advertised address and port); source-IP capture alone will register the server's apparent network address, which may not be reachable by a client on another laptop. The supplied database contract has no session routes. Consequently, sessions currently live in the acm-server process memory and are lost when it restarts. For sessions to survive restart or work across multiple server instances, the database contract needs session create/read endpoints.

## API

- `POST /register` accepts JSON `{ "username": "alice", "password": "secret123" }`. Passwords must be at least eight characters and are hashed with scrypt before being sent to acm-db.
- `POST /login` accepts the same fields, checks the password, creates a random in-memory session token, and sets an HttpOnly `session_id` cookie.
- `GET /whoami` reads the session cookie and returns the current `user_id` and `username`.
- `GET /health` is a lightweight process health check; it does not check dependencies.

Set `COOKIE_SECURE=true` when serving HTTPS. Set `SESSION_TTL_SECONDS` to change session lifetime. User records are stored through acm-db; sessions currently live in server memory.

## Container

Build from this directory and pass `DNS_URL` at runtime. The image contains only the server; it does not bundle the DNS or database services.
