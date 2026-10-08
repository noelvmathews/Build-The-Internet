# acm-dns

Service-discovery / DNS microservice for **Build the Internet**. Services register a
domain name; the server records the **source IP of the request**; anyone can later
resolve that name to an IP. Pure Go standard library, in-memory, O(1) lookups.

`openapi.yaml` is the source of truth. Contract endpoints are implemented exactly:

| Endpoint | Success | Errors |
|---|---|---|
| `POST /register` `{"domain":"acm-db"}` | `200 {"status":"ok"}` | `400 {"error":"..."}` |
| `GET /lookup?domain=acm-db` | `200 {"domain":"acm-db","destination":"10.0.0.7"}` | `404 {"error":"Domain not registered"}` |

Additive extras (do not alter the contract): `GET /health`, `GET /events`.

## Run

```bash
cp .env.example .env && set -a && source .env && set +a   # optional
go run ./cmd/server                                        # listens on ACM_DNS_HOST:ACM_DNS_PORT
```

Quality gate before demo:

```bash
go fmt ./... && go vet ./... && go test ./... && go test -race ./...
go test -bench=. -benchmem ./internal/registry
ACM_DNS_URL=http://localhost:8000 ./scripts/smoke.sh      # against a running server
```

## Configuration (env vars, nothing hardcoded)

| Variable | Default | Meaning |
|---|---|---|
| `ACM_DNS_HOST` | `0.0.0.0` | Listen address (bind-all, not a specific IP) |
| `ACM_DNS_PORT` | `8000` | Listen port |
| `ACM_DNS_TTL` | `0` (off) | Lease length, e.g. `30s`. Clients must re-register more often than this |
| `ACM_DNS_ALLOWED_DOMAINS` | empty (any) | Comma-separated allowlist, e.g. `acm-db,acm-server,acm-app`; others get `403` |
| `ACM_DNS_CORS_ORIGIN` | empty (off) | e.g. `*` so a browser app can call acm-dns directly |
| `ACM_DNS_LOG_LEVEL` / `ACM_DNS_LOG_FORMAT` | `info` / `json` | `debug\|info\|warn\|error` / `json\|text` |

## curl cheat-sheet

```bash
export ACM_DNS_URL=http://localhost:8000     # or wherever acm-dns runs

curl -s -X POST "$ACM_DNS_URL/register" -H 'Content-Type: application/json' -d '{"domain":"acm-db"}'
# {"status":"ok"}

curl -s "$ACM_DNS_URL/lookup?domain=acm-db"
# {"domain":"acm-db","destination":"<caller IP as seen by acm-dns>"}

curl -si "$ACM_DNS_URL/lookup?domain=ghost"                       # 404 {"error":"Domain not registered"}
curl -si -X POST "$ACM_DNS_URL/register" -d '{}'                  # 400 Missing required 'domain' field
curl -si -X POST "$ACM_DNS_URL/register" -d '{oops'               # 400 Invalid JSON body
curl -s  "$ACM_DNS_URL/health"                                    # counters, uptime, domain count
curl -s  "$ACM_DNS_URL/events?after=0"                            # recent events for the UI
```

## Behaviour where the contract is silent

| Topic | Behaviour |
|---|---|
| Duplicate register | Overwrites with the newest source IP, returns `200` (this is what makes "restart acm-db" work) and refreshes the lease |
| Domain names | Trimmed, lower-cased; ASCII `a-z 0-9 - _` and `.` separators only; max 253 chars / 63 per label; otherwise `400` |
| `/lookup` without/with bad `domain` | `400 {"error":...}` |
| Content-Type | Not enforced, so teammates' clients can't break on it; unknown JSON fields ignored |
| Body size | Capped at 1 MiB, larger gives `400 Request body too large` |
| Wrong method / unknown path | `405` (+`Allow` header) / `404`, always JSON |
| TTL | Off by default. If `ACM_DNS_TTL>0`, an entry not re-registered in time is treated as not found (`404`) |
| Allowlist | Off by default. If set, unlisted names get `403 Domain not permitted` on register |

## Trust model / security

* The contract has **no authentication**. Anyone who can reach acm-dns can register any name
  from their own IP. Mitigations without changing the contract: strict input validation,
  the optional allowlist, and running acm-dns on the hackathon network only.
* The registered IP is taken from the **TCP connection** (`RemoteAddr`). `X-Forwarded-For`,
  `X-Real-IP`, `Forwarded` are deliberately ignored, since clients can forge them.
* IPv4-mapped IPv6 (`::ffff:10.0.0.5`) is normalized to `10.0.0.5`.
* Panics are recovered and return a generic `500`; stack traces never reach clients.
* Caveat: behind Docker NAT or a reverse proxy the "source IP" is the proxy's address. On a
  single machine every service registers as `127.0.0.1`, which still works.

## Integration guide for teammates

**Important: the contract returns an IP only, not a port.** Agree on ports out-of-band and
read them from env vars (e.g. `ACM_DB_PORT=8002`). Never hardcode IPs; the IP comes from DNS.

**1. Register on startup, with bounded retry (acm-db, acm-server, acm-app):**

```go
func registerWithDNS(dnsURL, name string) error {
	body := fmt.Sprintf(`{"domain":%q}`, name)
	backoff := 500 * time.Millisecond
	for attempt := 1; attempt <= 8; attempt++ {
		resp, err := http.Post(dnsURL+"/register", "application/json", strings.NewReader(body))
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
		}
		time.Sleep(backoff)
		if backoff < 8*time.Second {
			backoff *= 2
		}
	}
	return errors.New("could not register with acm-dns")
}
```

If DNS runs with `ACM_DNS_TTL=15s`, also re-POST `/register` every ~5s in a goroutine
(heartbeat). If a service dies, its entry disappears after the TTL and lookups return 404.

**2. Discover (e.g. acm-server finding acm-db):**

```bash
curl -s "$ACM_DNS_URL/lookup?domain=acm-db"   # -> {"domain":"acm-db","destination":"10.0.0.7"}
# then connect to http://<destination>:$ACM_DB_PORT
```

**3. Status meanings**

| Status | Meaning | Client should |
|---|---|---|
| 200 | Resolved / registered | Use `destination` |
| 404 | Not registered (or lease expired) | Show "unavailable", retry with backoff |
| 400 | Bad request body/param | Fix the request (not retryable) |
| 403 | Name not allowed (only with allowlist) | Use a permitted name |
| 405 / 5xx | Wrong method / server problem | Retry later |
| connection error | acm-dns down | Retry with backoff; keep last known IP meanwhile |

## For acm-app (frontend)

Poll `GET /events?after=<last seq>` every 500-1000 ms (set `ACM_DNS_CORS_ORIGIN` if the
browser calls acm-dns directly). Each event: `{seq, time, type, domain, ip, detail}` with
types `DOMAIN_REGISTERED`, `DOMAIN_UPDATED`, `DOMAIN_EXPIRED`, `REGISTER_FAILED`,
`LOOKUP_FOUND`, `LOOKUP_NOT_FOUND`, `LOOKUP_FAILED`. Map to UI states:
`REGISTERED`, `FOUND` (green), `NOT_FOUND` / `EXPIRED` (red = "DB unavailable").
`GET /health` gives live counters. The same events go to stdout as structured JSON logs.

## Demo script (for judges)

1. `ACM_DNS_TTL=15s go run ./cmd/server`. Show the empty `/health`.
2. Start acm-db, which self-registers. `curl .../lookup?domain=acm-db` shows its IP.
3. Start acm-server, which registers and asks acm-dns "where is acm-db?", then connects.
   UI: `acm-server → DNS LOOKUP → acm-dns ✓ → acm-db FOUND ✓`.
4. **Kill acm-db.** After ≤15 s, lookup gives `404`. UI shows "DB unavailable" (controlled error).
5. Restart acm-db. It re-registers, DNS updates, acm-server discovers it again: SUCCESS.

(With TTL off, step 4 shows up as a connection failure to the stale IP rather than a DNS 404.)

## Layout

```
cmd/server/main.go            wiring, timeouts, graceful shutdown
internal/config               env loading + validation
internal/validate             domain-name normalization
internal/registry             RWMutex map, TTL, sweeper (+ tests, benchmarks)
internal/handlers             contract endpoints, middleware (+ tests)
internal/events               ring buffer feeding /events
internal/logging              slog setup
scripts/smoke.sh              curl end-to-end check
openapi.yaml                  the contract
```
