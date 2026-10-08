```markdown
# 🌐 4-Node Distributed Microservice Mesh

A contract-driven, zero-trust distributed system featuring dynamic service discovery, identity provisioning, private credential persistence, and real-time frontend telemetry across physically isolated nodes.

---

## 🏛️ System Architecture

The pipeline consists of four distinct, decoupled microservices communicating strictly via predefined OpenAPI 3.0 contracts[cite: 7]:


```

```
                ┌──────────────────────────────────────────────┐
                │               acm-dns (Go)                   │
                │        Dynamic Discovery Registry            │
                │  • Anti-Hijack Guard  • In-Memory Leases     │
                └──────────────────▲───────────────────────────┘
                                   │
                     1. Dynamic    │   1. Register /
                     Lookup        │      Heartbeat
                                   │

```

┌────────────────────────┐            ▼            ┌────────────────────────┐
│     acm-app (Mac)      ├────────────────────────►│  acm-server (Windows)  │
│   Client Gateway & UI  │   2. Authenticate Flow  │  Auth & Session Engine │
│ • Telemetry Visualizer │                         │ • Brute-Force Rate-Lim │
│ • Local Async Proxy    │◄────────────────────────┤ • Zero-Overwrite Guard │
└────────────────────────┘    3. Session Cookie    └───────────┬────────────┘
│
│ 4. Private Sync
▼
┌────────────────────────┐
│     acm-db (Linux)     │
│ Private Storage Engine │
│ • Network Restricted   │
└────────────────────────┘

```

### Microservices Breakdown
* **`acm-dns` (Service Discovery Node)**: High-throughput dynamic DNS registry written in Go[cite: 7]. Resolves hostnames dynamically without static routing tables or hardcoded IPs[cite: 7]. Enforces in-memory lease tracking and remote TCP source-IP validation[cite: 1].
* **`acm-server` (Application & Identity Node)**: Manages user registration, credential hashing, and cookie-based session verification[cite: 7]. Implements automated rate-limiting against credential stuffing and prevents overwriting existing accounts.
* **`acm-db` (Persistence Node)**: Dedicated database service storing sensitive user records and credentials[cite: 7]. Enforces strict perimeter isolation: unreachable from public verifiers, accessible solely by the authorized application server.
* **`acm-app` (Web Client & Gateway)**: Interactive web telemetry dashboard visualizing inter-node resolution pipelines in real time with an icon-based progress indicator[cite: 7].

---

## 🔒 Security Hardening & Zero-Trust Policies

* **DNS Anti-Hijack Validation**: Rejects unauthorized `POST /register` overrides if a domain is already registered to a different IP (`HTTP 409 Conflict`), preventing node-spoofing attacks.
* **Brute-Force Rate Limiting**: Monitors consecutive failed authentication attempts against `POST /login` and throttles malicious actors with `HTTP 429 Too Many Requests`.
* **Zero-Overwrite Registration**: Returns `HTTP 400 Bad Request` when duplicate usernames are registered, ensuring existing user credentials cannot be overwritten.
* **Database Network Boundary**: Completely blocks external network access to `/db/users`, securing the data layer from client-side exfiltration.

---

## 📂 Repository Structure

```text
.
├── client/          # acm-app: Interactive dashboard & client gateway
│   ├── index.html   # Real-time telemetry & multi-stage status indicators
│   └── app_server.py# Async proxy & local static server
├── server/          # acm-server: Auth engine, rate-limiter & session manager
├── dns/             # acm-dns: Go-based dynamic registry with anti-hijack guards
│   ├── cmd/
│   └── internal/
├── db/              # acm-db: Isolated credential store and schema
├── contracts/       # OpenAPI 3.0 specification contracts
├── verify.sh        # Automated compliance, latency, and security test suite
└── README.md

```

---

## 🚀 Execution & Verification Flow

### 1. Dynamic Service Registration

Each physical node registers its domain with the DNS registry upon startup:

```bash
curl -X POST http://<DNS_HOST>:8000/register \
  -H "Content-Type: application/json" \
  -d '{"domain":"acm-client"}'

```

### 2. Client Authentication Pipeline

The client dynamically resolves targets at runtime without static addresses:

1. `GET /lookup?domain=acm-server` fetches target coordinates dynamically.


2. `POST /login` issues credentials against the resolved server endpoint.
3. `GET /whoami` validates persistent session tokens.

### 3. Verification Suite

Run the automated test runner to validate reachability, latency, error boundaries, and security compliance:

```bash
chmod +x verify.sh
./verify.sh <DNS_HOST>:8000

```

```text
--- Phase 1: Validation Phase ---
Registering acm-verifier with DNS... ✅
Resolving acm-verifier... ✅
Resolving acm-client... ✅
  Verifying reachability for acm-client... ✅
Resolving acm-server... ✅
  Verifying reachability for acm-server... ✅
Resolving acm-db... ✅
  Verifying reachability for acm-db... 🔒 not reachable from verifier (OK - DB should be private)

--- Phase 3: Error Handling Phase ---
Testing DNS lookup for non-existent domain... ✅
Testing Server request to non-existent endpoint... ✅

--- Phase 4: Security Phase ---
Testing re-registration of an existing user... ✅
Testing acm-db is NOT accessible from verifier... ✅
Testing brute-force protection on /login... ✅
Testing DNS record hijack (re-registering existing records from verifier)...
  Re-registering acm-server... ✅
  Re-registering acm-db... ✅
  Re-registering acm-client... ✅

=========================================
✅ All executed verification steps passed!

```

```

```
