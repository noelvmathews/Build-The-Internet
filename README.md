# 🌐 4-Node Distributed Microservice Mesh

A contract-driven, zero-trust distributed system simulating core internet infrastructure across physically distinct host nodes using strict OpenAPI 3.0 contracts. The architecture eliminates hardcoded IP addresses entirely, resolving all communication dynamically at runtime through a custom discovery layer.

## System Architecture & Nodes

* **`acm-dns` (Service Discovery)**: Written in Go, this node manages dynamic host discovery using remote TCP source-IP detection (`r.RemoteAddr`) and thread-safe in-memory lease tracking.


* **`acm-server` (Application & Auth)**: Handles user provisioning, password hashing, and session management, dynamically querying the DNS node to reach the database.


* **`acm-db` (Credential Persistence)**: Stores hashed credentials in isolation, restricted from public network callers and accessible solely by the application server.


* **`acm-app` (Client Gateway & UI)**: A web interface featuring real-time telemetry and a 3-stage visualizer (Discovery ➔ Identity ➔ Session) backed by a local asynchronous Python proxy.



## Security & Verification

The architecture is hardened against adversarial network conditions and verified via an automated test runner (`verify.sh`):

* **DNS Anti-Hijack Guard**: Blocks attempts to re-register active domain records from unauthorized external IPs with `HTTP 409 Conflict`.


* **Brute-Force Rate Limiting**: Tracks failed authentication attempts on `POST /login` and issues `HTTP 429 Too Many Requests` to prevent credential stuffing.


* **Zero-Overwrite Registration**: Prevents duplicate username registrations from overwriting stored passwords, strictly enforcing `HTTP 400 Bad Request`.


* **Perimeter Isolation**: Enforces network-level isolation on `acm-db` so unauthorized external queries cannot reach stored records.



## Quickstart & Verification

1. Start the Go DNS server on the discovery host: `cd dns && go run ./cmd/server`.


2. Launch the DB and Auth server instances on their respective host machines.


3. Register each host node with the DNS registry:
`curl -X POST http://<DNS_IP>:8000/register -H "Content-Type: application/json" -d '{"domain":"<SERVICE_NAME>"}'`

4. Start the client UI on your local machine (`cd client && python3 app_server.py`) and access the dashboard at `http://localhost:4000`.


5. Execute the test runner to validate reachability, status codes, and security policies:
`./verify.sh <DNS_IP>:8000`
