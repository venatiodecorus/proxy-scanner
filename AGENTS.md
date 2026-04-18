# Proxy Scanner — Agent Instructions

## Project Overview

This is a Go monorepo that produces three container images for an open proxy scanning system, deployed via Docker Compose.

## Architecture

Three components, three container images:

1. **Scanner** (`cmd/scanner/`, `docker/Dockerfile.scanner`) — Go binary wrapping masscan. Runs on-demand via Docker Compose scan profile. Scans IPv4 space for open proxy ports, then enqueues candidates into the SQLite database. The Scanner writes masscan JSON output to disk (for debugging) but the primary data path is the `candidates` queue table in SQLite.
2. **Validator** (`cmd/validator/`, `docker/Dockerfile.validator`) — Go binary. Runs on-demand via Docker Compose scan profile. Reads candidates from the `candidates` queue table, validates each as a working proxy (HTTP/HTTPS/SOCKS4/SOCKS5), measures latency, checks anonymity, checks DNSBL blocklists, detects CONNECT support and TLS cert issues, tags with GeoIP. Validated proxies are upserted into the `proxies` table; processed candidates are deleted from the queue. On startup, resets any `processing` candidates back to `pending` for crash recovery.
3. **API** (`cmd/api/`, `docker/Dockerfile.api`) — Go REST API. Runs continuously. Serves proxy data from SQLite at `http://localhost:8080/v1/`.

All three components share a SQLite database via a Docker named volume. The `candidates` table acts as a durable work queue — the Scanner enqueues, the Validator dequeues and processes. Candidates are removed from the queue after processing (whether validated or failed), so the Validator never reprocesses the same candidate.

## Code Structure

```
cmd/scanner/main.go  — Scanner entry point (runs masscan, enqueues results to SQLite)
cmd/validator/main.go — Validator entry point (dequeues candidates, validates, writes to proxies table)
cmd/api/main.go      — API entry point (REST endpoints, request logging)
internal/proxy/       — Proxy checking logic (checker.go, geoip.go, types.go)
internal/blocklist/    — DNSBL blocklist checking (dnsbl.go)
internal/database/    — SQLite operations (sqlite.go) — includes candidates queue
internal/scanner/     — Masscan output parser (parser.go)
data/                 — GeoLite2 .mmdb databases (City, ASN, Country) — committed to repo
config/exclude/       — Modular CIDR exclusion lists (merged at Docker build time)
docker/               — Dockerfiles for all three images
docker-compose.yml    — Docker Compose configuration
.github/workflows/    — CI (test on PR) and build+push (images to GHCR on main)
```

## Key Technical Details

- **Go module**: `github.com/venatiodecorus/proxy-scanner`
- **Database**: SQLite with WAL mode. Single writer (validator), single reader (API). DB file at `/data/proxies.db`.
- **Candidates queue**: The `candidates` table in SQLite serves as a durable work queue. Scanner enqueues (INSERT OR IGNORE), Validator dequeues (SELECT pending → UPDATE to processing) and deletes after processing. On validator startup, any `processing` candidates are reset to `pending` for crash recovery.
- **Scan output**: Masscan JSON at `/data/candidates.json` on the shared volume (debugging artifact). The primary data path is the SQLite queue.
- **Container registry**: `ghcr.io/venatiodecorus/proxy-scanner-{scanner,validator,api}`
- **GeoIP**: MaxMind GeoLite2-City + ASN databases bundled in the validator image at `/geoip/`. Source `.mmdb` files are committed in `data/`.
- **Egress IP**: Validator auto-detects public IP at startup via external services (ipify, ifconfig.me, etc.). Override with `ORIGIN_IP` env var.
- **CI/CD**: GitHub Actions builds and pushes all 3 images to GHCR on push to main. PRs run tests + vet.
- **Docker Compose**: Scanner and validator are in the `scan` profile (`docker compose --profile scan up`). API runs by default (`docker compose up -d api`). Data persists via a named volume `scanner-data`.

## Development Guidelines

- All Go code uses standard library where possible. Minimal external dependencies.
- Key dependencies: `mattn/go-sqlite3` (CGO SQLite driver), `oschwald/maxminddb-golang` (GeoIP/ASN lookups).
- The API uses only the standard library `net/http` — no web framework.
- Tests should be runnable with `go test ./...` without network access or external databases.
- Dockerfiles use multi-stage builds. Final images are distroless (Go) or minimal Alpine (scanner).

## Environment Variables

### Scanner (`cmd/scanner`)
- `SCAN_RATE` — Masscan packets per second (default: `50000`)
- `SCAN_PORTS` — Comma-separated port list (default: `3128,8080,1080,8888,9050,8443,3129,80,443,1081`)
- `SCAN_ADAPTER` — Network interface for masscan (default: `ens3`)
- `EXCLUDE_FILE` — Path to CIDR exclusion file (default: `/config/exclude.conf`)
- `DB_PATH` — Path to SQLite database (default: `/data/proxies.db`)
- `OUTPUT_FILE` — Path for masscan JSON output (default: `/data/candidates.json`)

### Validator (`cmd/validator`)
- `DB_PATH` — Path to SQLite database (default: `/data/proxies.db`)
- `GEOIP_CITY_DB` — Path to MaxMind GeoLite2-City database (default: `/geoip/GeoLite2-City.mmdb`)
- `GEOIP_ASN_DB` — Path to MaxMind GeoLite2-ASN database (default: `/geoip/GeoLite2-ASN.mmdb`)
- `ORIGIN_IP` — Public IP of the scanner node for anonymity detection (default: auto-detected)
- `WORKERS` — Number of concurrent validation goroutines (default: `500`)
- `TIMEOUT` — Per-proxy validation timeout in seconds (default: `10`)
- `TEST_URL` — URL to request through the proxy for validation (default: `http://httpbin.org/ip`)
- `SKIP_BLOCKLIST` — Set to `true` to disable DNSBL blocklist checking (default: `false`)
- `BATCH_SIZE` — Number of candidates to dequeue per batch (default: `1000`)

### API (`cmd/api`)
- `DB_PATH` — Path to SQLite database (default: `/data/proxies.db`)
- `LISTEN_ADDR` — Address to listen on (default: `:8080`)
- `API_TOKEN` — Bearer token required for all endpoints except `/v1/health`. Auth is disabled when unset (default: unset/disabled)

## Coding Conventions

- Use structured logging (`log/slog` from Go 1.21+).
- Error handling: wrap errors with context using `fmt.Errorf("doing X: %w", err)`.
- No global state. Pass dependencies explicitly.
- Database operations go through the `database.DB` struct, not raw SQL in business logic.
- Proxy checking logic is in `internal/proxy/checker.go`. Each protocol has its own check function.
- Blocklist checking is in `internal/blocklist/dnsbl.go`. Uses DNSBL (DNS-based blocklists) to flag known-abuse IPs.
- The validator orchestrates: parse input -> fan out to workers -> check proxy -> check blocklists -> write to DB.

## Testing

- `go test ./...` runs all tests.
- Database tests use in-memory SQLite (`:memory:`).
- Proxy checker tests use mock HTTP servers where possible.
- No integration tests that require real network scanning.

## Exclusion List Management

The scan exclusion list is split into modular files under `config/exclude/`:

- `00-iana-special.conf` — IANA Special-Purpose Address Registry (RFC 6890). Non-negotiable; these are non-routable.
- `10-military.conf` — US DoD/military allocations. Do not scan.
- `20-cloud-providers.conf` — Our hosting provider (Hetzner). Avoids self-scanning and abuse complaints.
- `30-infrastructure.conf` — Root DNS, IXPs, RIR infrastructure. Critical internet infra.
- `90-custom.conf` — Manual additions from abuse complaints or opt-out requests.

Files are numbered so they merge in predictable order via `cat config/exclude/*.conf`. The Dockerfile strips comments and blank lines at build time to produce a clean CIDR-only file for masscan.

**To add a new exclusion**: Add the CIDR to the appropriate file (usually `90-custom.conf`), commit, push. The scanner image rebuilds automatically via GitHub Actions.

## Deployment Notes

- Run the API continuously: `docker compose up -d api`
- Run a scan: `docker compose --profile scan up scanner`
- Run the validator: `docker compose --profile scan up validator`
- The scanner and validator can be run independently. The scanner enqueues candidates to SQLite; the validator dequeues and processes them.
- The three components share a named Docker volume `scanner-data` mounted at `/data`.
- SQLite WAL mode allows concurrent reads (API) while the validator writes.
- Rate limit masscan to 50k pps to avoid abuse complaints.