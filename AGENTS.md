# Proxy Scanner — Agent Instructions

## Project Overview

This is a Go monorepo that produces three container images for an open proxy scanning system, deployed via Docker Compose.

## Architecture

Four components, four container images:

1. **Scanner** (`cmd/scanner/`, `docker/Dockerfile.scanner`) — Go binary wrapping masscan. Runs on-demand via Docker Compose scan profile. Scans IPv4 space for open proxy ports, then enqueues candidates into the SQLite database. The Scanner writes masscan JSON output to disk (for debugging) but the primary data path is the `candidates` queue table in SQLite.
2. **Validator** (`cmd/validator/`, `docker/Dockerfile.validator`) — Go binary. Runs on-demand via Docker Compose scan profile. Reads candidates from the `candidates` queue table, validates each as a working proxy (HTTP/HTTPS/SOCKS4/SOCKS5), measures latency, checks anonymity, checks DNSBL blocklists, detects CONNECT support and TLS cert issues, tags with GeoIP. Validated proxies are upserted into the `proxies` table; processed candidates are deleted from the queue. On startup, resets any `processing` candidates back to `pending` for crash recovery.
3. **Revalidator** (`cmd/revalidator/`, `docker/Dockerfile.revalidator`) — Go binary. Long-running, runs by default alongside the API. Periodically rechecks proxies in the `proxies` table to keep the live set fresh. Marks proxies `stale` after consecutive failures and evicts them after a grace period. Uses the same checker code as the Validator.
4. **API** (`cmd/api/`, `docker/Dockerfile.api`) — Go REST API. Runs continuously. Serves proxy data from SQLite at `http://localhost:8080/v1/`.

All four components share a SQLite database via a Docker named volume. The `candidates` table acts as a durable work queue — the Scanner enqueues, the Validator dequeues and processes. Candidates are removed from the queue after processing (whether validated or failed), so the Validator never reprocesses the same candidate.

The `proxies` table tracks per-row liveness via `status` (`active` or `stale`), `last_checked_at`, `last_ok_at`, `consecutive_failures`, `check_count`, and `success_count`. The Revalidator drives the lifecycle: successful rechecks reset failures and refresh latency; failures increment the counter; reaching the failure threshold flips a row to `stale` (hidden from API by default); rows that stay stale past the grace period get hard-deleted.

## Code Structure

```
cmd/scanner/main.go      — Scanner entry point (runs masscan, enqueues results to SQLite)
cmd/validator/main.go    — Validator entry point (dequeues candidates, validates, writes to proxies table)
cmd/revalidator/main.go  — Revalidator entry point (rechecks proxies, evicts dead ones)
cmd/api/main.go          — API entry point (REST endpoints, request logging)
internal/proxy/          — Proxy checking logic (checker.go, geoip.go, types.go)
internal/blocklist/      — DNSBL blocklist checking (dnsbl.go)
internal/database/       — SQLite operations (sqlite.go) — includes candidates queue + liveness tracking
internal/scanner/        — Masscan output parser (parser.go)
data/                    — GeoLite2 .mmdb databases (City, ASN, Country) — committed to repo
config/exclude/          — Modular CIDR exclusion lists (merged at Docker build time)
docker/                  — Dockerfiles for all four images
docker-compose.yml       — Docker Compose configuration
.github/workflows/       — CI (test on PR) and build+push (images to GHCR on main)
```

## Key Technical Details

- **Go module**: `github.com/venatiodecorus/proxy-scanner`
- **Database**: SQLite with WAL mode. Single writer (validator), single reader (API). DB file at `/data/proxies.db`.
- **Candidates queue**: The `candidates` table in SQLite serves as a durable work queue. Scanner enqueues (INSERT OR IGNORE), Validator dequeues (SELECT pending → UPDATE to processing) and deletes after processing. On validator startup, any `processing` candidates are reset to `pending` for crash recovery.
- **Scan output**: Masscan JSON at `/data/candidates.json` on the shared volume (debugging artifact). The primary data path is the SQLite queue.
- **Scan resume**: The scanner supports masscan's `--resume` feature for incremental scanning. When `SCAN_TIMEOUT` is set, the scanner sends SIGINT to masscan after the timeout, causing masscan to save its state to `/data/paused.conf`. On the next run, the scanner detects this file and resumes from where it left off. This allows weekly scan sessions that make incremental progress through the entire IPv4 space without re-scanning previously covered ranges.
- **Masscan build**: Scanner image builds masscan from a pinned upstream master commit (see `docker/Dockerfile.scanner`) rather than using Alpine's `masscan` package. The last tagged masscan release (1.3.2, Feb 2021) predates the fix for upstream issue [#559](https://github.com/robertdavidgraham/masscan/issues/559) — paused.conf contains a `nocapture = servername` line that 1.3.2's config parser cannot read back, making `--resume` fail immediately. Master fixed this in commit `9065684c` (2023-06-07). Bump `MASSCAN_SHA` in the Dockerfile deliberately, not automatically.
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
- `RESUME_FILE` — Path for masscan resume state file (default: `/data/paused.conf`). If this file exists at startup, the scanner resumes the previous scan from this state.
- `SCAN_TIMEOUT` — Maximum duration for a scan session (e.g. `4h`, `30m`). When set, sends SIGINT to masscan after this duration, causing it to save state to `RESUME_FILE` for next run. Unset by default (scan runs to completion). Enables incremental weekly scanning.

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

### Revalidator (`cmd/revalidator`)
- `DB_PATH` — Path to SQLite database (default: `/data/proxies.db`)
- `GEOIP_CITY_DB` / `GEOIP_ASN_DB` — Path to MaxMind databases (defaults: `/geoip/...`)
- `WORKERS` — Concurrent recheck goroutines (default: `100`, lower than validator since this is background work)
- `TIMEOUT` — Per-check timeout in seconds (default: `10`)
- `TEST_URL` — URL to request through the proxy (default: `http://httpbin.org/ip`)
- `ORIGIN_IP` — Public IP for anonymity detection (default: auto-detected)
- `SKIP_BLOCKLIST` — Disable DNSBL on rechecks (default: `false`)
- `BATCH_SIZE` — Proxies pulled per recheck batch (default: `500`)
- `RECHECK_INTERVAL` — Don't recheck a proxy more often than this (default: `1h`)
- `IDLE_SLEEP` — Sleep duration when nothing is due for recheck (default: `60s`)
- `FAILURE_THRESHOLD` — Consecutive failures before marking `stale` (default: `3`)
- `EVICT_AFTER` — Delete stale proxies after this much time without success (default: `168h` / 7 days)
- `EVICT_INTERVAL` — How often to run the eviction sweep (default: `1h`)

### API (`cmd/api`)
- `DB_PATH` — Path to SQLite database (default: `/data/proxies.db`)
- `LISTEN_ADDR` — Address to listen on (default: `:8080`)
- `API_TOKEN` — Bearer token required for all endpoints except `/v1/health`. Auth is disabled when unset (default: unset/disabled)

The API filters by proxy status. Default is `?status=active` (only proxies that passed their last recheck). Use `?status=stale` to see proxies in the failure-recovery grace period, or `?status=all` to see both. The legacy `?alive=false` parameter is treated as `?status=all`.

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

- Run the API and revalidator continuously: `docker compose up -d api revalidator`
- Run a scan: `docker compose --profile scan up scanner`
- Run the validator: `docker compose --profile scan up validator`
- The scanner and validator can be run independently. The scanner enqueues candidates to SQLite; the validator dequeues and processes them.
- The revalidator runs by default (no profile required) alongside the API. It rechecks existing proxies on `RECHECK_INTERVAL` (default 1h), demotes failing ones to `stale` after `FAILURE_THRESHOLD` consecutive failures, and hard-deletes them after `EVICT_AFTER` without a successful check.
- For incremental weekly scanning: Set `SCAN_TIMEOUT` (e.g. `4h`) so masscan saves state on timeout. Next run resumes automatically via `/data/paused.conf`.
- All four components share a named Docker volume `scanner-data` mounted at `/data`.
- SQLite WAL mode allows concurrent reads (API) and writes from validator + revalidator. The single-writer constraint is handled by `_busy_timeout=5000` and per-process connections; transient `SQLITE_BUSY` retries are expected during heavy validator runs.
- Rate limit masscan to 50k pps to avoid abuse complaints.