# Proxy Scanner — Agent Instructions

## Project Overview

This is a Go monorepo that produces three container images for an open proxy scanning system deployed on Kubernetes (k3s on Hetzner Cloud via FluxCD GitOps).

## Architecture

Three components, three container images:

1. **Scanner** (`docker/Dockerfile.scanner`) — Alpine + masscan. Runs as a K8s CronJob. Scans IPv4 space for open proxy ports. Outputs JSON to a shared PVC.
2. **Validator** (`cmd/validator/`, `docker/Dockerfile.validator`) — Go binary. Runs as a K8s Job after the scanner. Reads masscan output, validates each candidate as a working proxy (HTTP/HTTPS/SOCKS4/SOCKS5), measures latency, checks anonymity, tags with GeoIP. Writes to SQLite on the shared PVC.
3. **API** (`cmd/api/`, `docker/Dockerfile.api`) — Go REST API. Runs as a K8s Deployment. Serves proxy data from SQLite. Internal ClusterIP service for other cluster workloads.

## Code Structure

```
cmd/validator/main.go    — Validator entry point (worker pool, egress IP detection)
cmd/api/main.go          — API entry point (REST endpoints, request logging)
internal/proxy/          — Proxy checking logic (checker.go, geoip.go, types.go)
internal/database/       — SQLite operations (sqlite.go)
internal/scanner/        — Masscan output parser (parser.go)
data/                    — GeoLite2 .mmdb databases (City, ASN, Country) — committed to repo
config/exclude/          — Modular CIDR exclusion lists (merged at Docker build time)
docker/                  — Dockerfiles + scan.sh for all three images
deploy/                  — Example Kubernetes manifests (reference only)
.github/workflows/       — CI (test on PR) and build+push (images to GHCR on main)
```

## Key Technical Details

- **Go module**: `github.com/venatiodecorus/proxy-scanner`
- **Database**: SQLite with WAL mode. Single writer (validator), single reader (API). DB file at `/data/proxies.db`.
- **Scan output**: Masscan JSON at `/data/candidates.json` on the shared PVC.
- **Container registry**: `ghcr.io/venatiodecorus/proxy-scanner-{scanner,validator,api}`
- **GeoIP**: MaxMind GeoLite2-City + ASN databases bundled in the validator image at `/geoip/`. Source `.mmdb` files are committed in `data/`.
- **Egress IP**: Validator auto-detects public IP at startup via external services (ipify, ifconfig.me, etc.). Override with `ORIGIN_IP` env var.
- **CI/CD**: GitHub Actions builds and pushes all 3 images to GHCR on push to main. PRs run tests + vet.

## Development Guidelines

- All Go code uses standard library where possible. Minimal external dependencies.
- Key dependencies: `mattn/go-sqlite3` (CGO SQLite driver), `oschwald/maxminddb-golang` (GeoIP/ASN lookups).
- The API uses only the standard library `net/http` — no web framework.
- Tests should be runnable with `go test ./...` without network access or external databases.
- Dockerfiles use multi-stage builds. Final images are distroless (Go) or minimal Alpine (scanner).
- The `deploy/` directory contains example K8s manifests for reference. The actual manifests live in a separate infra/FluxCD repo.

## Environment Variables

### Validator (`cmd/validator`)
- `SCAN_INPUT` — Path to masscan JSON output (default: `/data/candidates.json`)
- `DB_PATH` — Path to SQLite database (default: `/data/proxies.db`)
- `GEOIP_CITY_DB` — Path to MaxMind GeoLite2-City database (default: `/geoip/GeoLite2-City.mmdb`)
- `GEOIP_ASN_DB` — Path to MaxMind GeoLite2-ASN database (default: `/geoip/GeoLite2-ASN.mmdb`)
- `ORIGIN_IP` — Public IP of the scanner node for anonymity detection (default: auto-detected)
- `WORKERS` — Number of concurrent validation goroutines (default: `500`)
- `TIMEOUT` — Per-proxy validation timeout in seconds (default: `10`)
- `TEST_URL` — URL to request through the proxy for validation (default: `http://httpbin.org/ip`)

### API (`cmd/api`)
- `DB_PATH` — Path to SQLite database (default: `/data/proxies.db`)
- `LISTEN_ADDR` — Address to listen on (default: `:8080`)

## Coding Conventions

- Use structured logging (`log/slog` from Go 1.21+).
- Error handling: wrap errors with context using `fmt.Errorf("doing X: %w", err)`.
- No global state. Pass dependencies explicitly.
- Database operations go through the `database.DB` struct, not raw SQL in business logic.
- Proxy checking logic is in `internal/proxy/checker.go`. Each protocol has its own check function.
- The validator orchestrates: parse input -> fan out to workers -> collect results -> write to DB.

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

- Kubernetes manifests in `deploy/` are examples only. Real manifests go in the infra repo.
- The three components share a single PVC mounted at `/data`.
- Scanner CronJob runs weekly. Validator Job runs after scanner completes. API Deployment runs continuously.
- Rate limit masscan to 50k pps on Hetzner Cloud to avoid abuse complaints.
- SQLite WAL mode allows concurrent reads (API) while the validator writes.
