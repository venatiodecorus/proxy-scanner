# Proxy Scanner — Agent Instructions

## Project Overview

This is a Go monorepo that produces four container images for a SOCKS-only open proxy scanning system, deployed via Docker Compose: scanner, validator, revalidator, and API.

## Architecture

Four components, four container images:

1. **Scanner** (`cmd/scanner/`, `docker/Dockerfile.scanner`) — Go binary wrapping masscan. Runs on-demand via Docker Compose scan profile. Scans IPv4 space on the SOCKS ports `1080,1081,9050`, then enqueues candidates into the SQLite database. The Scanner writes masscan JSON output to disk (for debugging) but the primary data path is the `candidates` queue table in SQLite.
2. **Validator** (`cmd/validator/`, `docker/Dockerfile.validator`) — Go binary. Runs on-demand via Docker Compose scan profile. Reads candidates from the `candidates` queue table, validates each as a working SOCKS4 or SOCKS5 proxy, measures latency, checks anonymity, applies mandatory `rbl.efnetrbl.org` eligibility checks to the endpoint and observed exit IP, optionally checks auxiliary DNSBLs, and tags with GeoIP. EFnet-listed candidates are rejected; indeterminate EFnet lookups are deferred and never accepted. Validated proxies are upserted into the `proxies` table; processed candidates are deleted from the queue. On startup, resets any `processing` candidates back to `pending` for crash recovery.
3. **Revalidator** (`cmd/revalidator/`, `docker/Dockerfile.revalidator`) — Go binary. Long-running, runs by default alongside the API. Periodically rechecks SOCKS proxies and mandatory EFnet eligibility to keep the live set fresh. Listed proxies are marked `stale`; indeterminate EFnet lookups fail closed. Other failures mark proxies `stale` after consecutive failures, and stale proxies are evicted after a grace period. Uses the same checker and blocklist code as the Validator.
4. **API** (`cmd/api/`, `docker/Dockerfile.api`) — Go REST API. Runs continuously. Serves proxy data from SQLite at `http://localhost:8080/v1/`.

All four components share a SQLite database via a Docker named volume. The `candidates` table acts as a durable work queue — the Scanner enqueues, the Validator dequeues and processes. Candidates are removed from the queue after processing (whether validated or failed), so the Validator never reprocesses the same candidate.

The `proxies` table tracks per-row liveness via `status` (`active` or `stale`), `last_checked_at`, `last_ok_at`, `consecutive_failures`, `check_count`, and `success_count`. The Revalidator drives the lifecycle: successful SOCKS and mandatory EFnet rechecks reset failures and refresh latency; failures increment the counter; EFnet-listed proxies are staled; reaching the failure threshold flips other failing rows to `stale` (hidden from API by default); rows that stay stale past the grace period get hard-deleted.

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
cmd/genexclude/          — Generator for the ASN-derived exclusion lists (dev tool, not shipped)
config/exclude/          — Modular CIDR exclusion lists (merged at Docker build time)
docker/                  — Dockerfiles for all four images
docker-compose.yml       — Docker Compose configuration
.github/workflows/       — CI (test on PR) and build+push (images to GHCR on main)
```

## Key Technical Details

- **Go module**: `github.com/venatiodecorus/proxy-scanner`
- **Database**: SQLite with WAL mode. The validator and revalidator write while the API reads. DB file at `/data/proxies.db`.
- **Candidates queue**: The `candidates` table in SQLite serves as a durable work queue. Scanner enqueues (INSERT OR IGNORE), Validator dequeues (SELECT pending → UPDATE to processing) and deletes after processing. On validator startup, any `processing` candidates are reset to `pending` for crash recovery.
- **Protocols and ports**: New scans and validation are SOCKS4/SOCKS5 only. The default target ports are `1080,1081,9050`.
- **Scan output**: Masscan JSON at `/data/candidates.json` on the shared volume (debugging artifact). The primary data path is the SQLite queue.
- **Scan resume**: The scanner supports masscan's `--resume` feature for incremental scanning. When `SCAN_TIMEOUT` is set, the scanner sends SIGINT to masscan after the timeout, causing masscan to save its state to `/data/paused.conf`. On the next run, the scanner detects this file and resumes from where it left off. This allows weekly scan sessions that make incremental progress through the entire IPv4 space without re-scanning previously covered ranges.
- **Masscan build**: Scanner image builds masscan from a pinned upstream master commit (see `docker/Dockerfile.scanner`) rather than using Alpine's `masscan` package. The last tagged masscan release (1.3.2, Feb 2021) predates the fix for upstream issue [#559](https://github.com/robertdavidgraham/masscan/issues/559) — paused.conf contains a `nocapture = servername` line that 1.3.2's config parser cannot read back, making `--resume` fail immediately. Master fixed this in commit `9065684c` (2023-06-07). Bump `MASSCAN_SHA` in the Dockerfile deliberately, not automatically.
- **EFnet eligibility hard gate**: Validator and revalidator query `rbl.efnetrbl.org` for both the proxy endpoint and observed exit IP. Listed candidates are rejected, listed existing proxies are marked `stale`, and indeterminate lookups are deferred or fail closed. This check cannot be disabled. `SKIP_AUX_BLOCKLISTS` controls only optional auxiliary DNSBLs.
- **Container registry**: `ghcr.io/venatiodecorus/proxy-scanner-{scanner,validator,revalidator,api}`
- **GeoIP**: MaxMind GeoLite2-City + ASN databases are bundled in the validator and revalidator images at `/geoip/`. Source `.mmdb` files are committed in `data/`.
- **Egress IP**: Validator and revalidator auto-detect the public IP at startup via external services (ipify, ifconfig.me, etc.). Override with `ORIGIN_IP` env var.
- **CI/CD**: GitHub Actions builds and pushes all 4 images to GHCR on push to main. PRs run tests + vet.
- **Docker Compose**: Scanner and validator are in the `scan` profile (`docker compose --profile scan up`). API and revalidator run by default (`docker compose up -d api revalidator`). Data persists via a named volume `scanner-data`.

## Development Guidelines

- All Go code uses standard library where possible. Minimal external dependencies.
- Key dependencies: `mattn/go-sqlite3` (CGO SQLite driver), `oschwald/maxminddb-golang` (GeoIP/ASN lookups).
- The API uses only the standard library `net/http` — no web framework.
- Tests should be runnable with `go test ./...` without network access or external databases.
- Dockerfiles use multi-stage builds. Final images are distroless (Go) or minimal Alpine (scanner).

## Environment Variables

### Scanner (`cmd/scanner`)
- `SCAN_RATE` — Masscan packets per second (default: `50000`)
- `SCAN_PORTS` — Comma-separated SOCKS port list (default: `1080,1081,9050`)
- `SCAN_ADAPTER` — Network interface for masscan. Unset/empty means masscan auto-detects the default-route interface (no default is baked in)
- `EXCLUDE_FILE` — Path to CIDR exclusion file (default: `/config/exclude.conf`). Validated at start-up; the scanner refuses to run if the file is missing, short, malformed, or fails a canary check. See "Fail-closed validation" below.
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
- `TEST_URL` — Origin URL to request through the SOCKS proxy for validation; the response must expose the observed IPv4 exit address (default: `http://httpbin.org/ip`)
- `SKIP_AUX_BLOCKLISTS` — Set to `true` to disable optional auxiliary DNSBLs (default: `false`). Mandatory endpoint and observed-exit checks against `rbl.efnetrbl.org` always run.
- `BATCH_SIZE` — Number of candidates to dequeue per batch (default: `1000`)

### Revalidator (`cmd/revalidator`)
- `DB_PATH` — Path to SQLite database (default: `/data/proxies.db`)
- `GEOIP_CITY_DB` / `GEOIP_ASN_DB` — Path to MaxMind databases (defaults: `/geoip/...`)
- `WORKERS` — Concurrent recheck goroutines (default: `100`, lower than validator since this is background work)
- `TIMEOUT` — Per-check timeout in seconds (default: `10`)
- `TEST_URL` — Origin URL to request through the SOCKS proxy; the response must expose the observed IPv4 exit address (default: `http://httpbin.org/ip`)
- `ORIGIN_IP` — Public IP for anonymity detection (default: auto-detected)
- `SKIP_AUX_BLOCKLISTS` — Disable optional auxiliary DNSBLs on rechecks (default: `false`). Mandatory endpoint and observed-exit checks against `rbl.efnetrbl.org` always run.
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

### Rotating endpoint (`GET /v1/proxies/rotate`)

Returns one proxy per call, cycling through the whole matching pool before repeating — distinct from `/v1/proxies/random`, which samples with replacement and can repeat immediately.

Rotation state is persisted on the `proxies` table (`last_served_at`, `serve_count`), not held in memory, so it survives restarts and is shared across API replicas. `database.RotateProxy` selects the least-recently-served match and stamps it in a **single `UPDATE ... RETURNING`** statement; keep it that way. Splitting the select and the update reintroduces the race where two concurrent callers get the same proxy.

Ordering is `last_served_at IS NOT NULL, last_served_at ASC, id ASC` — never-served proxies go out first. `idx_proxies_rotation` backs this.

Two deliberate default differences from the other routes, because the endpoint's contract is "a proxy you can use right now": `status` is forced to `active`, and `blocklisted=false` is applied unless the caller passes `blocklisted` explicitly. `limit`/`offset` are ignored. `?format=text` returns a bare `scheme://ip:port` for shell pipelines, and rotating responses set `Cache-Control: no-store`.

Note that `serve_count` is *not* a health signal — the validator and revalidator never touch it.

## Coding Conventions

- Use structured logging (`log/slog` from Go 1.21+).
- Error handling: wrap errors with context using `fmt.Errorf("doing X: %w", err)`.
- No global state. Pass dependencies explicitly.
- Database operations go through the `database.DB` struct, not raw SQL in business logic.
- Proxy checking logic is in `internal/proxy/checker.go`, with SOCKS4 and SOCKS5 check functions only for new validation.
- Blocklist checking is in `internal/blocklist/dnsbl.go`. Treat `rbl.efnetrbl.org` as a mandatory eligibility gate for both endpoint and observed exit IP; optional auxiliary DNSBLs may be skipped with `SKIP_AUX_BLOCKLISTS`.
- Never convert an indeterminate EFnet lookup into an eligible result. Initial validation must defer it, and revalidation must fail closed.
- The validator orchestrates: parse input -> fan out to workers -> check SOCKS proxy -> enforce EFnet eligibility -> optionally check auxiliary blocklists -> write to DB.

## Testing

- `go test ./...` runs all tests.
- Database tests use in-memory SQLite (`:memory:`).
- Proxy checker tests use local mock origin and SOCKS servers where possible.
- No integration tests that require real network scanning.

## Exclusion List Management

Masscan is invoked against `0.0.0.0/0`. There is no allowlist, so the exclusion list is the only thing keeping the scan off networks it must not touch. Treat these files and the code that validates them as safety-critical.

The list is split into modular files under `config/exclude/`:

- `00-iana-special.conf` — IANA Special-Purpose Address Registry (RFC 6890). Non-negotiable; these are non-routable.
- `10-military.conf` — Military /8 allocations (US DoD legacy /8s plus UK MOD `25.0.0.0/8`). Whole /8s only.
- `11-military-asn.conf` — **GENERATED.** Military/defense networks by ASN organisation name. This is what covers the hundreds of DoD/Air Force/Navy prefixes outside the /8s.
- `12-government-asn.conf` — **GENERATED.** Federal, state, municipal and foreign government networks; law enforcement and intelligence agencies.
- `20-cloud-providers.conf` — Hand-written Hetzner supernets. Known incomplete; kept only as a backstop.
- `21-selfhost-asn.conf` — **GENERATED.** Complete hosting-provider self-exclusion by ASN.
- `30-infrastructure.conf` — Root DNS, IXPs, RIR infrastructure. Critical internet infra.
- `90-custom.conf` — Manual additions from abuse complaints or opt-out requests.

Files are numbered so they merge in predictable order via `cat config/exclude/*.conf`. The Dockerfile strips comments and blank lines at build time to produce a clean CIDR-only file for masscan.

**Never hand-edit a `*-asn.conf` file.** Regenerate with `go run ./cmd/genexclude` (see `cmd/genexclude/main.go` for the organisation-name regexps and the short false-positive denylist). Use `-list-orgs <military|government|selfhost>` to audit which organisations matched. Regenerate after refreshing `data/GeoLite2-ASN.mmdb`.

**Bias toward over-excluding.** A false positive costs one proxy candidate; a false negative means scanning a military or government network.

**To add a new exclusion**: Add the CIDR to `90-custom.conf`, commit, push. The scanner image rebuilds automatically via GitHub Actions. Exclusions are baked in at build time, so an opt-out only takes effect once the new image rolls out.

### Fail-closed validation

Do not weaken either of these, and do not add a flag to bypass them:

- `docker/Dockerfile.scanner` fails the image build if the merged list has fewer than `MIN_EXCLUDE_ENTRIES` (2000) entries.
- `cmd/scanner/exclude.go` re-validates at start-up before masscan runs: the file must parse cleanly, clear the same floor, and cover every address in `excludeCanaries` — one canary per fragment, so an unmerged fragment is detected rather than assumed present. Add a canary when you add a fragment.

`TestCommittedExcludeListPassesPreflight` in `cmd/scanner/exclude_test.go` runs the runtime validation against the real committed files, so CI catches an unsafe list before it ships.

## Deployment Notes

- Run the API and revalidator continuously: `docker compose up -d api revalidator`
- Run a scan: `docker compose --profile scan up scanner`
- Run the validator: `docker compose --profile scan up validator`
- The scanner and validator can be run independently. The scanner enqueues candidates to SQLite; the validator dequeues and processes them.
- The revalidator runs by default (no profile required) alongside the API. It rechecks existing SOCKS proxies and mandatory EFnet eligibility on `RECHECK_INTERVAL` (default 1h), immediately stales EFnet-listed proxies, demotes other failing ones to `stale` after `FAILURE_THRESHOLD` consecutive failures, and hard-deletes them after `EVICT_AFTER` without a successful check.
- When cutting over from the historical mixed-port scanner, back up the database, remove `/data/paused.conf`, clear the old candidates queue, and remove HTTP/HTTPS proxy rows explicitly; this cleanup is intentionally not automatic.
- For incremental scanning: Set `SCAN_TIMEOUT` (e.g. `4h`) so masscan saves state on timeout. Next run resumes automatically via `/data/paused.conf`.
- **Schedule** is systemd timers, defined in `deploy/systemd/` and installed to `/etc/systemd/system/` by `deploy/bootstrap.sh`: `proxy-scanner-scan.timer` daily at 02:00 UTC, `proxy-scanner-validate.timer` daily at 07:00 UTC. The validator also chains off the scanner via `OnSuccess=` so the queue drains as soon as a sweep session ends. Full runbook in `deploy/README.md`.
- No `flock` is needed under systemd — it refuses to start a second instance of an active unit, so overlapping masscan sessions (which would corrupt `paused.conf` and double the packet rate) cannot happen.
- `proxy-scanner-scan.service` sets `KillSignal=SIGINT`. Do not change it: masscan only writes `paused.conf` on SIGINT, and a SIGTERM silently discards the session's progress.
- `SCAN_ADAPTER` unset means "let masscan pick the default-route interface". Do not reintroduce a hardcoded default — the old `ens3` was an OpenStack-ism that breaks on Debian. `buildMasscanArgs` omits the flag entirely when it is empty.
- A full IPv4 sweep is ~56h of masscan time (3.37B addresses in scope × 3 ports / 50k pps), so daily 4h sessions complete a sweep about every 14 days. Recompute if `SCAN_PORTS`, `SCAN_RATE`, or the exclusion lists change — some older notes in this repo assumed a single port and understated it as ~24h.
- The validator is a batch job: it drains the candidates queue and exits. It is normally triggered by `OnSuccess=` when a scan session finishes; if you ever drive it on a timer alone, keep that cadence matched to the scanner's or candidates accumulate.
- All four components share a named Docker volume `scanner-data` mounted at `/data`.
- SQLite WAL mode allows concurrent reads (API) and writes from validator + revalidator. The single-writer constraint is handled by `_busy_timeout=5000` and per-process connections; transient `SQLITE_BUSY` retries are expected during heavy validator runs.
- Rate limit masscan to 50k pps to avoid abuse complaints. `docker-compose.yml` must not exceed this; higher rates also cause packet loss on Hetzner Cloud's shared NICs, which silently costs coverage.