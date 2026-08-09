# Proxy Scanner

A system that scans the public IPv4 space for open SOCKS4 and SOCKS5 proxies, validates them, enforces mandatory EFnet RBL eligibility checks, measures latency, classifies anonymity level, enriches with GeoIP/ASN data, and exposes verified proxies via a REST API.

Deployed via Docker Compose.

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                   Docker Compose                          │
│                                                          │
│  ┌──────────────┐    on-demand (scan profile)            │
│  │  scanner     │──→ masscan sweep of IPv4 space         │
│  │  (Go+masscan)│    enqueues candidates to SQLite       │
│  └──────┬───────┘                                        │
│         │ candidates table (SQLite queue)                 │
│         ▼                                                │
│  ┌──────────────┐    on-demand (scan profile)            │
│  │  validator   │──→ Go: validates SOCKS4/SOCKS5,        │
│  │  (Go)        │    enforces EFnet RBL, tags GeoIP/ASN  │
│  └──────┬───────┘                                        │
│         │ proxies table (SQLite)                         │
│         ▼                                                │
│  ┌──────────────┐    always running                      │
│  │  revalidator │──→ Go: rechecks proxies, marks stale,  │
│  │  (Go)        │    evicts after grace period           │
│  └──────┬───────┘                                        │
│         │ SQLite                                         │
│         ▼                                                │
│  ┌──────────────┐    always running                      │
│  │  api         │──→ REST API for proxy data             │
│  │  (Go)        │    http://localhost:8080/v1/           │
│  └──────────────┘                                        │
└──────────────────────────────────────────────────────────┘
```

Four components, four container images:

| Component | Image | Purpose |
|-----------|-------|---------|
| Scanner | `ghcr.io/venatiodecorus/proxy-scanner-scanner` | Masscan sweep → SQLite queue |
| Validator | `ghcr.io/venatiodecorus/proxy-scanner-validator` | Dequeue candidates, validate SOCKS4/SOCKS5 proxies, enforce EFnet RBL eligibility, write to `proxies` table |
| Revalidator | `ghcr.io/venatiodecorus/proxy-scanner-revalidator` | Periodically rechecks live proxies and EFnet eligibility, demotes failing or listed ones to `stale`, evicts dead ones |
| API | `ghcr.io/venatiodecorus/proxy-scanner-api` | REST API serving proxy data from SQLite |

The scanner and validator communicate through a `candidates` table in SQLite (stored on a shared Docker volume). The scanner enqueues IP:port candidates from the default SOCKS port set (`1080,1081,9050`); the validator dequeues, validates, and deletes them. This allows them to run independently — scan one week, validate the next.

EFnet RBL eligibility is a mandatory hard gate. The validator checks both the proxy endpoint IP and the observed exit IP against `rbl.efnetrbl.org`; a listed address rejects the candidate. The revalidator applies the same checks and marks listed proxies `stale`. Indeterminate EFnet lookups are never treated as eligible: initial validation is deferred, and revalidation fails closed. Optional auxiliary DNSBL checks can be disabled with `SKIP_AUX_BLOCKLISTS=true`, but EFnet checks cannot be disabled.

The revalidator runs continuously alongside the API and rechecks the `proxies` table on a configurable interval (default 1h). Proxies that fail `FAILURE_THRESHOLD` consecutive checks (default 3) are marked `stale` (hidden from the API by default); proxies that stay stale for `EVICT_AFTER` (default 7 days) without a successful recheck are deleted.

## Quick Start

```bash
# Pull images and start the API + revalidator
docker compose up -d api revalidator

# Run a scan (scanner enqueues to SQLite)
docker compose --profile scan up scanner

# Run the validator (dequeues from SQLite, validates, writes to proxies table)
docker compose --profile scan up validator
```

## SOCKS-only cutover

Existing data is not deleted automatically. Before the first scan with this release, stop the scanner, validator, and revalidator and back up `/data/proxies.db`. A saved masscan resume file contains the old mixed-port scan configuration, so remove `/data/paused.conf` and rotate `/data/candidates.json` before starting a new SOCKS-only scan.

For a clean cutover, clear candidates from the previous mixed-port campaign and remove previously validated HTTP/HTTPS rows:

```sql
DELETE FROM candidates;
DELETE FROM proxies WHERE protocol NOT IN ('socks4', 'socks5');
```

The validator now requires `TEST_URL` to return the observed IPv4 exit address in its response body. The default `http://httpbin.org/ip` satisfies this requirement.

## Incremental Scanning

The scanner supports masscan's `--resume` feature for incremental scanning. When `SCAN_TIMEOUT` is set, the scanner sends SIGINT to masscan after the timeout, causing it to save its state to `/data/paused.conf`. On the next run, the scanner detects this file and resumes from where it left off.

```bash
# Set SCAN_TIMEOUT in docker-compose.yml or environment
SCAN_TIMEOUT=4h

# Each session continues where the last one stopped
docker compose --profile scan up scanner
```

Masscan randomizes scan order by default, so resumed scans won't re-scan previously covered segments.

### How long a full sweep takes

| | |
|---|---|
| Addresses in scope after exclusions | 3,369,972,995 (78.5% of IPv4) |
| Ports per address (`SCAN_PORTS`) | 3 |
| Total probes | 10,109,918,985 |
| At `SCAN_RATE=50000` | **~56 hours of masscan time** |
| With `SCAN_TIMEOUT=4h`, sessions per sweep | ~14 |

At the default daily cadence that means a full sweep roughly **every 14 days**. Scale from there: doubling `SCAN_RATE` halves it, and so does dropping to a single port. Recompute this if you change `SCAN_PORTS`, `SCAN_RATE`, or the exclusion lists — the probe count is `addresses_in_scope × ports`, and older docs in this repo assumed a single port.

## Scan Schedule

Scheduling is handled by systemd timers on the host. See [`deploy/README.md`](deploy/README.md) for the full runbook.

| Unit | Schedule | Notes |
|---|---|---|
| `proxy-scanner-scan.timer` | Daily, 02:00 UTC | One 4h session (`SCAN_TIMEOUT`), then saves resume state |
| `proxy-scanner-validate.timer` | Daily, 07:00 UTC | Safety net; normally the validator runs via `OnSuccess=` the moment a scan session ends |

```sh
systemctl list-timers 'proxy-scanner*'        # what's scheduled
systemctl start proxy-scanner-scan.service    # run a session now
systemctl stop proxy-scanner-scan.service     # graceful stop, saves paused.conf
journalctl -fu proxy-scanner-scan.service     # follow it
```

To change the cadence, edit `OnCalendar=` in `/etc/systemd/system/proxy-scanner-scan.timer`, then `systemctl daemon-reload && systemctl restart proxy-scanner-scan.timer`.

Two properties worth knowing:

- **Overlap is structurally impossible.** systemd will not start a second instance of an already-active unit. The previous cron setup needed `flock -n` for this, because two concurrent masscan sessions would corrupt the single `paused.conf` *and* double the effective packet rate.
- **Stopping a scan must send SIGINT.** masscan only writes its resume file on SIGINT; SIGTERM kills it and the session's progress is lost. `proxy-scanner-scan.service` sets `KillSignal=SIGINT` for this reason — prefer `systemctl stop` over `docker kill`.

## Firewalling masscan's Source Ports

masscan brings its own IP stack and sends from `--source-port 40000-56383`. The host kernel knows nothing about those connections, so it answers the returning SYN-ACKs with RSTs — unnecessary traffic to every host you probe, from a port range you are not actually serving. masscan warns about this itself.

Scans work without the rule, so `deploy/install.sh` does not apply it unprompted. Do it before a real sweep.

### Add

The rule goes in its own nftables table. That matters for two reasons: a minimal Debian install may have no `inet filter` table to append to, and a dedicated table can be removed in one command without touching anything else's rules.

```sh
sudo nft add table inet masscan
sudo nft add chain inet masscan input '{ type filter hook input priority -10; policy accept; }'
sudo nft add rule inet masscan input tcp dport 40000-56383 counter drop
```

Verify — the counter should climb while a scan is running:

```sh
sudo nft list table inet masscan
```

Make it survive a reboot by appending the table to `/etc/nftables.conf`:

```sh
sudo tee -a /etc/nftables.conf >/dev/null <<'EOF'

# Drop kernel responses on masscan's source-port range (see README).
table inet masscan {
    chain input {
        type filter hook input priority -10; policy accept;
        tcp dport 40000-56383 counter drop
    }
}
EOF
sudo systemctl enable --now nftables
sudo nft -c -f /etc/nftables.conf && echo "nftables.conf is valid"
```

### Remove

```sh
# Drop it from the running ruleset
sudo nft delete table inet masscan
```

Then delete the `table inet masscan { ... }` block from `/etc/nftables.conf` so it does not come back on reboot, and re-validate:

```sh
sudo nft -c -f /etc/nftables.conf && echo "nftables.conf is valid"
```

Confirm it is gone (this should report no such table):

```sh
sudo nft list table inet masscan
```

### iptables hosts

If the box uses iptables rather than nftables, the add and remove are symmetric — `-I` to insert, `-D` with the identical rule spec to delete:

```sh
sudo iptables -I INPUT -p tcp --dport 40000:56383 -j DROP   # add
sudo iptables -D INPUT -p tcp --dport 40000:56383 -j DROP   # remove
```

Persist with `iptables-save > /etc/iptables/rules.v4` (package `iptables-persistent`).

## Stopping and Resuming

### Graceful stop (saves scan progress)

To stop the scanner mid-scan without losing progress, send SIGINT — masscan saves its state to `paused.conf` and the Go scanner parses any results already written:

```bash
docker kill --signal=SIGINT proxy-scanner-scanner
```

Do **not** use `docker stop` or `docker compose down` — these send SIGTERM, which kills masscan before it can save resume state.

The validator can be stopped anytime with `docker compose --profile scan down validator`. It resets any in-progress candidates back to `pending` on next startup, so no work is lost.

### Monitoring progress

```bash
# Watch candidate count in the queue
sudo watch -n 5 'sqlite3 /var/lib/docker/volumes/proxy-scanner_scanner-data/_data/proxies.db "SELECT status, COUNT(*) FROM candidates GROUP BY status"'

# Watch active validated proxy count
sudo watch -n 5 'sqlite3 /var/lib/docker/volumes/proxy-scanner_scanner-data/_data/proxies.db "SELECT status, COUNT(*) FROM proxies GROUP BY status"'

# Watch live scan progress (masscan writes to JSON as it scans)
sudo watch -n 5 'wc -l /var/lib/docker/volumes/proxy-scanner_scanner-data/_data/candidates.json'
docker logs -f proxy-scanner-scanner
docker logs -f proxy-scanner-validator
```

The scanner and validator also emit structured progress totals every 15 minutes. Scanner entries include elapsed time, completed masscan JSON records, output size, and pending queue depth. Validator entries include processed/dequeued totals, verified proxies, EFnet rejections, deferred candidates, and pending queue depth.

## Monitoring Bandwidth

If your VPS has limited bandwidth, install **vnstat** on the host to track usage across all containers:

```bash
sudo apt install vnstat
sudo systemctl enable --now vnstat

# Monthly totals
vnstat -m

# Daily totals
vnstat -d

# Live traffic
vnstat -l
```

Since the scanner uses `network_mode: host`, all container traffic flows through the host interface and is captured by vnstat.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/health` | Health check |
| `GET` | `/v1/proxies` | List proxies with filters |
| `GET` | `/v1/proxies/random` | Random proxy matching filters (samples with replacement) |
| `GET` | `/v1/proxies/rotate` | **Rotating endpoint** — a different proxy on every call |
| `GET` | `/v1/proxies/{id}` | Single proxy by ID |
| `GET` | `/v1/stats` | Aggregate statistics |

### Rotating Endpoint

`GET /v1/proxies/rotate` is the endpoint to hit when you want a fresh proxy per request rather than a list. Each call returns the **least recently served** proxy matching your filters and stamps it, so successive calls walk the entire matching pool before repeating any entry.

This is the difference from `/v1/proxies/random`, which samples uniformly with replacement and can hand you the same proxy twice in a row.

Two defaults differ from the other routes, because this endpoint's contract is "a proxy you can use right now":

- Only `active` proxies are considered (the `status` parameter is ignored).
- Blocklisted proxies are excluded unless you pass `blocklisted=true`.

The claim and the serve-stamp happen in a single SQL statement, so concurrent callers never receive the same proxy. Rotation state lives in the `last_served_at` / `serve_count` columns, so it survives API restarts and is shared across replicas.

```bash
# JSON, with a ready-to-use connection URL alongside the usual proxy fields
curl "http://localhost:8080/v1/proxies/rotate"
# => {"id":42,...,"serve_count":7,"url":"socks5://203.0.113.9:1080"}

# Filtered the same way as the list route
curl "http://localhost:8080/v1/proxies/rotate?protocol=socks5&country=DE&max_latency=500"

# format=text returns a bare proxy URL, for shell pipelines
curl -s "http://localhost:8080/v1/proxies/rotate?format=text"
# => socks5://203.0.113.9:1080

# Fetch a page through a freshly rotated proxy
curl -sx "$(curl -s http://localhost:8080/v1/proxies/rotate?format=text)" https://example.com
```

Returns `404` when nothing matches the filters.

### Query Parameters for `/v1/proxies`, `/v1/proxies/random` and `/v1/proxies/rotate`

| Parameter | Example | Description |
|-----------|---------|-------------|
| `protocol` | `socks4`, `socks5` | Filter by protocol. New validation results are SOCKS-only; the API schema remains compatible with historical stored protocol values. |
| `anonymity` | `elite`, `anonymous`, `transparent` | Filter by anonymity level |
| `country` | `US`, `DE` | Filter by ISO country code |
| `max_latency` | `500` | Maximum latency in ms |
| `limit` | `50` | Results per page (default 100, max 1000) |
| `offset` | `100` | Pagination offset |
| `status` | `active`, `stale`, `all` | Liveness filter (default: `active`). `stale` = recently failing but kept around; `all` = both. Ignored by `/rotate`, which is always `active`. |
| `alive` | `false` | Legacy alias for `status=all`. |
| `blocklisted` | `true`, `false` | Filter by blocklist status. `/rotate` defaults to `false`; the other routes do not filter by default. |
| `format` | `text` | `/rotate` only. Returns a bare `socks5://ip:port` as `text/plain` instead of JSON. |

`limit` and `offset` are ignored by `/rotate` and `/random`, which always return a single proxy.

### Example Responses

```bash
# Get 5 fast elite SOCKS5 proxies in Germany
curl "http://localhost:8080/v1/proxies?protocol=socks5&anonymity=elite&country=DE&max_latency=500&limit=5"

# Get a random SOCKS4 proxy
curl "http://localhost:8080/v1/proxies/random?protocol=socks4"

# Stats overview
curl "http://localhost:8080/v1/stats"
```

## Prerequisites

- Docker
- Go 1.23+ and GCC (for local development only)

## Local Development

### Run Tests

```bash
go test ./... -v
```

### Build Binaries

```bash
# Scanner
CGO_ENABLED=1 go build -o bin/scanner ./cmd/scanner/

# Validator
CGO_ENABLED=1 go build -o bin/validator ./cmd/validator/

# Revalidator
CGO_ENABLED=1 go build -o bin/revalidator ./cmd/revalidator/

# API
CGO_ENABLED=1 go build -o bin/api ./cmd/api/
```

### Run the API Locally

```bash
CGO_ENABLED=1 go build -o bin/api ./cmd/api/
DB_PATH=./test.db LISTEN_ADDR=:8080 ./bin/api

# In another terminal
curl http://localhost:8080/v1/health
curl http://localhost:8080/v1/stats
```

### Run the Validator Locally

The validator reads from the SQLite candidates queue. Create test candidates directly:

```bash
CGO_ENABLED=1 go build -o bin/validator ./cmd/validator/
DB_PATH=./test.db \
  GEOIP_CITY_DB=./data/GeoLite2-City.mmdb \
  GEOIP_ASN_DB=./data/GeoLite2-ASN.mmdb \
  WORKERS=10 \
  TIMEOUT=5 \
  ./bin/validator
```

### Build Docker Images Locally

```bash
# Scanner
docker build -f docker/Dockerfile.scanner -t proxy-scanner-scanner .

# Validator
docker build -f docker/Dockerfile.validator -t proxy-scanner-validator .

# Revalidator
docker build -f docker/Dockerfile.revalidator -t proxy-scanner-revalidator .

# API
docker build -f docker/Dockerfile.api -t proxy-scanner-api .
```

## Project Structure

```
cmd/
  scanner/main.go            Entry point: masscan wrapper + SQLite queue
  validator/main.go          Entry point: dequeue, validate, write to proxies table
  revalidator/main.go        Entry point: rechecks proxies, marks stale, evicts dead
  api/main.go                Entry point: REST API server
internal/
  proxy/
    checker.go               SOCKS4/SOCKS5 proxy validation
    geoip.go                 MaxMind GeoLite2 City + ASN lookups
    types.go                 Shared types (Proxy, Candidate, CandidateEntry, etc.)
  database/
    sqlite.go                SQLite operations (queue, upsert, query, stats)
  blocklist/
    dnsbl.go                 Mandatory EFnet RBL and optional auxiliary DNSBL checks
  scanner/
    parser.go                Masscan JSON output parser
data/
  GeoLite2-City.mmdb         MaxMind City database (bundled in validator image)
  GeoLite2-ASN.mmdb          MaxMind ASN database (bundled in validator image)
  GeoLite2-Country.mmdb     MaxMind Country database
config/
  exclude/                   Modular CIDR exclusion lists (merged at build time)
    00-iana-special.conf      IANA Special-Purpose Address Registry (RFC 6890)
    10-military.conf          Military /8 allocations (hand-maintained)
    11-military-asn.conf      Military/defense networks by ASN org (GENERATED)
    12-government-asn.conf    Government networks by ASN org (GENERATED)
    20-cloud-providers.conf   Hetzner supernets (hand-maintained backstop)
    21-selfhost-asn.conf      Hosting provider self-exclusion by ASN (GENERATED)
    30-infrastructure.conf    Root DNS, IXPs, RIR infrastructure
    90-custom.conf            Manual additions (abuse complaints)
docker/
  Dockerfile.scanner         Multi-stage Go build + masscan
  Dockerfile.validator       Multi-stage Go build + GeoIP databases
  Dockerfile.revalidator     Multi-stage Go build + GeoIP databases
  Dockerfile.api             Multi-stage Go build
docker-compose.yml           Docker Compose configuration
.github/workflows/
  ci.yaml                    Tests + vet on pull requests
  build-push.yaml            Build and push images to GHCR on push to main
```

## CI/CD

- **Pull requests**: GitHub Actions runs `go test` and `go vet`
- **Push to main**: Builds all 4 Docker images and pushes to GHCR with `sha-<commit>` and `latest` tags

No additional secrets or configuration required. The workflow uses the built-in `GITHUB_TOKEN`.

## Scan Exclusion List

The scanner targets `0.0.0.0/0`. There is no allowlist — the exclusion list is the *only* thing keeping the scan off networks it must not touch, so treat it as a safety-critical component.

Networks are excluded via modular config files in `config/exclude/`, which the scanner Dockerfile merges at build time (~7,500 entries covering roughly 7% of IPv4).

### Hand-maintained vs. generated

`00-iana-special.conf`, `10-military.conf`, `20-cloud-providers.conf`, `30-infrastructure.conf` and `90-custom.conf` are edited by hand.

The `*-asn.conf` files are **generated** and must not be hand-edited. They are derived from ASN organisation names in `data/GeoLite2-ASN.mmdb`, because hand-curated lists can only realistically cover whole /8s — and military organisations hold many hundreds of smaller prefixes outside those /8s (US DoD ASNs alone announce ~1000 prefixes, mostly /16s scattered through `128.0.0.0/3`).

```sh
go run ./cmd/genexclude                       # regenerate the *-asn.conf files
go run ./cmd/genexclude -list-orgs military    # audit which organisations matched
```

Regenerate whenever `data/GeoLite2-ASN.mmdb` is refreshed, and review the diff before committing.

### Fail-closed validation

Two independent checks guard against shipping or running a broken exclusion list:

- **Build time** — `docker/Dockerfile.scanner` fails the build if the merged file has fewer than `MIN_EXCLUDE_ENTRIES` (2000) entries.
- **Start-up** — `cmd/scanner/exclude.go` re-validates before masscan sends a packet: the file must parse cleanly, clear the same entry-count floor, and *cover a set of canary addresses* drawn from every fragment (RFC1918, US DoD /8, UK MOD /8, a DoD /16, Navy, Air Force, US House of Representatives, FAA, our own provider, a root nameserver). If any canary is uncovered, the scan aborts with an error naming it.

`TestCommittedExcludeListPassesPreflight` runs that same validation against the real committed files in CI.

### Adding an exclusion

To add a new exclusion (e.g., after an abuse complaint):

1. Add the CIDR to `config/exclude/90-custom.conf`
2. Commit and push to main
3. GitHub Actions rebuilds and pushes the scanner image to GHCR
4. **On the scanner host, pull it:** `sudo /opt/proxy-scanner/update.sh`

Step 4 is manual and easy to forget. Exclusions are baked into the image at build time, so until the host pulls the new image the old list is still in force and the range keeps being scanned — a pushed commit is not an honoured opt-out. The next scan session after the pull picks it up.

To confirm what the image on the host actually contains:

```sh
docker run --rm --entrypoint grep \
  ghcr.io/venatiodecorus/proxy-scanner-scanner:latest -c . /config/exclude.conf
```

## Environment Variables

### Scanner

| Variable | Default | Description |
|----------|---------|-------------|
| `SCAN_RATE` | `50000` | Masscan packets per second |
| `SCAN_PORTS` | `1080,1081,9050` | SOCKS target ports (comma-separated) |
| `SCAN_ADAPTER` | *(empty)* | Network interface for masscan. Empty means masscan auto-detects the default-route interface |
| `EXCLUDE_FILE` | `/config/exclude.conf` | CIDR exclusion list |
| `DB_PATH` | `/data/proxies.db` | SQLite database path |
| `OUTPUT_FILE` | `/data/candidates.json` | Masscan JSON output (debugging artifact) |
| `RESUME_FILE` | `/data/paused.conf` | Masscan resume state file |
| `SCAN_TIMEOUT` | *(none)* | Max scan duration (e.g. `4h`, `30m`). Sends SIGINT to masscan on timeout, enabling incremental scanning across many sessions. Set to `4h` in `docker-compose.yml` |

### Validator

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_PATH` | `/data/proxies.db` | Path to SQLite database |
| `GEOIP_CITY_DB` | `/geoip/GeoLite2-City.mmdb` | MaxMind City database |
| `GEOIP_ASN_DB` | `/geoip/GeoLite2-ASN.mmdb` | MaxMind ASN database |
| `ORIGIN_IP` | *(auto-detected)* | Public IP for anonymity detection |
| `WORKERS` | `500` | Concurrent validation goroutines |
| `TIMEOUT` | `10` | Per-proxy timeout in seconds |
| `TEST_URL` | `http://httpbin.org/ip` | Origin URL requested through SOCKS proxies; response must expose the observed IPv4 exit address |
| `SKIP_AUX_BLOCKLISTS` | `false` | Disable optional auxiliary DNSBLs only; mandatory endpoint and observed-exit checks against `rbl.efnetrbl.org` remain enabled |
| `BATCH_SIZE` | `1000` | Candidates to dequeue per batch |

### Revalidator

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_PATH` | `/data/proxies.db` | Path to SQLite database |
| `GEOIP_CITY_DB` | `/geoip/GeoLite2-City.mmdb` | MaxMind City database |
| `GEOIP_ASN_DB` | `/geoip/GeoLite2-ASN.mmdb` | MaxMind ASN database |
| `ORIGIN_IP` | *(auto-detected)* | Public IP for anonymity detection |
| `WORKERS` | `100` | Concurrent recheck goroutines |
| `TIMEOUT` | `10` | Per-proxy timeout in seconds |
| `TEST_URL` | `http://httpbin.org/ip` | Origin URL requested through SOCKS proxies; response must expose the observed IPv4 exit address |
| `SKIP_AUX_BLOCKLISTS` | `false` | Disable optional auxiliary DNSBLs only; mandatory endpoint and observed-exit checks against `rbl.efnetrbl.org` remain enabled |
| `BATCH_SIZE` | `500` | Proxies pulled per recheck batch |
| `RECHECK_INTERVAL` | `1h` | Minimum interval between proxy rechecks |
| `IDLE_SLEEP` | `60s` | Sleep duration when nothing is due |
| `FAILURE_THRESHOLD` | `3` | Consecutive failures before marking a proxy `stale` |
| `EVICT_AFTER` | `168h` | Delete stale proxies after 7 days without success |
| `EVICT_INTERVAL` | `1h` | Interval between eviction sweeps |

### API

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_PATH` | `/data/proxies.db` | Path to SQLite database |
| `LISTEN_ADDR` | `:8080` | Listen address |
| `API_TOKEN` | *(unset)* | Bearer token for auth (disabled when unset) |

## License

See LICENSE file.