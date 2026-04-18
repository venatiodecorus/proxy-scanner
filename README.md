# Proxy Scanner

A system that scans the public IPv4 space for open proxies (HTTP, HTTPS, SOCKS4, SOCKS5), validates them, measures latency, classifies anonymity level, enriches with GeoIP/ASN data, and exposes verified proxies via a REST API.

Deployed via Docker Compose.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  Docker Compose                          │
│                                                         │
│  ┌──────────────┐    on-demand (scan profile)           │
│  │  scanner     │──→ masscan sweep of IPv4 space        │
│  │  (Go+masscan)│    enqueues candidates to SQLite      │
│  └──────┬───────┘                                       │
│         │ candidates table (SQLite queue)                │
│         ▼                                               │
│  ┌──────────────┐    on-demand (scan profile)           │
│  │  validator   │──→ Go: dequeues candidates, validates │
│  │  (Go)        │    proxies, GeoIP/ASN tagging          │
│  └──────┬───────┘                                       │
│         │ SQLite                                        │
│         ▼                                               │
│  ┌──────────────┐    always running                      │
│  │  api         │──→ REST API for proxy data            │
│  │  (Go)        │    http://localhost:8080/v1/          │
│  └──────────────┘                                       │
└─────────────────────────────────────────────────────────┘
```

Three components, three container images:

| Component | Image | Purpose |
|-----------|-------|---------|
| Scanner | `ghcr.io/venatiodecorus/proxy-scanner-scanner` | Masscan sweep → SQLite queue |
| Validator | `ghcr.io/venatiodecorus/proxy-scanner-validator` | Dequeue candidates, validate proxies, write to `proxies` table |
| API | `ghcr.io/venatiodecorus/proxy-scanner-api` | REST API serving proxy data from SQLite |

The scanner and validator communicate through a `candidates` table in SQLite (stored on a shared Docker volume). The scanner enqueues IP:port candidates; the validator dequeues, validates, and deletes them. This allows them to run independently — scan one week, validate the next.

## Quick Start

```bash
# Pull images and start the API
docker compose up -d api

# Run a scan (scanner enqueues to SQLite)
docker compose --profile scan up scanner

# Run the validator (dequeues from SQLite, validates, writes to proxies table)
docker compose --profile scan up validator
```

## Incremental Scanning

The scanner supports masscan's `--resume` feature for incremental weekly scanning. When `SCAN_TIMEOUT` is set, the scanner sends SIGINT to masscan after the timeout, causing it to save its state to `/data/paused.conf`. On the next run, the scanner detects this file and resumes from where it left off.

```bash
# Set SCAN_TIMEOUT in docker-compose.yml or environment
SCAN_TIMEOUT=4h

# Run weekly — each session continues where the last one stopped
docker compose --profile scan up scanner
```

Masscan randomizes scan order by default, so resumed scans won't re-scan previously covered segments.

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

# Watch validated proxy count
sudo watch -n 5 'sqlite3 /var/lib/docker/volumes/proxy-scanner_scanner-data/_data/proxies.db "SELECT COUNT(*) FROM proxies WHERE alive = 1"'

# Watch live scan progress (masscan writes to JSON as it scans)
sudo watch -n 5 'wc -l /var/lib/docker/volumes/proxy-scanner_scanner-data/_data/candidates.json'
docker logs -f proxy-scanner-scanner
docker logs -f proxy-scanner-validator
```

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
| `GET` | `/v1/proxies/random` | Random proxy matching filters |
| `GET` | `/v1/proxies/{id}` | Single proxy by ID |
| `GET` | `/v1/stats` | Aggregate statistics |

### Query Parameters for `/v1/proxies` and `/v1/proxies/random`

| Parameter | Example | Description |
|-----------|---------|-------------|
| `protocol` | `http`, `socks5` | Filter by protocol |
| `anonymity` | `elite`, `anonymous`, `transparent` | Filter by anonymity level |
| `country` | `US`, `DE` | Filter by ISO country code |
| `max_latency` | `500` | Maximum latency in ms |
| `limit` | `50` | Results per page (default 100, max 1000) |
| `offset` | `100` | Pagination offset |
| `alive` | `false` | Include dead proxies (default: alive only) |

### Example Responses

```bash
# Get 5 fast elite SOCKS5 proxies in Germany
curl "http://localhost:8080/v1/proxies?protocol=socks5&anonymity=elite&country=DE&max_latency=500&limit=5"

# Get a random HTTP proxy
curl "http://localhost:8080/v1/proxies/random?protocol=http"

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

# API
docker build -f docker/Dockerfile.api -t proxy-scanner-api .
```

## Project Structure

```
cmd/
  scanner/main.go            Entry point: masscan wrapper + SQLite queue
  validator/main.go          Entry point: dequeue, validate, write to proxies table
  api/main.go                Entry point: REST API server
internal/
  proxy/
    checker.go               HTTP/HTTPS/SOCKS4/SOCKS5 proxy validation
    geoip.go                 MaxMind GeoLite2 City + ASN lookups
    types.go                 Shared types (Proxy, Candidate, CandidateEntry, etc.)
  database/
    sqlite.go                SQLite operations (queue, upsert, query, stats)
  blocklist/
    dnsbl.go                 DNSBL blocklist checking
  scanner/
    parser.go                Masscan JSON output parser
data/
  GeoLite2-City.mmdb         MaxMind City database (bundled in validator image)
  GeoLite2-ASN.mmdb          MaxMind ASN database (bundled in validator image)
  GeoLite2-Country.mmdb     MaxMind Country database
config/
  exclude/                   Modular CIDR exclusion lists (merged at build time)
    00-iana-special.conf      IANA Special-Purpose Address Registry (RFC 6890)
    10-military.conf          US DoD/military networks
    20-cloud-providers.conf   Hetzner (self-exclusion)
    30-infrastructure.conf    Root DNS, IXPs, RIR infrastructure
    90-custom.conf            Manual additions (abuse complaints)
docker/
  Dockerfile.scanner         Multi-stage Go build + masscan
  Dockerfile.validator       Multi-stage Go build + GeoIP databases
  Dockerfile.api             Multi-stage Go build
docker-compose.yml           Docker Compose configuration
.github/workflows/
  ci.yaml                    Tests + vet on pull requests
  build-push.yaml            Build and push images to GHCR on push to main
```

## CI/CD

- **Pull requests**: GitHub Actions runs `go test` and `go vet`
- **Push to main**: Builds all 3 Docker images and pushes to GHCR with `sha-<commit>` and `latest` tags

No additional secrets or configuration required. The workflow uses the built-in `GITHUB_TOKEN`.

## Scan Exclusion List

Networks are excluded from scanning via modular config files in `config/exclude/`. The scanner Dockerfile merges them at build time.

To add a new exclusion (e.g., after an abuse complaint):

1. Add the CIDR to `config/exclude/90-custom.conf`
2. Commit and push to main
3. GitHub Actions rebuilds the scanner image

## Environment Variables

### Scanner

| Variable | Default | Description |
|----------|---------|-------------|
| `SCAN_RATE` | `50000` | Masscan packets per second |
| `SCAN_PORTS` | `3128,8080,1080,...` | Target ports (comma-separated) |
| `SCAN_ADAPTER` | `ens3` | Network interface for masscan |
| `EXCLUDE_FILE` | `/config/exclude.conf` | CIDR exclusion list |
| `DB_PATH` | `/data/proxies.db` | SQLite database path |
| `OUTPUT_FILE` | `/data/candidates.json` | Masscan JSON output (debugging artifact) |
| `RESUME_FILE` | `/data/paused.conf` | Masscan resume state file |
| `SCAN_TIMEOUT` | *(none)* | Max scan duration (e.g. `4h`, `30m`). Sends SIGINT to masscan on timeout, enabling incremental weekly scanning |

### Validator

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_PATH` | `/data/proxies.db` | Path to SQLite database |
| `GEOIP_CITY_DB` | `/geoip/GeoLite2-City.mmdb` | MaxMind City database |
| `GEOIP_ASN_DB` | `/geoip/GeoLite2-ASN.mmdb` | MaxMind ASN database |
| `ORIGIN_IP` | *(auto-detected)* | Public IP for anonymity detection |
| `WORKERS` | `500` | Concurrent validation goroutines |
| `TIMEOUT` | `10` | Per-proxy timeout in seconds |
| `TEST_URL` | `http://httpbin.org/ip` | URL to request through proxies |
| `SKIP_BLOCKLIST` | `false` | Disable DNSBL blocklist checking |
| `BATCH_SIZE` | `1000` | Candidates to dequeue per batch |

### API

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_PATH` | `/data/proxies.db` | Path to SQLite database |
| `LISTEN_ADDR` | `:8080` | Listen address |
| `API_TOKEN` | *(unset)* | Bearer token for auth (disabled when unset) |

## License

See LICENSE file.