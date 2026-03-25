# Proxy Scanner

A Kubernetes-native system that scans the public IPv4 space for open proxies (HTTP, HTTPS, SOCKS4, SOCKS5), validates them, measures latency, classifies anonymity level, enriches with GeoIP/ASN data, and exposes verified proxies via a REST API.

Designed for GitOps deployment on k3s (Hetzner Cloud) with FluxCD.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   k3s Cluster (Hetzner)                  │
│                                                         │
│  ┌──────────────┐    CronJob (weekly)                   │
│  │  scanner     │──→ masscan sweep of IPv4 space        │
│  │  (masscan)   │    outputs candidate IPs to PVC       │
│  └──────┬───────┘                                       │
│         │ candidates.json                               │
│         ▼                                               │
│  ┌──────────────┐    Job (after scan completes)         │
│  │  validator   │──→ Go: validates proxies, measures    │
│  │  (Go)        │    latency, GeoIP/ASN tagging         │
│  └──────┬───────┘                                       │
│         │ SQLite                                        │
│         ▼                                               │
│  ┌──────────────┐    Deployment (always running)        │
│  │  api         │──→ REST API for proxy data            │
│  │  (Go)        │                                       │
│  └──────────────┘                                       │
│                                                         │
│  Internal: http://proxy-api.proxy-scanner.svc/v1/       │
└─────────────────────────────────────────────────────────┘
```

Three components, three container images:

| Component | Image | K8s Resource | Purpose |
|-----------|-------|-------------|---------|
| Scanner | `ghcr.io/venatiodecorus/proxy-scanner-scanner` | CronJob | Masscan sweep of IPv4 space for open proxy ports |
| Validator | `ghcr.io/venatiodecorus/proxy-scanner-validator` | CronJob/Job | Validates candidates, measures latency, GeoIP/ASN enrichment |
| API | `ghcr.io/venatiodecorus/proxy-scanner-api` | Deployment | REST API serving proxy data from SQLite |

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
curl "http://proxy-api.proxy-scanner/v1/proxies?protocol=socks5&anonymity=elite&country=DE&max_latency=500&limit=5"

# Get a random HTTP proxy
curl "http://proxy-api.proxy-scanner/v1/proxies/random?protocol=http"

# Stats overview
curl "http://proxy-api.proxy-scanner/v1/stats"
```

## Prerequisites

- Go 1.23+
- GCC (for CGO / SQLite compilation)
- Docker (for building images)
- `masscan` (only needed if running the scanner locally)

## Local Development

### Run Tests

```bash
go test ./... -v
```

### Build Binaries

```bash
# Validator
CGO_ENABLED=1 go build -o bin/validator ./cmd/validator/

# API
CGO_ENABLED=1 go build -o bin/api ./cmd/api/
```

### Run the API Locally

```bash
# Create an empty database
CGO_ENABLED=1 go build -o bin/api ./cmd/api/
DB_PATH=./test.db LISTEN_ADDR=:8080 ./bin/api

# In another terminal
curl http://localhost:8080/v1/health
curl http://localhost:8080/v1/stats
```

### Run the Validator Locally

The validator expects a masscan JSON output file. You can create a test input:

```bash
# Create a small test candidates file
cat > /tmp/candidates.json << 'EOF'
[
  {"ip": "1.2.3.4", "timestamp": "1234567890", "ports": [{"port": 8080, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64}]},
  {"ip": "5.6.7.8", "timestamp": "1234567891", "ports": [{"port": 3128, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 128}]}
]
EOF

# Run validator (these IPs won't actually be proxies, but it tests the pipeline)
CGO_ENABLED=1 go build -o bin/validator ./cmd/validator/
SCAN_INPUT=/tmp/candidates.json \
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
  validator/main.go          Entry point: validation worker pool
  api/main.go                Entry point: REST API server
internal/
  proxy/
    checker.go               HTTP/HTTPS/SOCKS4/SOCKS5 proxy validation
    geoip.go                 MaxMind GeoLite2 City + ASN lookups
    types.go                 Shared types (Proxy, Candidate, CheckResult, etc.)
  database/
    sqlite.go                SQLite operations (upsert, query, stats, scan runs)
  scanner/
    parser.go                Masscan JSON output parser
data/
  GeoLite2-City.mmdb         MaxMind City database (bundled in validator image)
  GeoLite2-ASN.mmdb          MaxMind ASN database (bundled in validator image)
  GeoLite2-Country.mmdb      MaxMind Country database
config/
  exclude/                   Modular CIDR exclusion lists (merged at build time)
    00-iana-special.conf     IANA Special-Purpose Address Registry (RFC 6890)
    10-military.conf         US DoD/military networks
    20-cloud-providers.conf  Hetzner (self-exclusion)
    30-infrastructure.conf   Root DNS, IXPs, RIR infrastructure
    90-custom.conf           Manual additions (abuse complaints)
docker/
  Dockerfile.scanner         Alpine + masscan
  Dockerfile.validator       Multi-stage Go build + GeoIP databases
  Dockerfile.api             Multi-stage Go build
  scan.sh                    Masscan wrapper script
deploy/                      Example Kubernetes manifests (reference only)
.github/workflows/
  ci.yaml                    Tests + vet on pull requests
  build-push.yaml            Build and push images to GHCR on push to main
```

## CI/CD

- **Pull requests**: GitHub Actions runs `go test` and `go vet`
- **Push to main**: Builds all 3 Docker images and pushes to GHCR with `sha-<commit>` and `latest` tags
- **Deployment**: FluxCD in the infra repo watches GHCR for new image tags

No additional secrets or configuration required. The workflow uses the built-in `GITHUB_TOKEN`.

## Scan Exclusion List

Networks are excluded from scanning via modular config files in `config/exclude/`. The scanner Dockerfile merges them at build time.

To add a new exclusion (e.g., after an abuse complaint):

1. Add the CIDR to `config/exclude/90-custom.conf`
2. Commit and push to main
3. GitHub Actions rebuilds the scanner image
4. FluxCD rolls out the update

## Environment Variables

### Validator

| Variable | Default | Description |
|----------|---------|-------------|
| `SCAN_INPUT` | `/data/candidates.json` | Path to masscan JSON output |
| `DB_PATH` | `/data/proxies.db` | Path to SQLite database |
| `GEOIP_CITY_DB` | `/geoip/GeoLite2-City.mmdb` | MaxMind City database |
| `GEOIP_ASN_DB` | `/geoip/GeoLite2-ASN.mmdb` | MaxMind ASN database |
| `ORIGIN_IP` | *(auto-detected)* | Public IP for anonymity detection |
| `WORKERS` | `500` | Concurrent validation goroutines |
| `TIMEOUT` | `10` | Per-proxy timeout in seconds |
| `TEST_URL` | `http://httpbin.org/ip` | URL to request through proxies |

### API

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_PATH` | `/data/proxies.db` | Path to SQLite database |
| `LISTEN_ADDR` | `:8080` | Listen address |

### Scanner

| Variable | Default | Description |
|----------|---------|-------------|
| `SCAN_RATE` | `50000` | Packets per second |
| `SCAN_PORTS` | `3128,8080,1080,...` | Target ports |
| `EXCLUDE_FILE` | `/config/exclude.conf` | CIDR exclusion list |
| `OUTPUT_FILE` | `/data/candidates.json` | Output path |

## License

See LICENSE file.
