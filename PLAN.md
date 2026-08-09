# Proxy Scanner — Implementation Plan

> **Historical document — superseded in the deployment sections.**
>
> This records the original plan and the phase-by-phase build-out. The
> application design (scanner → candidate queue → validator → SQLite → API,
> plus the revalidator) still matches reality, but **the deployment story
> below does not.**
>
> There is no Kubernetes, no k3s cluster, no FluxCD, and no PVC. The system runs
> as Docker containers on a single Debian host, scheduled by systemd timers.
> References to CronJobs, PVCs, GitOps reconciliation and a `deploy/` directory
> of Kubernetes manifests are all obsolete — note that `deploy/` now holds the
> systemd units and host install scripts instead.
>
> For how this is actually deployed and operated, read
> [`deploy/README.md`](deploy/README.md) and the README.

## Overview

A system that scans the public IPv4 space for open SOCKS4/SOCKS5 proxies, validates them behind a mandatory EFnet RBL eligibility gate, tests speed, and exposes verified proxies via a REST API.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   k3s Cluster (Hetzner)                  │
│                                                         │
│  ┌──────────────┐    CronJob (weekly)                   │
│  │  scan-job    │──→ masscan sweep of IPv4 space        │
│  │  (masscan)   │    outputs candidate IPs to PVC       │
│  └──────┬───────┘                                       │
│         │ writes candidates.json to shared PVC          │
│         ▼                                               │
│  ┌──────────────┐    Job (triggered after scan)         │
│  │  validate-job│──→ Go binary: connects through each   │
│  │  (Go)        │    SOCKS proxy, enforces EFnet RBL,   │
│  │              │    measures latency and anonymity      │
│  └──────┬───────┘                                       │
│         │ writes verified proxies to SQLite              │
│         ▼                                               │
│  ┌──────────────┐    Deployment (always running)        │
│  │  proxy-api   │──→ Go REST API serving proxy data     │
│  │  (Go)        │    from SQLite on PVC                 │
│  └──────┬───────┘                                       │
│         │                                               │
│    ┌────┴────┐                                          │
│    │  PVC    │  SQLite DB + scan artifacts               │
│    │ (10Gi)  │                                          │
│    └─────────┘                                          │
│                                                         │
│  Other cluster services query proxy-api via             │
│  ClusterIP Service: http://proxy-api.proxy-scanner/v1/  │
└─────────────────────────────────────────────────────────┘
```

## Components

### 1. Scanner (masscan CronJob)
- Alpine-based container with masscan
- Scans `0.0.0.0/0` minus excluded ranges at 50k pps (~56h full sweep across 3 ports; see README "How long a full sweep takes")
- Targets SOCKS ports: 1080, 1081, 9050
- Outputs JSON to shared PVC
- Triggers validator job on completion

### 2. Validator (Go Job)
- Reads masscan JSON output
- Tests each candidate as a SOCKS4 or SOCKS5 proxy
- Enforces mandatory `rbl.efnetrbl.org` eligibility checks for both endpoint and observed exit IP; listed candidates are rejected and indeterminate lookups are deferred rather than accepted
- Optional auxiliary DNSBLs may be skipped with `SKIP_AUX_BLOCKLISTS`, but the EFnet gate cannot be disabled
- Measures latency, checks anonymity level (transparent/anonymous/elite)
- GeoIP tagging via bundled MaxMind GeoLite2-City + ASN databases
- ASN (Autonomous System Number) enrichment for network-level metadata
- Auto-detects egress IP at startup for anonymity classification (zero-config)
- Worker pool of 500-1000 goroutines for concurrent validation
- Writes results to SQLite on shared PVC

### 3. API (Go Deployment)
- REST API serving proxy data from SQLite (WAL mode for concurrent read/write)
- Endpoints:
  - `GET /v1/proxies` — list with filters (protocol, anonymity, country, min_speed, limit)
  - `GET /v1/proxies/random` — random proxy matching filters
  - `GET /v1/proxies/:id` — proxy details
  - `GET /v1/stats` — scan statistics
  - `GET /v1/health` — health check
- ClusterIP Service for internal cluster access

## Database Schema (SQLite)

```sql
CREATE TABLE proxies (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT NOT NULL,
    port        INTEGER NOT NULL,
    protocol    TEXT NOT NULL,
    anonymity   TEXT,
    country     TEXT,
    city        TEXT,
    asn         INTEGER,
    asn_org     TEXT,
    latency_ms  INTEGER,
    last_seen   DATETIME NOT NULL,
    first_seen  DATETIME NOT NULL,
    alive       BOOLEAN DEFAULT TRUE,
    UNIQUE(ip, port, protocol)
);

CREATE TABLE scan_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  DATETIME NOT NULL,
    finished_at DATETIME,
    candidates  INTEGER,
    verified    INTEGER,
    status      TEXT
);

CREATE INDEX idx_proxies_alive ON proxies(alive, protocol);
CREATE INDEX idx_proxies_latency ON proxies(alive, latency_ms);
CREATE INDEX idx_proxies_country ON proxies(alive, country);
```

## Project Structure

```
proxy-scanner/
├── cmd/
│   ├── validator/
│   │   └── main.go
│   └── api/
│       └── main.go
├── internal/
│   ├── proxy/
│   │   ├── checker.go
│   │   ├── checker_test.go
│   │   ├── geoip.go
│   │   └── types.go
│   ├── database/
│   │   ├── sqlite.go
│   │   └── sqlite_test.go
│   └── scanner/
│       ├── parser.go
│       └── parser_test.go
├── data/
│   ├── GeoLite2-City.mmdb
│   ├── GeoLite2-ASN.mmdb
│   └── GeoLite2-Country.mmdb
├── config/
│   └── exclude/
│       ├── 00-iana-special.conf
│       ├── 10-military.conf
│       ├── 20-cloud-providers.conf
│       ├── 30-infrastructure.conf
│       └── 90-custom.conf
├── docker/
│   ├── Dockerfile.scanner
│   ├── Dockerfile.validator
│   ├── Dockerfile.api
│   └── scan.sh
├── deploy/
│   ├── namespace.yaml
│   ├── pvc.yaml
│   ├── configmap.yaml
│   ├── scanner-cronjob.yaml
│   ├── validator-job.yaml
│   ├── api-deployment.yaml
│   └── api-service.yaml
├── .github/
│   └── workflows/
│       ├── ci.yaml
│       └── build-push.yaml
├── go.mod
├── go.sum
├── PLAN.md
├── AGENTS.md
└── .gitignore
```

## Container Images

Published to GHCR:
- `ghcr.io/venatiodecorus/proxy-scanner-scanner`
- `ghcr.io/venatiodecorus/proxy-scanner-validator`
- `ghcr.io/venatiodecorus/proxy-scanner-api`

## Key Design Decisions

1. **50k pps scan rate** — Conservative for Hetzner Cloud shared NICs. A full IPv4 sweep is ~56h of masscan time across the 3 SOCKS ports (the original ~24h figure assumed a single port), so with `SCAN_TIMEOUT=4h` and the daily cron a sweep completes about every 14 days.
2. **SQLite over PostgreSQL** — Write-once-read-many workload. Single writer (validator), single reader (API). WAL mode enables concurrent access. Dataset (50k-200k proxies) fits trivially.
3. **Separate scan/validate phases** — Masscan excels at raw port discovery. Go excels at concurrent proxy negotiation. Each can be debugged independently.
4. **CronJob + Job over Deployment** — Batch workloads with clear start/end. No wasted resources between runs.
5. **Go over Python/nmap** — Goroutine pool handles thousands of concurrent proxy tests. Nmap NSE scripts are slow and hard to parallelize.
6. **GeoIP via MaxMind GeoLite2-City + ASN** — Tags proxies with country/city/ASN for filtering. Databases bundled in validator image (~80MB total).
7. **Egress IP auto-detection** — Validator auto-detects its public IP at startup for anonymity classification. Zero-config by default; overridable via `ORIGIN_IP` env var.
8. **GitHub Actions CI/CD** — PR checks run tests/vet. Pushes to main build and push all 4 images to GHCR with `sha-*` and `latest` tags.

---

## Implementation Phases & Progress

### Phase 1: Foundation
- [x] PLAN.md created
- [x] AGENTS.md created
- [x] Go module initialized
- [x] Shared types (`internal/proxy/types.go`)
- [x] SQLite database layer (`internal/database/sqlite.go`)
- [x] Database tests (`internal/database/sqlite_test.go`)

### Phase 2: Masscan Parser
- [x] Parse masscan JSON output (`internal/scanner/parser.go`)
- [x] Parser tests (`internal/scanner/parser_test.go`)

### Phase 3: Proxy Checker
- [x] HTTP/HTTPS proxy checker (`internal/proxy/checker.go`)
- [x] SOCKS4/SOCKS5 proxy checker
- [x] Latency measurement
- [x] Anonymity detection (transparent/anonymous/elite)
- [x] GeoIP tagging
- [x] Checker tests (`internal/proxy/checker_test.go`)

### Phase 4: Validator CLI
- [x] Entry point (`cmd/validator/main.go`)
- [x] Worker pool orchestration
- [x] Read masscan output, validate, write to SQLite
- [x] Scan run tracking (start/finish/stats)

### Phase 5: REST API
- [x] Entry point (`cmd/api/main.go`)
- [x] `GET /v1/proxies` with filtering
- [x] `GET /v1/proxies/random`
- [x] `GET /v1/proxies/:id`
- [x] `GET /v1/stats`
- [x] `GET /v1/health`

### Phase 6: Dockerfiles
- [x] `docker/Dockerfile.scanner` (masscan)
- [x] `docker/Dockerfile.validator` (Go)
- [x] `docker/Dockerfile.api` (Go)

### Phase 7: Configuration
- [x] `config/exclude/` (modular CIDR exclusion lists)
- [x] `.gitignore`

### Phase 8: Kubernetes Manifests (examples)
- [x] `deploy/namespace.yaml`
- [x] `deploy/pvc.yaml`
- [x] `deploy/configmap.yaml`
- [x] `deploy/scanner-cronjob.yaml`
- [x] `deploy/validator-job.yaml`
- [x] `deploy/api-deployment.yaml`
- [x] `deploy/api-service.yaml`

### Phase 9: GitOps & CI/CD Improvements
- [x] GeoLite2 databases (City, ASN, Country) extracted and committed to `data/`
- [x] GeoLite2 databases bundled into validator Docker image at `/geoip/`
- [x] ASN field added to Proxy type, database schema, and GeoIP lookups
- [x] Egress IP auto-detection at validator startup (queries ipify/ifconfig.me/icanhazip/checkip.amazonaws.com)
- [x] `ORIGIN_IP` env var override preserved for manual configuration
- [x] GitHub Actions CI workflow (`.github/workflows/ci.yaml`) — tests + vet on PRs
- [x] GitHub Actions build+push workflow (`.github/workflows/build-push.yaml`) — builds all 4 images to GHCR on push to main
- [x] ConfigMap updated: removed `GEOIP_DB` (bundled), `ORIGIN_IP` (auto-detected)
- [x] PLAN.md and AGENTS.md updated

### Phase 10: Comprehensive Exclusion List
- [x] Split monolithic `config/exclude.conf` into modular category files under `config/exclude/`
- [x] `00-iana-special.conf` — Full IANA Special-Purpose Address Registry (RFC 6890): all non-routable, reserved, private, loopback, link-local, multicast, documentation, benchmarking, and broadcast ranges
- [x] `10-military.conf` — Complete US DoD/military allocations from IANA IPv4 Address Space Registry (13 /8 blocks)
- [x] `20-cloud-providers.conf` — Hetzner Online GmbH ranges (self-exclusion); intentionally does NOT exclude AWS/GCP/Azure since proxies run on those
- [x] `30-infrastructure.conf` — Root DNS server anycast addresses, major IXP peering LANs (DE-CIX, AMS-IX, LINX, Equinix), RIR infrastructure (ARIN, RIPE, APNIC)
- [x] `90-custom.conf` — Empty template with instructions for adding abuse-complaint exclusions
- [x] Dockerfile.scanner updated: merges all `config/exclude/*.conf` at build time into a single clean CIDR file
- [x] 88 unique exclusion entries across all categories, zero duplicates
      *(superseded: the generated `*-asn.conf` lists brought this to ~7,600 entries)*
- [x] Adding exclusions: edit file, commit, push, image rebuilds
      *(superseded: the rollout is not automatic — the host must pull the new
      image with `update.sh` before the exclusion takes effect)*
