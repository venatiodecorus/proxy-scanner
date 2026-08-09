# Deployment

The scanner runs as containers on a single Debian host, scheduled by systemd
timers. There is no infrastructure-as-code layer and no CI deploy step: CI builds
images and pushes them to GHCR, and the host pulls them itself.

## What the host actually needs

Short list, because it is shorter than it looks:

1. **Docker** with the `compose` plugin.
2. **`/opt/proxy-scanner/docker-compose.yml`** — installed by `install.sh`.
3. **`/opt/proxy-scanner/.env`** — optional. Every value has a working default;
   set `API_BIND_ADDR` and `API_TOKEN` if you want the API reachable off-box.
4. **The systemd units** — installed by `install.sh`.
5. **Access to the GHCR images.** See "Image visibility" below.

Nothing else. In particular, the host does **not** need:

- **The repo, at runtime.** You need a checkout only to *run* `install.sh`; after
  that nothing reads from it.
- **A Go toolchain.** Everything runs from prebuilt images.
- **The exclusion lists.** `Dockerfile.scanner` merges `config/exclude/*.conf`
  into `/config/exclude.conf` at image build time, so they ship inside the
  scanner image. `cmd/genexclude` regenerates the *committed* lists when
  `data/GeoLite2-ASN.mmdb` is refreshed — that is a dev-machine task, done on a
  branch and pushed, never on the scanner box.
- **The GeoLite2 databases.** Baked into the validator and revalidator images
  (`COPY data/GeoLite2-*.mmdb /geoip/`).
- **A data volume to pre-create.** Compose creates `scanner-data` on first use.

## Where to run it from: /opt, not a home-directory checkout

Recommendation: keep `/opt/proxy-scanner` holding **only** `docker-compose.yml`
and `.env`, and treat the git checkout as a delivery mechanism you can put
anywhere (or delete afterwards).

Pointing `WorkingDirectory=` at a git working tree is the option to avoid. The
reason is not tidiness — it is that a checkout is *mutable state you change for
unrelated reasons*. `git checkout some-branch` to look at something would
silently change what the next timer firing runs, and a half-finished rebase or a
dirty tree becomes production configuration. A three-line copy into `/opt`
decouples "what is deployed" from "what I happen to have checked out".

Secondary reasons: systemd units run as root, and a root unit whose working
directory lives under `/home/<user>` breaks if the user is removed, if `/home`
is a separate late-mounted filesystem, or if permissions change. `.env` holding
`API_TOKEN` also does not belong inside a git tree, however carefully it is
ignored.

The cost is one command when the compose file changes: re-run `install.sh`.

## Install

On the Debian host, with Docker already present:

```sh
git clone https://github.com/venatiodecorus/proxy-scanner.git
cd proxy-scanner
sudo ./deploy/install.sh
```

The script is idempotent. It copies the compose file (backing up a differing
previous copy), seeds `.env` only if absent, **creates systemd units only if they
do not already exist** (`--force` to overwrite ones that differ, showing a diff
otherwise), validates the compose file, pulls images, and enables the timers.

It does not install Docker, create users, add SSH keys, or touch firewall rules.

Flags: `--force` (overwrite differing units), `--no-pull` (skip the image pull),
`--help`.

## Image visibility

`docker compose pull` fails on any GHCR package that is private. As of writing,
`proxy-scanner-scanner`, `-validator` and `-api` are anonymously pullable but
**`proxy-scanner-revalidator` is private**. Either flip it public (GitHub →
Packages → the package → Package settings → Change visibility) or log in on the
host:

```sh
echo "$GHCR_PAT" | docker login ghcr.io -u <github-username> --password-stdin
```

with a token carrying `read:packages`. Check any package with:

```sh
docker manifest inspect ghcr.io/venatiodecorus/proxy-scanner-revalidator:latest
```

## Recommended: firewall masscan's source ports

masscan uses its own IP stack and sends from `--source-port 40000-56383`. The
host kernel does not know about those connections, so it answers the returning
SYN-ACKs with RSTs — extra traffic to every host you probe, from a port range
you are not really listening on. masscan itself warns about this.

Scans work without the rule, which is why `install.sh` does not apply it
unprompted. Put it in place before a real sweep.

The rule lives in its own table rather than being appended to `inet filter`: a
minimal Debian install may have no such table, and a dedicated one can be removed
in a single command without disturbing anything else.

### Add

```sh
sudo nft add table inet masscan
sudo nft add chain inet masscan input '{ type filter hook input priority -10; policy accept; }'
sudo nft add rule inet masscan input tcp dport 40000-56383 counter drop

# Verify — the counter climbs while a scan runs
sudo nft list table inet masscan
```

Persist across reboots:

```sh
sudo tee -a /etc/nftables.conf >/dev/null <<'EOF'

# Drop kernel responses on masscan's source-port range.
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
sudo nft delete table inet masscan          # running ruleset
sudo nft list table inet masscan            # should report no such table
```

Then delete the `table inet masscan { ... }` block from `/etc/nftables.conf` and
re-check it with `sudo nft -c -f /etc/nftables.conf`, or the rule returns on the
next reboot.

### iptables hosts

Add and remove are symmetric — same rule spec, `-I` versus `-D`:

```sh
sudo iptables -I INPUT -p tcp --dport 40000:56383 -j DROP   # add
sudo iptables -D INPUT -p tcp --dport 40000:56383 -j DROP   # remove
```

Persist with `iptables-save > /etc/iptables/rules.v4` (package
`iptables-persistent`).

## Layout

```
deploy/
  install.sh                Idempotent host install (compose file + units)
  update.sh                 Pull new images, restart the long-running services
  env.example               Config template -> /opt/proxy-scanner/.env
  systemd/
    proxy-scanner.service           API + revalidator (long-running)
    proxy-scanner-scan.service      One masscan session (one-shot)
    proxy-scanner-scan.timer        Daily at 02:00 UTC
    proxy-scanner-validate.service  Drain the candidates queue (one-shot)
    proxy-scanner-validate.timer    Daily at 07:00 UTC (safety net)
```

On the host:

```
/opt/proxy-scanner/docker-compose.yml
/opt/proxy-scanner/.env                       (not in git)
/opt/proxy-scanner/update.sh                  (copied by install.sh)
/etc/systemd/system/proxy-scanner*.{service,timer}
```

Persistent data lives in the `scanner-data` Docker volume mounted at `/data`
(SQLite database, masscan resume state, candidate JSON).

## Day-to-day

```sh
# What is scheduled, and when it next fires
systemctl list-timers 'proxy-scanner*'

# Run a scan session right now (ignores the timer)
systemctl start proxy-scanner-scan.service

# Follow a running session
journalctl -fu proxy-scanner-scan.service

# Stop a session gracefully — masscan saves paused.conf and the next
# session resumes from there
systemctl stop proxy-scanner-scan.service

# Validate whatever is queued, without waiting for the timer
systemctl start proxy-scanner-validate.service

# Pull new images and restart the API/revalidator
sudo /opt/proxy-scanner/update.sh

# API health
curl -s http://127.0.0.1:8080/v1/health
```

## Scheduling notes

A full IPv4 sweep is roughly **56 hours** of masscan time (3.37B addresses in
scope after exclusions × 3 ports ÷ 50k pps). `SCAN_TIMEOUT=4h` bounds each
session, so a sweep takes about **14 daily sessions ≈ 2 weeks**.

To change the cadence, edit `OnCalendar=` in
`/etc/systemd/system/proxy-scanner-scan.timer`, then
`systemctl daemon-reload && systemctl restart proxy-scanner-scan.timer`.

Three properties worth knowing:

- **No overlap protection needed.** systemd will not start a second instance of
  a unit that is already active. A cron-based schedule needs `flock -n` for this,
  because two concurrent masscan sessions would corrupt the single `paused.conf`
  *and* double the effective packet rate.
- **The validator chains off the scanner.** `proxy-scanner-scan.service` declares
  `OnSuccess=proxy-scanner-validate.service`, so the queue is drained the moment
  a sweep session ends rather than at a clock time that might land before it
  finishes. The 07:00 timer is only a safety net for when a scan was skipped but
  candidates are still pending; an empty queue makes that a no-op. Requires
  systemd 249+ (Debian 12 ships 252).
- **Stopping a scan must send SIGINT.** masscan only writes its resume file on
  SIGINT — SIGTERM kills it and the session's progress is lost. The unit sets
  `KillSignal=SIGINT` for exactly this reason. Do not change it, and prefer
  `systemctl stop` over `docker kill`.

Logs go to the journal, so there is no logrotate config; `install.sh` caps
journald at 500M instead.

## Retiring the Terraform config

`infra/` (OVH/OpenStack via Terraform Cloud) is being replaced by this directory.
The one thing to be careful about: **deleting the `.tf` files does not delete the
VM.** State lives in the Terraform Cloud workspace and the instance keeps running
regardless.

Since the new box starts fresh with no data migration, the sequence is:

1. Run `install.sh` on the new Debian host; confirm a scan session and a
   validation run both complete.
2. Delete `infra/` — `main.tf`, `variables.tf`, `outputs.tf`, `cloud-init.yaml`.
3. Drop the Terraform entries from `.gitignore` (`infra/.terraform/`,
   `infra/.terraform.lock.hcl`, `*.tfstate*`, `*.tfvars`, `override.tf*`,
   `crash.log`).
4. Decommission the old instance: `terraform destroy`, then delete the Terraform
   Cloud workspace. (To keep the old box running but unmanaged instead, delete
   the workspace *without* destroying — Terraform Cloud will warn that resources
   become unmanaged, which would be the intent.)
5. **Revoke the OpenStack API credentials** stored as workspace environment
   variables, and delete the local `openrc.sh` (gitignored, so it only exists on
   your machine).
6. Delete the now-unused GitHub Actions secrets `VPS_HOST` and `VPS_SSH_KEY`.

What Terraform and its cloud-init used to do, and what replaces it:

| Terraform / cloud-init did | Now |
|---|---|
| Provision the OVH instance | By hand |
| Generate an SSH keypair, open SSH ingress | By hand / provider firewall / Tailscale |
| Install Docker | Preinstalled on the new box |
| Write `docker-compose.yml` (templated in) | `deploy/install.sh` copies it |
| `/etc/cron.d/proxy-scanner` schedule | systemd timers in `deploy/systemd/` |
| `/etc/logrotate.d/proxy-scanner` | journald (`SystemMaxUse=500M`) |
| Pull images, start the API | `deploy/install.sh`, then `deploy/update.sh` |
| CI `deploy` job SSHing into the VPS | Removed — the host pulls for itself |

Two things that were quietly broken under the old setup and do not carry over:
the CI deploy job SSHed in as a `deploy` user that cloud-init never created (it
only added `ubuntu` to the docker group), and `SCAN_ADAPTER` was hardcoded to the
OpenStack-specific `ens3`, which does not exist on Debian. `SCAN_ADAPTER` is now
empty by default, meaning masscan auto-detects the default-route interface.
