# Deploying the Hydra API for real

This document covers what standing up `api/` (docs/PAID_API_DESIGN.md) on
a real host actually requires — a domain, TLS, persistent data, and
backups. It does not choose a cloud provider for you (that's a cost/
Central-America-latency decision, not this document's to make) and does
not stand up real infrastructure — it's the walkthrough for whoever does.

Scope: a single host running the container this repo already builds
(`Dockerfile`/`docker-compose.yml`). Multi-region/high-availability
database replication is explicitly out of scope — a single host with real
backups (`api/backup_worker.py`) is the right target for Hydra's actual
current scale, not a distributed database. Point-in-time recovery beyond
"restore the most recent daily snapshot" is also out of scope for now —
see that module's own docstring for the retention policy this implies.

## 1. A host that can run the container

Any VM that can run Docker works — a DigitalOcean Droplet, a Hetzner Cloud
server, an AWS Lightsail instance or a plain EC2 box are all reasonable,
named here as examples, not a recommendation for one over the others.

**Resource floor — honestly, this has not been load-tested, so benchmark
before committing to a size**: the API process itself (`uvicorn`,
FastAPI, SQLite) is lightweight — the real cost driver is that each scan
shells out to `naabu`/`httpx`/`nuclei`/etc. as real subprocesses, and
`api_settings.max_concurrent_scans` (default 3, `api/settings.py`) caps
how many of those can run at once on one host. What to actually measure
before picking an instance size:

- Peak RSS of a single real scan's subprocess tree against a
  representative target (nuclei's template engine and browser-probe's
  WebKit process are the two most likely memory-heavy steps).
- Whether 3 concurrent scans' combined CPU/memory footprint fits inside a
  candidate instance size with headroom left for the API process, backups,
  and Caddy — multiply the single-scan number above by
  `max_concurrent_scans` as a starting estimate, then verify for real
  rather than trusting the multiplication alone (subprocess memory
  doesn't always scale perfectly linearly under shared page cache).
- Disk: `output/<scan_id>/` artifacts per scan (Part B's retention
  purge job already bounds how long these accumulate, but size the disk
  for the busiest tier's retention window, e.g. Ultra's 24 months, times
  a realistic per-scan artifact size) plus backup snapshot space
  (`api_settings.backup_retention_count` local snapshots, each
  containing every account's `recon.db` — likely far smaller than the raw
  `output/` artifacts, but not zero).

A 2 vCPU / 4 GB instance is a reasonable starting guess for light traffic
(a handful of concurrent scans), not a verified number — resize based on
what the benchmarks above actually show.

## 2. A real domain and TLS

The simplest correct path: a reverse proxy that gets Let's Encrypt
certificates automatically, with minimal config. This repo's
`docker-compose.yml` already wires this up via
[Caddy](https://caddyserver.com/) — Caddy issues and renews TLS
certificates on its own, with no separate `certbot`/cron-renewal setup to
maintain, which is the whole reason it's the one named here over a bare
`nginx` + manual certificate management.

Steps:

1. Point a real DNS `A` (and `AAAA`, if the host has IPv6) record at the
   host's public IP — e.g. `api.yourdomain.com`. This has to resolve
   publicly before step 4, since Let's Encrypt validates domain ownership
   over the real internet, not from inside the container.
2. `cp Caddyfile.example Caddyfile` — **do this before `docker compose
   up`**: if `Caddyfile` doesn't exist yet when Compose starts the
   `caddy` service, Docker will silently create it as an empty
   *directory* instead of mounting your file, and Caddy will fail to
   start with a confusing error. This is a genuine, easy-to-hit Docker
   bind-mount gotcha, not a hypothetical.
3. Edit `Caddyfile`, replacing `api.yourdomain.com` with your real domain:
   ```
   api.yourdomain.com {
       reverse_proxy api:8000
   }
   ```
   That's the entire config — Caddy defaults to automatic HTTPS via
   Let's Encrypt for any domain-shaped site address, no separate flag.
4. Ensure ports 80 and 443 are open on the host's firewall/security group
   — port 80 is needed for Let's Encrypt's HTTP-01 challenge, not just
   443.
5. `docker compose up -d caddy api` (see §5 for the full command, with
   `.env` and volumes). Watch `docker compose logs -f caddy` on first
   start — a successful certificate issuance logs it explicitly; a DNS
   record that hasn't propagated yet, or a firewall blocking port 80,
   shows up here as a clear failure, not a silent one.

The API container itself (`uvicorn api.main:app`) has no TLS of its own,
by design — `docker-compose.yml`'s `api` service binds its port to
`127.0.0.1:8000` only (never a public interface directly), so Caddy is
the only path anything outside the host can reach it through.
`X-API-Key` authentication is not a substitute for transport
encryption — without TLS, every key would be sent in plaintext.

## 3. Persistent data — confirmed correct, not assumed

`docker-compose.yml`'s `api` service mounts `./docker-data/api_data` (host)
to `/app/api_data` (container) — `APISettings.data_dir`'s own default
(`api/settings.py`) resolves to exactly `/app/api_data` inside this image
(`WORKDIR /app`), so no extra environment variable is needed for this to
land in the right place. This ONE mounted volume already covers
everything that needs to survive container recreation:

- `control.db` (accounts, keys, billing, the scan registry)
- every account's own `output/`/`recon.db` (`api/tenancy.py`)
- `api/backup_worker.py`'s own local backup snapshots
  (`api_data/backups/<timestamp>/`) — the backup destination lives under
  the SAME mounted volume as the data it backs up, which is fine for
  surviving a container recreation but is **not**, by itself, protection
  against the underlying disk dying — that's what §4's remote upload is
  for.

One-time host setup, matching `docs/DOCKER.md`'s existing convention for
the CLI service's own volumes:

```bash
mkdir -p docker-data/api_data
sudo chown -R 10001:10001 docker-data/api_data   # the image's non-root uid:gid
```

## 4. Backup configuration for this deployment

`api/backup_worker.py`'s loop runs automatically inside the `api`
container — nothing extra to start. What to actually configure, in `.env`
(picked up by `docker-compose.yml`'s existing `env_file:` line, same as
every other API setting):

| Variable | Default | What it does |
|---|---|---|
| `HYDRA_API_BACKUP_INTERVAL_SECONDS` | `86400` (daily) | How often a backup runs. |
| `HYDRA_API_BACKUP_RETENTION_COUNT` | `7` | Local snapshots kept; older ones are rotated out (never below 1, regardless of misconfiguration). |
| `HYDRA_API_BACKUP_S3_BUCKET` | unset (local-only) | Set this to enable remote upload — **do this before going live**, since local-only backups don't survive the host's disk failing. |
| `HYDRA_API_BACKUP_S3_PREFIX` | `hydra-backups` | Key prefix under the bucket. |
| `HYDRA_API_BACKUP_S3_ENDPOINT_URL` | unset (real AWS) | Set this for a non-AWS S3-compatible provider (DigitalOcean Spaces, Backblaze B2, Cloudflare R2). |
| `HYDRA_API_BACKUP_S3_REGION` | unset | The bucket's region, if your provider needs one. |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | unset | Read by `boto3` itself, not a Hydra-specific variable — the standard credential env vars every S3-compatible provider's own docs use. |

Once a bucket is configured, confirm it's actually working by checking the
`api` container's own logs after the first backup cycle
(`docker compose logs api | grep hydra.api.backup`) — a successful remote
upload logs the real object count and destination; a misconfigured bucket
logs the failure loudly (and never breaks the local backup that already
succeeded — see that module's own docstring).

**Test a real restore before you need one for real** — this is the whole
point of `tests/test_backup_and_restore.py` already existing, but running
it once against THIS deployment's real backup output, on a throwaway
target directory, is worth doing as part of first standing this up:

```bash
docker compose run --rm api \
  python -m api.restore_backup /app/api_data/backups/<a-real-timestamp> /tmp/restore-check
```

## 5. Running it

```bash
cp api/.env.example .env   # then edit — every API-specific variable, documented inline
cp Caddyfile.example Caddyfile   # then edit — see §2
mkdir -p docker-data/api_data && sudo chown -R 10001:10001 docker-data/api_data

docker compose build
docker compose up -d api caddy
docker compose logs -f api caddy   # watch startup: worker/reconciliation/backup/monitoring
                                    # loops starting, and Caddy's certificate issuance
```

**`api/.env.example`, not `config/.env.example`** — confirmed by reading
the code, not assumed: `api/tenancy.py::account_settings` constructs each
account's `config.settings.Settings` DIRECTLY (`Settings(project_root=...)`),
never via `Settings.from_env()`, so an API-triggered scan never reads
`config/.env.example`'s `ENABLE_*`/tool-path variables at all — every
account gets the exact same fixed tool selection (that dataclass's own
hardcoded defaults) regardless of what's in the environment. This is
deliberate per-tenant isolation (a shared server-level env var steering
every account's scan behavior would itself be a real multi-tenancy leak),
not an oversight, but it does mean copying `config/.env.example` into an
API-only deployment's `.env` accomplishes nothing — `api/.env.example` is
the file that actually matters here. If this same host is ALSO running
the separate `hydra` CLI service from `docker-compose.yml`, copy
`config/.env.example` too; the two files' variables never collide.

## 6. How do I know it's actually up

`GET /health` (added by the "Basic observability" task,
`api/health.py`/`api/routers/health.py`) — unauthenticated, so any
uptime monitor can point straight at it:

```bash
curl -s https://api.yourdomain.com/health
```

Point an external uptime monitor (UptimeRobot, Better Uptime, a simple
cron+curl, whatever's already in use) at this URL, expecting `200`.
Unlike a bare "the process is running" check, this genuinely verifies
`control_db` is reachable (a real query, not just an in-memory object)
and that the scan-worker, reconciliation, backup, and continuous-
monitoring loops are each still alive (a real per-loop heartbeat timestamp, not just "the asyncio
task object hasn't been garbage collected" — see `api/health.py`'s own
docstring for why that distinction matters). A `503` response body
names exactly which check failed:

```json
{"status": "unhealthy", "checks": {"control_db": "ok", "scan_worker": "stale: last alive 245s ago (threshold 60s)", ...}}
```

`docker compose logs api` is still worth checking on first deploy too —
each loop logs a real "started" line at `api/main.py`'s own `lifespan`
startup, which `/health` alone can't tell you (a loop that never
started at all vs. one that started and later went stale look
identical to `/health` until enough time passes for the staleness
threshold to trip).

**Error tracking (Sentry)**: set `SENTRY_DSN` to get unhandled
exceptions reported automatically — unset means it's simply off, no
separate flag needed. See `docs/PAID_API_DESIGN.md`'s "Basic
observability" section for exactly what gets scrubbed before anything
is sent (API keys, the Postmark/Wompi secrets, never a raw webhook
body).
