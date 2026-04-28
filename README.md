# Greycode v2

Greycode is a security enrichment platform for high-volume telemetry triage.
It ingests indicators (SHA-256 hashes, IPs, domains), enriches them asynchronously, maintains searchable indexes in Redis, and provides a built-in analyst UI for investigation and disposition workflows.

## What it does

- **Ingests telemetry** via API endpoints for process, network, and DNS events.
- **Classifies indicators** into statuses (for example `RED`, `GREEN`, `GREY`) based on enrichment and blacklist hits.
- **Runs async workers** for VirusTotal lookups, staged candidate selection, blacklist feed refresh/rechecks, and dirty index sync.
- **Serves a web UI** for login, triage, settings, tagging, comments, and audit-related actions.
- **Stores state in Redis** using hash records + secondary indexes for fast table/search views.

## Repository layout

```text
.
├── greycode_core/         # FastAPI app, templates, static assets, enrichment + indexing logic
├── vt_worker/             # VirusTotal worker (async API querying + status updates)
├── selector/              # Candidate selector / budget-aware VT queue feeder
├── blacklist_worker/      # Vendor feed updater + known IP/domain recheck worker
├── dirty_index_worker/    # Rebuild/sync worker for dirty index sets
├── nginx/                 # NGINX config + static landing assets
├── bulk_import.py         # CLI helper for importing process events in bulk
├── requirements.txt       # Python dependencies
└── Dockerfile             # Container image for greycode_core app
```

## Core services

### 1) API + UI (`greycode_core`)

Primary app served by FastAPI (`greycode_core/main.py`).

Notable endpoint groups:

- **Auth/UI:** `/login`, `/ui`, `/ui/sysmon/{event_id}`, `/ui/settings`, etc.
- **Ingestion:**
  - `POST /enrich/process`
  - `POST /enrich/process/bulk`
  - `POST /enrich/network`
  - `POST /enrich/network/bulk`
  - `POST /enrich/dns`
  - `POST /enrich/dns/bulk`
- **Indicator status:**
  - `GET /status/{sha256}`
  - `GET /status/ip/{ip}`
  - `GET /status/domain/{domain}`

### 2) VT worker (`vt_worker`)

Consumes queued SHA-256 items, calls VirusTotal, updates canonical records, and can emit alerts when status transitions to malicious.

### 3) Selector (`selector`)

Chooses which staged hashes should be sent to the VT queue using:

- rarity/age gating,
- lease/backoff checks,
- a rolling 24-hour budget,
- rare/common mix controls.

### 4) Blacklist worker (`blacklist_worker`)

Fetches vendor blacklist feeds on interval, persists vendor state, and rechecks known IP/domain indicators.

### 5) Dirty index worker (`dirty_index_worker`)

Drains dirty indicator sets and re-syncs secondary indexes so UI/search views remain consistent.

## Requirements

- Python 3.12+
- Redis (default host expected by services: `redis`, port `6379`)
- `GREYCODE_SESSION_SECRET` (required)

Install dependencies:

```bash
pip install -r requirements.txt
```

## Environment variables

Common variables used across services:

- `GREYCODE_SESSION_SECRET` (**required**): session signing + config secret derivation.
- `REDIS_HOST` (default `redis`)
- `REDIS_PORT` (default `6379`)

Selector/VT-related runtime controls include:

- `VT_ENABLED` (selector gate)
- `VT_BUDGET_24H`
- `SELECTOR_INTERVAL_SECONDS`
- `ENQUEUE_PER_TICK`
- `RARE_MAX`
- `MIN_AGE_SECONDS`

> Note: VirusTotal API credentials are stored in settings/config state consumed by workers (not hardcoded in this repo).

## Running locally (development)

### 1) Start Redis

Example using Docker:

```bash
docker run --rm --name greycode-redis -p 6379:6379 redis:7
```

If running services outside Docker, set `REDIS_HOST=localhost`.

### 2) Start API/UI

```bash
export GREYCODE_SESSION_SECRET='replace-with-a-long-random-secret'
export REDIS_HOST=localhost
uvicorn greycode_core.main:app --host 0.0.0.0 --port 8000 --reload
```

### 3) Start workers (separate terminals)

```bash
export REDIS_HOST=localhost
python -m selector.selector
python -m vt_worker.worker
python blacklist_worker/worker.py
python dirty_index_worker/worker.py
```

## Example ingestion requests

### Process event

```bash
curl -X POST http://localhost:8000/enrich/process \
  -H 'Content-Type: application/json' \
  -d '{
    "sha256": "275a021bbfb6489e54d471899f7db9d1ae5ebf1b4c90beec59d839be1316a9ee",
    "computer": "WS-001",
    "image": "C:\\Users\\alice\\Downloads\\invoice.exe"
  }'
```

### Network event

```bash
curl -X POST http://localhost:8000/enrich/network \
  -H 'Content-Type: application/json' \
  -d '{
    "computer": "WS-001",
    "source_ip": "10.1.2.3",
    "destination_ip": "203.0.113.10",
    "destination_port": "443",
    "image": "C:\\Windows\\System32\\curl.exe"
  }'
```

### DNS event

```bash
curl -X POST http://localhost:8000/enrich/dns \
  -H 'Content-Type: application/json' \
  -d '{
    "computer": "WS-001",
    "query_name": "example.org",
    "query_status": "SUCCESS",
    "image": "C:\\Windows\\System32\\nslookup.exe"
  }'
```

## Bulk import helper

Use `bulk_import.py` to submit a JSON array of process events:

```bash
python bulk_import.py ./events.json --url http://localhost:8000/enrich/process
```

Expected JSON shape:

```json
[
  {
    "sha256": "...",
    "computer": "WS-001",
    "image": "C:\\path\\to\\binary.exe"
  }
]
```

## Security and deployment notes

- Put Greycode behind TLS termination (NGINX config is provided under `nginx/`).
- Rotate `GREYCODE_SESSION_SECRET` securely and keep it out of source control.
- Restrict network access to Redis and service containers.
- Tune VT budget/worker intervals for your API tier and expected event volume.

## License

MIT. See `LICENSE`.
