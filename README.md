# Greycode

**Greycode** is a lightweight, modular threat enrichment microservice built to analyze and classify security-relevant artifacts like file hashes, IPs, and domains — starting with process hashes from Sysmon Event ID 1.

---

## 🚀 Features

- FastAPI-based microservice for hash enrichment
- Redis-backed in-memory cache
- Asynchronous VirusTotal integration (rate-limited)
- Background blacklist worker for feed sync and indicator rechecks
- Containerized via Docker + Compose
- Clean JSON output — easy to integrate with Cribl, Splunk, Kafka, etc.

---

## 📦 Directory Structure

```
greycode/
├── greycode_core/        # FastAPI API to receive enrichment requests
├── vt_worker/            # Background worker to query VirusTotal
├── selector/             # Background worker for queue handling
├── blacklist_worker/     # Background worker for blacklist feed sync/rechecks
├── docker-compose.yml    # Multi-container setup
├── requirements.txt      # Python dependencies
└── README.md             # This file
```

---

## 🧪 Usage

### 1. Clone & Start

```bash
git clone https://github.com/yourorg/greycode.git
cd greycode
docker-compose up --build
```

### 2. Send Enrichment Request

```bash
curl -X POST http://localhost:8000/enrich/process \
  -H 'Content-Type: application/json' \
  -d '{
    "sha256": "275a021bbfb6489e54d471899f7db9d1ae5ebf1b4c90beec59d839be1316a9ee",
    "computer": "WS-001",
    "image": "C:\\Users\\alice\\Downloads\\invoice.exe"
  }'
```
There is also a bulk_import script

Response:
```json
{
  "status": "GREEN",
  "source": "vt"
}
```

### 3. View VT Worker Logs

```bash
docker-compose logs -f vt-worker
```

---

## 🔐 Environment Variables

Set your VirusTotal API key in `docker-compose.yml`:
```yaml
environment:
  - VT_API_KEY=your_virustotal_api_key
```

---

## 🛠️ Roadmap

- [ ] Add support for DNS (Sysmon ID 22) and IPs (Sysmon ID 3)
- [ ] Web UI for hash review & manual tagging
- [ ] Alert forwarder container (e.g., Cribl HTTP, Kafka)

---

## 🧠 License
MIT. Created for blue teams who like their telemetry enriched, but lean.
