# KOVIL MAP - Backend

![Python](https://img.shields.io/badge/Python-3.12%2B-blue.svg) ![FastAPI](https://img.shields.io/badge/FastAPI-local-green.svg) ![License](https://img.shields.io/badge/License-MIT-green.svg)

The backend is a local FastAPI application that powers map rendering, data ingestion, cracking orchestration, RAW capture processing, WarDrive classification, and workspace analytics.

## Quick Start

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

Endpoints:

- API: `http://127.0.0.1:8000`
- Swagger: `http://127.0.0.1:8000/docs`
- ReDoc: `http://127.0.0.1:8000/redoc`

## What the Backend Owns

### Data and map intelligence

- loads the main network dataset from local files under `backend/data/`
- merges GPS, handshake, RAW, Wardrive, and fingerprint-derived information
- classifies WarDrive points using country packs in `backend/data/maps/<country_code>/`
- calculates zones, adaptive hotspots, and analytical summaries

### Cracking orchestration

- wraps Hashcat, Aircrack-ng, and HCX conversion flows
- tracks jobs, history, and runtime status through WebSocket events
- exposes attack insights, recommendations, and quality gate checks
- supports batch cracking and canonical hybrid RAW/Wardrive hash generation

### RAW Sniffer workflows

- indexes `raw_*.pcap` metadata and generated RAW hashes
- exposes BSSID-level RAW context
- prepares canonical `__wdrs__.22000` hashes via hash-first pipeline with PCAP fallback

### WarDrive workspace services

- sessions catalog built from manifest-managed Wardrive CSV entries
- active/ignored ingest state persisted in `backend/data/wardrive/manifest.json`
- session tags persisted in `backend/data/wardrive/session_tags.json`
- merged session artifacts written to `backend/data/wardrive/merged/`
- route replay, focused compare, and session merge workflows
- map inventory and country-pack validation hooks
- runtime caches and explicit refresh endpoint for local-first performance

## Current Router Families

Mounted router groups include:

- `config`, `sync`, `map`, `zones`, `vendors`, `files`
- `handshakes`, `convert`, `hashcat`, `aircrack`, `batches`, `jobs`, `history`
- `fingerprint`, `rawsniffer`, `data_health`, `insights`, `analytics`, `maintenance`, `wardrive`

See [`docs/05-API-ENDPOINTS/reference.md`](../docs/05-API-ENDPOINTS/reference.md) for the full surface.

## WarDrive Country Packs

Country packs follow this structure:

```text
backend/data/maps/
  br/
    country.json
    layers/
      01-state/
      02-city/
      03-neighborhood/
      04-sector/
```

Each dataset is described by `metadata.json` and loaded generically by hierarchy order.

Helpful docs:

- [`docs/03-DEVELOPMENT/maps-country-packs.md`](../docs/03-DEVELOPMENT/maps-country-packs.md)
- [`docs/02-FEATURES/wardrive-import.md`](../docs/02-FEATURES/wardrive-import.md)

Validate map packs with:

```bash
cd backend
PYTHONPATH=. python -m app.tools.validate_maps --pretty
```

## Testing

Install dev dependencies:

```bash
cd backend
source .venv/bin/activate
pip install -r requirements-dev.txt
```

Run the backend suite:

```bash
pytest app/tests
```

Coverage command used in the repo:

```bash
pytest app/tests --cov=app/api --cov=app/core --cov=app/schemas --cov=app/services --cov=app/utils --cov-report=term-missing --cov-fail-under=90
```

Tests are organized by domain under:

```text
app/tests/
  api/
  core/
  jobs/
  services/
  tools/
  utils/
  ws/
```

## Common Developer Tasks

Export OpenAPI:

```bash
python backend/scripts/export_openapi.py backend/openapi.json
```

Inspect RAW PCAP metadata:

```bash
python backend/scripts/extract_pcap_metadata.py backend/data/BrucePCAP/raw_1.pcap --pretty
```

Lint and format:

```bash
ruff check app
black --check app
```

## Security Notes

Optional local API/WS auth is enabled when `KOVIL_API_TOKEN` is set.

- HTTP: `X-KOVIL-Token`
- WebSocket: `?token=...` or `X-KOVIL-Token`

The backend is designed for local/offline use and avoids remote shell execution for sync operations by using SFTP-based flows.

## Related Documentation

- [`../README.md`](../README.md)
- [`../docs/INDEX.md`](../docs/INDEX.md)
- [`../docs/03-DEVELOPMENT/scripts-reference.md`](../docs/03-DEVELOPMENT/scripts-reference.md)
- [`../docs/05-API-ENDPOINTS/reference.md`](../docs/05-API-ENDPOINTS/reference.md)
- [`../docs/02-FEATURES/cracking-engine.md`](../docs/02-FEATURES/cracking-engine.md)
- [`../docs/02-FEATURES/raw-sniffer.md`](../docs/02-FEATURES/raw-sniffer.md)
