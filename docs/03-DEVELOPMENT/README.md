# Development Guide

This section documents how to work on the current codebase as it exists today: FastAPI in `backend/`, Electron plus vanilla JS in `frontend/`, and documentation in `docs/`.

## Core Guides

- [`backend-setup.md`](backend-setup.md)
- [`frontend-setup.md`](frontend-setup.md)
- [`testing.md`](testing.md)
- [`debugging.md`](debugging.md)
- [`ci-cd-pipeline.md`](ci-cd-pipeline.md)
- [`scripts-reference.md`](scripts-reference.md)
- [`maps-country-packs.md`](maps-country-packs.md)

## Quick Dev Flow

```bash
# terminal 1
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
python main.py

# terminal 2
cd frontend
npm install
npm start
```

Or use the root launchers:

- macOS: `./run_dev_mac.sh`
- Windows: `run_dev.bat`

## Current Stack

### Backend

- FastAPI routers under `backend/app/api/routers/`
- services under `backend/app/services/`
- jobs under `backend/app/jobs/`
- schemas under `backend/app/schemas/`
- file-backed local data in `backend/data/`

### Frontend

- Electron main process
- sandboxed renderer with vanilla JavaScript modules
- Leaflet-based map rendering
- UI logic split by domain (`ui_analytics.js`, `ui_wardrive.js`, `ui_raw.js`, `ui_components/`)

## Practical Notes

- there is no React runtime in the renderer
- there is no legacy one-shot build script; use the current launcher/build steps documented in this repo
- prefer documenting feature behavior in `docs/02-FEATURES/` and public API behavior in `docs/05-API-ENDPOINTS/`

## Where to Contribute

- new backend capability: `backend/app/services/` + router + tests
- new frontend workflow: `frontend/src/modules/` + tests
- map country packs: `backend/data/maps/<country_code>/` + manifests
- docs refresh: keep `docs/` as the canonical link target
