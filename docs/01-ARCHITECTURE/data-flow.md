# Data Flow

This page summarizes how local files become backend state, API responses, map overlays, and operator actions.

## 1. Local Sources

Typical data enters through:

- handshake captures in `backend/data/handshakes/`
- Brucegotchi handshake captures in `backend/data/BrucePCAP/handshakes/`
- M5 Evil handshake captures in `backend/data/m5evil/handshakes/`
- Bruce RAW captures in `backend/data/BrucePCAP/rawsniffer/`
- M5 Evil RAW captures in `backend/data/m5evil/rawsniffer/`
- Wardrive CSV files in `backend/data/wardrive/`
- Wardrive ingest metadata in `backend/data/wardrive/manifest.json`
- merged Wardrive sessions in `backend/data/wardrive/merged/`
- map packs in `backend/data/maps/<country_code>/`
- derived artifacts such as `.details`, `.cracked`, `.try`, `raw_*.22000`, and canonical `__wdrs__.22000`

## 2. Backend Loading and Enrichment

- `data_loader.py` builds the in-memory dataset for the map
- Wardrive ingest first syncs the local manifest, resolves duplicate CSVs by hash, and loads only active session files
- fingerprint, RAW, and handshake metadata enrich existing networks
- WarDrive services add region hierarchy, zones, sessions, vehicle tags, and inventory
- analytics services derive heatmaps, adaptive hotspots, and summaries from the cached dataset

## 3. Delivery to the Frontend

### REST

- `GET /api/map/data` for full map data refresh
- workspace and supporting endpoints for map/recon analytics, WarDrive, cracking, RAW, and summaries

### WebSocket

- `data_update` triggers refresh after syncs or runtime reloads
- `job_update` / job progress events drive Processes and long-running workflows

## 4. Renderer Flow

The Electron renderer transforms backend JSON into:

- filtered marker sets
- themed popup cards
- side-panel lists and summaries
- map/recon analytics overlays and WarDrive overlays
- process feedback and action states for cracking and RAW workflows
