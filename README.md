# KOVIL MAP

[![Quality](https://github.com/vitormartins1/kovil.map/actions/workflows/quality.yml/badge.svg?branch=main)](https://github.com/vitormartins1/kovil.map/actions/workflows/quality.yml) [![Security](https://github.com/vitormartins1/kovil.map/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/vitormartins1/kovil.map/actions/workflows/security.yml) ![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-blue.svg) ![License](https://img.shields.io/badge/License-MIT-purple.svg)

KOVIL MAP is a local-first desktop command center for Wi-Fi reconnaissance, map intelligence, cracking workflows, RAW capture enrichment, and WarDrive analysis.

It combines an Electron frontend with a FastAPI backend and keeps the operational workflow in one place:

- map and popup intelligence for known networks
- cracking operations with Hashcat, Aircrack-ng, HCX tools, history, and quality gates
- RAW Sniffer ingestion and hybrid RAW-to-hash preparation
- WarDrive workspace with country-based region hierarchy, sessions, vehicle tags, and map inventory
- Analytics workspace with adaptive hotspots, heatmaps, channel/device summaries, and WarDrive context
- remote sync profiles for Pwnagotchi over SSH/SFTP, M5Evil Cardputer over Admin WebUI, and Bruce WebUI

## Recent Highlights

- Recon Center now uses cache-first lazy loading per tab and per selected target, with cache manifest invalidation and faster reopen behavior
- COMMS and SIGINT were expanded with richer visual intelligence: minimal stacked bars, refreshed relationship graph, Likely Device Groups, and Probe Geocorrelation
- WarDrive Workspace was redesigned for large sessions with a Replay Dock, Active Region summary, Workspace Explorer, and non-blocking skeleton loading
- RAW ingestion now treats Bruce RAW, M5Evil RAW, and M5Evil Master Sniffer captures as source-aware enrichment inputs across Recon, Geo, and analytics
- Professional, Synthwave, and Military themes now apply more consistently across the major workspaces and shared panel chrome

## Documentation

The canonical documentation hub lives in [`docs/INDEX.md`](docs/INDEX.md).

Main entry points:

- [`docs/00-GETTING_STARTED/`](docs/00-GETTING_STARTED/) - installation and first run
- [`docs/01-ARCHITECTURE/`](docs/01-ARCHITECTURE/) - system design and data flow
- [`docs/02-FEATURES/`](docs/02-FEATURES/) - WarDrive, RAW Sniffer, cracking, analytics, spatial normalization
- [`docs/03-DEVELOPMENT/`](docs/03-DEVELOPMENT/) - setup, testing, scripts, country-pack maps
- [`docs/05-API-ENDPOINTS/`](docs/05-API-ENDPOINTS/) - REST and WebSocket reference
- [`docs/07-OPERATIONS/`](docs/07-OPERATIONS/) - practical workflows
- [`SECURITY.md`](SECURITY.md) - security policy
- [`CONTRIBUTING.md`](CONTRIBUTING.md) - branch/PR workflow
- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) - community expectations
- [`LICENSE`](LICENSE) - MIT license

## Open Source Status

KOVIL MAP is published as open source under the MIT license.

- `main` remains the stable branch
- `dev` remains the public integration branch
- repository documentation stays bilingual at the root where applicable
- local operational data and device credentials are not part of the published repository state

## Community

- use GitHub Issues for bugs and feature requests
- use private disclosure for sensitive security reports
- follow [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) when contributing

## Current Product Surface

### Map Workspace

- Leaflet-based tactical map with clustering, heatmap, conquered zones, to-conquer zones, discovered zones, and Intelligence Zones sourced from Recon Center cluster analysis
- modern popups with overview, signal, security, RAW, and access sections
- inline actions for cracking, favorites, targets, and password visibility when applicable
- Wardrive-only networks rendered with dedicated source semantics without forcing cracking CTAs
- search by SSID or MAC address without separators, plus an inline clear action that resets the current filter
- Intelligence Zones can overlap active map zones and reuse the same polygon generation style as the other zone layers for visual consistency

### Recon Center

- seven-tab offensive intelligence workspace: Surface, Intel, Ops, Geo, SIGINT, Report, and COMMS
- COMMS Cluster Intelligence can project geospatial clusters back onto the map as Intelligence Zones and list them in the ZONES panel
- COMMS now separates Device Intelligence from Top Vendors and uses compact mini-bars for security, origins, and device distribution
- refreshed Communication Graph uses a full-width graph canvas with secondary intelligence cards below it for easier interaction
- Intel tab includes lazy-load Threat Analysis plus severity filter chips for vulnerability flags
- Recon tabs use cache-first rendering, per-tab snapshots, per-section hydration, and per-target detail fetches instead of eager full-tab loading
- SIGINT now includes unmatched target SSIDs, enriched probing-client context, Likely Device Groups, and Probe Geocorrelation
- contextual hints/tooltips explain ambiguous metrics and intelligence cards across the workspace
- Ops tab includes an Attack Planner with batch MAC input, strategy selection, and wordlist selection from the backend catalog

### Visual Themes

- four visual themes: Cyberpunk, Professional, Synthwave, and Military
- Cyberpunk keeps the sharper terminal-style language for left-panel lists, popups, and System Configuration while the other themes provide their own tailored overrides

### WarDrive Workspace

- dedicated workspace mode with region hierarchy and DBSCAN zones
- sessions list backed by `backend/data/wardrive/*.csv`
- session-based filtering across hierarchy, zones, and markers
- per-session vehicle tagging persisted in `backend/data/wardrive/session_tags.json`
- map inventory view based on country packs in `backend/data/maps/<country_code>/`
- warm reopen and explicit refresh flow for local/offline use
- replay with compare mode, camera follow, zoom presets, timing modes, and slower/faster pace presets for real-world drives
- large-session UX now uses a Replay Dock, compact Active Region summary, and a Workspace Explorer that separates Regions and Zones
- shell-first loading with animated skeletons helps the WarDrive UI paint before heavy region/zone work completes

### Analytics Workspace

- adaptive hotspots based on spatial clustering instead of fixed tactical cells
- heatmap-first opening behavior without auto-drawing hotspot shapes on load
- hotspot details with prioritized candidate MACs and add-to-targets flow
- channel/device summaries plus WarDrive context, including top transport modes

### Cracking and RAW Workflows

- `.pcap` to `.22000` conversion with `hcxpcapngtool`
- Hashcat, Aircrack-ng, batch cracking, history, attack insights, and quality gate
- RAW Sniffer extraction from `raw_*.pcap`
- source-aware RAW semantics for Bruce RAW, M5Evil RAW, and M5Evil Master Sniffer captures
- `RAW Sniffer` accordion inside Cracking Operations with source-aware RAW PCAP / RAW `.22000` management
- `BUILD CANONICAL` and `BUILD CANONICAL FROM ALL` generating canonical hybrid hashes like `<ssid>_<mac>__wdrs__.22000`
- handshake-set catalog that groups Pwnagotchi, Brucegotchi, and M5Evil captures by BSSID and recommends the best capture by quality score
- cracking details panel organized by capture origin/device with grouped accordions, active-parent highlighting, optional single-open behavior, and collapsible legacy/shared artifacts
- capture-scoped derived artifacts under `backend/data/handshakes/captures/<capture_id>/` for conversion, fingerprint extraction, Aircrack, and history writes
- capture-specific actions via `capture_id` for conversion, fingerprint extraction, and Aircrack workflows
- manual `BUILD COMBINED CANDIDATE` flow for one BSSID, producing deduplicated combined `.22000` artifacts under `backend/data/handshakes/combined/`
- selected combined candidates expose a `COMBINED ORIGIN` summary showing included captures, sources, and dedupe results
- RAW PCAP details extraction scoped to the selected BSSID, plus capture-wide RAW Analysis in the dedicated RAW workspace
- `RAW ANALYSIS` now appears in the Process panel while the capture-wide report is being built
- RAW capture delete flow that also removes cached metadata and sibling `.22000` artifacts when present
- `Sync` can now pull M5Evil Cardputer handshakes, `RawSniff`, `masterSniffer`, and Wardrive CSVs automatically into the local catalog
- `Sync` can now pull Bruce WebUI handshakes, RAW captures, and Wardrive CSVs using fixed remote paths (`/BrucePacket/Handshakes`, `/BrucePacket`, `/Wardrive`)

## Repository Layout

```text
backend/   FastAPI backend, jobs, services, tests, local data
frontend/  Electron app, renderer modules, CSS, unit tests
docs/      Canonical product, API, development, and operations docs
docs/scripts/  Docs-only utilities
backend/scripts/  Backend CLI utilities
backend/scripts/manual/  Legacy and ad-hoc helpers
```

## Local Development

### Recommended launcher

- macOS: `./run_dev_mac.sh`
- Windows: `run_dev.bat`

### Manual launch

Backend:

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

Frontend:

```bash
cd frontend
npm install
npm start
```

## Testing

Backend:

```bash
cd backend
./.venv/bin/python -m pytest app/tests --cov=app/api --cov=app/core --cov=app/schemas --cov=app/services --cov=app/utils --cov-report=term-missing
```

Frontend:

```bash
cd frontend
npm run test:unit
npm run test:unit:coverage
npm run test:smoke:packaged
```

## Responsible Use

This project is intended for authorized security research, lab work, auditing, and learning. Many features are dual-use. You are responsible for using it only on networks, captures, devices, and systems you own or are explicitly authorized to assess.

## License

Licensed under the [MIT License](LICENSE).
