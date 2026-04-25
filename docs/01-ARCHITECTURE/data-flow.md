# Data Flow

This page summarizes how local evidence becomes map state, workspace context, cracking artifacts, and operator actions.

## 1. Inputs

KOVIL MAP is local-first. The backend reads operator-owned files from `backend/data/` and builds a consolidated runtime dataset.

Primary inputs:

- classic Pwnagotchi-style handshakes in `backend/data/handshakes/`
- Bruce handshakes in `backend/data/BrucePCAP/handshakes/`
- M5Evil handshakes in `backend/data/m5evil/handshakes/`
- Bruce RAW PCAPs in `backend/data/BrucePCAP/rawsniffer/`
- M5Evil RAW PCAPs in `backend/data/m5evil/rawsniffer/` and `backend/data/m5evil/mastersniffer/`
- WarDrive CSV sessions in `backend/data/wardrive/`
- map country packs in `backend/data/maps/<country_code>/`
- demo runtime files copied from `backend/demo_data/showcase-core-v5/` when Demo Mode is active

## 2. Source-Specific Loading

Each source keeps its own operational meaning:

- Pwnagotchi contributes classic GPS-backed or no-GPS handshake evidence.
- Bruce contributes handshakes, RAW captures, and WarDrive CSV sessions.
- M5Evil contributes handshakes, RawSniffer captures, Master Sniffer captures, and WarDrive CSV sessions.
- WarDrive CSVs contribute route observations, session metadata, transport tags, and region inventory.
- RAW PCAPs contribute radio metadata and hash opportunities for networks already known elsewhere.

The loader keeps source labels so the frontend can show provenance instead of collapsing everything into one generic file list.

## 3. Normalization and Enrichment

The backend consolidates raw files into network records.

Important enrichment steps:

- handshake cataloging groups captures by BSSID and source
- sidecars such as `.details`, `.22000`, `.try`, and `.cracked` attach to the source PCAP basename
- WarDrive sessions are controlled by `manifest.json` and transport tags in `session_tags.json`
- spatial normalization spreads dense observations into stable display coordinates while preserving raw route coordinates for replay
- RAW metadata adds beacon, EAPOL, PMKID, probe, and warning context
- network state classification normalizes `open`, `gps_only`, `locked`, `no_gps_locked`, `not_ready`, and `cracked`

## 4. Runtime Dataset

`data_loader.py` produces the consolidated dataset consumed by the map and related services.

That dataset feeds:

- Tactical Map markers, counters, popups, and source filters
- No-GPS lists for evidence without coordinates
- Targets and Favorites state
- Batch candidate discovery
- Recon Center summaries and target intelligence
- WarDrive region and zone calculations
- Tactical Analytics heatmaps, hotspots, opportunity scores, and channel summaries

## 5. Workspace-Specific Views

Workspaces do not own separate unrelated datasets. They project the same local evidence through task-specific views.

| Workspace | Data projection |
|---|---|
| Tactical Map | consolidated map state, zones, overlays, popups, targets, favorites |
| No-GPS | non-geolocated networks with evidence and cracking readiness |
| Batch | selected targets and generated `batch_*.22000` packages |
| Recon Center | attack surface, SIGINT, COMMS, GEO, OPS, reports, and intelligence zones |
| WarDrive | sessions, route replay, region hierarchy, transport tags, active region, and route inventory |
| Raw Sniffer | RAW file inventory, metadata cache, RAW Analysis, generated RAW hashes, and BSSID raw context |
| Cracking Operations | artifact-aware file views and actions for PCAP, RAW PCAP, `.22000`, `.details`, history, combined, and batch files |

## 6. Jobs and Process Feedback

Long-running or visually important work is represented in the Process panel.

Typical process-backed flows include:

- remote sync stages for Pwnagotchi, Bruce, and M5Evil
- WarDrive and RAW import feedback
- RAW metadata extraction and RAW Analysis
- Recon scans such as probe intelligence and deep threat analysis
- HCX conversion, Hashcat, Aircrack, PMK, WPS, and batch cracking jobs

Backend jobs emit WebSocket updates when available. Some UI-driven operations mirror synchronous backend work into Process entries so operators still receive consistent progress feedback.

## 7. Results Returning to the Product

Generated artifacts become part of the same local evidence loop:

- `.details` improves fingerprint and file summary views
- `.22000` creates crack-ready hash material
- `.try` stores history and attempt context
- `.cracked` updates cracked status and popup access
- combined candidates live under `backend/data/handshakes/combined/<mac_clean>/<build_id>/`
- canonical RAW/Wardrive hybrid hashes use `__wdrs__.22000`

After reload or event propagation, those results update map status, Recon intelligence, batch review, cracking history, target readiness, and zones.

## 8. Demo Mode

Demo Mode is a safe temporary switch, not a merge.

When installed, `showcase-core-v5` replaces mutable runtime roots with synthetic data and keeps one temporary active snapshot for restore. When removed, the previous runtime dataset is restored and the temporary snapshot is deleted.

This lets operators explore the full data flow without exposing real captures or field data.
