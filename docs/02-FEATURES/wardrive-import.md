# WarDrive Workspace and CSV Import

KOVIL MAP supports WiGLE-compatible Wardrive CSV imports and exposes them through a dedicated WarDrive workspace instead of treating them as a flat data dump.

## Data Entry Point

Drop CSV files into:

```text
backend/data/wardrive/
```

For the current local import layout across handshakes, RAW, and WarDrive, see [`../00-GETTING_STARTED/manual-import-layout.md`](../00-GETTING_STARTED/manual-import-layout.md).

Then refresh the local dataset:

- click `SYNC` in the app, or
- call `POST /api/wardrive/refresh`, or
- restart the backend

New CSVs dropped in the root Wardrive folder are discovered as `original` sessions. The loader now syncs a local manifest and only ingests active entries from that manifest instead of blindly consuming every `*.csv` it sees.

Managed sidecars and generated artifacts now include:

```text
backend/data/wardrive/
  manifest.json
  session_tags.json
  merged/
    merged-YYYYMMDD-HHMMSS.csv
```

- `manifest.json` is the source of truth for active vs ignored Wardrive files
- `session_tags.json` keeps transport labels separate from the ingest manifest
- `merged/*.csv` stores session merge outputs generated from the workspace

## What the Workspace Does

The WarDrive workspace is not just an importer. It provides:

- region hierarchy driven by map country packs
- session inventory from CSV files
- multi-selection by session
- per-session vehicle tagging
- single-session route replay
- 2-3 session compare with active-session focus
- Active Region summary with quick-open access to region zones
- Workspace Explorer with separate `Regions` and `Zones` views
- collapsible region tree for large hierarchies
- region-scoped DBSCAN zones
- map inventory view for active and ignored datasets
- session merge for selected replay sessions
- warm reopen behavior and explicit refresh
- shell-first loading with animated skeletons during large-session hydration

## Current Layout

### Left side

- `WARDRIVE SESSIONS`
- session KPIs (`loaded`, `selected`, `networks`, `points`)
- sort controls (`none`, `date`, `duration`, `nets` + direction)
- per-session vehicle tag button with popover picker
- merged-session badge when the session was produced by a workspace merge
- transport summary showing up to 8 transport modes when available

### Right side

The WarDrive right panel has two header tabs:

- `WORKSPACE`
- `MAP INVENTORY`

The workspace view now uses a denser shell designed for very large sessions:

- `ROUTE REPLAY` at the top as a compact Replay Dock
- `ACTIVE REGION` as the current scope summary
- `WORKSPACE EXPLORER` below, with switchable `REGIONS` and `ZONES` panes

The inventory view exposes dataset health, formats, coverage, CRS diagnostics, and ignored/legacy entries.

`ROUTE REPLAY` behavior is now:

- `0` selected sessions: workspace-wide summary only
- `1` selected session: full replay for that session with themed zones
- `2-3` selected sessions: compare mode with all routes visible, one active replay session at a time, active primary zone, and one aggregated secondary zone for the other selected sessions
- `>3` selected sessions: replay is disabled, but the workspace still filters hierarchy, markers, and zones to the selected sessions

Replay controls now include:

- `FOLLOW CAMERA`, which can lock the map onto the active playhead only while playback is running
- zoom presets for follow mode: `Current`, `City (13)`, `Street (15)`, `Close (17)`, `Very Close (19)`
- timing modes: `Real time`, `Compress idle`, `Uniform path`
- pace presets from `0.05x · Very Slow` up to `8x · Ultra`
- compact action rows for `Play`, `Reset`, `Follow`, `Focus Track`, and `Merge Sessions`
- mode help moved into contextual tooltip hints to preserve vertical space

Important replay interaction rules:

- follow mode is optional and off by default
- map interaction is locked only while follow mode is active during playback
- pause, reset, or end of replay returns manual camera control to the operator
- `FOCUS TRACK` still fits the full selected route and stays separate from camera follow

`REGIONS` now supports expand/collapse per branch so large hierarchies can be navigated without excessive scrolling.

`ACTIVE REGION` is intentionally compact:

- region label and region kind now share the same title line
- breadcrumb lineage stays visible below the title
- KPI chips (`NETS`, `CRACKED`, `OPEN`, `LOCKED`) are rendered on one line when space allows
- the summary includes a direct action to open the currently available zones

## Session Model

Every CSV file becomes a session with metadata such as:

- `session_id`
- `label`
- `source_file`
- `started_at`
- `ended_at`
- `networks_count`
- `points_count`
- `transport_mode`
- `session_type` (`original` or `merged`)
- `merged_from_session_ids`
- `merged_at`

Vehicle tags are stored in the sidecar file:

```text
backend/data/wardrive/session_tags.json
```

Supported transport modes:

- `walk`
- `bike`
- `motorcycle`
- `boat`
- `plane`
- `helicopter`
- `car`
- `bus`
- `train`
- `metro`

## Session Merge

The Route Replay card can merge `2-3` selected sessions into one new active WarDrive session.

Current merge behavior:

- available only when the selected sessions are replayable
- writes a new CSV to `backend/data/wardrive/merged/`
- keeps the first `WigleWifi-*` line once
- keeps the CSV column header once
- appends all data rows in the exact order of the selected sessions
- does not deduplicate rows in v1
- keeps original source CSVs on disk as record, but marks them ignored in `manifest.json`
- automatically switches the workspace selection to the merged session after success

The merge logic was implemented natively in KOVIL MAP, but the row-concatenation strategy is intentionally based on the Evil-M5Project Wardriving utility reference:

- [Evil-M5Project Wardriving Utilities](https://github.com/7h30th3r0n3/Evil-M5Project/tree/main/utilities/wardriving)

## Manifest-Driven Ingest

WarDrive ingest is now manifest-driven to prevent accidental double import when:

- an already merged source CSV is copied back into `backend/data/wardrive/`
- an original CSV already consumed by a merge is reintroduced under the same name
- a duplicate file is reimported under a different filename

The loader discovers CSVs, hashes them, syncs `manifest.json`, and then ingests only entries marked as active.

## Session Filtering Behavior

When one or more sessions are selected:

- WarDrive hierarchy uses only those sessions
- WarDrive zones use only those sessions
- WarDrive markers on the map use only those sessions
- marker and zone positions use normalized display coordinates for the selected session scope
- replay tracks and distance calculations continue to use raw coordinates
- source is forced to `ward` inside the workspace to avoid cross-source ambiguity

Clearing the selection restores the previous source choice.

## Country Packs and Region Hierarchy

Administrative maps are loaded from:

```text
backend/data/maps/<country_code>/
```

A country pack uses:

- `country.json` for country-level metadata
- `layers/<order>-<name>/.../metadata.json` for dataset manifests

The hierarchy is generic and order-driven, so it can represent different administrative models across countries. The UI displays:

- deepest matched region as the primary title
- full lineage as breadcrumb / display path
- level labels from metadata, not from hardcoded country-specific names

## Map Inventory

The inventory view reflects the current manifest-driven dataset state, including:

- active datasets
- ignored or legacy datasets
- CRS notes and incompatibilities
- depth coverage by level
- files loaded per dataset
- validation errors surfaced by the loader

For deeper validation, run:

```bash
cd backend
PYTHONPATH=. python -m app.tools.validate_maps --pretty
```

## Performance Notes

WarDrive uses a local-first caching strategy:

- backend caches classification, hierarchy payloads, outlines, and zones
- the frontend keeps a warm workspace snapshot for instant reopen after first load
- `POST /api/wardrive/refresh` is the explicit cache-busting entry point

Recent UX additions for large sessions:

- the workspace shell renders before heavy replay/region/zone work completes
- loading states use animated skeleton placeholders instead of blocking text-only spinners
- hierarchy, replay, and zones hydrate independently so one slow section does not prevent the rest of the workspace from painting

## Related Endpoints

- `GET /api/wardrive/hierarchy`
- `GET /api/wardrive/inventory`
- `GET /api/wardrive/sessions`
- `POST /api/wardrive/sessions/tracks`
- `POST /api/wardrive/sessions/merge`
- `POST /api/wardrive/sessions/tag`
- `POST /api/wardrive/refresh`
- `POST /api/wardrive/zones`

See [`../05-API-ENDPOINTS/reference.md`](../05-API-ENDPOINTS/reference.md) for the full API surface.
