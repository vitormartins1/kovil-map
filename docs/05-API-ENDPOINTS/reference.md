# API Reference

This page summarizes the current REST surface exposed by the local FastAPI backend.

Base URL:

```text
http://127.0.0.1:8000
```

All successful responses use the common `ok(...)` envelope, typically:

```json
{
  "status": "success",
  "data": {}
}
```

## Authentication

If `KOVIL_API_TOKEN` is set, send it as:

- HTTP: `X-KOVIL-Token`
- WebSocket: query parameter or header equivalent

## Router Families

### Core and data

- `GET /api/health`
- `GET /api/config`
- `PUT /api/config`
- `POST /api/sync`
- `POST /api/sync/trust-host-key`
- `GET /api/map/data`
- `POST /api/zones`
- `POST /api/zones/to-conquer`
- `GET /api/vendors/{mac}`
- `GET /api/files/{filename}`

### Handshakes, cracking, and history

- `GET /api/handshakes/{mac}/files`
- `GET /api/handshakes/{mac}/set`
- `POST /api/handshakes/{mac}/combine-captures`
- `GET /api/handshakes/{mac}/raw-context`
- `POST /api/handshakes/{mac}/raw-prepare`
- `POST /api/handshakes/{mac}/raw-prepare-all`
- `POST /api/convert/hcx`
- `POST /api/convert/hcx/batch`
- `POST /api/hashcat/jobs`
- `POST /api/hashcat/association/preview`
- `GET /api/hashcat/devices`
- `GET /api/hashcat/rules`
- `GET /api/hashcat/masks`
- `POST /api/aircrack/jobs`
- `GET /api/wordlists/custom`
- `GET /api/batches`
- `GET /api/batches/{filename}`
- `GET /api/batches/{filename}/files`
- `DELETE /api/batches/{filename}`
- `GET /api/jobs`
- `GET /api/jobs/{job_id}`
- `PATCH /api/jobs/{job_id}`
- `GET /api/history`
- `DELETE /api/history`

### Fingerprint, RAW, and insights

- `POST /api/fingerprint/extract`
- `GET /api/fingerprint/details`
- `GET /api/rawsniffer/files`
- `DELETE /api/rawsniffer/files/{filename}`
- `GET /api/rawsniffer/hashes`
- `GET /api/rawsniffer/metadata`
- `POST /api/rawsniffer/extract`
- `POST /api/rawsniffer/analyze`
- `GET /api/rawsniffer/analysis/{raw_item_id}`
- `GET /api/data-health/summary`
- `GET /api/insights/score`
- `GET /api/insights/attack-recommendation`
- `GET /api/insights/quality-gate`

### Analytics

- `GET /api/analytics/heatmap`
- `GET /api/analytics/hotspots`
- `GET /api/analytics/channel-summary`

### Recon Center

- `GET /api/recon/cache-manifest`
- `GET /api/recon/kill-chain`
- `GET /api/recon/kill-chain/summary`
- `GET /api/recon/kill-chain/stage`
- `POST /api/recon/kill-chain/snapshot`
- `GET /api/recon/kill-chain/history`
- `GET /api/recon/vulnerability-matrix`
- `GET /api/recon/target-detail`
- `GET /api/recon/attack-effectiveness`
- `GET /api/recon/temporal-intel`
- `GET /api/recon/audit-report`
- `POST /api/recon/audit-report/snapshot`
- `GET /api/recon/audit-report/snapshots`
- `GET /api/recon/audit-report/compare`
- `POST /api/recon/attack-plan`
- `GET /api/recon/comms/device-fingerprints`
- `GET /api/recon/comms/colocation`
- `GET /api/recon/comms/relationship-graph`
- `GET /api/recon/comms/spectrum`
- `GET /api/recon/comms/signal-landscape`
- `GET /api/recon/probe-intel`
- `GET /api/recon/probe-intel/status`
- `POST /api/recon/probe-intel/scan`
- `GET /api/recon/probe-intel/pcap`
- `GET /api/recon/probe-intel/derandom`
- `GET /api/recon/probe-intel/geocorrelation`
- `GET /api/recon/deep-analysis`
- `GET /api/recon/deep-analysis/status`
- `POST /api/recon/deep-analysis/scan`
- `GET /api/recon/deep-analysis/pcap`

### PMK Database

- `GET /api/pmk/databases`
- `GET /api/pmk/databases/{db_name}/stats`
- `POST /api/pmk/build`
- `POST /api/pmk/attack`
- `DELETE /api/pmk/databases/{db_name}`

### WPS

- `POST /api/wps/attack`

### WarDrive

- `GET /api/wardrive/hierarchy`
- `GET /api/wardrive/inventory`
- `GET /api/wardrive/sessions`
- `POST /api/wardrive/sessions/tracks`
- `POST /api/wardrive/sessions/merge`
- `POST /api/wardrive/sessions/tag`
- `POST /api/wardrive/refresh`
- `POST /api/wardrive/zones`

## Important Current Notes

- `GET /api/config` returns a sanitized client payload; use `pwn_pass_configured` instead of expecting raw passwords back from the API
- remote sync now supports two profiles under one run: `pwnagotchi` and `m5evil`
- `POST /api/sync/trust-host-key` is part of the Pwnagotchi SSH flow; M5Evil uses `Admin WebUI` instead
- handshake discovery now has two read models: `/files` for compatibility and `/set` for grouped handshake captures with quality scoring
- conversion, fingerprint extraction, and Aircrack operations can target a capture by `capture_id` instead of only by filename
- new derived handshake artifacts are resolved by `capture_id` but written beside the source PCAP using the source basename
- manual combined one-BSSID candidates are exposed through `/api/handshakes/{mac}/combine-captures` and resolved through `combined_build_id`
- the legacy public geolocation endpoint is not part of the mounted router surface anymore
- hotspot generation is adaptive; `cell_size_m` is still accepted for compatibility on some analytics routes but is no longer the controlling UI concept for hotspots
- canonical hybrid RAW hashes use the `__wdrs__.22000` naming convention
- capture-wide RAW Analysis is still generated through a synchronous API call, but the frontend mirrors it into the Process panel for visual status tracking
- WarDrive CSV ingest is manifest-driven; `backend/data/wardrive/manifest.json` determines which session files are active vs ignored
- Recon Center now exposes a lightweight `cache-manifest` route so the frontend can reuse only fresh cached tab snapshots
- Attack Surface can be loaded lazily through `kill-chain/summary` and `kill-chain/stage` instead of always requiring the full kill-chain payload
- Target details can be fetched per MAC through `/api/recon/target-detail`, which is the preferred route for drawer hydration
- probe intelligence now includes de-randomization and geocorrelation read models in addition to the base `probe-intel` response

## Related Docs

- [`config-runtime-endpoints.md`](config-runtime-endpoints.md)
- [`analytics-endpoints.md`](analytics-endpoints.md)
- [`cracking-endpoints.md`](cracking-endpoints.md)
- [`operations-endpoints.md`](operations-endpoints.md)
- [`rawsniffer-endpoints.md`](rawsniffer-endpoints.md)
- [`map-endpoints.md`](map-endpoints.md)
- [`recon-endpoints.md`](recon-endpoints.md)
