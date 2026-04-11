# API Architecture & Overview

The KOVIL MAP backend exposes a local-first REST API built with FastAPI. It acts as the control plane for the desktop app, covering map rendering data, cracking workflows, RAW enrichment, analytics, WarDrive operations, and background job orchestration.

## Design Goals

- local operation first, with the backend bound to `127.0.0.1`
- explicit router families for each product area
- background-job execution for long-running work
- normalized response envelopes for frontend consumption
- safe subprocess execution and validated file access

## Base URL

```text
http://127.0.0.1:8000/api
```

## Authentication Model

The API is still designed for local desktop use, but auth behavior is no longer fully open by default in every environment.

- packaged runtime expects local token auth
- development can enable the same behavior with `KOVIL_API_TOKEN` or `KOVIL_REQUIRE_API_TOKEN=1`
- HTTP requests can send `X-KOVIL-Token` or `Authorization: Bearer ...`
- WebSocket connections can pass the token in headers or query params

## Response Shape

Successful responses use the `ok(data)` envelope:

```json
{
  "status": "success",
  "data": {}
}
```

Errors are normalized through the shared exception handlers:

```json
{
  "status": "error",
  "error": {
    "message": "Handshake file not found"
  }
}
```

## Main API Domains

### Map and spatial data

- `GET /api/map/data`
- `POST /api/zones`
- `POST /api/zones/to-conquer`
- `GET /api/vendors/{mac}`

This domain feeds the tactical map, popups, clustering, and derived spatial overlays.

### Handshakes and cracking

- `GET /api/handshakes/{mac}/files`
- `GET /api/handshakes/{mac}/set`
- `POST /api/convert/hcx`
- `POST /api/hashcat/jobs`
- `POST /api/aircrack/jobs`
- `POST /api/fingerprint/extract`

Handshake operations now support a handshake-set model keyed by BSSID/MAC. Conversion, fingerprint extraction, and Aircrack flows can target either a legacy `filename` or a capture-specific `capture_id`.

### RAW and enrichment

- `GET /api/rawsniffer/files`
- `DELETE /api/rawsniffer/files/{filename}`
- `GET /api/rawsniffer/metadata`
- `POST /api/rawsniffer/extract`
- `POST /api/rawsniffer/analyze`
- `GET /api/rawsniffer/analysis/{raw_item_id}`
- `GET /api/handshakes/{mac}/raw-context`

These routes cover file-centric RAW processing, capture-wide RAW analysis, and BSSID-centric hybrid preparation.

### WarDrive and analytics

- `GET /api/wardrive/hierarchy`
- `GET /api/wardrive/inventory`
- `GET /api/wardrive/sessions`
- `POST /api/wardrive/sessions/tracks`
- `GET /api/analytics/heatmap`
- `GET /api/analytics/hotspots`
- `GET /api/analytics/channel-summary`

### Config and system runtime

- `GET /api/config`
- `PUT /api/config`
- `GET /api/jobs`
- `GET /api/history`
- `WS /ws`

`GET /api/config` returns a sanitized client payload. Sensitive fields such as `pwn_pass` are not echoed back to the renderer; instead, the UI receives `pwn_pass_configured`.

## Background Job Pattern

Long-running operations do not block the request/response cycle.

Typical flow:

1. The frontend starts a job via HTTP.
2. The backend validates input and schedules work through the Job Manager.
3. The process runs in the background.
4. The frontend receives `job_update` / `job_complete` events over WebSocket.
5. The UI refreshes only the affected panels or datasets.

This pattern is used by cracking, RAW extraction, sync-related post-processing, and other heavy operations.

## Interactive API Docs

When the backend is running locally, Swagger UI is available at:

```text
http://127.0.0.1:8000/docs
```

## Related Docs

- [`reference.md`](../05-API-ENDPOINTS/reference.md)
- [`cracking-endpoints.md`](../05-API-ENDPOINTS/cracking-endpoints.md)
- [`sync-endpoints.md`](../05-API-ENDPOINTS/sync-endpoints.md)
- [`data-flow.md`](data-flow.md)
