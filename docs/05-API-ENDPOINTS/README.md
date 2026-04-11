# API Endpoints

This section documents the REST and WebSocket surface exposed by the local FastAPI backend.

## Documentation Sections

### [Reference](reference.md)

High-level router inventory and current platform notes.

### [Config & Runtime Endpoints](config-runtime-endpoints.md)

Configuration reads/writes, health checks, and runtime catalog helpers.

### [Map Endpoints](map-endpoints.md)

Map data, zones, vendors, and tactical overlays.

### [Cracking Endpoints](cracking-endpoints.md)

Handshake discovery, conversion, fingerprint extraction, cracking jobs, hybrid RAW preparation, and batch helpers.

### [Sync Endpoints](sync-endpoints.md)

Remote sync, config reads/writes, and related runtime events.

### [RawSniffer Endpoints](rawsniffer-endpoints.md)

RAW file listing, metadata extraction, generated hash listing, and RAW file deletion.

### [Analytics Endpoints](analytics-endpoints.md)

Heatmaps, hotspots, and channel summaries.

### [Recon Endpoints](recon-endpoints.md)

Recon Center data models, snapshots, attack planning, probe intelligence, and COMMS views.

### [Operations Endpoints](operations-endpoints.md)

Jobs, history, quality/readiness, PMK, WPS, fingerprint, and maintenance-oriented helpers.

### [WebSocket Events](websocket-events.md)

Realtime job, sync, and data-refresh events.

## Response Envelope

Successful responses use the shared `ok(data)` format:

```json
{
  "status": "success",
  "data": {}
}
```

Error responses are normalized through the backend exception handlers:

```json
{
  "status": "error",
  "error": {
    "message": "Not found"
  }
}
```

## Authentication

KOVIL MAP does not use a JWT login flow.

Auth is local-runtime oriented:

- HTTP: `X-KOVIL-Token` or `Authorization: Bearer ...`
- WebSocket: token via headers or query param
- packaged runtime expects local token auth by default
- development can enable it with `KOVIL_API_TOKEN` or `KOVIL_REQUIRE_API_TOKEN=1`

## Base URLs

| Surface | URL |
| --- | --- |
| REST | `http://127.0.0.1:8000/api` |
| Swagger UI | `http://127.0.0.1:8000/docs` |
| WebSocket | `ws://127.0.0.1:8000/ws` |

## Recommended Reading Order

1. Start with [reference.md](reference.md).
2. Read the feature-specific router docs you actually use.
3. Check [websocket-events.md](websocket-events.md) for realtime behavior.
4. Cross-reference [docs/07-OPERATIONS](../07-OPERATIONS/README.md) for practical workflows.
