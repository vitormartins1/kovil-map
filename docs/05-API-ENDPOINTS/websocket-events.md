# WebSocket Events

KOVIL MAP uses WebSockets for real-time updates so the frontend can react to long-running jobs and data changes without polling.

## Connection

```text
ws://127.0.0.1:8000/ws
```

If `KOVIL_API_TOKEN` is enabled, pass the token in the query string:

```text
ws://127.0.0.1:8000/ws?token=YOUR_TOKEN
```

---

## Server-to-Client Events

All messages are JSON objects with at least a `type` field.

### `job_progress`

Progress updates for cracking, sync, or RAW extraction jobs.

### `job_update`

Emitted when a job changes state, for example from queued to running.

### `job_complete`

Emitted when a job finishes successfully or fails.

### `data_update`

Emitted when on-disk data changes and the map or lists should refresh.
