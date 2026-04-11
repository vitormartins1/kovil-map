# Operations Endpoints

This page groups the operational endpoints that support cracking workflows, runtime observability, and data quality checks outside the main map and recon surfaces.

## Jobs and History

- `GET /api/jobs`
- `GET /api/jobs/{job_id}`
- `PATCH /api/jobs/{job_id}`
- `GET /api/history`
- `DELETE /api/history`

`PATCH /api/jobs/{job_id}` currently supports canceling a running job via `status=canceled`.

## Readiness, Quality, and Data Health

- `GET /api/data-health/summary`
- `GET /api/insights/score`
- `GET /api/insights/attack-recommendation`
- `GET /api/insights/handshake-readiness`
- `GET /api/insights/quality-gate`

These routes help the UI explain why a target is or is not ready for follow-up actions.

## Fingerprint and Support Analysis

- `POST /api/fingerprint/extract`
- `GET /api/fingerprint/details`

These endpoints bridge raw capture evidence into normalized detail payloads used across cracking and recon screens.

## PMK and WPS

- `GET /api/pmk/databases`
- `GET /api/pmk/databases/{db_name}/stats`
- `POST /api/pmk/build`
- `POST /api/pmk/attack`
- `DELETE /api/pmk/databases/{db_name}`
- `POST /api/wps/attack`

## Notes

- most write operations here trigger local jobs or filesystem changes
- contributors should document new operational routes in this section or the dedicated feature docs
- all runtime artifacts produced by these flows should remain local and out of tracked repository state
