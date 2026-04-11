# Config & Runtime Endpoints

This page documents the small but important runtime endpoints that external contributors and operators usually touch first.

## Health

### `GET /`

Simple root health response used by lightweight probes and packaged runtime boot checks.

### `GET /api/health`

Canonical API health endpoint for frontend boot and smoke tests.

## Configuration

### `GET /api/config`

Returns the sanitized desktop configuration payload.

Key behavior:

- secrets such as `pwn_pass`, `m5_web_password`, and `bruce_web_password` are not returned directly
- the client receives `*_configured` flags instead
- values come from `backend/config.json`

### `PUT /api/config`

Updates configuration values through the validated schema.

Typical use cases:

- tool paths
- sync profiles
- UI theme and workspace preferences
- local security-related settings such as known-hosts path

## Catalog Helpers

These routes are small read models used across the UI and public docs:

- `GET /api/vendors/{mac}`
- `GET /api/wordlists/custom`

## Notes

- the repository ships with a sanitized `backend/config.json`
- local contributors should not commit personal config changes
- when auth is enabled, use `X-KOVIL-Token` or `Authorization: Bearer ...`
