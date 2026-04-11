# Technical Hardening

This document describes the defensive hardening used in KOVIL MAP.

The app follows a defense-in-depth approach.

## Frontend Hardening

- `contextIsolation: true`
- `nodeIntegration: false`
- `sandbox: true`
- communication with the OS only through the preload bridge
- restrictive CSP
- renderer runtime assets are vendored locally; remote CDN JavaScript is not executed by default
- API token transport is handled by the preload bridge instead of exposing the raw token to renderer modules
- `textContent` preferred over `innerHTML`

## Backend Hardening

- external commands are executed with `shell=False`
- command arguments are passed as lists
- Pydantic validation is strict
- the backend binds to `127.0.0.1` by default
- file paths are checked against allowed directories
- `GET /api/config` returns a sanitized client payload and does not echo `pwn_pass`
- packaged runtime expects local token auth instead of leaving the API open by default

## SSH Hardening

- SSH host key verification is supported
- SFTP is used instead of arbitrary remote shell execution

## Protected Mode

Auth behavior is now:

1. packaged runtime enables local API auth by default
2. development can enable the same behavior with `KOVIL_API_TOKEN` or `KOVIL_REQUIRE_API_TOKEN=1`
3. HTTP requests use `X-KOVIL-Token` or `Authorization: Bearer ...`
4. WebSocket connections can pass the token in query params or headers
5. `KOVIL_ALLOW_INSECURE_NO_AUTH=1` is an explicit dev-only override when you intentionally want no auth

## CORS

- packaged runtime keeps localhost browser CORS disabled unless `KOVIL_ALLOW_LOCALHOST_CORS=1`
- development keeps localhost/browser flows available for normal local tooling

## Contributor Checklist

- never use `shell=True`
- never render raw HTML from untrusted data
- validate file paths
- never commit secrets
- avoid large or unmaintained dependencies

## Reporting Issues

Do not open public issues for security problems. Use the vulnerability disclosure process instead.

---
