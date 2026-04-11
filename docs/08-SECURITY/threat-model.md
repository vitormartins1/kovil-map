# Threat Model

This document describes the threat model for KOVIL MAP using STRIDE as the baseline.

## Architecture and Trust Boundaries

KOVIL MAP runs as a local client-server application: the frontend and backend live on the user machine but in separate processes.

Components:

1. Electron frontend
2. Python/FastAPI backend
3. local filesystem
4. remote devices reached over SSH

Trust boundaries:

- renderer to backend over localhost HTTP/WebSocket
- backend to the OS when launching tools
- backend to remote devices over SSH
- filesystem to app when importing CSV and PCAP files

## Critical Assets

| Asset | Risk |
|---|---|
| SSH credentials | theft via local malware or XSS/RCE |
| host integrity | remote code execution |
| network data | leakage or exfiltration |
| local API | unauthorized cracking or control |

## STRIDE Summary

- **Spoofing:** mitigate with localhost binding, optional API token, and restricted CORS
- **Tampering:** validate imports and use `shell=False`
- **Repudiation:** local logs and job history provide traceability
- **Information disclosure:** keep secrets out of logs and protect config files
- **Denial of service:** limit concurrency and validate file sizes
- **Elevation of privilege:** harden Electron and avoid command injection

## Main Attack Surfaces

- parsing imported `.pcap`, `.csv`, and `.json` files
- launching external tools such as Hashcat and Aircrack
- SSH synchronization with remote devices

## Residual Risk

| Risk | Level | Mitigation |
|---|---|---|
| XSS in the frontend | high | CSP, sanitization, code review |
| command injection | medium | `shell=False` and tests |
| local credential theft | medium | hide secrets and warn users |
| malformed-file crashes | low | robust exception handling |

## User Recommendations

1. Do not run the app as root or Administrator.
2. Only import wardrive data from trusted sources.
3. Do not expose the backend on public networks without authentication.
4. Keep Hashcat and GPU drivers updated.

## Hardening Status

- frontend sandbox: enabled
- context isolation: enabled
- anti-shell injection: implemented
- path traversal checks: implemented
- SSH host verification: available
