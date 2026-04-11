# System Architecture

This section explains how KOVIL MAP is built today: a local FastAPI backend, an Electron frontend, a Leaflet-based map, and file-backed operational data.

## Core Documents

- [`system-design.md`](system-design.md)
- [`data-flow.md`](data-flow.md)
- [`api-overview.md`](api-overview.md)
- [`frontend-structure.md`](frontend-structure.md)

## One-Screen Mental Model

```text
Electron shell
  -> sandboxed renderer (vanilla JS modules)
  -> talks to local FastAPI via HTTP + WebSocket
  -> renders map, workspaces, popups, and operational panels

FastAPI backend
  -> loads local data from backend/data/
  -> enriches and merges Wi-Fi records
  -> orchestrates jobs and external tools
  -> emits runtime updates over WebSocket
```

## Key Architectural Decisions

- local-first and file-backed instead of DB-centric
- Electron security hardening with preload bridge and sandboxed renderer
- service-oriented backend modules for cracking, analytics, RAW, sync, and WarDrive
- workspace-driven frontend UX for Recon Center, WarDrive, and Sniffer flows, with the tactical map as the default cockpit
- progressive modularization of large frontend workspaces through feature-local helper modules
