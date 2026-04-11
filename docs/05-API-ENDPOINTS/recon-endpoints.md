# Recon Endpoints

Recon Center exposes the densest read-model surface in KOVIL MAP. These endpoints are optimized for tab-level hydration, cache-aware UI loading, and drill-down analysis.

## Core Recon Views

- `GET /api/recon/cache-manifest`
- `GET /api/recon/kill-chain`
- `GET /api/recon/kill-chain/summary`
- `GET /api/recon/kill-chain/stage`
- `GET /api/recon/vulnerability-matrix`
- `GET /api/recon/target-detail`
- `GET /api/recon/attack-effectiveness`
- `GET /api/recon/temporal-intel`
- `GET /api/recon/audit-report`

## Snapshots and Comparisons

- `POST /api/recon/kill-chain/snapshot`
- `GET /api/recon/kill-chain/history`
- `POST /api/recon/audit-report/snapshot`
- `GET /api/recon/audit-report/snapshots`
- `GET /api/recon/audit-report/compare`

These routes support historical views and lightweight comparison workflows. Snapshot artifacts are stored under the local runtime data root and should be treated as operator data, not as versioned repository content.

## Attack Planning

- `POST /api/recon/attack-plan`

Used by Recon Ops flows to transform target and strategy context into an actionable plan proposal.

## COMMS and Probe Intelligence

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

## Deep Analysis

- `GET /api/recon/deep-analysis`
- `GET /api/recon/deep-analysis/status`
- `POST /api/recon/deep-analysis/scan`
- `GET /api/recon/deep-analysis/pcap`

## Notes

- Recon responses are intentionally shaped for frontend workspaces rather than generic CRUD
- `cache-manifest` is the preferred lightweight freshness check before fetching heavier tabs
- `target-detail` is the preferred drill-down route for on-demand target hydration
