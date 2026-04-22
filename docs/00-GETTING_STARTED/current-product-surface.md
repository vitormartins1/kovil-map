# Current Product Surface

This page is the canonical reference for the current operator-facing names used in KOVIL MAP.

If you see older internal names such as `analytics` in code, state flags, or some technical docs, read them as implementation details, not as the current top-level UI naming.

![WarDrive workspace replaying a Rio de Janeiro session](../assets/screenshots/wardrive-sessions.gif)

## Default Cockpit

When KOVIL MAP opens, the default surface is the **Tactical Map**.

From there, operators can:

- inspect networks and clusters
- open popup intelligence and actions
- use side panels such as Zones, Targets, Favorites, Cracking, Processes, and Logs
- switch into dedicated workflows when needed

## Current View Switcher

The top-right view switcher currently exposes these context buttons:

- `MAP`
- `NO-GPS`
- `BATCH`
- `RECON`
- `WARDRIVE`
- `SNIFFER`

`MAP` is the default cockpit. `RECON`, `WARDRIVE`, and `SNIFFER` are the main specialized workspaces.

## Main Surfaces

| Surface | Purpose | Typical use |
|---|---|---|
| `Tactical Map` | main operational cockpit | review known networks, clusters, zones, targets, and popup actions |
| `Recon Center` | intelligence workspace | attack surface review, target intel, SIGINT, COMMS, GEO, OPS, reports |
| `WarDrive Workspace` | route/session workspace | inspect CSV sessions, replay tracks, review regions, compare route-derived inventory |
| `Raw Sniffer` | RAW capture workspace | inspect RAW captures, run metadata analysis, prepare crack-ready artifacts |
| `Batch` | multi-target execution workspace | organize and review batch cracking inputs |
| `No-GPS` | non-geolocated network workspace | inspect networks that exist without usable map coordinates |

## Supporting Panels

Outside the view switcher, KOVIL MAP also exposes supporting panels that remain important to the operator workflow:

- `ZONES`
- `TARGETS`
- `FAVORITES`
- `CRACKING OPERATIONS`
- `PROCESSES`
- `LOGS`

These panels support the Tactical Map and can be suspended or reshaped when a dedicated workspace takes over the center workflow.

## Terminology Notes

- `Recon Center` is the current user-facing intelligence workspace.
- `Tactical Analytics` still exists as a domain and backend/API layer.
- `analytics` may still appear in module names, DOM ids, state keys, and endpoint paths.
- Those legacy names do not mean there is still a separate top-level `Analytics` screen in the UI.

## Where to Go Next

- [First Run Guide](first-run.md)
- [Runtime Modes](runtime-modes.md)
- [Map Operations](../07-OPERATIONS/map-operations.md)
- [Workflows by Objective](../07-OPERATIONS/workflows-by-objective.md)
