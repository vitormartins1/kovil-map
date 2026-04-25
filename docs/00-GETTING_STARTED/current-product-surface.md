# Current Product Surface

This page is the operator-facing reference for KOVIL MAP's current screens, workspaces, and supporting panels.

For the higher-level mental model, start with [Product Overview and Operator Mental Model](product-overview.md).

## Default Cockpit

KOVIL MAP opens on the **Tactical Map**. This is the main cockpit for inspecting networks, zones, target lists, popups, and status counters.

The map is where most workflows begin and end:

- imported and synced data becomes map state
- workspace outputs return as overlays, side-panel entries, or cracking artifacts
- network popups provide quick pivots into Recon, Cracking Operations, Targets, and Favorites

## View Switcher

The top-right view switcher exposes the current primary surfaces:

| Button | Surface | Use it for |
|---|---|---|
| `MAP` | Tactical Map | consolidated network view, popups, zones, targets, favorites, and map overlays |
| `NO-GPS` | No-GPS workspace | evidence-backed networks that do not yet have usable coordinates |
| `BATCH` | Batch workspace | creating and reviewing multi-target cracking work packages |
| `RECON` | Recon Center | attack surface, SIGINT, COMMS, GEO, OPS, reporting, and intelligence zones |
| `WARDRIVE` | WarDrive Workspace | CSV sessions, route replay, active region, zones, session tags, and map inventory |
| `SNIFFER` | Raw Sniffer | RAW PCAP inventory, metadata extraction, RAW Analysis, and generated RAW hashes |

## Supporting Panels

Supporting panels connect the map and workspaces:

| Panel | Purpose |
|---|---|
| `ZONES` | conquered, to-conquer, discovered, and intelligence overlays |
| `TARGETS` | temporary mission list for networks to inspect, crack, or batch |
| `FAVORITES` | persistent shortlist of networks or places worth revisiting |
| `CRACKING OPERATIONS` | artifact-aware controls for PCAP, RAW PCAP, `.22000`, `.details`, combined, batch, and history files |
| `PROCESSES` | visual progress for sync, imports, scans, RAW analysis, conversion, cracking, and batch jobs |
| `LOGS` | local operational feedback and troubleshooting context |

## Status Counters

Map and workspace counters use normalized network state:

- `OPEN`: open or weakly-open networks
- `LOCKED`: GPS-backed encrypted networks with usable cracking artifacts
- `NO-GPS LOCKED`: encrypted networks with artifacts but without usable coordinates
- `WARDRIVE`: networks observed through route/session data
- `PWNED` or `CRACKED`: networks with recovered credentials
- `NOT READY`: partial evidence that can be inspected but is not fully attack-ready

## Common Handoffs

- Map popup -> Cracking Operations for single-network cracking.
- Map popup -> Recon Center for target intelligence and attack surface.
- WarDrive session -> Tactical Map for route-derived context and zones.
- Raw Sniffer item -> Cracking Operations for RAW details, hash generation, or canonical hybrid preparation.
- Targets -> Batch for multi-network cracking packages.
- Recon COMMS -> Intelligence Zones on the map.

## Terminology Notes

- `Recon Center` is the current user-facing intelligence workspace.
- `Tactical Analytics` is still the backend/domain name for heatmaps, hotspots, opportunity scoring, and channel summaries.
- `analytics` may appear in API paths, module names, or state keys because those are implementation details, not a separate top-level screen.

## Where to Go Next

- [Product Overview and Operator Mental Model](product-overview.md)
- [First Run Guide](first-run.md)
- [Runtime Modes](runtime-modes.md)
- [Map Operations](../07-OPERATIONS/map-operations.md)
- [Workflows by Objective](../07-OPERATIONS/workflows-by-objective.md)
