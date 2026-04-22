# Product Overview and Operator Mental Model

KOVIL MAP is a local-first desktop command center for Wi-Fi reconnaissance, WarDrive analysis, RAW/PCAP enrichment, and cracking workflows.

The app is designed around one operational loop:

```text
collect or import evidence
  -> normalize and enrich local data
  -> review the tactical map
  -> pivot into a focused workspace
  -> run analysis or cracking jobs
  -> return results to the map, zones, targets, and history
```

## What the Project Is For

Use KOVIL MAP when you need one local place to:

- ingest captures from Pwnagotchi, Bruce, M5Evil, manual folders, or WarDrive CSVs
- understand where networks were seen and how they relate spatially
- separate open, GPS-only, locked, not-ready, and cracked networks
- inspect RAW captures without flooding the map with every raw-only observation
- turn PCAPs into `.22000`, `.details`, `.try`, `.cracked`, and combined-candidate artifacts
- plan single-target or batch cracking campaigns
- keep long-running sync, scan, analysis, and cracking work visible in the Process panel
- demonstrate the product safely with the synthetic `showcase-core-v5` demo pack

## Main Data Types

| Data | Where it comes from | What it enables |
|---|---|---|
| Handshake PCAPs | Pwnagotchi, Bruce, M5Evil, manual imports | locked/no-GPS locked targets, HCX conversion, cracking, details extraction |
| WarDrive CSVs | WiGLE-like exports from devices or manual files | route replay, map coverage, regions, zones, transport tags, GPS-backed network context |
| RAW PCAPs | Bruce RAW, M5Evil RawSniffer, M5Evil Master Sniffer | EAPOL/beacon/probe metadata, RAW Analysis, canonical hybrid hash preparation |
| Derived sidecars | local tools and app workflows | `.details`, `.22000`, `.try`, `.cracked`, combined candidates, PMK/WPS helper state |
| Demo data | `showcase-core-v5` | safe screenshots, onboarding, realistic map/recon/cracking examples without field data |

## Main Workspaces

The Tactical Map is the default cockpit. It shows the consolidated network state, spatial overlays, popup actions, and handoffs into deeper workflows.

Dedicated workspaces take over when the operator needs a focused task:

- `NO-GPS` triages networks that have evidence but no usable coordinates.
- `BATCH` builds and reviews multi-target cracking work packages.
- `RECON` turns the dataset into attack surface, SIGINT, COMMS, GEO, OPS, and report views.
- `WARDRIVE` replays and compares CSV sessions, explores regions/zones, and manages route inventory.
- `SNIFFER` reviews RAW captures, metadata, generated RAW hashes, and RAW Analysis reports.

Supporting panels keep the workflow connected:

- `ZONES` exposes conquered, to-conquer, discovered, and intelligence zones.
- `TARGETS` is the mission list for networks you plan to inspect, attack, or batch.
- `FAVORITES` is the persistent shortlist for networks or places worth revisiting.
- `CRACKING OPERATIONS` is the artifact-aware action panel for selected files and networks.
- `PROCESSES` tracks long-running work such as sync, scans, conversion, cracking, and analysis.

## How the Flows Connect

The important design idea is that each workspace adds context back to the same local operational picture.

- Remote sync downloads files, reloads local state, and creates Process entries.
- WarDrive sessions add GPS context, transport tags, active regions, zones, and route inventory.
- RAW Sniffer adds radio evidence and crack-ready hybrid candidates for networks already known to the map.
- Recon Center adds prioritization, communication intelligence, SIGINT, threat analysis, and intelligence zones.
- Cracking Operations writes results back as sidecars, which update map status, popups, history, and batch views.
- Demo Mode temporarily replaces runtime data so all of the above can be explored safely.

## Network State Vocabulary

KOVIL MAP uses network states to keep map counters, popups, pickers, and cracking flows consistent.

| State | Meaning |
|---|---|
| `open` | open or weakly-open network; not a cracking target |
| `gps_only` | GPS-backed network with no usable cracking artifact |
| `locked` | GPS-backed encrypted network with usable cracking artifacts |
| `no_gps_locked` | non-geolocated encrypted network with usable cracking artifacts |
| `not_ready` | partial evidence exists, but it is not fully attack-ready |
| `cracked` | a password or cracked artifact is already present |

## Recommended Reading Paths

- New operator: [First Run Guide](first-run.md) -> [Workflows by Objective](../07-OPERATIONS/workflows-by-objective.md)
- Screenshot/demo user: [Demo Mode](demo-mode.md) -> [Current Product Surface](current-product-surface.md)
- Device user: [Remote Sync How-To](../07-OPERATIONS/remote-sync-howto.md) -> [Sync Remote](../02-FEATURES/sync-remote.md)
- WarDrive user: [WarDrive Import](../02-FEATURES/wardrive-import.md) -> [Map Operations](../07-OPERATIONS/map-operations.md)
- Cracking user: [Cracking Workflow](../07-OPERATIONS/cracking-workflow.md) -> [Cracking Engine](../02-FEATURES/cracking-engine.md)
- Developer: [Data Flow](../01-ARCHITECTURE/data-flow.md) -> [System Design](../01-ARCHITECTURE/system-design.md)
