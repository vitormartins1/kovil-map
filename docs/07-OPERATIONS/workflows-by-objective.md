# Workflows by Objective

This page helps operators start from a concrete goal instead of from a feature name.

## Quick Selector

| Objective | Start here |
|---|---|
| Try the app safely without devices | Demo Mode -> Tactical Map -> Workflows below |
| Pull data from a remote device and triage targets | Remote Sync -> Tactical Map -> Recon Center |
| Review a WarDrive route or CSV session | Tactical Map -> WarDrive Workspace -> Zones |
| Turn RAW captures into crack-ready material | Raw Sniffer -> Cracking Operations |
| Crack one high-priority target | Tactical Map or No-GPS -> Cracking Operations |
| Crack many targets efficiently | Targets -> Batch -> Cracking Operations |
| Investigate captured activity | Recon Center -> SIGINT / INTEL / COMMS |
| Clean up non-geolocated evidence | No-GPS -> Cracking Operations -> Map |

## 1. Explore with Demo Data

Use this when you want screenshots, onboarding, or a safe tour without field data.

1. Open `System Settings`.
2. Go to `Maintenance`.
3. Click `INSTALL DEMO DATA`.
4. Start on the Tactical Map and inspect the status counters, zones, targets, and popups.
5. Open `WARDRIVE` to replay the synthetic Rio sessions.
6. Open `RECON` to inspect COMMS, SIGINT, GEO, OPS, and report views.
7. Open `SNIFFER` and Cracking Operations to inspect RAW and handshake artifacts.
8. Remove demo data from `Maintenance` when finished.

Recommended docs:

- [Demo Mode](../00-GETTING_STARTED/demo-mode.md)
- [Product Overview](../00-GETTING_STARTED/product-overview.md)
- [Current Product Surface](../00-GETTING_STARTED/current-product-surface.md)

## 2. Sync Remote Data and Triage Targets

Use this when your starting point is a Pwnagotchi, Bruce, or M5Evil device.

1. Configure device connection settings.
2. Run `Sync`.
3. Watch the device-specific Process entries for handshake, RAW, and WarDrive downloads.
4. Confirm the new data appears on the Tactical Map and in supporting panels.
5. Use popups, Targets, Favorites, and zone views to triage the most relevant networks.
6. Pivot into Recon Center for deeper context when needed.

Recommended docs:

- [Remote Sync How-To](remote-sync-howto.md)
- [Sync Remote](../02-FEATURES/sync-remote.md)
- [First Run Guide](../00-GETTING_STARTED/first-run.md)

## 3. Review a WarDrive Route

Use this when your starting point is a WiGLE-like CSV, Bruce Wardrive export, M5Evil Wardrive export, or imported route history.

1. Import or sync the CSV session.
2. Start on the Tactical Map to verify route-derived coverage.
3. Open `WARDRIVE`.
4. Select one or more sessions.
5. Use route replay, active region, transport tags, region hierarchy, and zones to inspect the route.
6. Use `FOCUS TRACK` when you need the full route in view.
7. Return to `MAP` when you want to compare route context with locked/cracked/open state.

Recommended docs:

- [WarDrive Import](../02-FEATURES/wardrive-import.md)
- [Map Operations](map-operations.md)
- [Spatial Normalization](../02-FEATURES/spatial-normalization.md)

## 4. Turn RAW Captures into Crack-Ready Artifacts

Use this when your starting point is Bruce RAW, M5Evil RawSniffer, or M5Evil Master Sniffer PCAPs.

1. Import or sync RAW PCAPs.
2. Open `SNIFFER`.
3. Extract metadata for pending files and review cache status.
4. Select a network with RAW context from the map or Cracking Operations.
5. Use RAW PCAP actions to extract details, generate a hash, or build the canonical WDRS hash.
6. Use the generated `.22000` or canonical `__wdrs__.22000` in Cracking Operations.
7. Track extraction, analysis, and cracking progress in `PROCESSES`.

Recommended docs:

- [Raw Sniffer](../02-FEATURES/raw-sniffer.md)
- [Cracking Engine](../02-FEATURES/cracking-engine.md)
- [Cracking Workflow](cracking-workflow.md)

## 5. Crack One High-Priority Target

Use this when one network is worth focused attention.

1. Select the network from a map popup, No-GPS entry, target list, or RAW context.
2. Open Cracking Operations.
3. Review capture quality, source grouping, details, attack insight, and history.
4. Convert PCAP to `.22000` if needed.
5. Choose Aircrack, Hashcat, PMK, WPS, mask, rule, straight, combinator, or association strategy.
6. Start the job and monitor progress in `PROCESSES`.
7. Revisit the map popup, target entry, and history after results land.

Recommended docs:

- [Cracking Workflow](cracking-workflow.md)
- [Cracking Engine](../02-FEATURES/cracking-engine.md)
- [Hashcat Integration](../04-INTEGRATIONS/hashcat.md)

## 6. Run a Batch Cracking Campaign

Use this when you have many viable targets and want to avoid launching the cracking engine once per network.

1. Use map popups, zones, Recon, or No-GPS to add networks to `TARGETS`.
2. Open `BATCH`.
3. Filter candidates by source, status, location, and artifact readiness.
4. Generate a batch package.
5. Review the batch manifest and quality summary.
6. Run the batch in Cracking Operations.
7. Let results distribute back to source artifacts, map state, and history.

Recommended docs:

- [Batch Cracking](../02-FEATURES/batch-cracking.md)
- [Batch Cracking How-To](batch-cracking-howto.md)
- [TargetList & Favorites](../02-FEATURES/targetlist-favorites.md)

## 7. Investigate Captured Activity

Use this when the goal is intelligence rather than immediate cracking.

1. Load the dataset and start on the Tactical Map.
2. Open `RECON`.
3. Use `SURFACE` for target posture and kill-chain staging.
4. Use `INTEL` for vulnerability matrix and deep packet threat analysis.
5. Use `SIGINT` for probe-request intelligence and likely device grouping.
6. Use `COMMS` and `GEO` for relationship and geospatial context.
7. Use `REPORT` when you need an audit-style summary.
8. Project relevant findings back to map overlays and Intelligence Zones.

Recommended docs:

- [Recon Center](../02-FEATURES/recon-center.md)
- [Tactical Analytics](../02-FEATURES/tactical-analytics.md)
- [Map Operations](map-operations.md)

## 8. Clean Up No-GPS Evidence

Use this when captures exist but the networks do not yet have coordinates.

1. Open `NO-GPS`.
2. Filter by source, status, artifact presence, SSID, or MAC.
3. Inspect locked and cracked entries separately.
4. Open Cracking Operations for usable captures.
5. Add important entries to Targets or Favorites.
6. Later, use WarDrive or GPS sidecars to connect the evidence back to map context when available.

Recommended docs:

- [Current Product Surface](../00-GETTING_STARTED/current-product-surface.md)
- [Cracking Workflow](cracking-workflow.md)
- [Manual Import Layout](../00-GETTING_STARTED/manual-import-layout.md)
