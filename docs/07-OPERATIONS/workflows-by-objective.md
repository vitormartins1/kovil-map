# Workflows by Objective

This page helps you start from a concrete goal instead of from a feature name.

## Quick Selector

| Objective | Start here |
|---|---|
| Pull data from a remote device and triage targets | [Remote Sync How-To](remote-sync-howto.md) + Tactical Map + Recon Center |
| Review a wardrive route or CSV session | Tactical Map + WarDrive Workspace |
| Turn captures into crack-ready material | Raw Sniffer + Cracking Workflow |
| Investigate suspicious activity inside captures | Recon Center |
| Run a focused cracking campaign | Tactical Map + Cracking Workflow + Batch |

## 1. Sync Remote Data and Triage Targets

Use this when your starting point is a Pwnagotchi, Bruce, or M5Evil device.

1. Configure the device connection in Settings.
2. Run `Sync`.
3. Confirm the new data appears on the Tactical Map and in the supporting panels.
4. Review interesting networks from popups, Targets, or Favorites.
5. Pivot into Recon Center for deeper target intelligence when needed.

Recommended docs:

- [Remote Sync How-To](remote-sync-howto.md)
- [First Run Guide](../00-GETTING_STARTED/first-run.md)
- [Recon Center](../02-FEATURES/recon-center.md)

## 2. Review a Wardrive Route

Use this when your starting point is a wardrive CSV or an imported route history.

1. Import or sync wardrive CSV data.
2. Start on the Tactical Map to verify route-derived network coverage.
3. Open `WARDRIVE` to inspect the session hierarchy.
4. Replay the route, inspect the active region, and compare the resulting inventory.
5. Return to the map when you want to compare wardrive-derived context with the broader dataset.

Recommended docs:

- [Map Operations](map-operations.md)
- [Wardrive Import](../02-FEATURES/wardrive-import.md)

## 3. Turn Captures into Crack-Ready Artifacts

Use this when your starting point is handshakes, RAW captures, or mixed capture folders.

1. Import or sync the raw materials.
2. Use `SNIFFER` when you need RAW metadata, file review, or generated artifact preparation.
3. Use cracking operations for HCX conversion, Aircrack, Hashcat, or batch execution.
4. Track long-running jobs in `PROCESSES`.
5. Re-check the selected network on the map or in Recon after results land.

Recommended docs:

- [Cracking Workflow](cracking-workflow.md)
- [Raw Sniffer](../02-FEATURES/raw-sniffer.md)
- [Cracking Engine](../02-FEATURES/cracking-engine.md)

## 4. Investigate Captured Activity

Use this when your goal is analysis rather than immediate cracking.

1. Load the dataset and start on the Tactical Map for initial context.
2. Open `RECON`.
3. Use `SURFACE` and `INTEL` for target posture and threat context.
4. Use `SIGINT` for probe-request analysis.
5. Use `COMMS` and `GEO` for relationship and geospatial context.
6. Use `REPORT` when you want a more audit-style summary.

Recommended docs:

- [Recon Center](../02-FEATURES/recon-center.md)
- [Map Operations](map-operations.md)
- [Tactical Analytics](../02-FEATURES/tactical-analytics.md)

## 5. Run a Focused Cracking Campaign

Use this when your goal is execution across one or many high-priority targets.

1. Prioritize targets on the map or from Recon Center.
2. Open cracking operations for a single target, or `BATCH` for a grouped campaign.
3. Choose strategy, wordlist, and any PMK/WPS path if applicable.
4. Monitor progress in `PROCESSES`.
5. Revisit the map, targets, and history once results complete.

Recommended docs:

- [Cracking Workflow](cracking-workflow.md)
- [Batch Cracking How-To](batch-cracking-howto.md)
- [TargetList & Favorites](../02-FEATURES/targetlist-favorites.md)
