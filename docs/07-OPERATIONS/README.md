# Operations Guide

This section explains the main operational workflows in KOVIL MAP.

## Operational Guides

### [Workflows by Objective](workflows-by-objective.md)

- start from a goal instead of a module name
- choose the shortest path through demo data, sync, map, Recon, WarDrive, Raw Sniffer, No-GPS, batch, and cracking flows

### [Map Operations](map-operations.md)

- navigate the map
- filter networks
- inspect popups, zones, overlays, targets, favorites, and workspace handoffs

### [Cracking Workflow](cracking-workflow.md)

- select a network
- inspect capture artifacts
- choose an attack mode or helper flow
- track progress and results

### [Remote Sync How-To](remote-sync-howto.md)

- configure SSH sync
- pull data from remote devices
- manage Pwnagotchi, M5Evil Cardputer, and Bruce profiles
- handle sync conflicts

### [Batch Cracking How-To](batch-cracking-howto.md)

- create batch work packages
- review batch manifests
- run batch cracking through Cracking Operations

### [Troubleshooting](troubleshooting.md)

- common issues
- logs and debug mode
- performance tuning

---

## Typical Workflows

### Live pentesting with a Pwnagotchi

1. Start the Pwnagotchi in the field.
2. Connect over SSH.
3. Open KOVIL MAP.
4. Sync remote handshakes.
5. Select priority targets.
6. Queue cracking jobs.
7. Watch results in real time.

### Post-run WarDrive review with a WiGLE-like CSV

1. Download or export a WiGLE CSV.
2. Open KOVIL MAP.
3. Import the CSV and let spatial normalization run.
4. Review the clusters on the map.
5. Open the WarDrive workspace for replay, active-region context, and session tags.
6. Move interesting locked networks into Targets.
7. Create a batch job or return to Recon Center for analysis.

### Pulling from an M5Evil Cardputer

1. Enable the `M5EVIL ADMIN WEBUI` profile in Settings.
2. Apply the Cardputer preset or adjust host, auth, and SD paths manually.
3. Click `Sync`.
4. Review imported handshakes and Wardrive CSVs.
5. Continue from Cracking Operations or the WarDrive workspace.

### Pulling from Bruce WebUI

1. Enable the `BRUCE WEBUI` profile in Settings.
2. Confirm host, port, and credentials.
3. Use `TEST CONNECTION` in `DEVICE SYNC`.
4. Click `Sync`.
5. Review imported handshakes, RAW captures, and Wardrive CSVs.

### Data analysis

1. Import multiple sources.
2. Apply filters.
3. Review the Tactical Map and move into Recon Center.
4. Export or summarize the resulting findings.

---

## Performance Tips

- many networks: use spatial normalization
- slow cracking: check the GPU and workload profile
- slow sync: check bandwidth and file sizes
- hot device: reduce the Pwnagotchi duty cycle

---

## Ethics

Use the tool only on networks you own or are explicitly authorized to test. See the Security section for policy details.
