# Features Guide

This section documents KOVIL MAP by operator journey instead of only by module name.

For the product-level mental model, read [Product Overview and Operator Mental Model](../00-GETTING_STARTED/product-overview.md).

## Collect and Import Evidence

| Feature | What it does |
|---|---|
| [Sync Remote](sync-remote.md) | pulls Pwnagotchi, Bruce, and M5Evil data through SSH/SFTP or WebUI flows |
| [Wardrive Import](wardrive-import.md) | loads WiGLE-like CSV sessions, route metadata, transport tags, and session inventory |
| [Raw Sniffer](raw-sniffer.md) | ingests Bruce and M5Evil RAW PCAPs for metadata, RAW Analysis, and hash preparation |
| [Spatial Normalization](spatial-normalization.md) | keeps dense GPS observations readable on the map without changing raw route data |

## Organize and Understand the Map

| Feature | What it does |
|---|---|
| [Tactical Analytics](tactical-analytics.md) | powers heatmaps, adaptive hotspots, opportunity scoring, and channel summaries |
| [TargetList & Favorites](targetlist-favorites.md) | separates mission targets from persistent revisit shortcuts |
| WarDrive regions and zones | connect route observations to administrative regions and zone overlays |
| Intelligence Zones | project Recon COMMS clusters back onto the Tactical Map |

## Analyze and Prioritize

| Feature | What it does |
|---|---|
| [Recon Center](recon-center.md) | unifies attack surface, INTEL, OPS, GEO, SIGINT, REPORT, and COMMS workflows |
| [Raw Sniffer](raw-sniffer.md) | adds EAPOL, PMKID, beacon, probe, and capture-quality evidence |
| [Tactical Analytics](tactical-analytics.md) | ranks opportunity and hotspot candidates for action |

## Crack and Validate

| Feature | What it does |
|---|---|
| [Cracking Engine](cracking-engine.md) | handles capture grouping, conversion, Hashcat, Aircrack-ng, PMK, WPS, history, and attack insight |
| [Batch Cracking](batch-cracking.md) | turns many targets into a single crackable work package |
| Combined candidates | merge eligible same-BSSID capture hashes without changing the default preferred-capture flow |
| Canonical RAW/WDRS hashes | turn RAW context into a visible `__wdrs__.22000` target when enough evidence exists |

## Demonstrate Safely

| Feature | What it does |
|---|---|
| [Demo Mode](../00-GETTING_STARTED/demo-mode.md) | temporarily swaps runtime data for synthetic `showcase-core-v5` data |
| Demo wordlists and UI seed | make screenshots, onboarding, targets, favorites, No-GPS, WarDrive, Recon, Raw Sniffer, and cracking flows non-empty |

## Which Path Should I Follow?

| Starting point | Recommended path |
|---|---|
| No devices yet | Demo Mode -> Tactical Map -> Workflows by Objective |
| Pwnagotchi, Bruce, or M5Evil | Sync Remote -> Tactical Map -> Recon Center or Cracking Operations |
| WarDrive CSV | Wardrive Import -> WarDrive Workspace -> Map zones |
| RAW PCAP | Raw Sniffer -> RAW context -> Cracking Operations |
| One locked network | Map or No-GPS -> Cracking Engine |
| Many locked networks | Targets -> Batch Cracking |
| Analysis-only task | Tactical Map -> Recon Center -> Intelligence Zones |

## Next Steps

1. Read [Product Overview and Operator Mental Model](../00-GETTING_STARTED/product-overview.md).
2. Pick a flow from [Workflows by Objective](../07-OPERATIONS/workflows-by-objective.md).
3. Open the feature page that matches the flow.
4. Use [Manual Import Layout](../00-GETTING_STARTED/manual-import-layout.md) when placing files by hand.
5. Use [API Reference](../05-API-ENDPOINTS/reference.md) when integrating or extending the backend.
