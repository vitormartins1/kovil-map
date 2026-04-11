# Features Guide

This section documents the core features of KOVIL MAP.

## Available Features

### 1. [Spatial Normalization](spatial-normalization.md)
Smart GPS coordinate normalization.

- visual separation for networks that share the same location
- deterministic jitter so repeated loads stay stable
- support for wardrive CSV imports
- tunable spread settings

### 2. [Wardrive Import](wardrive-import.md)
WiGLE and wardriving data import.

- WiGLE CSV support
- automatic deduplication
- spatial normalization applied on import
- designed for large datasets
- replay controls with compare mode, camera follow, timing modes, and configurable pace/zoom
- large-session workspace shell with Replay Dock, Active Region, Workspace Explorer, and skeleton loading

### 3. [Cracking Engine](cracking-engine.md)
Integrated cracking engine.

- Hashcat integration
- Aircrack-ng integration
- dictionary attacks
- masks, rules, and incremental strategies
- handshake sets across Pwnagotchi, Brucegotchi, and M5Evil with quality scoring, combined candidates, and source-aware accordions

### 4. [Batch Cracking](batch-cracking.md)
Batch attacks across many networks.

- queueing and orchestration
- progress tracking
- prioritization
- resume on failure

### 5. [Raw Sniffer](raw-sniffer.md)
Raw capture ingestion and enrichment.

- live capture or PCAP parsing
- source-aware Bruce and M5Evil RAW integration
- separate semantics for M5Evil RAW Sniffer and M5Evil Master Sniffer captures
- network-scoped RAW details for one selected BSSID
- capture-wide RAW Analysis reports
- canonical WDRS hash preparation
- delete flow for selected RAW captures and their generated sidecars

### 6. [Sync Remote](sync-remote.md)
Remote synchronization with mixed transports.

- SSH/SFTP and WebUI transports
- automatic updates
- per-target host-key trust
- one-click sync for Pwnagotchi, M5Evil Cardputer, and Bruce
- Wardrive CSV ingest for M5Evil Cardputer and Bruce

### 7. [TargetList & Favorites](targetlist-favorites.md)
Operational prioritization for networks.

- favorite networks
- target lists
- priority scores
- tags and annotations

### 8. [Tactical Analytics](tactical-analytics.md)
Geospatial intelligence and tactical analysis.

- heatmaps and adaptive hotspots
- opportunity scoring
- channel intelligence
- multidimensional filtering

### 9. [Recon Center](recon-center.md)
Unified offensive intelligence workspace.

- PMKID optimizer with hash type classification
- COMMS intelligence with relationship graph, device fingerprints, and Cluster Intelligence
- cache-first lazy loading per tab, per section, and per selected target
- richer COMMS cards with security/origin/device mini-bars and a full-width Communication Graph
- Intelligence Zones projected from COMMS clusters back onto the tactical map
- probe request intelligence (SIGINT) with Likely Device Groups and Probe Geocorrelation
- advanced packet analysis with deauth/disassoc threat detection
- severity filter chips for Intel vulnerability flags
- Attack Planner with backend wordlist selection in OPS
- PMK database for accelerated cracking
- WPS PIN brute-force with Pixie Dust support
- reusable hints/tooltips for intelligence metrics and cards
- drawer-based Target Details where applicable and full-width tabs elsewhere

---

## Which Feature Should I Use?

| Use case | Feature |
|---|---|
| "Networks are clustered together on the map" | Spatial Normalization |
| "I want to import WiGLE data" | Wardrive Import |
| "I have a handshake and want to crack it" | Cracking Engine |
| "I want to attack 100 networks at once" | Batch Cracking |
| "I have data from my ESP32" | Raw Sniffer |
| "I want data from a remote Pwnagotchi, M5Evil Cardputer, or Bruce" | Sync Remote |
| "I want to focus on specific networks" | TargetList & Favorites |
| "I want to understand attack patterns and hotspots" | Tactical Analytics |
| "I need to prioritize targets by opportunity" | Tactical Analytics |
| "I want to map my attack surface and find PMKID targets" | Recon Center |
| "I want to analyze probe requests from captures" | Recon Center (SIGINT) |
| "I want to detect deauth attacks in my PCAPs" | Recon Center (INTEL) |
| "I want to pre-compute PMK hashes for faster cracking" | Recon Center (PMK Database) |
| "I want to brute-force a WPS PIN" | Recon Center (WPS Attack) |

---

## Next Steps

1. Pick the feature that matches your workflow
2. Read its full documentation
3. If you think in tasks instead of modules, read [Workflows by Objective](../07-OPERATIONS/workflows-by-objective.md)
4. Browse examples in [06-CODE-EXAMPLES](../06-CODE-EXAMPLES/)
5. Check the operational guides in [07-OPERATIONS](../07-OPERATIONS/)

---

## Tip

Many features work well together:

- **Wardrive CSV** + **Spatial Normalization** = clear cluster visualization
- **Raw Sniffer** + **Batch Cracking** = a full pentest workflow
- **Sync Remote** + **Raw Sniffer** = near-real-time remote ingest with downstream RAW enrichment
