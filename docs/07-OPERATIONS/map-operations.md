# Map Operations

The tactical map is the center of the application. It is where operators review networks, inspect metadata, jump into cracking, and move between workspaces.

## Core Navigation

- pan by dragging the map
- zoom with wheel or `+` / `-`
- click markers or clusters to inspect networks
- use workspace buttons on the top-right action group to switch contexts

## Current Top Action Model

The current view switcher keeps the tactical map as the default surface and exposes dedicated context buttons on the right:

- `NO-GPS`
- `BATCH`
- `RECON`
- `WARDRIVE`
- `SNIFFER`

`RECON`, `WARDRIVE`, and `SNIFFER` are the main specialized workspaces. Older internal IDs may still use `analytics` naming, but the current user-facing intelligence workspace is `RECON` / Recon Center.

When Recon, WarDrive, or Sniffer is active, the UI temporarily suspends or reshapes other panels so the selected workspace can own the center workflow cleanly.

The older user-facing `Locate Me` and `Export SSIDs` actions are no longer part of the current product flow.

## Layers and Overlays

Operators can still work with the classic map overlays:

- marker clustering
- heatmap
- conquered zones
- to-conquer zones
- discovered zones
- Intelligence Zones generated from Recon Center COMMS cluster analysis

WarDrive adds its own workspace-specific overlays on top of the same map surface. Recon Center contributes intelligence-driven map context such as Intelligence Zones.

### Intelligence Zones

- toggled from the top-left map action group
- sourced from Recon Center `COMMS -> Cluster Intelligence`
- rendered with the same polygon-generation style as the other zone layers
- allowed to overlap conquered, to-conquer, and discovered zones without subtraction
- listed in the left `ZONES` panel under `INTELLIGENCE`

## Popup Experience

Clicking a network opens a structured popup card instead of the older line-by-line dump.

### Popup sections

- header with SSID and state chips
- overview
- signal / capture
- security / fingerprint
- RAW summary
- access

### Header chips

Depending on the network state, the popup may show chips such as:

- `CRACKED`
- `HIDDEN`
- `LOCKED`
- `GPS ONLY`
- encryption/security chip (for example `WPA2`)
- `PCAP`
- `HANDSHAKE`

`PCAP` means a capture file exists. `HANDSHAKE` means the hash-ready state exists for cracking purposes.

### Popup actions

The popup preserves the current action model:

- toggle favorite
- toggle target when the network is eligible
- open Cracking Operations
- toggle password visibility when the network is already cracked

Wardrive-only / GPS-only networks do not show the access section used for cracking.

## Workspace Expectations

### Recon Center

- opens as the current intelligence workspace
- centralizes attack surface, target intel, SIGINT, COMMS, GEO, OPS, and reports
- contributes map-facing outputs such as Intelligence Zones instead of behaving like a separate analytics screen

### WarDrive

- keeps its own session and region workflow
- can filter by selected sessions
- can switch between `WORKSPACE` and `MAP INVENTORY`
- uses explicit refresh instead of silent heavy recalculation on every reopen

### Sniffer

- keeps the RAW capture workflow centered on RAW files, metadata, and generated hash artifacts
