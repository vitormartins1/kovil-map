# Recon Center

The Recon Center is the unified offensive intelligence workspace. It consolidates attack surface analysis, target intelligence, communications intelligence, signal intelligence, geospatial clustering, and operational planning into a single tabbed interface.

Recon is the analysis-first complement to the Tactical Map. Operators usually enter it after sync/import or map triage, then return its findings to map overlays, Intelligence Zones, Targets, Favorites, or Cracking Operations.

## Tabs Overview

| Tab | Purpose | Right Panel |
|-----|---------|-------------|
| **SURFACE** | Attack surface mapping with kill-chain staging | Drawer Target Details |
| **INTEL** | Vulnerability matrix + deep packet threat analysis | Drawer Target Details |
| **OPS** | Operational status and attack effectiveness | Full-width |
| **GEO** | Geospatial intelligence | Full-width |
| **SIGINT** | Probe request intelligence from captured traffic | Full-width |
| **REPORT** | Audit report and temporal intel | Full-width |
| **COMMS** | Communications intelligence, device census, and cluster intelligence | Full-width |

---

## Recent UX and Performance Changes

Recent work in Recon Center focused on making the workspace denser and faster without forcing a full eager load:

- cache-first lazy loading per tab, per section, and per selected target
- cache invalidation through a dedicated Recon cache manifest
- reusable hints/tooltips for ambiguous metrics and intelligence cards
- progressive hydration so heavy sections can render independently
- compact COMMS cards with shared mini-bar visualizations
- richer SIGINT analysis with geocorrelation and likely-device grouping

---

## Feature: COMMS Cluster Intelligence and Intelligence Zones

The COMMS tab includes a Cluster Intelligence section built from geospatial co-location analysis. These clusters can also be projected onto the tactical map as Intelligence Zones.

### How it works

1. The backend groups GPS-tagged networks that co-locate within the same spatial neighborhood.
2. Cluster cards expose center, radius, dominant encryption, source breakdown, and network membership.
3. The map can toggle a dedicated Intelligence Zones layer from the main toolbar.
4. Intelligence Zones are listed in the left-side `ZONES` panel under an `INTELLIGENCE` section.
5. Their polygons follow the same overlap-based geometry generation used by conquered, to-conquer, and discovered zones, but they intentionally do not subtract from other active layers.

### Visibility

- **COMMS tab**: Device Intelligence, Top Vendors, refreshed Cluster Intelligence cards, and a full-width Communication Graph
- **Map toolbar**: `Toggle Intelligence Zones`
- **ZONES panel**: `INTELLIGENCE` subsection with focus-on-click behavior

### Recent COMMS UX additions

- `Device Intelligence` and `Top Vendors` are rendered as separate sections
- compact mini stacked bars summarize security posture without taking a full text row
- cluster cards can now summarize security, origin, and device distribution with the same visual language
- clusters labeled `Mixed` explain that no single first SSID token owns at least half of the cluster membership
- the Communication Graph now uses a full-width graph area, with supporting intelligence cards rendered below it instead of sharing the same horizontal row
- cluster network membership is intentionally secondary; the main card now prioritizes radius, confidence context, security/origin/device mix, and dominant cluster traits

### Notes

- Intelligence Zones can overlap the other zone families when multiple layers are active.
- The old user-facing radar toggle has been retired in favor of the Intelligence Zones toggle.

---

## Feature: PMKID Optimizer

Identifies WPA/WPA2 networks with extractable PMKID hashes. PMKID attacks require only a single EAPOL frame (no full 4-way handshake), making them significantly faster and more reliable.

### How it works

1. Scans all `.22000` hash files across the workspace
2. Classifies each line by format prefix: `WPA*01*` (PMKID) vs `WPA*02*` (EAPOL 4-way)
3. Flags networks with `has_pmkid = True` in the vulnerability matrix
4. Surfaces PMKID-only networks as critical-severity flags

### Visibility

- **SURFACE tab**: Kill-chain classifies networks into `pmkid_only`, `eapol_only`, and `both` hash types
- **INTEL tab**: Vulnerability matrix shows `PMKID` flag with critical severity badge
- **Target Details**: Evidence row shows PMKID hash availability per target

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/recon/vulnerability-matrix` | Per-network vulnerability flags including PMKID detection |
| `GET` | `/api/recon/kill-chain` | Kill-chain staging with hash type breakdown |

---

## Feature: Probe Request Intelligence (SIGINT)

Aggregates WiFi probe requests from network captures to reveal client behavior patterns: which SSIDs clients are searching for, client distribution, and signal strengths.

### How it works

1. Scans all `.pcap` / `.pcapng` files across handshake, Bruce, and M5Evil directories
2. Runs `tshark` per PCAP to extract probe request frames (`wlan.fc.type_subtype==0x04`)
3. Extracts: client MAC, probed SSID, signal strength, timestamp
4. Aggregates into per-client and per-SSID indices
5. Returns top results ranked by probe frequency

### Data returned

- **Summary**: total probes, unique clients, unique SSIDs, broadcast probes, PCAPs scanned
- **Unmatched Target SSIDs**: SSIDs seen in probes but not confidently tied to a known network in the local dataset
- **SSIDs**: top probed SSIDs with known-context enrichment, shape hints (`human`, `uuid_like`, `generated_like`, etc.), and sample network evidence
- **Clients**: top active clients with vendor/OUI context, known-vs-unmatched SSID summary, average signal, and time window
- **Likely Device Groups**: de-randomization view that groups random MACs by shared probing behavior
- **Probe Geocorrelation**: heuristic location hypotheses built from probed SSIDs that match GPS-tagged known networks

### Visibility

- **SIGINT tab**: KPI row plus `Unmatched Target SSIDs`, `Most Probed SSIDs`, `Top Probing Clients`, `Likely Device Groups`, and `Probe Geocorrelation`

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/recon/probe-intel` | Full probe request analysis |
| `GET` | `/api/recon/probe-intel/status` | Cache status (fresh, stale, or empty) |
| `POST` | `/api/recon/probe-intel/scan` | Trigger background scan job |
| `GET` | `/api/recon/probe-intel/pcap` | Per-PCAP probe breakdown |
| `GET` | `/api/recon/probe-intel/derandom` | Likely-device grouping for randomized MACs |
| `GET` | `/api/recon/probe-intel/geocorrelation` | Geospatial hypotheses derived from known GPS-tagged SSID matches |

### Lazy-load behavior

The SIGINT tab checks the cache status endpoint first. If cached data exists and is fresh, it renders immediately. If stale or empty, a **PROCESS** button is shown. Clicking it triggers a background `probe_intel_scan` job with real-time progress in the Process Panel.

---

## Feature: Advanced Packet Analysis (Threat Detection)

Detects Deauthentication and Disassociation attacks across captured traffic. Identifies which BSSIDs are being targeted, attack frequency, unique sources, and potential flood attacks.

### How it works

1. Scans all `.pcap` / `.pcapng` files (same roots as Probe Intel)
2. Runs two `tshark` queries per PCAP:
   - Deauth frames: `wlan.fc.type_subtype==0x0c`
   - Disassociation frames: `wlan.fc.type_subtype==0x0a`
3. Aggregates per-BSSID: deauth count, disassoc count, unique sources/targets, reason codes
4. Applies flood heuristic: triggers if `deauth_count > 50` from a single source
5. Returns sorted by total frame count

### Data returned

- **Summary**: total deauth, total disassoc, targeted BSSIDs, PCAPs scanned, flood detected flag
- **Threats by BSSID**: deauth/disassoc counts, unique sources, top reason codes, flood indicator per target

### Visibility

- **INTEL tab**: Threat Analysis panel below the vulnerability matrix with KPI row and top-15 targeted BSSIDs table
- **INTEL tab**: Severity filter chips (`CRITICAL`, `WARNING`, `GOOD`, `INFO`) can filter the vulnerability matrix by flag severity

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/recon/deep-analysis` | Full deauth/disassoc threat analysis |
| `GET` | `/api/recon/deep-analysis/status` | Cache status (fresh, stale, or empty) |
| `POST` | `/api/recon/deep-analysis/scan` | Trigger background scan job |
| `GET` | `/api/recon/deep-analysis/pcap` | Per-PCAP threat breakdown |

### Lazy-load behavior

The INTEL tab renders the vulnerability matrix immediately. The threat analysis section checks cache status first. If empty or stale, an **ANALYZE THREATS** button is shown. Clicking it triggers a background `deep_analysis_scan` job with per-PCAP progress.

---

## Feature: PMK Database

Pre-computes PMK (Pairwise Master Key) hashes for a specific SSID+wordlist combination using `airolib-ng`. Dramatically accelerates subsequent crack attempts by skipping the PBKDF2 key derivation step.

### How it works

1. **Build**: Imports a wordlist into an SQLite database via `airolib-ng`, computes PMK hashes for the target SSID
2. **Attack**: Feeds pre-computed PMK candidates directly to `aircrack-ng`, bypassing key derivation entirely
3. Databases are persistent — once built, they can be reused for any capture targeting the same SSID

### Use case

When the same SSID is attacked multiple times with different captures or wordlists, PMK databases eliminate redundant PBKDF2 computation, which is the primary bottleneck in WPA/WPA2 cracking.

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/pmk/databases` | List available PMK databases |
| `GET` | `/api/pmk/databases/{db_name}/stats` | Stats for a specific database |
| `POST` | `/api/pmk/build` | Start PMK database build job |
| `POST` | `/api/pmk/attack` | Crack using pre-computed PMK database |
| `DELETE` | `/api/pmk/databases/{db_name}` | Remove a PMK database |

### Background jobs

PMK builds run as `pmk` job type in the job manager. Progress is emitted via WebSocket `job_update` events and visible in the Process Panel.

---

## Feature: WPS Attack

Launches WPS PIN brute-force attacks against networks with WPS enabled. Supports Reaver and Bully tools, including Pixie Dust accelerated attacks.

### How it works

1. Validates that target BSSID has WPS enabled
2. Executes Reaver or Bully with configurable parameters (delay, max attempts, Pixie Dust mode)
3. Parses real-time output for PIN attempts and discovery rate
4. On success: extracts WPS PIN and derives the PSK

### Pixie Dust

When enabled, the attack attempts to exploit a weakness in the WPS random number generator. If the target router is vulnerable, the PIN is recovered in seconds rather than hours.

### Endpoint

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/wps/attack` | Start WPS PIN brute-force attack |

### Configuration

Requires `reaver` and/or `bully` binaries. Paths are configurable via `reaver_path` and `bully_path` in `config.json`.

---

## Feature: Attack Planner (OPS)

The OPS tab includes an Attack Planner for batch planning before starting crack jobs.

### How it works

1. Paste one or more target MAC addresses.
2. Choose `Auto-select`, `Dictionary`, `Bruteforce`, or `PMK` strategy.
3. Select a wordlist from the backend wordlist catalog when needed.
4. Generate a preview that separates executable and skipped operations.

### Visibility

- **OPS tab**: Attack Planner panel with targets, strategy, wordlist selector, and plan preview

### Endpoint

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/recon/attack-plan` | Build a batch attack execution plan |

---

## UX: Cache-First Lazy-Load Architecture

Recon Center tabs load content on-demand. Only the active tab fetches its primary payload, and the UI prefers fresh cached snapshots when available.

### Behavior

1. Clicking a tab calls `renderTab(tab_name)` which dispatches to the tab-specific render function
2. If a fresh tab snapshot exists, the tab paints immediately from cache
3. Secondary or volatile sections hydrate afterward without blocking the first paint
4. If no fresh cache exists, the tab renders a shell/skeleton and fetches only what that tab needs
5. Target detail requests are fetched individually by MAC instead of forcing a large vulnerability-matrix fallback
6. Errors are caught and displayed inline

### Cache strategy

Recon Center now uses three complementary layers:

1. **Tab snapshots** for previously visited tabs
2. **Section/page cache** for paginated or independently hydrated sub-panels
3. **Target detail cache** for individual selected networks

Freshness is validated through `GET /api/recon/cache-manifest`, which lets the frontend reuse only cache entries that still match the active dataset and recent artifact signatures.

### Attack Surface behavior

The `SURFACE` tab no longer needs the full kill-chain payload for the first paint:

1. `GET /api/recon/kill-chain/summary` renders stage cards and top KPIs
2. stage members are fetched only when the operator expands or searches within a stage through `GET /api/recon/kill-chain/stage`
3. `Recommended Targets` hydrate after the summary is visible

### Target Details behavior

When a target is selected:

1. Recon first tries a cached detail snapshot for that MAC
2. if absent, the drawer renders a local stub immediately when possible
3. the full payload is fetched through `GET /api/recon/target-detail`
4. `Attack History` remains a separate lazy hydration step

---

## UX: Dynamic Right Panel

The Target Details right panel is visible only on tabs that use it (SURFACE and INTEL). On all other tabs (OPS, GEO, SIGINT, REPORT), the right panel and divider are hidden, giving the tab content full width.

### Behavior

1. `renderTab()` checks if the active tab is in `TABS_WITH_RIGHT_PANEL` (attack-surface, target-intel)
2. If not, adds `recon-right-hidden` CSS class to the split container — hides right column + divider
3. If yes, removes the class — restores the split layout
4. Right panel content persists across tab switches (selected target is not cleared)

### Target Details content

When a target is selected (by clicking a network chip on SURFACE or a vulnerability row on INTEL):

- **SSID** and **MAC** address
- **Stage** tag (Discovered → Captured → Hash Ready → Under Attack → Cracked)
- **Attack Score** gauge (0–100)
- **Evidence table**: Handshake, EAPOL, Beacons, PMKIDs, Passwords (✓/✗)
- **Flags**: Severity-colored badges (PMKID, EAPOL, Multi-Capture, WEP, Hidden, etc.)
- **Sources**: List of capture devices

---

## All Recon Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/recon/kill-chain` | Kill-chain staging with hash type breakdown |
| `GET` | `/api/recon/cache-manifest` | Lightweight cache invalidation fingerprint for Recon tab snapshots |
| `GET` | `/api/recon/kill-chain/summary` | Lightweight Attack Surface summary for first paint |
| `GET` | `/api/recon/kill-chain/stage` | On-demand stage members for Attack Surface |
| `GET` | `/api/recon/vulnerability-matrix` | Per-network vulnerability flags |
| `GET` | `/api/recon/target-detail` | Per-target detail payload for the right-side drawer |
| `GET` | `/api/recon/attack-effectiveness` | Attack method effectiveness metrics |
| `GET` | `/api/recon/temporal-intel` | Temporal intelligence and trends |
| `GET` | `/api/recon/audit-report` | Full audit report generation |
| `POST` | `/api/recon/kill-chain/snapshot` | Save a kill-chain snapshot for trends |
| `GET` | `/api/recon/kill-chain/history` | Read kill-chain history for sparklines and trends |
| `POST` | `/api/recon/audit-report/snapshot` | Save an audit report snapshot |
| `GET` | `/api/recon/audit-report/snapshots` | List audit report snapshots |
| `GET` | `/api/recon/audit-report/compare` | Compare saved audit report snapshots |
| `POST` | `/api/recon/attack-plan` | Build a batch attack plan |
| `GET` | `/api/recon/probe-intel` | Probe request analysis |
| `GET` | `/api/recon/probe-intel/status` | Probe intel cache status |
| `POST` | `/api/recon/probe-intel/scan` | Trigger probe intel background scan |
| `GET` | `/api/recon/probe-intel/pcap` | Per-PCAP probe breakdown |
| `GET` | `/api/recon/probe-intel/derandom` | Likely-device grouping for randomized MACs |
| `GET` | `/api/recon/probe-intel/geocorrelation` | Geospatial inference from probe behavior |
| `GET` | `/api/recon/deep-analysis` | Deauth/disassoc threat analysis |
| `GET` | `/api/recon/deep-analysis/status` | Deep analysis cache status |
| `POST` | `/api/recon/deep-analysis/scan` | Trigger deep analysis background scan |
| `GET` | `/api/recon/deep-analysis/pcap` | Per-PCAP threat breakdown |
| `GET` | `/api/recon/comms/relationship-graph` | AP-client relationship graph |
| `GET` | `/api/recon/comms/device-fingerprints` | Device fingerprint summaries |
| `GET` | `/api/recon/comms/colocation` | Geospatial cluster intelligence and map-ready zone geometry |
| `GET` | `/api/recon/comms/spectrum` | Channel and spectrum intelligence |
| `GET` | `/api/recon/comms/signal-landscape` | Signal distribution and strength analysis |
| `GET` | `/api/pmk/databases` | List PMK databases |
| `GET` | `/api/pmk/databases/{db_name}/stats` | PMK database stats |
| `POST` | `/api/pmk/build` | Build PMK database |
| `POST` | `/api/pmk/attack` | Attack with PMK database |
| `DELETE` | `/api/pmk/databases/{db_name}` | Delete PMK database |
| `POST` | `/api/wps/attack` | Start WPS PIN attack |
