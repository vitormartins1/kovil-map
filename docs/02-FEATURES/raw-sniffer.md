# RAW Sniffer

RAW Sniffer integrates `raw_*.pcap` captures into the local dataset and into cracking workflows without forcing every RAW artifact into the main map view.

## Scope

RAW Sniffer currently powers three things:

- metadata extraction from `raw_*.pcap`
- source-aware enrichment for Bruce RAW, M5Evil RAW Sniffer, and M5Evil Master Sniffer captures
- BSSID-level RAW context for networks already known to the map
- network-scoped details extraction from RAW PCAPs for one selected BSSID at a time
- capture-scoped RAW Analysis reports for full RAW captures
- canonical hybrid hash preparation for cracking
- deletion of selected RAW captures together with their cached metadata and sibling generated `.22000` when present

## RAW File Sources

The service scans source-aware RAW roots for files such as:

```text
raw_1.pcap
raw_12.pcap
raw_capture_name.pcap
```

Recommended layout:

```text
backend/data/BrucePCAP/
  handshakes/
  rawsniffer/
  .metadata/
backend/data/m5evil/
  handshakes/
  mastersniffer/
  rawsniffer/
  .metadata/
```

Notes:

- new Bruce RAW captures should be placed in `backend/data/BrucePCAP/rawsniffer/`
- new M5Evil `RawSniff_*.pcap` captures should be placed in `backend/data/m5evil/rawsniffer/`
- new M5Evil `masterSniffer_*.pcap` captures should be placed in `backend/data/m5evil/mastersniffer/`
- legacy Bruce RAW captures in `backend/data/BrucePCAP/` are still readable for backward compatibility
- `backend/data/BrucePCAP/handshakes/` is reserved for Brucegotchi handshake captures, not RAW files
- `backend/data/m5evil/handshakes/` is reserved for `HS_*.pcap` M5Evil handshake captures, not RAW files
- RAW metadata cache lives in the source-specific `.metadata/` directory
- generated handshake sidecars still remain centralized in `backend/data/handshakes/`

Metadata caches are stored under the local RAW metadata directory and reused until the source file changes.

## Extracted Metadata

Typical RAW-derived metadata includes:

- `channel`
- `frequency_mhz`
- `beacon_count`
- `eapol_count`
- `probe_client_count`
- `processed_at`
- warnings and aggregate counters per BSSID

This metadata enriches existing networks in the main dataset. RAW-only networks are not promoted to first-class map markers by default in this phase.

## Source Semantics and Downstream Integration

RAW inputs are normalized into source-aware families so the rest of the product can reason about where the evidence came from:

- `bruce_raw` / `bruce_raw_sniffing` -> `BRUCEGOTCHI + RAWSNIFFER`
- `m5evil_raw_sniffing` -> `M5Evil + RAWSNIFFER`
- `m5evil_master_raw_sniffing` -> `M5Evil + RAWSNIFFER`

That normalization is used not only in the dedicated RAW workspace, but also in:

- Recon Center source breakdowns
- Geo / analytics source counters
- list badges and source filters across the frontend

Important behavior:

- RAW enrichment contributes to those counters only when the RAW capture adds context to a network already known in the consolidated dataset
- RAW-only networks are still intentionally excluded from the main map and from Recon-driven network lists in this phase

## RAW Sniffer UI

The app exposes a dedicated `RAW SNIFFER` panel where operators can:

- list RAW captures
- see which device family produced each RAW file
- distinguish M5Evil `RAWSNIFFER` from M5Evil `MASTER SNIFFER`
- see cache status
- inspect metadata
- reprocess selected or pending files
- review generated RAW hashes
- build and inspect capture-scoped RAW Analysis reports
- follow RAW Analysis progress from the shared Process panel while the report is being built
- delete a selected RAW capture and clean up its local sidecars

## Hybrid Cracking Integration

Cracking Operations includes a `RAW Sniffer` accordion whenever a selected BSSID has RAW context.

That section is network-first and source-aware:

- it groups RAW items by device family such as `Bruce` and `M5Evil`
- M5Evil items also expose a subtype label such as `RAWSNIFFER` or `MASTER SNIFFER`
- it lists linked RAW PCAPs and linked RAW `.22000` files associated with the current BSSID
- selecting a RAW PCAP exposes `EXTRACT DETAILS`, `GENERATE HASH`, `QUICK ATTACK`, and `BUILD CANONICAL`
- selecting a RAW `.22000` exposes cracking actions directly
- `BUILD CANONICAL FROM ALL` processes the entire RAW context for the BSSID

If the operator enters Cracking Operations from `RAW SNIFFER > Raw Hashes` by clicking a `raw_*.22000` entry, the UI switches to a hash-scoped flat list (similar to batch files) instead of the default device-grouped RAW accordion. This hash-scoped view shows only same-prefix artifacts for the selected RAW hash (`.22000`, `.details`, `.try`, `.cracked`) and suppresses source/device labeling.

## Canonical Hybrid Hash

The official visible output for the hybrid RAW/Wardrive flow is a canonical hash file in `HANDSHAKES_DIR`:

```text
<ssid_slug>_<mac_clean>__wdrs__.22000
```

Example pattern:

```text
my-network_aabbccddeeff__wdrs__.22000
```

Important behavior:

- the canonical file is deduplicated across multiple RAW inputs
- item-level prepare and prepare-all both feed the same canonical pipeline
- the canonical output is still visible in Cracking Operations, but it is no longer framed as a legacy-only artifact
- legacy per-source `__wdrs__raw_*` artifacts are hidden from the main captured-files list
- sidecar runtime state is tracked through `.wdrs.json`

## RAW Network Details

When `EXTRACT DETAILS` is triggered from a selected RAW PCAP inside Cracking Operations, the generated `.details` file is scoped to the currently selected BSSID.

Current naming scheme:

```text
__rawdetails__<raw_stem>_<normalized_mac>.details
```

Example:

```text
__rawdetails__HAL_22_aabbccddeeff.details
```

Important behavior:

- the extractor filters tshark-derived rows to the requested BSSID when `raw_item_id + bssid` are provided
- the same RAW PCAP can generate different `.details` files for different BSSIDs
- these files behave like normal network details in Cracking Operations, but they remain RAW-context artifacts

## RAW Analysis

RAW Analysis is a separate capture-scoped report for the full RAW file.

It is primarily surfaced in the `RAW SNIFFER` panel and can be linked from Cracking Operations through `OPEN RAW ANALYSIS`.

Typical report content includes:

- capture duration and frame totals
- top networks and top clients
- handshake candidate hints
- hidden-to-revealed SSID behavior
- noisy-capture indicators and warnings

Current UX note:

- `ANALYZE SELECTED` creates a visual `RAW ANALYSIS` entry in the Process panel while the report is being generated
- the current implementation is still a synchronous backend call, so the process entry is UI-driven rather than a cancelable backend job

## Hash-First Canonical Strategy

`BUILD CANONICAL FROM ALL` uses this policy:

1. try linked RAW `.22000` hashes first
2. filter valid lines for the selected BSSID
3. dedupe and merge them into the canonical `__wdrs__.22000`
4. fall back to PCAP-based extraction only when hash inputs are missing or insufficient

This keeps the workflow aligned with the existing Raw Sniffer processing pipeline instead of redoing unnecessary PCAP work.

## RAW Context by BSSID

`GET /api/handshakes/{mac}/raw-context` returns BSSID-scoped RAW context, including:

- source-aware `raw_item_id` values
- hash files linked to the BSSID
- fallback PCAP entries when relevant
- source/device labels such as `Bruce` and `M5Evil`
- subtype labels such as `RAWSNIFFER` and `MASTER SNIFFER` when relevant
- network-aware `details_present` and `details_filename`
- RAW Analysis availability/summary when cached
- aggregate counters such as EAPOL and beacon totals

## Related Endpoints

- `GET /api/rawsniffer/files`
- `DELETE /api/rawsniffer/files/{filename}`
- `GET /api/rawsniffer/hashes`
- `GET /api/rawsniffer/metadata`
- `POST /api/rawsniffer/extract`
- `POST /api/rawsniffer/analyze`
- `GET /api/rawsniffer/analysis/{raw_item_id}`
- `GET /api/handshakes/{mac}/raw-context`
- `POST /api/handshakes/{mac}/raw-prepare`
- `POST /api/handshakes/{mac}/raw-prepare-all`

## Related Docs

- [`../00-GETTING_STARTED/manual-import-layout.md`](../00-GETTING_STARTED/manual-import-layout.md)
- [`cracking-engine.md`](cracking-engine.md)
