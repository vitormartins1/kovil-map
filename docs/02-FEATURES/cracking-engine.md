# Cracking Engine

The Cracking Engine is the operational layer that turns local captures, hashes, and intelligence into guided cracking workflows.

## What It Covers

- `.pcap` to `.22000` conversion
- Hashcat job orchestration
- Aircrack-ng job orchestration
- attack insights and quality gate
- history and process monitoring
- batch cracking
- hybrid RAW/Wardrive preparation through canonical WDRS hashes
- handshake sets that group multiple captures for the same BSSID across Pwnagotchi, Brucegotchi, and M5Evil
- preferred-capture scoring based on artifact quality instead of source priority alone

## Main Inputs

The panel can operate on:

- `.pcap`
- `.22000`
- `batch_*.22000`
- `.details`
- `.cracked`
- `.try`
- canonical `__wdrs__.22000`
- `capture_id` selectors for per-capture operations inside a handshake set
- explicit combined-candidate `.22000` artifacts for one BSSID

## Handshake Sets

Handshake handling is now network-first instead of source-first.

For a single BSSID, KOVIL MAP can group multiple local captures coming from:

- `backend/data/handshakes/` for legacy Pwnagotchi-style captures
- `backend/data/BrucePCAP/handshakes/`
- `backend/data/m5evil/handshakes/`

Current folder semantics:

- new Brucegotchi handshake imports should go to `backend/data/BrucePCAP/handshakes/`
- new M5Evil handshake imports should go to `backend/data/m5evil/handshakes/`
- classic Pwnagotchi-style `.pcap` plus GPS sidecars still belong in `backend/data/handshakes/`
- new derived artifacts now prefer capture-scoped storage in `backend/data/handshakes/captures/<capture_id>/`
- shared legacy sidecars in `backend/data/handshakes/` remain readable as fallback compatibility artifacts

Each capture receives:

- a stable `capture_id`
- source/device labeling
- artifact discovery (`.pcap`, `.details`, `.22000`, `.cracked`, `.try`)
- a quality score with tier and reasons

Current artifact write model:

- `capture.details`
- `capture.22000`
- `capture.try`
- `capture.cracked`
- `manifest.json`

These live under:

```text
backend/data/handshakes/captures/<capture_id>/
```

This lets cracking, history, and fingerprint flows stay capture-specific even when multiple devices saw the same BSSID.

The preferred capture is chosen mainly from:

- valid non-empty `.22000`
- available `.details`
- richer security/fingerprint metadata
- cracked credential presence
- artifact freshness against the source `.pcap`
- SSID quality and basic file sanity

Source family is used only as a deterministic tie-breaker when quality is otherwise equal.

## Main Sections in Cracking Operations

Depending on the selected file and network context, the panel may show:

- handshake set summary
- grouped captures by source / device
- a `COMBINED CANDIDATES` accordion for manual one-BSSID combined builds
- quality score ordering and tier explanations
- captured files
- `RAW Sniffer` as a dedicated accordion above legacy/shared artifacts when the network has RAW context
- file details / metadata
- generate hash actions
- legacy / shared artifacts in a separate collapsible section
- cracking engine controls
- attack insights
- history
- a configurable accordion behavior in Settings (`Keep Multiple Open` or `Single Open Branch`)

The default cracking and fingerprint actions target the highest-ranked capture, but the operator can switch to another capture from the same handshake set when needed.

## Combined Candidates

When a BSSID has at least two eligible captures, Cracking Operations can build an explicit combined candidate.

`BUILD COMBINED CANDIDATE`:

- collects the selected BSSID's capture-specific `.22000` inputs first
- converts `.pcap` inputs only when needed
- deduplicates WPA lines
- writes the output under:

```text
backend/data/handshakes/combined/<mac_clean>/<build_id>/
  combined.22000
  manifest.json
```

Combined candidates are manual crack targets. They do not automatically replace the preferred capture.

When a combined candidate is selected, Cracking Operations also shows a `COMBINED ORIGIN` summary with:

- the included source captures
- whether each source came from an existing `.22000` or a converted `.pcap`
- deduped hash count for the build

## Attack Intelligence

Before or during cracking, the backend exposes:

- opportunity score
- attack recommendation
- quality gate state (`passed`, `blocked`, `overrideable`)
- association previews for association-based modes

## Hybrid RAW/Wardrive Flow

When a network exists in WarDrive or another capture source and also has RAW context, Cracking Operations can build a canonical hybrid hash.

### `RAW Sniffer` Accordion

The RAW accordion is grouped by device family, for example:

- `Bruce`
- `M5Evil`
- `Canonical (WDRS)`

Within each source group, the panel can list:

- RAW PCAPs
- RAW `.22000` files
- RAW-derived BSSID-scoped `.details`
- canonical WDRS outputs related to the selected network

When Cracking Operations is opened from the RAW Sniffer `Raw Hashes` list (`raw_*.22000` selection), the panel uses a flat, batch-like view for that hash scope instead of the device-grouped RAW accordion. In this mode:

- only same-prefix artifacts are listed (for example `.22000`, `.details`, `.try`, `.cracked`)
- source/device badges are removed to avoid origin confusion for hash-only workflows
- a compact handshake-summary block is shown with RAW hash metrics (valid, matched, EAPOL missing, invalid)

### `BUILD CANONICAL`

Processes one selected RAW source item for the selected BSSID and updates the canonical `__wdrs__.22000`.

### `BUILD CANONICAL FROM ALL`

Starts an asynchronous job that:

- processes the full RAW context for the BSSID
- prefers RAW hash inputs first
- falls back to PCAP extraction only if needed
- updates the canonical `__wdrs__.22000`
- emits process updates to the Process panel

### RAW PCAP Network Details

`EXTRACT DETAILS` on a selected RAW PCAP now generates a network-scoped `.details` file for the currently selected BSSID only.

That means:

- the same RAW PCAP can produce multiple `.details` files across different networks
- details extraction no longer silently falls back to "the first network in the capture" when the UI already knows the current target BSSID
- the generated details item is shown under the selected RAW source item in Cracking Operations

### RAW Analysis

Cracking Operations stays network-first, so the full capture-wide RAW Analysis report does not live in the main cracking file list.

Instead:

- the dedicated `RAW SNIFFER` panel is the primary home for full RAW Analysis
- Cracking Operations can show a lightweight summary
- `OPEN RAW ANALYSIS` is available when analysis already exists for the selected RAW PCAP

### Status semantics

The UI treats these as final outcomes:

- `COMPLETED`
- `PARTIAL`
- `UP TO DATE`
- `ERROR`

`UP TO DATE` means the canonical output already matches the current RAW context and does not need regeneration.

Capture-wide `RAW ANALYSIS` also surfaces in the Process panel as a visual process entry while the report is being built from the RAW workspace.

## Supported Tools

- Hashcat
- Aircrack-ng
- HCX tools / `hcxpcapngtool`
- `tshark` for details/fingerprint-derived metadata

## Batch Cracking

Batch flows still operate through `batch_*.22000` plus their manifests. The hybrid WDRS flow does not replace batch cracking; it complements per-BSSID preparation when the useful material lives in RAW context instead of classic handshake files.

When a `batch_*.22000` file is selected in Cracking Operations, the handshake-summary block uses manifest-oriented metrics instead of source-family tags. The summary focuses on:

- total items
- handshake OK count
- EAPOL missing count
- invalid count
- cracked count

When a network has a handshake set summary in the map dataset, batch helpers can prefer `preferred_handshake_capture_id` to build batch inputs from the recommended capture rather than relying only on legacy filename priority.

## Related Docs

- [`../00-GETTING_STARTED/manual-import-layout.md`](../00-GETTING_STARTED/manual-import-layout.md)
- [`raw-sniffer.md`](raw-sniffer.md)
- [`batch-cracking.md`](batch-cracking.md)
- [`../07-OPERATIONS/cracking-workflow.md`](../07-OPERATIONS/cracking-workflow.md)
- [`../05-API-ENDPOINTS/cracking-endpoints.md`](../05-API-ENDPOINTS/cracking-endpoints.md)
