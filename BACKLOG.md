# KOVIL MAP Backlog

**Last updated:** April 7, 2026  
**Tracked initiatives:** 25

This backlog is public-facing. It may include both contributor-friendly roadmap items and maintainer-owned release/readiness work, but it should not contain secrets, personal infrastructure details, or private operational notes.

## Legend

### Priority

| Priority | Meaning |
| --- | --- |
| `CRITICAL` | blocks other work, affects security, or is required before public release |
| `HIGH` | important user or workflow impact |
| `MEDIUM` | valuable improvement, but not urgent |
| `LOW` | nice-to-have, cleanup, or longer-tail polish |

### Status

| Status | Meaning |
| --- | --- |
| `TODO` | not started |
| `IN PROGRESS` | active work |
| `IN REVIEW` | implemented and waiting for review |
| `DONE` | completed and merged |

## 1. Handshake Lifecycle

### Capture-scoped derived artifacts

- Priority: `HIGH`
- Status: `TODO`
- Estimate: `12-16h`
- Complexity: `High`
- Goal: finish the handshake-set redesign by moving derived artifacts away from the current shared legacy model in `backend/data/handshakes/` and toward capture-scoped storage.
- Requirements:
  - namespaced `.details`, `.22000`, `.try`, and `.cracked` per capture
  - read compatibility for existing legacy/shared artifacts
  - API and UI provenance that clearly distinguishes capture-specific vs shared artifacts
  - regression coverage for Brucegotchi and M5 Evil basename collisions

### Opt-in combined candidate build for one BSSID

- Priority: `MEDIUM`
- Status: `TODO`
- Estimate: `10-14h`
- Complexity: `High`
- Goal: let the operator explicitly combine multiple valid captures from the same handshake set to improve cracking odds without changing the default preferred-capture workflow.
- Requirements:
  - manual action in the cracking panel
  - deterministic dedupe and provenance manifest
  - no automatic background merge in v1
  - tests for quality scoring, fallback, and operator override

## 2. Quality Gates and Release Safety

### Apply branch protection for `dev` and `main`

- Priority: `CRITICAL`
- Status: `TODO`
- Estimate: `3-5h`
- Complexity: `Medium`
- Goal: enforce the refactored CI/CD model in GitHub so merges are blocked unless the expected `Quality` and `Security` checks pass.
- Process:
  - open GitHub repository settings: `Settings -> Branches -> Add branch protection rule`
  - create one rule for `dev`
  - create one rule for `main`
  - enable `Require a pull request before merging`
  - enable `Require status checks to pass before merging`
  - enable `Require branches to be up to date before merging`
  - disable force pushes and deletions
  - keep merge strategy recommendation aligned with the repo policy (`squash`)
- Required checks to configure for both `dev` and `main`:
  - `Quality / Artifact Guardrails`
  - `Quality / Backend Lint`
  - `Quality / Backend Unit Tests`
  - `Quality / Backend OpenAPI`
  - `Quality / Frontend Lint`
  - `Quality / Frontend Unit Tests`
  - `Quality / Frontend Validate`
  - `Security / SAST`
  - `Security / SBOM`
  - `Security / SCA`
  - `Security / Summary`
- Validation checklist:
  - open a PR into `dev` and confirm merge is blocked when any required check fails
  - open a PR into `main` and confirm the same behavior
  - verify bot-created promotion PRs also wait for the required checks
  - document any GitHub UI naming differences if the displayed check names diverge from the workflow job names

### Frontend branch coverage back to threshold

- Priority: `HIGH`
- Status: `TODO`
- Estimate: `8-12h`
- Complexity: `Medium`
- Goal: restore a passing `jest --coverage` run without lowering the current frontend branch threshold.
- Requirements:
  - targeted tests for `ui.js`, `map.js`, `ui_wardrive.js`, and related helpers
  - keep global coverage thresholds unchanged
  - document the local command flow contributors should use before merging

### Packaged desktop smoke checks

- Priority: `MEDIUM`
- Status: `TODO`
- Estimate: `6-8h`
- Complexity: `Medium`
- Goal: add repeatable verification for packaged Windows, macOS, and Linux builds.
- Requirements:
  - verify the correct bundled backend binary per platform
  - launch the packaged app and confirm backend startup
  - probe `/api/health` after boot
  - document the release smoke checklist

## 3. Refactoring and Organization

### Clarify `/scripts` vs `/backend/scripts`

- Priority: `MEDIUM`
- Status: `TODO`
- Estimate: `4-6h`
- Complexity: `Low`
- Goal: define clear ownership and purpose for root scripts vs backend-only scripts.
- Deliverables:
  - cleaner folder structure
  - updated docs in `docs/03-DEVELOPMENT/`
  - local READMEs where helpful

### Backend scripts cleanup

- Priority: `MEDIUM`
- Status: `TODO`
- Estimate: `6-8h`
- Complexity: `Medium`
- Goal: audit backend scripts, remove obsolete helpers, and document maintained ones.
- Actions:
  - document each maintained script
  - remove legacy scripts
  - improve help output and logging consistency

## 4. Open-source Preparation

### Cleanup and mock data

- Priority: `CRITICAL`
- Status: `TODO`
- Estimate: `16-20h`
- Complexity: `High`
- Goal: prepare the codebase for public publication with safe demo-ready data.
- Tasks:
  - remove personal absolute paths
  - remove private IPs, hostnames, tokens, and credentials
  - replace real SSIDs and MACs with mock data
  - provide demo datasets under a dedicated data root
  - add a first-run demo bootstrap script

### Data-sensitivity review before publishing

- Priority: `CRITICAL`
- Status: `TODO`
- Estimate: `10-12h`
- Complexity: `High`
- Goal: perform a repository-wide sensitivity audit before any public release.
- Audit areas:
  - source files
  - config files
  - git history
  - `backend/data/`
  - generated logs and local artifacts

## 5. Map and Visualization

### Improve non-aggressive cluster modes

- Priority: `HIGH`
- Status: `TODO`
- Estimate: `12-16h`
- Complexity: `High`
- Goal: improve cluster modes other than the strongest current grouping option.
- Investigation areas:
  - why the current best mode performs better
  - how thresholds should differ by mode
  - how mixed datasets behave
  - whether a smarter automatic mode should exist

## 6. Device Integrations

### Expand M5Evil auto-sync beyond Cardputer

- Priority: `MEDIUM`
- Status: `TODO`
- Estimate: `10-14h`
- Complexity: `Medium`
- Goal: extend the new `M5Evil Cardputer` auto-sync flow to other compatible devices in the M5 / Evil-M5 ecosystem when they expose the same web transport and storage model.
- Requirements:
  - validate which devices expose the same `Admin WebUI` workflow used by Cardputer
  - confirm SD-card folder layout compatibility for handshakes and Wardrive exports
  - add presets for confirmed-compatible targets such as `M5 Core2`, `M5 AtomS3`, and other supported Evil-M5 variants
  - keep the current Cardputer profile backward compatible
  - document any per-device path or capability differences in `docs/04-INTEGRATIONS/`

## 7. Offensive Intelligence — Tier 1 (Future)

> **Decision (April 7, 2026):** Tier 1 features leverage existing tool capabilities and data to add intelligence layers. Documented here for future implementation after Tier 2 is complete.

### Wordlist Arsenal Manager

- Priority: `HIGH`
- Status: `TODO`
- Estimate: `14-18h`
- Complexity: `High`
- Goal: full CRUD + effectiveness analytics for wordlists. Upload, merge, split. Dashboard showing success rate per wordlist × encryption × device type.
- Notes: depends on custom wordlist generation research (separate initiative)

### Attack History Intelligence

- Priority: `HIGH`
- Status: `TODO`
- Estimate: `10-14h`
- Complexity: `Medium`
- Goal: aggregation API over existing history logs. Success rate by mode, by encryption, by wordlist. Timeline and correlation analysis.
- Notes: data already exists in `.try` files and history service

### Smart Attack Sequencer

- Priority: `MEDIUM`
- Status: `TODO`
- Estimate: `16-20h`
- Complexity: `High`
- Goal: given a target MAC, suggest optimal attack sequence based on encryption, device type, and success history.
- Notes: depends on Attack History Intelligence

### Hashcat Session/Restore

- Priority: `HIGH`
- Status: `TODO`
- Estimate: `8-10h`
- Complexity: `Medium`
- Goal: add `--session` and `--restore` support to hashcat. Pausable/resumable jobs in UI.

### PRINCE Attack Mode

- Priority: `MEDIUM`
- Status: `TODO`
- Estimate: `6-8h`
- Complexity: `Low`
- Goal: new hashcat attack mode using PRINCE preprocessor for passphrase generation.

### Markov Chain Candidates

- Priority: `MEDIUM`
- Status: `TODO`
- Estimate: `8-12h`
- Complexity: `Medium`
- Goal: `--markov-hcstat2` profiles (English, Portuguese, numeric) for statistically-probable candidates.

### Kill-Chain Diagnostic

- Priority: `MEDIUM`
- Status: `TODO`
- Estimate: `6-8h`
- Complexity: `Low`
- Goal: expand kill-chain endpoint with "why stuck" explanations per network (missing conversion, empty .22000, no EAPOL, etc.).

### Loopback Mode

- Priority: `LOW`
- Status: `TODO`
- Estimate: `4-6h`
- Complexity: `Low`
- Goal: `--loopback` mode where cracked passwords feed future attacks. Pattern learning from real passwords.

## 8. Custom Wordlist Generation (Research)

> **Decision (April 7, 2026):** Deferred pending research into existing open-source wordlist generation tools and repositories. User is evaluating external solutions to integrate rather than building from scratch.

### Custom Wordlist Generator

- Priority: `HIGH`
- Status: `TODO`
- Estimate: `TBD`
- Complexity: `TBD`
- Goal: generate targeted wordlists based on SSID, region, language, and patterns from cracked passwords. Integration approach (custom vs external tool) pending research.

## 9. Source Origin Intelligence & Session Management

> **Context:** the project already classifies wardrive files by device (Bruce, M5Evil, uncategorized) and tracks pwnagotchi GPS origin separately. Sessions are grouped per CSV, with merge support (2-3 sessions at a time) and transport tagging. The next step is to elevate source origin from a per-file label into a first-class system feature with merged-file awareness, multi-source overlap analysis, clean session lineage, and a dedicated UI.

### Unified Source Origin Model

- Priority: `HIGH`
- Status: `TODO`
- Estimate: `10-14h`
- Complexity: `High`
- Goal: promote source origin from scattered per-file helpers (`_classify_wardrive_device`, `_is_bruce_wardrive_source`, `_is_m5evil_wardrive_source`) into a single origin model that covers all data sources uniformly — including merged sessions.
- Context:
  - today, device classification runs at CSV load time and writes a `device` field (`bruce` / `m5evil` / `uncategorized`) per `wardrive_observation`
  - merged CSVs in `backend/data/wardrive/merged/` inherit no device label; the merge manifest tracks `source_leaf_session_ids` and `source_hashes` but the merged file itself is classified as `uncategorized`
  - pwnagotchi handshakes have their own origin path but no equivalent `device` tag
  - raw-sniffer data (Bruce Raw Sniffing, M5Evil Raw Sniffing, M5Evil Master Raw Sniffing) carries implicit source in the filename but is not exposed in the origin model
- Implementation plan:
  1. **Origin enum** — define a canonical set of origins in a shared module (`app/core/origins.py` or similar): `PWNAGOTCHI`, `BRUCEGOTCHI`, `BRUCE_WARDRIVE`, `M5EVIL_WARDRIVE`, `BRUCE_RAW_SNIFFING`, `M5EVIL_RAW_SNIFFING`, `M5EVIL_MASTER_RAW_SNIFFING`, `MERGED`, `UNKNOWN`
  2. **Merged origin resolution** — when a merged session is created, compute a composite origin: if all leaf sessions share the same device, the merged session inherits that device (e.g. `BRUCE_WARDRIVE`); if mixed, tag as `MERGED` with a `leaf_origins` array for drill-down
  3. **Retroactive tagging** — on data reload, backfill existing merged CSVs using their `source_leaf_session_ids` to resolve leaf device types
  4. **Extend manifest** — add `device` and optionally `leaf_origins` to the wardrive manifest entry for merged files
  5. **Unify pwnagotchi + raw-sniffer** — add equivalent origin fields to handshake and raw-sniffer data dicts so every network carries a consistent `origin` key
- Tests:
  - merged session of all-Bruce leaves → `BRUCE_WARDRIVE`
  - merged session of Bruce + M5Evil leaves → `MERGED` with `leaf_origins: [BRUCE_WARDRIVE, M5EVIL_WARDRIVE]`
  - merged-of-merged (transitive) resolves leaf origins correctly
  - existing CSVs without manifest `device` field get backfilled on reload

### Multi-Source Overlap Analysis

- Priority: `HIGH`
- Status: `TODO`
- Estimate: `12-16h`
- Complexity: `High`
- Goal: identify and surface networks captured by multiple distinct sources, enabling the operator to understand capture redundancy, coverage gaps, and source reliability.
- Context:
  - each network already stores a `wardrive_sessions` array with one entry per detecting session, plus optional pwnagotchi data
  - today, no API or UI answers "which networks were seen by both Bruce wardrive AND pwnagotchi?" or "how many networks are single-source vs multi-source?"
- Implementation plan:
  1. **Overlap computation** — at temporal-intel build time, compute per-network a `source_origins` set (using the unified origin model). Classify each network as `single_source` or `multi_source` with the contributing origins.
  2. **Summary stats** — add to the temporal-intel response:
     - `overlap.total_multi_source` — count of networks seen by ≥2 distinct origins
     - `overlap.total_single_source` — count of networks seen by exactly 1 origin
     - `overlap.by_origin_pair` — for each pair of origins, count of shared networks (e.g. `{"bruce_wardrive+pwnagotchi": 42}`)
     - `overlap.exclusive_by_origin` — count of networks seen ONLY by that origin
  3. **Network-level field** — add `source_origins: string[]` to each network in the data dict, available for the frontend to query and filter
  4. **Merge intelligence** — when preparing a session merge, show the operator how much overlap the selected sessions have (shared MACs, new MACs, GPS improvement potential)
- Tests:
  - network seen by bruce wardrive + pwnagotchi → `multi_source`, origins set `{BRUCE_WARDRIVE, PWNAGOTCHI}`
  - network seen only by M5Evil → `single_source`, exclusive to `M5EVIL_WARDRIVE`
  - overlap pair counts are symmetric and sum correctly
  - merge preview shows correct deduplicated MAC count

### Session Lineage & Merge Tree

- Priority: `MEDIUM`
- Status: `TODO`
- Estimate: `8-12h`
- Complexity: `Medium`
- Goal: provide a clear lineage view from any session back to its original source files, including transitive merges, and expose this in the UI.
- Context:
  - the merge manifest already tracks `merged_from_session_ids` and `source_leaf_session_ids` (transitive)
  - `source_hashes` preserves SHA256 of all leaf files
  - the frontend session panel shows merged sessions but does not visualize the merge tree or allow navigating parent→child relationships
- Implementation plan:
  1. **Lineage API** — `GET /api/wardrive/sessions/{id}/lineage` returning a tree structure: `{session, device, children: [...]}` for merge parents, or `{session, device, merged_into: [...]}` for leaf sessions
  2. **Session detail enrichment** — in the session list API, include `is_merged`, `merge_depth` (0 for originals, 1 for first-level merge, 2+ for transitive), and `leaf_count`
  3. **Frontend merge tree** — in the Wardrive session detail panel, render a compact tree diagram (ASCII or simple HTML/CSS) showing the lineage: original files → merged session → optionally merged again
  4. **Merge provenance badges** — in the session list, show a badge for merged sessions with the merge depth and leaf origins (e.g. "Merged · 14 Bruce sessions")
  5. **Reverse lookup** — from any original session, show which merged sessions it participates in
- Tests:
  - lineage API returns correct tree for single-level and multi-level merges
  - leaf_count matches actual number of original CSVs
  - reverse lookup from leaf to merged session is consistent

### Source Origin Dashboard (Geo Tab Integration)

- Priority: `MEDIUM`
- Status: `TODO`
- Estimate: `10-14h`
- Complexity: `Medium`
- Goal: expand the existing GPS Origin section in the Geo tab into a richer Source Origin Dashboard integrating overlap, session lineage, and capture quality metrics.
- Context:
  - the Geo tab Spatial Coverage section already shows GPS Origin bars (pwnagotchi, wardrive:bruce, wardrive:m5evil, wardrive:uncategorized) and per-source GPS counts
  - no UI currently surfaces multi-source overlap, merge contribution, or per-origin quality
- Implementation plan:
  1. **Overlap visualization** — add a Venn-style or matrix chart showing pairwise overlap between origins (e.g. how many networks are shared between bruce wardrive and pwnagotchi)
  2. **Exclusive vs shared bars** — in the GPS Origin section, split each bar into "exclusive" (only this origin) and "shared" (also seen by other origins) segments with distinct opacity
  3. **Merged contribution** — show how many networks come exclusively from merged sessions vs already present in individual sessions (justifies the merge operation)
  4. **Per-origin quality KPIs** — average GPS accuracy, median RSSI, encryption distribution breakdown per origin
  5. **Session count by origin** — small counter showing how many sessions feed each origin bar
- Deliverables:
  - extended temporal-intel response with overlap data
  - new Geo tab sub-section or enriched Spatial Coverage section
  - responsive layout for the overlap matrix

### Session Management UX Improvements

- Priority: `MEDIUM`
- Status: `TODO`
- Estimate: `8-10h`
- Complexity: `Medium`
- Goal: improve the wardrive session management workflow with better filtering, grouping, and merge guidance.
- Context:
  - the session panel supports sorting (date, duration, distance, nets) and transport tagging
  - merge is limited to 2-3 sessions at a time with no guidance on WHICH sessions to merge
  - no grouping by device or origin in the session list
- Implementation plan:
  1. **Group by origin** — add a grouping toggle that clusters sessions by device origin (all Bruce sessions together, all M5Evil together, merged sessions separate)
  2. **Merge suggestions** — when the operator selects sessions for merge, show a preview panel with: shared MACs, unique MACs per session, GPS coverage delta, date range span
  3. **Batch merge** — extend the 2-3 session limit to allow selecting a device-origin group and merging all sessions of that origin into one (with confirmation + preview)
  4. **Duplicate indicator** — in the session list, flag sessions that are 100% subsets of a merged session (all their MACs already exist in a merged file)
  5. **Filter by origin** — add quick filter chips for each origin type in the session panel header

## Summary

| Area | Count | Priority band |
| --- | --- | --- |
| Handshake lifecycle | 2 | High / Medium |
| Quality gates and release safety | 3 | Critical / High / Medium |
| Refactoring / organization | 2 | Medium |
| Open-source preparation | 2 | Critical |
| Map visualization | 1 | High |
| Device integrations | 1 | Medium |
| Offensive intelligence — Tier 1 | 8 | High / Medium / Low |
| Custom wordlist generation | 1 | High (TBD) |
| Source origin intelligence & session mgmt | 5 | High / Medium |

**Estimated total effort:** `~217-289h`

**Owner:** Vitor Martins
