# Cracking Endpoints

These endpoints cover file conversion, cracking jobs, hybrid RAW preparation, and related operational helpers.

Base path:

```text
/api
```

## Conversion

### `POST /api/convert/hcx`

Convert one capture into `.22000`.

Body can target either the legacy filename flow or the new handshake-capture flow:

```json
{
  "filename": "MyWifi_aabbccddeeff.pcap",
  "capture_id": null
}
```

At least one of `filename` or `capture_id` is required.

When `capture_id` is used, the backend resolves the original capture and writes the generated `.22000` beside that source PCAP, using the same basename:

```text
backend/data/<source-family>/.../<pcap-basename>.22000
```

### `POST /api/convert/hcx/batch`

Build a `batch_*.22000` plus manifest from multiple capture files.

Body supports either `filenames[]`, `capture_ids[]`, or a mix when the UI is working from a handshake-set selection.

## Hashcat and Aircrack Jobs

### `POST /api/hashcat/jobs`

Starts a Hashcat job.

Typical fields include:

- `filename`
- `attack_mode`
- `wordlist`
- `wordlist_2`
- `rule_file`
- `mask_file`
- `association_hints`
- `device_id`
- `is_optimized`
- `skip_quality_gate`

### `POST /api/hashcat/association/preview`

Returns candidate previews for association modes without starting cracking.

### `POST /api/aircrack/jobs`

Starts an Aircrack-ng job for a selected capture.

The request supports `filename` or `capture_id`, which makes it possible to target a specific capture inside a multi-device handshake set.

When a capture target is used, Aircrack writes derived outputs such as `.cracked` beside the resolved source capture.

## Handshake File Discovery

### `GET /api/handshakes/{mac}/files`

Returns the main files related to a BSSID.

Important current behavior:

- hides empty `.22000` outputs
- hides sidecar `.wdrs.json`
- hides legacy per-source `__wdrs__raw_*` files from the main list
- hides `raw_*.22000` noise from the standard captured-files view

The response stays flat for compatibility, but now includes capture context when available:

- `capture_id`
- `source`
- `device_label`
- `source_path_role`
- `is_preferred`
- `legacy_shared`
- `artifact_scope`
- `artifact_owner_capture_id`
- `combined_build_id` when the file comes from a combined candidate

### `GET /api/handshakes/{mac}/set`

Returns the richer handshake-set model for a BSSID.

Typical top-level fields:

- `handshake_set_id`
- `mac`
- `resolved_ssid`
- `sources`
- `preferred_capture_id`
- `artifact_summary`
- `captures[]`
- `flat_files[]`
- `combined_candidates[]`

Each capture includes:

- `capture_id`
- `source`
- `device_label`
- `source_filename`
- `source_path_role`
- `resolved_ssid`
- `quality` with `score`, `tier`, `reasons`, `valid_hash_lines`, `details_richness`
- grouped `artifacts`
- `is_preferred`
- `legacy_shared_artifacts`

This endpoint is the preferred read model for UIs that want to show per-device captures instead of a flat filename list.

### `POST /api/handshakes/{mac}/combine-captures`

Builds a manual combined `.22000` candidate for one BSSID from multiple captures in the same handshake set.

Body:

```json
{
  "capture_ids": ["cap-a", "cap-b"]
}
```

Typical response fields:

- `status`
- `build_id`
- `output_file`
- `included_capture_ids`
- `deduped_hash_count`

### `POST /api/fingerprint/extract`

Extracts `.details` metadata from a capture.

Like conversion and Aircrack, this endpoint accepts either:

- `filename`
- `capture_id`
- `raw_item_id`

When `raw_item_id` is used for a RAW PCAP, the UI should also send the selected `bssid` so the generated `.details` file is scoped to the current network instead of the first network seen inside the capture.

`GET /api/fingerprint/details` remains sidecar-oriented and reads the generated `.details` file from `HANDSHAKES_DIR`.

For capture-specific details, the UI should pass `capture_id` back when reading the artifact so the backend can resolve the sidecar next to the correct source PCAP.

## Hybrid RAW Preparation

### `GET /api/handshakes/{mac}/raw-context`

Returns BSSID-scoped RAW context for Cracking Operations.

The payload may include:

- `present`
- `bssid`
- `files_count`
- `hash_files_count`
- `aggregate`
- source-aware `raw_item_id`
- `source`
- `device_label`
- `source_path_role`
- network-aware `details_present`
- network-aware `details_filename`
- `analysis_present`
- `analysis_summary`
- `files[]` for PCAP fallback context
- `hash_files[]` for hash-first context

### `POST /api/handshakes/{mac}/raw-prepare`

Processes one RAW source item into the canonical hybrid hash.

Body:

```json
{
  "raw_item_id": "raw::pcap::abc123",
  "force": false
}
```

Current semantics:

- `raw_item_id` is the preferred selector
- `source_file` remains accepted for compatibility
- `source_file` may be a RAW hash or a RAW PCAP context item
- output is the canonical `__wdrs__.22000`
- per-source persistent WDRS artifacts are no longer the official visible output

Typical statuses:

- `success`
- `success_partial`
- `up_to_date`
- `error`

### `POST /api/handshakes/{mac}/raw-prepare-all`

Starts an asynchronous prepare-all job for the whole RAW context of a BSSID.

Body:

```json
{
  "force": false
}
```

Response:

```json
{
  "status": "success",
  "data": {
    "status": "started",
    "job_id": "...",
    "total_files": 3,
    "force": false
  }
}
```

## History and Supporting Endpoints

- `GET /api/jobs`
- `GET /api/jobs/{job_id}`
- `PATCH /api/jobs/{job_id}`
- `GET /api/history`
- `DELETE /api/history`
- `GET /api/files/{filename}`
- `GET /api/wordlists/custom`
- `GET /api/hashcat/rules`
- `GET /api/hashcat/masks`
- `GET /api/hashcat/devices`
- `GET /api/batches`
- `GET /api/batches/{filename}`
- `GET /api/batches/{filename}/files`
- `DELETE /api/batches/{filename}`

`GET /api/files/{filename}` now also supports:

- `capture_id`
- `combined_build_id`
- `mac`

These optional selectors let the backend resolve capture-specific and combined artifacts instead of relying only on the root handshake folder.
