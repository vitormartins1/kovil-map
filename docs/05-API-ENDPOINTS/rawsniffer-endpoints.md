# RAW Sniffer Endpoints

These endpoints manage RAW capture files and their metadata.

Base path:

```text
/api/rawsniffer
```

## `GET /api/rawsniffer/files`

Lists RAW PCAP files and their cache state.

Typical fields:

- `filename`
- `raw_item_id`
- `source`
- `device_label`
- `source_path_role`
- `size`
- `mtime`
- `cache_status`
- `analysis_present`
- metadata path/details depending on service output

## `DELETE /api/rawsniffer/files/{filename}`

Deletes one selected RAW PCAP and its local generated sidecars.

Current behavior:

- accepts only RAW-style `.pcap` filenames
- rejects `HS_*.pcap` handshake captures
- removes the source `.pcap`
- removes cached metadata for that RAW file
- removes the sibling generated `.22000` when it exists

## `GET /api/rawsniffer/hashes`

Lists RAW-generated hash files known to the service.

Use this endpoint when working directly with RAW hash generation or diagnostics.

## `GET /api/rawsniffer/metadata`

Reads cached metadata for a RAW file.

Query parameters:

- `filename` (required)
- `refresh` (optional boolean)

When `refresh=true`, metadata extraction is executed synchronously for that file.

## `POST /api/rawsniffer/extract`

Starts RAW extraction jobs.

Body:

```json
{
  "filename": "raw_1.pcap",
  "force": false,
  "only_pending": false
}
```

Common modes:

- single file extract
- pending-only extract
- full RAW reprocessing

## `POST /api/rawsniffer/analyze`

Builds or refreshes a capture-scoped RAW Analysis report for one RAW item.

Body:

```json
{
  "raw_item_id": "raw::pcap::abc123",
  "force": false
}
```

Current UI behavior:

- the RAW workspace creates a `RAW ANALYSIS` entry in the Process panel while this request is running
- this is a frontend-tracked process indicator; the backend endpoint is still synchronous in the current version

## `GET /api/rawsniffer/analysis/{raw_item_id}`

Returns the cached RAW Analysis report for one RAW capture.

Typical sections:

- `capture`
- `highlights`
- per-network rollups
- client activity
- handshake candidate hints

## Relationship to Cracking Operations

The RAW router manages RAW files themselves. BSSID-scoped hybrid preparation for cracking lives under the handshake router instead:

- `GET /api/handshakes/{mac}/raw-context`
- `POST /api/handshakes/{mac}/raw-prepare`
- `POST /api/handshakes/{mac}/raw-prepare-all`

That split is intentional:

- `/api/rawsniffer/*` = file-centric RAW operations and capture-wide RAW analysis
- `/api/handshakes/{mac}/*` = target-centric cracking preparation
