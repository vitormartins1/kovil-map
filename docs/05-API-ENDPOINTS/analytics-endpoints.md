# Analytics Endpoints

Analytics endpoints power the adaptive Analytics workspace.

Base path:

```text
/api/analytics
```

## GET `/api/analytics/heatmap`

Returns heatmap cells for the current filters.

### Query parameters

- `metric`: `opportunity`, `density`, `eapol`, `beacon`, `probe`
- `time_window`: `all`, `24h`
- `source`: `all`, `pwn`, `bruce`, `ward`, `raw`
- `security`: `all`, `locked`, `open`, `cracked`
- `device_type`: `all`, `router_ap`, `phone_hotspot`, `camera_ap`, `printer_ap`, `iot_ap`, `unknown`
- `channel`: optional integer
- `cell_size_m`: integer `50..300`

`cell_size_m` still matters for the heatmap cell grid.

### Response highlights

- `cells[]`
- `stats`
- `filters`
- `generated_at`

## GET `/api/analytics/hotspots`

Returns adaptive hotspot clusters.

### Query parameters

Same filter set as heatmap, plus:

- `limit`: `1..50`
- `cell_size_m`: accepted for backward compatibility but deprecated/ignored by hotspot generation

### Response highlights

Each hotspot can include:

- `id`
- `center_lat`, `center_lng`
- `radius_m`
- `score`
- `networks_count`
- `members_count`
- `locked_count`
- `top_channels`
- `top_sources`
- `candidate_macs`
- `sample_macs`
- `raw_eapol_sum`
- `raw_beacon_sum`
- `raw_probe_peak_sum`
- `extent_bbox`
- `mesh`
- `algorithm_meta`
- `recommended_action`

The root payload also includes an `algorithm` object describing the adaptive DBSCAN strategy.

## GET `/api/analytics/channel-summary`

Returns channel summary, device summary, and WarDrive context for the current filters.

### Response highlights

- `channels[]`
- `device_summary[]`
- `wardrive_context`

`wardrive_context` currently includes:

- `sessions_count`
- `networks_count`
- `points_count`
- `top_transport_modes` (up to 8)

## Current UX Contract

The frontend uses these endpoints like this:

- load heatmap and hotspot list at workspace open
- do not auto-select a hotspot
- draw hotspot highlight only after a user click
- use `candidate_macs` for `ADD TO TARGETS`
