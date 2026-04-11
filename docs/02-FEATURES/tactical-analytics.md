# Analytics v2

Analytics v2 replaces the old fixed-cell tactical hotspot workflow with adaptive spatial clustering and a cleaner workspace UX.

## Current Product Behavior

When Analytics opens:

- the heatmap loads immediately
- the hotspot list loads immediately
- no hotspot is auto-selected
- no hotspot circle is drawn on the map until the operator clicks a hotspot

## Hotspots Are Adaptive Now

Hotspots are no longer based on a user-selected `cell_size_m` UI control.

Instead, the backend builds adaptive hotspots with a clustering pipeline based on the filtered dataset:

- clustering via DBSCAN
- `eps_m` derived from local nearest-neighbor density and clamped to a safe range
- `min_samples` adjusted for small datasets
- per-hotspot `radius_m` derived from member dispersion, not fixed tactical cells

## Heatmap vs Hotspots

The heatmap remains useful for density and opportunity overlays.

Hotspots are now a separate analytical layer that returns:

- `members_count`
- `candidate_macs`
- `extent_bbox`
- `mesh`
- `algorithm` / `algorithm_meta`
- `recommended_action`

The map highlights a hotspot only when it is selected from the list.

## Mesh-Based Map Highlighting

The analytics hotspot payload now includes a `mesh` representation for each hotspot. This enables the frontend to highlight an influence area that follows the actual cluster geometry more closely than the old fixed-radius-only mental model.

## Hotspot Details

Hotspot Details focuses on actionable information instead of dumping the full cluster membership.

Current behavior:

- `candidate_macs` are ranked in the backend
- the frontend displays a capped subset in the details panel
- `ADD TO TARGETS` uses prioritized candidate MACs and adds up to 8 unique candidates per action

The ranking favors:

- locked targets
- not-yet-cracked targets
- stronger RAW EAPOL evidence
- higher opportunity score
- fresher observations

## Filters

Analytics still supports the current common filters:

- metric
- time window (`all`, `24h`)
- source
- security
- device type
- channel

The old hotspot `cell_size_m` selector is gone from the UI. The backend still accepts `cell_size_m` on `/api/analytics/hotspots` for compatibility, but the parameter is deprecated and ignored by hotspot generation.

## WarDrive Context in Analytics

Analytics also shows non-filtering WarDrive context in the right panel, including:

- session count
- networks count
- points count
- top transport modes (up to 8)

This context respects the selected analytics `time_window` but does not turn Analytics into a WarDrive-session filter in this phase.

## Related Endpoints

- `GET /api/analytics/heatmap`
- `GET /api/analytics/hotspots`
- `GET /api/analytics/channel-summary`
