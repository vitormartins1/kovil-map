## Showcase Core v2 Route Sources

This directory stores the sanitized route geometry used to build the
`showcase-core-v2` demo pack.

The assets here contain only route waypoints and timing metadata:

- `timestamp`
- `lat`
- `lng`
- `altitude_m`
- `speed_kmh`
- `accuracy_m`

They intentionally do not contain any SSIDs, BSSIDs, vendors, channels, or any
other Wi-Fi observations.

Current tracked route files are built from public road-following geometry around
Rio tourist corridors. If you want to swap them for a real Wardrive trace later,
use:

```bash
cd backend
.venv313/bin/python -m app.tools.import_wigle_route_source --input path/to/export.csv --output demo_data_sources/showcase-core-v2/routes/my_route.csv
```

That tool keeps only the GPS/timestamp path and strips all Wi-Fi identity
fields. The demo builder then combines those route-only traces with a denser
synthetic Wi-Fi overlay, including cross-surface hero networks plus
corridor-only Wardrive density networks, to generate the final Wardrive CSV
files that ship in `backend/demo_data/showcase-core-v2/`.
