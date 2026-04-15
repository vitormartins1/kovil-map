# Showcase Core V3 Sources

This directory stores the sanitized source material used to build `showcase-core-v3`.

It intentionally separates:

- `seeds/`: GPX track seeds for the compact Rio tourist loops
- `routes/`: sanitized route CSVs consumed by the public demo builder
- `density_profile.json`: statistical calibration derived from a private Wardrive reference file
- `route_build_report.json`: validation output for the compact V3 corridors

Safety rules for this source tree:

- keep only route geometry and timing metadata
- never commit SSIDs, BSSIDs, vendors, channels, or other Wi-Fi identities from field captures
- use the private reference Wardrive CSV only for statistics, never for route or identity reuse

Useful commands:

```bash
cd backend
.venv313/bin/python -m app.tools.analyze_wardrive_density --input /path/to/wardriving-03.csv --output demo_data_sources/showcase-core-v3/density_profile.json
.venv313/bin/python -m app.tools.build_demo_v3_routes --density-profile demo_data_sources/showcase-core-v3/density_profile.json --seeds-root demo_data_sources/showcase-core-v3/seeds --routes-root demo_data_sources/showcase-core-v3/routes --metadata demo_data_sources/showcase-core-v3/route_build_report.json
.venv313/bin/python -m app.tools.build_demo_data --validate
```
