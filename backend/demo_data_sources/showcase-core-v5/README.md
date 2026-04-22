# Showcase Core v5 Route Sources

This directory stores the sanitized route sources used to build the public
`showcase-core-v5` demo pack.

Contents:

- `seeds/`: public-safe GPX seeds used as compact corridor inputs
- `routes/`: final sanitized CSV routes with only `timestamp`, `lat`, `lng`,
  `altitude_m`, `speed_kmh`, and `accuracy_m`
- `density_profile.json`: statistical profile derived from a private Wardrive
  reference file and sanitized for public distribution
- `route_build_report.json`: per-route geometry and validation summary

Safety guarantees:

- No SSIDs, BSSIDs, vendors, channels, or observed Wi-Fi identities are stored
  in this directory.
- The density profile is used only to calibrate synthetic Wardrive generation.
- All demo networks generated from these routes remain fictional and use
  locally administered MAC addresses.
