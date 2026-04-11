# KOVIL MAP - Frontend

![Electron](https://img.shields.io/badge/Electron-28-blue.svg) ![Stack](https://img.shields.io/badge/Renderer-Vanilla%20JS-green.svg) ![License](https://img.shields.io/badge/License-MIT-green.svg)

The frontend is an Electron application with a vanilla JavaScript renderer. It owns the tactical map UI, the workspace transitions, the popup experience, and the operational panels that sit on top of the local backend.

## Current UI Surface

### Top workspaces

The primary workspace buttons are:

- `ANALYTICS`
- `WARDRIVE`
- `SNIFFER`

They live in the right-side top action group and coordinate panel suspension/restoration across the map UI.

### Core panels

- left sidebar panels styled in the same visual language as WarDrive
- Cracking Operations, Processes, and Logs on the right when not suspended by a workspace
- dedicated WarDrive sessions panel with sorting, vehicle tags, and session filtering
- dedicated RAW Sniffer center panel for RAW file processing and inspection
- analytics panels for filters, summaries, hotspots, and hotspot details
- Recon Center with Surface, Intel, Ops, Geo, SIGINT, Report, and COMMS views

### Map interactions

- cluster, heatmap, conquered, to-conquer, discovered, and Intelligence Zone layers
- modern popup cards with themed sections: overview, signal, security, RAW, and access
- inline actions for favorites, targets, password visibility, and cracking entry

### Visual themes

- Cyberpunk, Professional, Synthwave, and Military visual themes
- Cyberpunk uses the sharper legacy look for popups, System Configuration, and left-panel cards
- the other themes apply their own tailored overrides without changing functional behavior

## Tech Stack

- Electron 28
- Vanilla JavaScript ES modules
- Leaflet and related plugins
- CSS variables and theme-driven styling
- Jest for renderer unit tests

## Project Structure

```text
frontend/
  main.js                     Electron main process
  preload.js                  secure bridge
  package.json
  src/
    index.html
    renderer.js
    css/
      cyberpunk.css
      styles.css
    modules/
      api.js
      map.js
      state.js
      ui.js
      ui_analytics.js
      ui_wardrive.js
      ui_raw.js
      ui_components/
```

## Development

Install dependencies:

```bash
cd frontend
npm install
```

Run the renderer:

```bash
npm start
```

In development mode, start the backend separately first or use the root launcher scripts:

- macOS: `./run_dev_mac.sh`
- Windows: `run_dev.bat`

## Build

```bash
cd frontend
npm run dist
```

The Electron build expects the packaged backend artifact in the location defined by `package.json`.

## Tests and Lint

```bash
npm run lint
npm run test:unit
npm run test:unit:coverage
```

## Notes for Contributors

- the renderer does not use React, Redux, or component frameworks
- state is coordinated through module-level stores and DOM-driven rendering helpers
- keep feature logic inside focused modules (`ui_wardrive.js`, `ui_analytics.js`, `ui_components/ui_cracking.js`, etc.)
- preserve the current secure Electron setup: `contextIsolation`, `sandbox`, and preload-mediated IPC

## Related Documentation

- [`../README.md`](../README.md)
- [`../docs/INDEX.md`](../docs/INDEX.md)
- [`../docs/01-ARCHITECTURE/frontend-structure.md`](../docs/01-ARCHITECTURE/frontend-structure.md)
- [`../docs/07-OPERATIONS/map-operations.md`](../docs/07-OPERATIONS/map-operations.md)
