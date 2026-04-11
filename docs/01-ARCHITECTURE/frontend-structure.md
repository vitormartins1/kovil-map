# Frontend Structure

The frontend uses Electron and a vanilla JavaScript renderer organized by domain instead of a component framework runtime.

## Main Pieces

### Electron main process

- owns the application window lifecycle
- can spawn the packaged backend in production scenarios
- handles native OS integrations through secure IPC

### Preload bridge

- exposes a limited `window.desktop` surface
- keeps `contextIsolation` and sandbox guarantees intact

### Renderer

- renders `index.html`
- loads ES modules from `src/modules/`
- coordinates the map, workspaces, popups, and panels

## Current Source Layout

```text
frontend/src/
  index.html
  renderer.js
  css/
    cyberpunk.css
    styles.css
  modules/
    api.js
    attack_modes.js
    cache_store.js
    config.js
    layout.js
    map.js
    map_wardrive_helpers.js
    map_raw.js
    platform.js
    socket.js
    state.js
    ui.js
    ui_analytics.js
    ui_multi.js
    ui_raw.js
    ui_recon.js
    ui_shell.js
    ui_wardrive.js
    recon/
      attack_surface_tab.js
      cache.js
      comms_tab.js
      geoint_tab.js
      operations_tab.js
      reports_tab.js
      sigint_tab.js
      sigint_graph_helpers.js
      target_intel_tab.js
      target_detail_flow.js
      ui_helpers.js
    wardrive/
      loading.js
      route_replay.js
    ui_components/
      ui_cracking.js
      ui_history.js
      ui_hints.js
      ui_lists.js
      ui_processes.js
      ui_settings.js
```

## Domain Split

- `api.js` - backend HTTP wrapper
- `socket.js` - WebSocket event distribution
- `map.js` - Leaflet rendering, popups, and overlays
- `map_wardrive_helpers.js` - pure geometry, replay and palette helpers shared inside the map layer
- `cache_store.js` - shared `sessionStorage` helpers used by feature-local caches
- `state.js` - shared UI/application state
- `ui.js` - global boot and top-level interactions
- `ui_shell.js` - startup shell and title-bar presentation helpers
- `ui_analytics.js` - analytics workspace
- `ui_recon.js` - Recon Center shell, orchestration, and tab wiring
- `ui_wardrive.js` - WarDrive workspace
- `ui_raw.js` - RAW Sniffer center panel
- `ui_multi.js` - batch/multi-file workspace
- `recon/` - Recon-specific cache and shared rendering helpers
  `attack_surface_tab.js` now owns the Attack Surface tab renderer and stage hydration flow
  `comms_tab.js` now owns the COMMS tab renderer, charts, and relationship-graph drawing flow
  `geoint_tab.js` now owns the GEOINT tab renderer, temporal activity views, and source/spatial coverage panels
  `operations_tab.js` now owns the Operations tab renderer, active-job polling, and attack-planner flow
  `reports_tab.js` now owns the Reports tab renderer, historical snapshot comparison, and checklist/data-quality flow
  `sigint_tab.js` now owns the SIGINT tab renderer, probe-intel loading states, and async enrichment panels
  `sigint_graph_helpers.js` now owns SIGINT geocorrelation and communication-graph helper/render logic
  `target_intel_tab.js` now owns the Target Intel tab renderer, threat-analysis lazy state, pagination, and table interactions
  `target_detail_flow.js` now owns target selection, drawer/right-panel detail rendering, and target-detail history hydration
- `wardrive/` - WarDrive-specific helpers extracted from the workspace shell
  `route_replay.js` now owns the Route Replay renderer, loading shell, and live control-state sync
- `ui_components/` - reusable operational panels

## Current Refactoring Direction

- keep feature entrypoints (`ui_recon.js`, `ui_wardrive.js`) as orchestration shells
- extract cache/session-storage logic into dedicated helpers instead of embedding it in renderers
- move visual microcomponents and loading/skeleton builders into feature-local modules
- preserve the vanilla JS + ES module architecture while reducing file-level monoliths

## State Layers

- `state.js` remains the shared runtime state container for global app modes and selections
- feature-specific caches should live in feature-local helpers and persist only stable snapshots
- view-only UI details such as expanded sections, sort mode, local filters, or drawers should stay inside feature modules instead of leaking into global state
