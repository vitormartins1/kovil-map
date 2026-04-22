# KOVIL MAP Documentation Hub

This is the canonical documentation index for the repository. Use `docs/` as the reference path in READMEs, links, and contributor notes.

## Repository Essentials

- [`../README.md`](../README.md)
- [`../CONTRIBUTING.md`](../CONTRIBUTING.md)
- [`../SECURITY.md`](../SECURITY.md)
- [`../CODE_OF_CONDUCT.md`](../CODE_OF_CONDUCT.md)
- [`../LICENSE`](../LICENSE)

## Start Here

### Getting Started

- [`00-GETTING_STARTED/README.md`](00-GETTING_STARTED/README.md)
- [`00-GETTING_STARTED/product-overview.md`](00-GETTING_STARTED/product-overview.md)
- [`00-GETTING_STARTED/installation.md`](00-GETTING_STARTED/installation.md)
- [`00-GETTING_STARTED/first-run.md`](00-GETTING_STARTED/first-run.md)
- [`00-GETTING_STARTED/current-product-surface.md`](00-GETTING_STARTED/current-product-surface.md)
- [`00-GETTING_STARTED/runtime-modes.md`](00-GETTING_STARTED/runtime-modes.md)
- [`00-GETTING_STARTED/manual-import-layout.md`](00-GETTING_STARTED/manual-import-layout.md)
- [`00-GETTING_STARTED/common-issues.md`](00-GETTING_STARTED/common-issues.md)
- [`00-GETTING_STARTED/demo-mode.md`](00-GETTING_STARTED/demo-mode.md)

### Architecture

- [`01-ARCHITECTURE/README.md`](01-ARCHITECTURE/README.md)
- [`01-ARCHITECTURE/system-design.md`](01-ARCHITECTURE/system-design.md)
- [`01-ARCHITECTURE/data-flow.md`](01-ARCHITECTURE/data-flow.md)
- [`01-ARCHITECTURE/api-overview.md`](01-ARCHITECTURE/api-overview.md)
- [`01-ARCHITECTURE/frontend-structure.md`](01-ARCHITECTURE/frontend-structure.md)

### Features

- [`02-FEATURES/README.md`](02-FEATURES/README.md)
- [`02-FEATURES/spatial-normalization.md`](02-FEATURES/spatial-normalization.md)
- [`02-FEATURES/wardrive-import.md`](02-FEATURES/wardrive-import.md)
- [`02-FEATURES/raw-sniffer.md`](02-FEATURES/raw-sniffer.md)
- [`02-FEATURES/cracking-engine.md`](02-FEATURES/cracking-engine.md)
- [`02-FEATURES/tactical-analytics.md`](02-FEATURES/tactical-analytics.md)
- [`02-FEATURES/batch-cracking.md`](02-FEATURES/batch-cracking.md)
- [`02-FEATURES/sync-remote.md`](02-FEATURES/sync-remote.md)
- [`02-FEATURES/targetlist-favorites.md`](02-FEATURES/targetlist-favorites.md)
- [`02-FEATURES/recon-center.md`](02-FEATURES/recon-center.md)

### Development

- [`03-DEVELOPMENT/README.md`](03-DEVELOPMENT/README.md)
- [`03-DEVELOPMENT/backend-setup.md`](03-DEVELOPMENT/backend-setup.md)
- [`03-DEVELOPMENT/frontend-setup.md`](03-DEVELOPMENT/frontend-setup.md)
- [`03-DEVELOPMENT/testing.md`](03-DEVELOPMENT/testing.md)
- [`03-DEVELOPMENT/debugging.md`](03-DEVELOPMENT/debugging.md)
- [`03-DEVELOPMENT/scripts-reference.md`](03-DEVELOPMENT/scripts-reference.md)
- [`03-DEVELOPMENT/maps-country-packs.md`](03-DEVELOPMENT/maps-country-packs.md)

### Integrations

- [`04-INTEGRATIONS/pwnagotchi.md`](04-INTEGRATIONS/pwnagotchi.md)
- [`04-INTEGRATIONS/m5evil-cardputer.md`](04-INTEGRATIONS/m5evil-cardputer.md)
- [`04-INTEGRATIONS/hashcat.md`](04-INTEGRATIONS/hashcat.md)
- [`04-INTEGRATIONS/aircrack-ng.md`](04-INTEGRATIONS/aircrack-ng.md)
- [`04-INTEGRATIONS/hcxtools.md`](04-INTEGRATIONS/hcxtools.md)
- [`04-INTEGRATIONS/ssh-sftp-remote.md`](04-INTEGRATIONS/ssh-sftp-remote.md)

### API Reference

- [`05-API-ENDPOINTS/reference.md`](05-API-ENDPOINTS/reference.md)
- [`05-API-ENDPOINTS/config-runtime-endpoints.md`](05-API-ENDPOINTS/config-runtime-endpoints.md)
- [`05-API-ENDPOINTS/analytics-endpoints.md`](05-API-ENDPOINTS/analytics-endpoints.md)
- [`05-API-ENDPOINTS/map-endpoints.md`](05-API-ENDPOINTS/map-endpoints.md)
- [`05-API-ENDPOINTS/cracking-endpoints.md`](05-API-ENDPOINTS/cracking-endpoints.md)
- [`05-API-ENDPOINTS/recon-endpoints.md`](05-API-ENDPOINTS/recon-endpoints.md)
- [`05-API-ENDPOINTS/operations-endpoints.md`](05-API-ENDPOINTS/operations-endpoints.md)
- [`05-API-ENDPOINTS/rawsniffer-endpoints.md`](05-API-ENDPOINTS/rawsniffer-endpoints.md)
- [`05-API-ENDPOINTS/sync-endpoints.md`](05-API-ENDPOINTS/sync-endpoints.md)
- [`05-API-ENDPOINTS/websocket-events.md`](05-API-ENDPOINTS/websocket-events.md)

### Code Examples

- [`06-CODE-EXAMPLES/README.md`](06-CODE-EXAMPLES/README.md)
- [`06-CODE-EXAMPLES/frontend-integration.js`](06-CODE-EXAMPLES/frontend-integration.js)
- [`06-CODE-EXAMPLES/adding-new-feature.md`](06-CODE-EXAMPLES/adding-new-feature.md)
- [`06-CODE-EXAMPLES/common-patterns.md`](06-CODE-EXAMPLES/common-patterns.md)

### Operations

- [`07-OPERATIONS/workflows-by-objective.md`](07-OPERATIONS/workflows-by-objective.md)
- [`07-OPERATIONS/map-operations.md`](07-OPERATIONS/map-operations.md)
- [`07-OPERATIONS/cracking-workflow.md`](07-OPERATIONS/cracking-workflow.md)
- [`07-OPERATIONS/remote-sync-howto.md`](07-OPERATIONS/remote-sync-howto.md)
- [`07-OPERATIONS/batch-cracking-howto.md`](07-OPERATIONS/batch-cracking-howto.md)
- [`07-OPERATIONS/troubleshooting.md`](07-OPERATIONS/troubleshooting.md)

### Security and Roadmap

- [`08-SECURITY/`](08-SECURITY/)
- [`09-ROADMAP/`](09-ROADMAP/)

## Recommended Launch Paths

### Understand the product first

- [`00-GETTING_STARTED/product-overview.md`](00-GETTING_STARTED/product-overview.md)
- [`00-GETTING_STARTED/current-product-surface.md`](00-GETTING_STARTED/current-product-surface.md)
- [`07-OPERATIONS/workflows-by-objective.md`](07-OPERATIONS/workflows-by-objective.md)

### Manual development

Backend:

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

Frontend:

```bash
cd frontend
npm install
npm start
```

### Root launchers

- macOS: `./run_dev_mac.sh`
- Windows: `run_dev.bat`

## Publishing Notes

- root docs are the public entrypoint for community and governance
- `backend/config.json` is a sanitized starter file, but local edits may contain secrets
- `backend/data/` is primarily local runtime state and should not receive real operational data in tracked files
