# Getting Started

This section helps you bring KOVIL MAP online quickly and points you to the next document that fits your role.

## Start Here

- [`installation.md`](installation.md) - system requirements and setup
- [`first-run.md`](first-run.md) - first launch, sync, and UI orientation
- [`manual-import-layout.md`](manual-import-layout.md) - current folder layout for manual imports
- [`common-issues.md`](common-issues.md) - common local problems and fixes
- [`demo-mode.md`](demo-mode.md) - safe demo workflow with mock data

## Fast Local Start

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

### Frontend

```bash
cd frontend
npm install
npm start
```

### Convenience Launchers

- macOS: `./run_dev_mac.sh`
- Windows: `run_dev.bat`

## What Happens on First Launch

- the backend creates local data and config directories if needed
- the frontend connects to `http://127.0.0.1:8000`
- the map loads the cached dataset from the backend
- workspaces such as Analytics, WarDrive, and Raw Sniffer remain opt-in and inactive at boot

## Suggested Next Steps

- explore the UI: [`first-run.md`](first-run.md)
- understand workflows: [`../07-OPERATIONS/`](../07-OPERATIONS/)
- configure development: [`../03-DEVELOPMENT/`](../03-DEVELOPMENT/)
