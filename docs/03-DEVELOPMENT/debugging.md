# Debugging Guide

This guide covers practical debugging techniques for KOVIL MAP.

---

## Backend

### 1. Logs

- keep the backend terminal visible in development
- in packaged builds, run the app from a terminal so logs are visible

### 2. Swagger UI

- open `http://127.0.0.1:8000/docs`
- test the endpoint directly before blaming the frontend
- if Swagger works and the UI does not, look for integration issues

### 3. PDB

Use `pdb.set_trace()` to pause execution and inspect state.

### 4. VS Code debugger

Use the standard Python launch configuration pointing at `backend/main.py`.

### 5. Inspecting data on disk

KOVIL MAP uses flat files, so you can inspect the runtime state directly:

- handshakes and map data: `backend/data/handshakes/`
- configuration: `backend/config.json`

---

## Frontend

### 1. Developer Tools

- open DevTools with `Ctrl+Shift+I` or `Cmd+Option+I`
- use the Console for JavaScript errors
- check Network for WebSocket and API calls
- add breakpoints in `src/modules/*.js`

### 2. Main process vs renderer

- renderer logs appear in DevTools
- main process logs appear in the terminal running `npm start`

### 3. Backend Busy

If the splash screen never clears, check whether the backend is reachable on port 8000 and whether `/api/health` succeeds.

---

## External Tools

### Hashcat and Aircrack

If a tool fails, copy the exact backend command from the logs and run it manually in a terminal.

### Sync and SSH

For Pwnagotchi issues, test the SSH connection manually and verify host-key settings.
