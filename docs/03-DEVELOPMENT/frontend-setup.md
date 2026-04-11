# Frontend Setup Guide

This guide explains how to set up the KOVIL MAP frontend development environment. The UI is built with Electron and vanilla JavaScript.

## Requirements

- Node.js 18+ LTS
- npm
- a running backend for full development mode

---

## Step-by-Step Setup

### 1. Enter the frontend directory

```bash
cd frontend
```

### 2. Install dependencies

```bash
npm install
```

---

## Run in Development Mode

```bash
npm start
```

Electron does not start the backend automatically in development. Start the backend in another terminal first.

Recommended flow:

1. `cd backend && python main.py`
2. `cd frontend && npm start`

---

## Build for Production

```bash
npm run dist
```

The output is written to `frontend/dist/`.

---

## Code Quality

```bash
npm run lint
npm run test:unit
```

---

## Common Troubleshooting

- **Electron failed to install** - retry after clearing the npm cache or check proxy restrictions
- **Backend Busy forever** - the frontend cannot reach `http://127.0.0.1:8000`
- **`MODULE_NOT_FOUND` on start** - run `npm install` again
