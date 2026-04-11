# Backend Setup Guide

This guide shows how to set up the KOVIL MAP backend development environment. The backend is built with Python and FastAPI.

## Requirements

- Python 3.12+
- Git
- Pip
- Optional external tools for real workloads:
  - `hashcat`
  - `hcxpcapngtool`
  - `aircrack-ng`
  - `tshark`

---

## Step-by-Step Setup

### 1. Enter the backend directory

```bash
cd backend
```

### 2. Create a virtual environment

```bash
# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate

# Windows PowerShell
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Windows CMD
python -m venv .venv
.\.venv\Scripts\activate.bat
```

You should see the virtual environment name in the prompt after activation.

### 3. Install dependencies

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### 4. Initial setup

On first run, the backend creates the required directories under `backend/data/`, including handshakes, wardrive data, and `config.json`.

---

## Run the Server

```bash
python main.py
```

Useful URLs:

- API: `http://127.0.0.1:8000`
- Swagger UI: `http://127.0.0.1:8000/docs`
- ReDoc: `http://127.0.0.1:8000/redoc`

---

## Run Tests

```bash
pytest
```

---

## Common Troubleshooting

- **`ModuleNotFoundError`** - activate the virtual environment and install dependencies
- **`Access Denied` on Windows** - allow scripts in PowerShell for the current process
- **`Port 8000 already in use`** - another service is already bound to the backend port
- **`Hashcat not found`** - configure the executable path in `config.json` or in the UI
