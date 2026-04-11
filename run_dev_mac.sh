#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Starting KOVIL MAP Development Environment..."

if ! command -v npm >/dev/null 2>&1; then
  echo "npm was not found. Install Node.js before using this launcher."
  exit 1
fi

VENV_PY="$ROOT_DIR/backend/.venv/bin/python"
if [[ -x "$VENV_PY" ]]; then
  PY_CMD="$VENV_PY"
  echo "Using backend venv Python: $PY_CMD"
else
  PY_CMD="python"
  if ! command -v "$PY_CMD" >/dev/null 2>&1; then
    if command -v python3 >/dev/null 2>&1; then
      PY_CMD="python3"
    else
      echo "Python not found (python/python3) and backend/.venv/bin/python does not exist."
      exit 1
    fi
  fi
  echo "Using system Python command: $PY_CMD"
fi

if [[ ! -d "$ROOT_DIR/frontend/node_modules" ]]; then
  echo "frontend/node_modules not found. Run 'npm install' inside frontend/ first."
fi

# Start Backend in a new Terminal window/tab
osascript - "$ROOT_DIR/backend" "$PY_CMD" <<'APPLESCRIPT'
on run argv
    set backendDir to item 1 of argv
    set pyCmd to item 2 of argv
    tell application "Terminal"
        activate
        do script "cd " & quoted form of backendDir & " && " & pyCmd & " main.py"
    end tell
end run
APPLESCRIPT

# Wait a bit for backend to initialize
sleep 2

# Start Frontend in current terminal
cd "$ROOT_DIR/frontend"
npm start

# When frontend closes, the script ends (backend terminal stays open for debugging)
echo "Frontend closed."
