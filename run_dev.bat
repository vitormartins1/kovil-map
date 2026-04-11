@echo off
setlocal
echo Starting KOVIL MAP Development Environment...

where npm >nul 2>nul
if errorlevel 1 (
  echo npm was not found. Install Node.js before using this launcher.
  exit /b 1
)

set "PY_CMD=python"
if exist "backend\.venv\Scripts\python.exe" (
  set "PY_CMD=backend\.venv\Scripts\python.exe"
)

if not exist "frontend\node_modules" (
  echo frontend\node_modules was not found. Run npm install inside frontend\ first.
)

:: Start Backend in a new window
start "KOVIL MAP Backend" cmd /k "%PY_CMD% backend\main.py"

:: Wait a bit for backend to initialize
timeout /t 2 /nobreak >nul

:: Start Frontend
cd frontend
npm start

:: When frontend closes, the script ends (backend window stays open for debugging)
echo Frontend closed.
endlocal
