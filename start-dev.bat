@echo off
setlocal

cd /d "%~dp0"

where python >nul 2>&1
if errorlevel 1 (
  echo [OCP] Python was not found in PATH.
  echo [OCP] Install Python 3.12+ and try again.
  exit /b 1
)

where npm >nul 2>&1
if errorlevel 1 (
  echo [OCP] npm was not found in PATH.
  echo [OCP] Install Node.js 20+ and try again.
  exit /b 1
)

if not exist "frontend\node_modules" (
  echo [OCP] frontend\node_modules was not found.
  echo [OCP] Run "cd frontend && npm install" first.
)

echo [OCP] Starting backend on http://localhost:8001
start "OCP Backend" cmd /k "cd /d ""%~dp0"" && python -m uvicorn backend.app.main:app --reload --port 8001"

echo [OCP] Starting frontend on http://localhost:5173
start "OCP Frontend" cmd /k "cd /d ""%~dp0frontend"" && npm run dev"

echo [OCP] Launcher started. Open http://localhost:5173 in your browser.
exit /b 0
