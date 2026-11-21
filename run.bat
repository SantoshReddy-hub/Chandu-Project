@echo off
REM Start the lab and the dashboard on Windows. Double-click this file.
cd /d "%~dp0"
docker info >nul 2>nul
if errorlevel 1 (
  echo Docker is not running. Open Docker Desktop first.
  pause & exit /b 1
)
docker compose up -d
echo Opening the scanner at http://localhost:8501  (close this window to stop it)
.venv\Scripts\streamlit run app.py --server.port 8501
