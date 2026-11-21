@echo off
REM One-time setup on Windows. Double-click this file, or run it from the project folder.
cd /d "%~dp0"

where py >nul 2>nul
if errorlevel 1 (
  echo Python is required. Install Python 3.11 from https://www.python.org/downloads/ and tick "Add python.exe to PATH".
  pause & exit /b 1
)
py -3.11 --version >nul 2>nul && (set "PY=py -3.11") || (set "PY=py -3")

where docker >nul 2>nul
if errorlevel 1 (
  echo Docker is required. Install Docker Desktop: https://www.docker.com/products/docker-desktop/
  pause & exit /b 1
)
docker info >nul 2>nul
if errorlevel 1 (
  echo Docker is installed but not running. Open Docker Desktop, wait until it says "running", then run setup.bat again.
  pause & exit /b 1
)

if not exist .venv %PY% -m venv .venv
.venv\Scripts\python -m pip install --upgrade pip --quiet
.venv\Scripts\pip install -r requirements.txt --quiet
echo ==^> Python packages installed

if not exist .env (
  for /f %%k in ('.venv\Scripts\python -c "import secrets; print(secrets.token_hex(24))"') do set "KEY=%%k"
  .venv\Scripts\python -c "import os,re; t=open('.env.example').read(); open('.env','w').write(re.sub(r'(?m)^ZAP_API_KEY=.*$', 'ZAP_API_KEY='+os.environ['KEY'], t))"
  echo ==^> Created .env with a random ZAP API key
)

echo ==^> Downloading and starting the lab (ZAP, DVWA, Juice Shop). The first time takes a few minutes...
docker compose up -d
echo.
echo Setup complete. Start the scanner by double-clicking run.bat
pause
