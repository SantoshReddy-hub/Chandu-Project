#!/usr/bin/env bash
# One-time setup on macOS or Linux. Run from the project folder:  ./setup.sh
set -e
cd "$(dirname "$0")"

PY=""
for c in python3.11 python3.12 python3; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then PY="$c"; break; fi
done
[ -n "$PY" ] || { echo "Python 3.10 or newer is required (3.11 recommended). Install it from https://www.python.org/downloads/"; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "Docker is required. Install Docker Desktop: https://www.docker.com/products/docker-desktop/"; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker is installed but not running. Open Docker Desktop, wait until it says 'running', then run ./setup.sh again."; exit 1; }

echo "==> Using $($PY --version)"
[ -d .venv ] || "$PY" -m venv .venv
.venv/bin/python -m pip install --upgrade pip --quiet
.venv/bin/pip install -r requirements.txt --quiet
echo "==> Python packages installed"

if [ ! -f .env ]; then
  KEY=$(.venv/bin/python -c 'import secrets; print(secrets.token_hex(24))')
  sed "s/^ZAP_API_KEY=.*/ZAP_API_KEY=$KEY/" .env.example > .env
  echo "==> Created .env with a random ZAP API key"
fi

echo "==> Downloading and starting the lab (ZAP, DVWA, Juice Shop). The first time takes a few minutes..."
docker compose up -d
echo
echo "Setup complete. Start the scanner with:  ./run.sh"
