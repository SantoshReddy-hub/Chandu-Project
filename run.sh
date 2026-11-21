#!/usr/bin/env bash
# Start the lab and the dashboard on macOS or Linux:  ./run.sh
set -e
cd "$(dirname "$0")"
docker info >/dev/null 2>&1 || { echo "Docker is not running. Open Docker Desktop first."; exit 1; }
docker compose up -d
echo "Opening the scanner at http://localhost:8501  (press Ctrl+C here to stop it)"
.venv/bin/streamlit run app.py --server.port 8501
