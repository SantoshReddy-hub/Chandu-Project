# Setup guide: install the scanner on a new laptop

This guide installs the Automated Web-Application Vulnerability Scanner on a fresh
Windows, macOS or Linux laptop. It takes about **20–30 minutes**, most of it downloading.

## What you need

| | Minimum |
|---|---|
| Laptop | 8 GB RAM (16 GB recommended), 10 GB free disk space |
| Internet | Needed for the first setup (about 3 GB of downloads) |
| Accounts | None (a GitHub login only if the repository is private) |

## Step 1: Install three programs

Install these once. Restart the laptop after installing Docker.

1. **Git**: <https://git-scm.com/downloads> (macOS: already installed, or run `xcode-select --install`)
2. **Python 3.11**: <https://www.python.org/downloads/release/python-3119/>
   - **Windows:** on the first installer screen, tick **"Add python.exe to PATH"**.
3. **Docker Desktop**: <https://www.docker.com/products/docker-desktop/>
   - **Windows:** accept the WSL 2 option if asked.
   - **Mac:** choose "Apple Silicon" or "Intel" to match the laptop (Apple menu → About This Mac).

Then **open Docker Desktop** and wait until it says *Engine running*.

## Step 2: Download the project

Open a terminal (**Windows:** "Command Prompt" or "PowerShell"; **Mac:** "Terminal") and run:

```bash
git clone https://github.com/SantoshReddy-hub/Chandu-Project.git vuln-scanner
cd vuln-scanner
```

If the repository is private, Git asks you to sign in to GitHub (the owner must first add your
GitHub account under the repository's **Settings → Collaborators**).

## Step 3: Run the one-time setup

**Windows:** double-click **`setup.bat`** in the `vuln-scanner` folder (or type `setup.bat` in the terminal).

**macOS / Linux:**

```bash
./setup.sh
```

The setup script:

1. Checks that Python and Docker are installed and Docker is running.
2. Creates a private Python environment (`.venv`) and installs the packages.
3. Creates a `.env` settings file with a random password for the ZAP engine.
4. Downloads and starts the lab: OWASP ZAP, DVWA and OWASP Juice Shop (first time: about 5–10 minutes).

## Step 4: Start the scanner

**Windows:** double-click **`run.bat`**.

**macOS / Linux:**

```bash
./run.sh
```

Then open **<http://localhost:8501>** in a browser. The sidebar should show
**ZAP engine connected** with a green dot (allow 1–2 minutes after Docker starts).

To stop: press **Ctrl+C** in the terminal (or close the window). The lab keeps running in
Docker in the background; stop it with `docker compose down` if you want to free memory.

## Step 5: First scan (2 minutes)

1. On **New scan**, click the **DVWA** demo target.
2. Choose **Quick**, tick the permission box, click **Start scan**.
3. When it finishes, open **Results** to see the charts, findings and fixes, and download the PDF.

DVWA's built-in lab login is `admin` / `password` if you open it yourself at
<http://127.0.0.1:8081>. The scanner logs in on its own.

## Everyday use

| Task | Windows | macOS / Linux |
|---|---|---|
| Start | Open Docker Desktop, double-click `run.bat` | Open Docker Desktop, `./run.sh` |
| Stop the dashboard | Close the window | Ctrl+C |
| Stop the lab | `docker compose down` | `docker compose down` |
| Command-line scan | `.venv\Scripts\python scan.py example.com --mode quick` | `.venv/bin/python scan.py example.com --mode quick` |
| Update to the latest version | `git pull` then `setup.bat` | `git pull` then `./setup.sh` |

## Scan modes and the law

- **Quick** and **Standard** only read what a website already shows, so they can be used on any URL.
- **Full** sends attack tests and runs only on sites you prove you own (a token file the
  dashboard explains) or on the local lab (DVWA, Juice Shop).
- Scanning systems without the owner's permission is an offence under the IT Act 2000
  (Sections 43 and 66) in India and similar laws elsewhere.

## Troubleshooting

| Problem | Fix |
|---|---|
| `python` or `py` is not recognised (Windows) | Reinstall Python 3.11 and tick "Add python.exe to PATH" |
| "Docker is not running" | Open Docker Desktop and wait for *Engine running* |
| Sidebar shows **ZAP engine not running** | Wait 1–2 minutes after starting; else run `docker compose up -d` and check `docker compose ps` |
| Port 8501 already in use | Another copy is running: close it, or run `streamlit run app.py --server.port 8502` from the `.venv` |
| Port 8081, 3000 or 8090 already in use | Another program uses it: stop that program, or change the left-hand port in `docker-compose.yml` |
| Full scan stops with "out of memory" | Give Docker more memory: Docker Desktop → Settings → Resources (6 GB or more) |
| DVWA login fails | Open <http://127.0.0.1:8081/setup.php> and click **Create / Reset Database** |
| Apple Silicon Mac: DVWA is slow | Normal: its image runs under emulation |

## What is in the project

| Path | Purpose |
|---|---|
| `app.py` | The dashboard |
| `scanner/` | Scanner engine: ZAP control, custom checks, scoring, reports |
| `scan.py`, `evaluate.py` | Command-line scan and accuracy evaluation |
| `docker-compose.yml` | The lab: ZAP, DVWA, Juice Shop (bound to this laptop only) |
| `lab/` | Test site and ground truth for accuracy measurement |
| `paper/` | Research paper (.docx), its figures and build scripts |
| `.env.example` | Settings template (setup copies it to `.env`) |
