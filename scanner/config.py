"""Central configuration: ZAP connection, lab presets and URL handling."""
import os
from urllib.parse import urlparse


def _load_dotenv():
    """Read KEY=value lines from the project's .env file (if any) into the environment,
    without overriding variables that are already set. docker compose reads the same file."""
    path = os.path.join(os.path.dirname(__file__), "..", ".env")
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                if value.strip():
                    os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv()

ZAP_API_URL = os.getenv("ZAP_API_URL", "http://127.0.0.1:8090")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "changeme-lab-key")

DB_PATH = os.getenv("SCANNER_DB", os.path.join(os.path.dirname(__file__), "..", "data", "scans.db"))
REPORT_DIR = os.path.join(os.path.dirname(__file__), "..", "reports")

# Lab presets: extra settings (login, exclusions) used automatically when a
# pasted URL points at the local DVWA or Juice Shop. `url` is what this machine uses; `zap_url` is what the
# ZAP container uses inside the Docker network.
LAB_TARGETS = {
    "DVWA": {
        "url": "http://127.0.0.1:8081", "zap_url": "http://dvwa", "auth": "dvwa",
        # Pages that would log ZAP out or wipe the lab database.
        # The CSRF demo form changes the admin password when submitted, which locks the scan out.
        "exclude": [r".*logout\.php.*", r".*setup\.php.*", r".*security\.php.*", r".*phpinfo\.php.*",
                    r".*/vulnerabilities/csrf/.*password_new.*"],
    },
    "OWASP Juice Shop": {
        "url": "http://127.0.0.1:3000", "zap_url": "http://juice-shop:3000",
        "exclude": [r".*socket\.io.*"],
        # Single-page app: crawl with a headless browser and seed known API routes.
        "ajax": True,
        "seeds": ["/rest/products/search?q=apple", "/api/Products", "/api/Feedbacks",
                  "/api/Challenges", "/rest/languages", "/rest/user/whoami"],
    },
}

# DVWA's published default lab account (local Docker lab only).
DVWA_USER = os.getenv("DVWA_USER", "admin")
DVWA_PASS = os.getenv("DVWA_PASS", "password")


def lab_target_for(url: str):
    for t in LAB_TARGETS.values():
        if url.startswith(t["url"]):
            return t
    return None

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}


class InvalidTarget(ValueError):
    pass


def normalize_url(raw: str) -> str:
    """Clean up a URL the customer pasted: trim, add https:// if missing, validate."""
    url = (raw or "").strip()
    if not url:
        raise InvalidTarget("Please enter a URL.")
    if "://" not in url:
        local = url.split("/")[0].split(":")[0].lower() in LOCAL_HOSTS
        url = ("http://" if local else "https://") + url
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        raise InvalidTarget("Only http:// and https:// URLs can be scanned.")
    if not p.hostname or ("." not in p.hostname and p.hostname not in LOCAL_HOSTS):
        raise InvalidTarget(f"'{raw}' does not look like a valid website address.")
    if p.hostname == "localhost":  # one spelling, so lab presets match
        url = url.replace("localhost", "127.0.0.1", 1)
    return url.rstrip("/") if p.path in ("", "/") else url


def is_local(url: str) -> bool:
    return (urlparse(url).hostname or "").lower() in LOCAL_HOSTS


def zap_url_for(url: str) -> str:
    """Translate a URL into the address ZAP sees from inside its Docker container."""
    for t in LAB_TARGETS.values():
        if url.startswith(t["url"]):
            return t["zap_url"] + url[len(t["url"]):]
    p = urlparse(url)
    if (p.hostname or "") in LOCAL_HOSTS:  # a site running on this Mac
        return url.replace(p.hostname, "host.docker.internal", 1)
    return url


def host_url_for(zap_side_url: str) -> str:
    """Reverse of zap_url_for, so results show the URL the customer entered."""
    for t in LAB_TARGETS.values():
        if zap_side_url.startswith(t["zap_url"]):
            return t["url"] + zap_side_url[len(t["zap_url"]):]
    return zap_side_url.replace("host.docker.internal", "127.0.0.1", 1)
