"""Domain ownership verification, required before intrusive (active) scans.

The customer proves they control a site by publishing a token at
    https://<their-domain>/.well-known/vulnscanner-verify.txt
Passive scans need no verification; active scans attack-test the site, which is
only legal with the owner's permission.
"""
import hashlib
import hmac
import os
import secrets
from urllib.parse import urlparse

import requests

from .config import is_local

VERIFY_PATH = "/.well-known/vulnscanner-verify.txt"
_KEY_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "secret.key")


def _secret() -> bytes:
    env = os.getenv("SCANNER_SECRET")
    if env:
        return env.encode()
    os.makedirs(os.path.dirname(_KEY_FILE), exist_ok=True)
    if not os.path.exists(_KEY_FILE):
        with open(_KEY_FILE, "w") as fh:
            fh.write(secrets.token_hex(32))
    return open(_KEY_FILE).read().strip().encode()


def token_for(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    return "vulnscanner-" + hmac.new(_secret(), host.encode(), hashlib.sha256).hexdigest()[:32]


def verification_url(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}{VERIFY_PATH}"


def is_verified(url: str) -> bool:
    """True if the site publishes its token (sites on this machine count as owned)."""
    if is_local(url):
        return True
    try:
        r = requests.get(verification_url(url), timeout=10, allow_redirects=False)
        return r.status_code == 200 and token_for(url) in r.text
    except requests.RequestException:
        return False
