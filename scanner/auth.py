"""Logs in to lab targets so scans can cover pages behind the login."""
import re

import requests

from .config import DVWA_PASS, DVWA_USER

TOKEN_RE = re.compile(r"name='user_token' value='([0-9a-f]+)'")


def _dvwa_try_login(s, base_url):
    r = s.get(base_url + "/login.php", timeout=10)
    r = s.post(base_url + "/login.php", timeout=10, data={
        "username": DVWA_USER, "password": DVWA_PASS, "Login": "Login",
        "user_token": TOKEN_RE.search(r.text).group(1),
    })
    return "logout" in r.text.lower()


def dvwa_reset_db(base_url):
    """Recreate DVWA's lab database (restores the default account)."""
    s = requests.Session()
    r = s.get(base_url + "/setup.php", timeout=10)
    s.post(base_url + "/setup.php", timeout=30, data={
        "create_db": "Create / Reset Database", "user_token": TOKEN_RE.search(r.text).group(1)})


def dvwa_login(base_url):
    """Log in to DVWA, set security level to 'low', return (session, cookie header).
    If an earlier scan changed the lab password, reset the lab DB and retry once."""
    s = requests.Session()
    if not _dvwa_try_login(s, base_url):
        dvwa_reset_db(base_url)
        s = requests.Session()
        if not _dvwa_try_login(s, base_url):
            raise RuntimeError("DVWA login failed even after resetting its database")
    jar = {c.name: c.value for c in s.cookies}
    jar["security"] = "low"
    s.cookies.clear()
    for k, v in jar.items():
        s.cookies.set(k, v)
    cookie = "; ".join(f"{k}={v}" for k, v in jar.items())
    return s, cookie


LOGINS = {"dvwa": dvwa_login}
