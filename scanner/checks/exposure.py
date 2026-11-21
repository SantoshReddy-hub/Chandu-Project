"""Looks for files and folders that should never be publicly reachable.

A "200 OK" is not proof: many sites answer every path with a normal page
(single-page apps, catch-all routes, or Instagram, where /backup.zip is the
profile of a user called "backup.zip"). So each path has a validator that
checks the response really is that kind of file, and responses that look like
the site's ordinary "page not found" page are ignored.
"""
import difflib
import re
from urllib.parse import urljoin

from ..models import Finding

MISCONF = "A05:2021 Security Misconfiguration"
BAC = "A01:2021 Broken Access Control"

LISTING_RE = re.compile(r"<title>\s*(index of /|directory listing for|listing directory)", re.I)
ENV_LINE = re.compile(r"^[A-Z][A-Z0-9_]{2,}=.*$", re.M)


def _is_html(r):
    return "html" in r.headers.get("Content-Type", "").lower() or r.text[:200].lstrip().lower().startswith(("<!doctype", "<html"))


# Each validator gets the response and returns True only if it is genuinely that file.
VALIDATORS = {
    "git":       lambda r: re.match(r"^(ref: refs/|[0-9a-f]{40}\s*$)", r.text.strip()) is not None,
    "env":       lambda r: not _is_html(r) and len(ENV_LINE.findall(r.text[:5000])) >= 2,
    "phpinfo":   lambda r: "PHP Version" in r.text and ("phpinfo()" in r.text or "PHP License" in r.text)
                           and ("Configuration File" in r.text or "System" in r.text),
    "php_src":   lambda r: not _is_html(r) and "<?php" in r.text[:2000],
    "zip":       lambda r: r.content[:4] == b"PK\x03\x04",
    "listing":   lambda r: LISTING_RE.search(r.text[:3000]) is not None,
    "apache":    lambda r: "Apache Server Status" in r.text,
    "robots":    lambda r: not r.text.lstrip().startswith("<") and re.search(r"^\s*disallow\s*:\s*\S", r.text, re.I | re.M) is not None,
}

# path, title, cwe, owasp, likelihood, impact, validator
PATHS = [
    (".git/HEAD", "Exposed Git repository", 538, MISCONF, 3, 3, "git"),
    (".env", "Exposed environment file", 538, MISCONF, 3, 3, "env"),
    ("phpinfo.php", "Exposed phpinfo() page", 200, MISCONF, 3, 2, "phpinfo"),
    ("config.php.bak", "Exposed config backup", 530, MISCONF, 3, 3, "php_src"),
    ("backup.zip", "Exposed backup archive", 530, MISCONF, 2, 3, "zip"),
    ("ftp/", "Exposed file directory (directory listing)", 548, BAC, 2, 2, "listing"),
    ("server-status", "Exposed Apache server-status", 200, MISCONF, 2, 2, "apache"),
    ("robots.txt", "robots.txt reveals paths", 200, MISCONF, 1, 1, "robots"),
]


def _similar(a, b):
    """Rough similarity of two pages (0..1), using page title and start of body."""
    ta = re.search(r"<title>(.*?)</title>", a, re.I | re.S)
    tb = re.search(r"<title>(.*?)</title>", b, re.I | re.S)
    if ta and tb and ta.group(1).strip() == tb.group(1).strip():
        return 1.0
    return difflib.SequenceMatcher(None, a[:3000], b[:3000]).quick_ratio()


def check_sensitive_files(url, session):
    base = url.split("?")[0]
    base = base if base.endswith("/") else base + "/"
    # What does this site answer for a path that cannot exist?
    baseline = session.get(urljoin(base, "this-path-should-not-exist-9f3a.txt"), timeout=10)
    catch_all = baseline.status_code == 200

    out = []
    for path, title, cwe, owasp, li, im, kind in PATHS:
        target = urljoin(base, path)
        try:
            r = session.get(target, timeout=10, allow_redirects=False)
        except Exception:
            continue
        if r.status_code != 200 or not VALIDATORS[kind](r):
            continue
        if catch_all and _is_html(r) and kind not in ("listing", "phpinfo", "apache") \
                and _similar(r.text, baseline.text) > 0.9:
            continue  # same as the site's catch-all page
        out.append(Finding(
            title=title, source="Custom:exposure", url=target, owasp=owasp, cwe=cwe,
            evidence=f"HTTP 200, {len(r.content)} bytes, {r.headers.get('Content-Type', 'unknown type')}; "
                     f"content verified as {kind}",
            likelihood=li, impact=im,
            description=f"{path} is publicly reachable and its content confirms it is a real "
                        f"{'directory listing' if kind == 'listing' else 'file'} that may leak sensitive information.",
            confidence="High",
        ))
    return out
