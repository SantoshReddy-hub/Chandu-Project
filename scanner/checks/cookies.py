"""Checks cookies set by the application for missing protection flags."""
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import requests

from ..models import Finding

OWASP = "A05:2021 Security Misconfiguration"
SESSION_HINTS = ("sess", "sid", "token", "auth", "jwt")
# Double-submit CSRF cookies must be readable by JavaScript, so HttpOnly is not expected.
CSRF_HINTS = ("csrf", "xsrf")


def _set_cookie_headers(resp):
    raw = getattr(resp.raw, "headers", None)
    if raw is not None and hasattr(raw, "get_all"):
        return raw.get_all("Set-Cookie") or []
    v = resp.headers.get("Set-Cookie")
    return [v] if v else []


def parse_set_cookie(header):
    """Split a Set-Cookie header into (name, value, {attribute: value}).
    Attributes are parsed separately so a cookie *named* '__Secure-x' is not
    mistaken for one that has the Secure flag."""
    parts = [p.strip() for p in header.split(";")]
    name, _, value = parts[0].partition("=")
    attrs = {}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        attrs[k.strip().lower()] = v.strip()
    return name.strip(), value.strip(), attrs


def is_deletion(value, attrs):
    """Servers delete a cookie by sending it empty and/or already expired.
    Such a cookie holds nothing worth protecting, so it is not a finding."""
    if value in ("", '""', "deleted"):
        return True
    max_age = attrs.get("max-age")
    if max_age is not None and max_age.lstrip("-").isdigit() and int(max_age) <= 0:
        return True
    if "expires" in attrs:
        try:
            exp = parsedate_to_datetime(attrs["expires"].replace("-", " "))
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            return exp < datetime.now(timezone.utc)
        except (TypeError, ValueError):
            pass
    return False


def _collect_set_cookies(url, session):
    """Fetch the page as a first-time visitor (a fresh session: servers only send
    a cookie the browser does not have yet, and earlier checks already received
    them) and gather Set-Cookie headers from every response, including redirects."""
    fresh = requests.Session()
    fresh.headers.update(session.headers)
    r = fresh.get(url, timeout=10, allow_redirects=True)
    seen, headers = set(), []
    for resp in r.history + [r]:
        for h in _set_cookie_headers(resp):
            name = h.split("=", 1)[0].strip()
            if name not in seen:
                seen.add(name)
                headers.append((resp.url, h))
    return headers


def check_cookie_flags(url, session):
    out = []
    for where, header in _collect_set_cookies(url, session):
        name, value, attrs = parse_set_cookie(header)
        if not name or is_deletion(value, attrs):
            continue
        is_csrf = any(h in name.lower() for h in CSRF_HINTS)
        is_session = not is_csrf and any(h in name.lower() for h in SESSION_HINTS)
        impact = 3 if is_session else 1
        evidence = header[:200]
        if "httponly" not in attrs and not is_csrf:
            out.append(Finding(
                title="Cookie without HttpOnly flag", source="Custom:cookies", url=url,
                owasp=OWASP, cwe=1004, param=name, evidence=evidence,
                description="JavaScript can read this cookie, so an XSS bug could steal it.",
                likelihood=2, impact=impact, confidence="High",
            ))
        if "samesite" not in attrs:
            out.append(Finding(
                title="Cookie without SameSite attribute", source="Custom:cookies", url=url,
                owasp=OWASP, cwe=1275, param=name, evidence=evidence,
                description="Cookie is sent on cross-site requests, which helps CSRF attacks.",
                likelihood=2, impact=min(impact, 2), confidence="High",
            ))
        if where.startswith("https") and "secure" not in attrs:
            out.append(Finding(
                title="Cookie without Secure flag", source="Custom:cookies", url=url,
                owasp=OWASP, cwe=614, param=name, evidence=evidence,
                description="Cookie can be sent over plain HTTP and intercepted.",
                likelihood=2, impact=impact, confidence="High",
            ))
    return out
