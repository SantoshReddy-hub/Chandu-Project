"""Checks whether traffic is protected by HTTPS, a valid certificate and HSTS."""
from urllib.parse import urlparse

import requests

from ..models import Finding

OWASP = "A02:2021 Cryptographic Failures"


def check_transport_security(url, session):
    out = []
    try:
        r = session.get(url, timeout=10, allow_redirects=True)
    except requests.exceptions.SSLError as e:
        out.append(Finding(
            title="Invalid or untrusted TLS certificate", source="Custom:transport", url=url,
            owasp=OWASP, cwe=295, evidence=str(e)[:200],
            description="Browsers will warn visitors, and connections can be intercepted.",
            likelihood=2, impact=3, confidence="High",
        ))
        r = session.get(url, timeout=10, allow_redirects=True, verify=False)

    if not r.url.startswith("https://"):
        has_password = 'type="password"' in r.text.lower() or "type='password'" in r.text.lower()
        out.append(Finding(
            title="Site served over plain HTTP" + (" with a login form" if has_password else ""),
            source="Custom:transport", url=r.url, owasp=OWASP, cwe=319,
            evidence="Final URL uses http://",
            description="Data, including passwords and session cookies, travels unencrypted.",
            likelihood=2, impact=3 if has_password else 2, confidence="High",
        ))
        # Does the site offer HTTPS at all?
        host = urlparse(r.url).netloc
        try:
            session.get(f"https://{host}/", timeout=5)
        except requests.RequestException:
            out[-1].evidence += "; HTTPS is not available on this host"
    elif "strict-transport-security" not in {k.lower() for k in r.headers}:
        out.append(Finding(
            title="Missing Strict-Transport-Security header", source="Custom:transport", url=r.url,
            owasp=OWASP, cwe=319, param="Strict-Transport-Security",
            evidence="HSTS header not present",
            description="Browsers may be downgraded to HTTP on first visit.",
            likelihood=1, impact=2, confidence="High",
        ))
    return out
