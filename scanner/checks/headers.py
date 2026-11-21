"""Checks for missing or weak HTTP security headers."""
from ..models import Finding

OWASP = "A05:2021 Security Misconfiguration"

REQUIRED = [
    # header, cwe, likelihood, impact, why it matters
    ("Content-Security-Policy", 693, 2, 3, "No CSP: injected scripts (XSS) run without restriction."),
    ("X-Frame-Options", 1021, 2, 2, "Page can be framed by other sites (clickjacking)."),
    ("X-Content-Type-Options", 693, 1, 2, "Browser may MIME-sniff responses into executable types."),
    ("Referrer-Policy", 200, 1, 1, "Full URLs (possibly with tokens) leak in the Referer header."),
    ("Permissions-Policy", 693, 1, 1, "Browser features (camera, mic, geolocation) are not restricted."),
]


def check_security_headers(url, session):
    r = session.get(url, timeout=10, allow_redirects=True)
    h = {k.lower(): v for k, v in r.headers.items()}
    out = []
    report_only = h.get("content-security-policy-report-only", "")
    for name, cwe, li, im, why in REQUIRED:
        if name.lower() not in h:
            # Frame protection can also come from CSP frame-ancestors.
            if name == "X-Frame-Options" and "frame-ancestors" in h.get("content-security-policy", ""):
                continue
            if name == "Content-Security-Policy" and report_only:
                # A policy exists but only reports violations; it blocks nothing yet.
                out.append(Finding(
                    title="Content-Security-Policy in report-only mode (not enforced)",
                    source="Custom:headers", url=r.url, owasp=OWASP, cwe=693, param=name,
                    evidence="Content-Security-Policy-Report-Only: " + report_only[:180],
                    description="The site monitors CSP violations but does not block them, so injected "
                                "scripts would still run. Switch to an enforced Content-Security-Policy "
                                "once the reports are clean.",
                    likelihood=2, impact=2, confidence="High",
                ))
                continue
            out.append(Finding(
                title=f"Missing {name} header", source="Custom:headers", url=r.url,
                owasp=OWASP, cwe=cwe, param=name, evidence="Header not present in response",
                description=why, likelihood=li, impact=im, confidence="High",
            ))
    csp = h.get("content-security-policy", "")
    if csp and is_weak_csp(csp):
        script = _script_directive(csp)
        bad = [t for t in ("'unsafe-eval'", "'unsafe-inline'") if t in script]
        out.append(Finding(
            title="Weak Content-Security-Policy", source="Custom:headers", url=r.url,
            owasp=OWASP, cwe=693, param="Content-Security-Policy",
            evidence=f"Policy contains {' and '.join(bad)}: {csp[:160]}",
            description=f"The script policy allows {' and '.join(bad)}. 'unsafe-eval' lets scripts turn text "
                        "into code with eval(), and 'unsafe-inline' lets inline scripts run, so an XSS bug "
                        "is easier to exploit.",
            likelihood=2, impact=2, confidence="High",
        ))
    return out


def is_weak_csp(csp):
    """'unsafe-eval' is always weak. 'unsafe-inline' is ignored by modern browsers
    when the same policy uses a nonce, a hash or 'strict-dynamic' (it is kept
    only as a fallback for old browsers), so that combination is not weak."""
    script = _script_directive(csp)
    if "'unsafe-eval'" in script:
        return True
    if "'unsafe-inline'" in script:
        return not any(t in script for t in ("'nonce-", "'sha256-", "'sha384-", "'sha512-", "'strict-dynamic'"))
    return False


def _script_directive(csp):
    """The directive that governs scripts: script-src, or default-src if absent."""
    parts = [d.strip() for d in csp.lower().split(";")]
    return next((d for d in parts if d.startswith("script-src ")), "") or \
        next((d for d in parts if d.startswith("default-src ")), "")
