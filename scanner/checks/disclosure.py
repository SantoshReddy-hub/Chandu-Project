"""Detects server/framework version banners and verbose error pages."""
import re
from urllib.parse import urljoin
from ..models import Finding

OWASP = "A05:2021 Security Misconfiguration"
VERSION_RE = re.compile(r"\d+\.\d+")
ERROR_MARKERS = [
    "Traceback (most recent call last)", "Fatal error:", "Warning: mysql",
    "at java.", "Stack trace:", "System.NullReferenceException", "SQLSTATE[",
]


def check_info_disclosure(url, session):
    out = []
    r = session.get(url, timeout=10)
    for hdr in ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"):
        v = r.headers.get(hdr)
        if v and VERSION_RE.search(v):
            out.append(Finding(
                title=f"Version disclosed in {hdr} header", source="Custom:disclosure", url=r.url,
                owasp=OWASP, cwe=497, param=hdr, evidence=f"{hdr}: {v}",
                description="Exact software versions help attackers find matching known exploits.",
                likelihood=2, impact=1, confidence="High",
            ))

    # Request a missing page and look for stack traces / framework errors.
    err = session.get(urljoin(url if url.endswith("/") else url + "/", "nonexistent-%7B%7D.php"), timeout=10)
    body = err.text[:20000]
    for m in ERROR_MARKERS:
        if m in body:
            out.append(Finding(
                title="Verbose error message", source="Custom:disclosure", url=err.url,
                owasp=OWASP, cwe=209, evidence=m,
                description="Error pages reveal internal details such as stack traces or file paths.",
                likelihood=2, impact=2, confidence="Medium",
            ))
            break
    return out
