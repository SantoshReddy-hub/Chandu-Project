"""Custom security checks. Each check takes (url, session) and returns a list of Findings."""
from .headers import check_security_headers
from .cookies import check_cookie_flags
from .exposure import check_sensitive_files
from .disclosure import check_info_disclosure
from .transport import check_transport_security

ALL_CHECKS = {
    "Security headers": check_security_headers,
    "Cookie flags": check_cookie_flags,
    "Sensitive file exposure": check_sensitive_files,
    "Information disclosure": check_info_disclosure,
    "Transport security (HTTPS/HSTS)": check_transport_security,
}
