"""Common finding format shared by ZAP results and custom checks."""
from dataclasses import dataclass, field, asdict


@dataclass
class Finding:
    title: str
    source: str              # "ZAP" or "Custom:<check>"
    url: str
    owasp: str = ""          # e.g. "A05:2021 Security Misconfiguration"
    cwe: int = 0
    param: str = ""
    evidence: str = ""
    description: str = ""
    likelihood: int = 2      # 1 (low) .. 3 (high)
    impact: int = 2          # 1 (low) .. 3 (high)
    confidence: str = "Medium"
    severity: str = ""       # filled by scoring
    risk_score: int = 0      # filled by scoring
    remediation: str = ""    # filled by remediation library
    extra: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)
