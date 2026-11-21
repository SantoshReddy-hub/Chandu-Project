"""Risk scoring: risk = likelihood (1-3) x impact (1-3), then mapped to a severity band.

  9      -> Critical
  6      -> High
  3-4    -> Medium
  2      -> Low
  1      -> Info
"""
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
CONFIDENCE_ADJ = {"False Positive": -9, "Low": -1}


def severity_for(score: int) -> str:
    if score >= 9:
        return "Critical"
    if score >= 6:
        return "High"
    if score >= 3:
        return "Medium"
    if score == 2:
        return "Low"
    return "Info"


def score(findings):
    for f in findings:
        s = max(0, f.likelihood * f.impact + CONFIDENCE_ADJ.get(f.confidence, 0))
        f.risk_score = s
        f.severity = severity_for(s)
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.index(f.severity), -f.risk_score))


# ZAP and the custom checks word the same issue differently; these aliases let
# them merge into one finding.
ALIASES = [
    ("content-security-policy", ["content security policy (csp) header not set", "missing content-security-policy"]),
    ("x-frame-options", ["anti-clickjacking", "x-frame-options"]),
    ("x-content-type-options", ["x-content-type-options"]),
    ("server", ['"server" http response', "version disclosed in server"]),
    ("strict-transport-security", ["strict-transport-security"]),
    ("cookie-httponly", ["httponly"]),
    ("cookie-samesite", ["samesite"]),
    ("cookie-secure", ["cookie without secure flag", "cookie no secure flag"]),
]


def _group_key(f):
    t, p = f.title.lower(), f.param.lower()
    for name, words in ALIASES:
        if p == name or any(w in t for w in words):
            # Cookie issues are per cookie: NID and SID missing SameSite are two findings.
            return (name, p) if name.startswith("cookie-") else name
    if p.startswith(("http://", "https://", "//")):
        # e.g. "Cross-Domain JavaScript Source File Inclusion" names each script URL
        # as the parameter; it is one issue, so list the scripts instead of repeating it.
        f.extra.setdefault("items", []).append(f.param)
        f.param = p = ""
    return (max(f.cwe, 0) or t, p)


def deduplicate(findings):
    """Merge repeats of the same issue (across pages and across engines) into one
    finding that lists every affected URL and every engine that reported it."""
    groups, out = {}, []
    for f in findings:
        k = _group_key(f)
        if k not in groups:
            f.extra.setdefault("urls", [f.url])
            f.extra.setdefault("found_by", [f.source])
            groups[k] = f
            out.append(f)
            continue
        g = groups[k]
        if f.url not in g.extra["urls"]:
            g.extra["urls"].append(f.url)
        if f.source not in g.extra["found_by"]:
            g.extra["found_by"].append(f.source)
        for item in f.extra.get("items", []):
            if item not in g.extra.setdefault("items", []):
                g.extra["items"].append(item)
        # Keep the rating of whichever engine scored it highest, as a pair.
        # (Taking the max likelihood from one and the max impact from the other
        # invented ratings neither engine gave, e.g. Low + Low -> Medium.)
        if f.likelihood * f.impact > g.likelihood * g.impact:
            g.likelihood, g.impact = f.likelihood, f.impact
        if not g.evidence and f.evidence:
            g.evidence = f.evidence
        # The custom check sees a report-only CSP, which is more precise than "not set".
        if "report-only" in f.title.lower() and "report-only" not in g.title.lower():
            g.title, g.description, g.evidence = f.title, f.description, f.evidence
            g.likelihood, g.impact = f.likelihood, f.impact
    for g in out:
        items = g.extra.get("items", [])
        if len(items) > 1:
            g.evidence = f"{len(items)} external sources, e.g. {items[0][:150]}"
        if len(g.extra["found_by"]) > 1:
            g.source = " + ".join(sorted({s.split(":")[0] for s in g.extra["found_by"]}))
    return out
