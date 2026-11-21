"""Drives OWASP ZAP through its API: spider -> passive scan -> active scan -> alerts."""
import os
import time
from contextlib import contextmanager
from zapv2 import ZAPv2

from .config import DB_PATH, ZAP_API_KEY, ZAP_API_URL
from .models import Finding

RISK_TO_LI = {  # ZAP risk -> (likelihood, impact)
    "High": (3, 3), "Medium": (2, 2), "Low": (1, 2), "Informational": (1, 1),
}

# Rough CWE -> OWASP Top 10 (2021) mapping for the categories ZAP reports most.
CWE_TO_OWASP = {
    89: "A03:2021 Injection", 79: "A03:2021 Injection", 78: "A03:2021 Injection",
    22: "A01:2021 Broken Access Control", 352: "A01:2021 Broken Access Control",
    639: "A01:2021 Broken Access Control", 200: "A01:2021 Broken Access Control",
    693: "A05:2021 Security Misconfiguration", 1021: "A05:2021 Security Misconfiguration",
    16: "A05:2021 Security Misconfiguration", 614: "A05:2021 Security Misconfiguration",
    1004: "A05:2021 Security Misconfiguration", 1275: "A05:2021 Security Misconfiguration",
    319: "A02:2021 Cryptographic Failures", 311: "A02:2021 Cryptographic Failures",
    1104: "A06:2021 Vulnerable and Outdated Components",
    1395: "A06:2021 Vulnerable and Outdated Components",
    345: "A08:2021 Software and Data Integrity Failures",
    829: "A08:2021 Software and Data Integrity Failures",
    20: "A03:2021 Injection", 74: "A03:2021 Injection", 94: "A03:2021 Injection",
    1295: "A05:2021 Security Misconfiguration", 615: "A05:2021 Security Misconfiguration",
    598: "A04:2021 Insecure Design", 525: "A04:2021 Insecure Design",
    918: "A10:2021 Server-Side Request Forgery",
    287: "A07:2021 Identification and Authentication Failures",
    497: "A05:2021 Security Misconfiguration", 209: "A05:2021 Security Misconfiguration",
}


LOCK_PATH = os.path.join(os.path.dirname(os.path.abspath(DB_PATH)), "zap.lock")


# ZAP rules known to produce many false positives on real sites. Their alerts
# are kept but marked for manual review and capped, so one guess cannot make a
# report look Critical.  pluginId -> (likelihood, impact, note)
NEEDS_REVIEW = {
    "10062": (2, 2, "ZAP flags long numbers that pass a checksum as possible credit-card or ID "
                    "numbers. On real sites these are usually internal IDs, so confirm by hand "
                    "before treating this as a leak."),  # PII Disclosure
}


# Cross-platform, non-blocking exclusive file lock (fcntl on macOS/Linux, msvcrt on Windows).
if os.name == "nt":
    import msvcrt

    def _try_lock(fh):
        try:
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
            return True
        except OSError:
            return False

    def _unlock(fh):
        fh.seek(0)
        msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
else:
    import fcntl

    def _try_lock(fh):
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            return False

    def _unlock(fh):
        fcntl.flock(fh, fcntl.LOCK_UN)


class ZapError(RuntimeError):
    pass


class ScanCancelled(RuntimeError):
    pass


@contextmanager
def zap_engine_lock(progress=lambda p, m: None, should_abort=lambda: False):
    """ZAP is one engine with one session: two scans at once wipe each other's
    results. This file lock queues scans (works across the dashboard and CLI)."""
    os.makedirs(os.path.dirname(LOCK_PATH), exist_ok=True)
    with open(LOCK_PATH, "a+") as fh:
        waited = False
        while True:
            if _try_lock(fh):
                break
            else:
                if should_abort():
                    raise ScanCancelled("Scan cancelled while waiting in the queue")
                if not waited:
                    progress(3, "Waiting for ZAP engine (another scan is running, yours is queued)")
                    waited = True
                time.sleep(3)
        try:
            yield
        finally:
            _unlock(fh)


class ZapScanner:
    def __init__(self, api_url=ZAP_API_URL, api_key=ZAP_API_KEY):
        self.zap = ZAPv2(apikey=api_key, proxies={"http": api_url, "https": api_url})
        self.should_abort = lambda: False

    def is_up(self) -> bool:
        try:
            return bool(self.zap.core.version)
        except Exception:
            return False

    def _wait(self, status_fn, scan_id, label, progress, lo, hi, timeout, stop_fn=None):
        """Poll a ZAP scan. On time-out or cancel, tell ZAP itself to stop: just
        returning would leave the scan running inside the engine and the next
        customer's scan would collide with it."""
        start = time.time()
        while True:
            if self.should_abort():
                if stop_fn:
                    stop_fn(scan_id)
                raise ScanCancelled("Scan cancelled")
            raw = status_fn(scan_id)
            if not str(raw).isdigit():
                raise ZapError(f"ZAP lost the {label.lower()} (reply: {raw}). "
                               "Another scan may have reset the engine; please run the scan again.")
            pct = int(raw)
            progress(lo + (hi - lo) * pct // 100, f"{label}: {pct}%")
            if pct >= 100:
                return
            if time.time() - start > timeout:
                if stop_fn:
                    stop_fn(scan_id)
                progress(hi, f"{label}: time limit reached at {pct}%, using results so far")
                return
            time.sleep(2)

    def scan(self, target, active=True, progress=lambda p, m: None, max_minutes=15,
             cookie=None, exclude=(), ajax=False, seeds=(), should_abort=lambda: False):
        """Run a full ZAP scan against `target` (as seen from inside Docker).

        cookie:  session cookie header so ZAP scans as a logged-in user.
        exclude: URL regexes ZAP must not visit (logout, DB reset, ...).
        """
        zap = self.zap
        self.should_abort = should_abort
        zap.core.new_session(name="scan", overwrite=True)
        for rx in exclude:
            zap.core.exclude_from_proxy(rx)
            zap.spider.exclude_from_scan(rx)
            zap.ascan.exclude_from_scan(rx)
        # Remove an old session rule, then add the current one.
        try:
            zap.replacer.remove_rule("lab-session")
        except Exception:
            pass
        if cookie:
            zap.replacer.add_rule(description="lab-session", enabled="true", matchtype="REQ_HEADER",
                                  matchregex="false", matchstring="Cookie", replacement=cookie)
        zap.core.access_url(url=target, followredirects=True)
        for path in seeds:  # known API routes a crawler cannot find in JavaScript
            try:
                zap.core.access_url(url=target.rstrip("/") + path, followredirects=True)
            except Exception:
                pass

        progress(5, "Spidering site")
        # Keep crawls of large public sites bounded and polite.
        zap.spider.set_option_max_duration(2 if not active else 5)
        zap.spider.set_option_max_depth(5)
        zap.spider.set_option_thread_count(3)
        sid = zap.spider.scan(target, maxchildren=None, recurse=True, subtreeonly=True)
        self._wait(zap.spider.status, sid, "Spider", progress, 5, 25 if ajax else 35, 300,
                   stop_fn=lambda i: zap.spider.stop(i))

        if ajax:
            progress(25, "AJAX spider (headless browser)")
            zap.ajaxSpider.set_option_browser_id("firefox-headless")
            zap.ajaxSpider.set_option_number_of_browsers(1)  # one browser keeps memory in check
            zap.ajaxSpider.set_option_max_duration(4)
            zap.ajaxSpider.scan(target)
            start = time.time()
            while zap.ajaxSpider.status == "running" and time.time() - start < 300:
                if should_abort():
                    zap.ajaxSpider.stop()
                    raise ScanCancelled("Scan cancelled")
                progress(25 + min(10, int((time.time() - start) / 24)),
                         f"AJAX spider: {zap.ajaxSpider.number_of_results} resources")
                time.sleep(3)

        progress(35, "Passive scanning")
        start = time.time()
        while int(zap.pscan.records_to_scan) > 0 and time.time() - start < 120:
            if should_abort():
                raise ScanCancelled("Scan cancelled")
            time.sleep(1)

        if active:
            progress(40, "Active scanning")
            # One slow rule (e.g. time-based SQL injection) must not stall the scan.
            zap.ascan.set_option_max_rule_duration_in_mins(2)
            # DOM XSS (40026) launches several headless Firefox browsers inside the
            # container; on an 8 GB machine that got ZAP killed for memory twice.
            zap.ascan.disable_scanners("40026")
            zap.ascan.set_option_max_scan_duration_in_mins(max_minutes)
            aid = zap.ascan.scan(target, recurse=True)
            self._wait(zap.ascan.status, aid, "Active scan", progress, 40, 85, max_minutes * 60,
                       stop_fn=lambda i: zap.ascan.stop(i))

        progress(85, "Collecting ZAP alerts")
        alerts = zap.core.alerts(baseurl=target)
        if not isinstance(alerts, list):
            raise ZapError(f"Unexpected reply from ZAP when collecting alerts: {str(alerts)[:120]}")
        return [self._to_finding(a) for a in alerts if isinstance(a, dict)]

    @staticmethod
    def _to_finding(a) -> Finding:
        cwe = int(a.get("cweid") or 0)
        li, im = RISK_TO_LI.get(a.get("risk"), (1, 1))
        title = a.get("alert", a.get("name", "ZAP alert"))
        description = a.get("description", "")
        confidence = a.get("confidence", "Medium")
        review = NEEDS_REVIEW.get(str(a.get("pluginId")))
        if review:
            li, im = min(li, review[0]), min(im, review[1])
            title += " (needs manual review)"
            description = "Needs manual review: " + review[2] + "\n\n" + description
            confidence = "Low"
        return Finding(
            title=title,
            source="ZAP",
            url=a.get("url", ""),
            owasp=CWE_TO_OWASP.get(cwe, "Other"),
            cwe=cwe,
            param=a.get("param", ""),
            evidence=(a.get("evidence") or "")[:300],
            description=description,
            likelihood=li, impact=im,
            confidence=confidence,
            remediation=a.get("solution", ""),
            extra={"zap_risk": a.get("risk"), "plugin_id": a.get("pluginId")},
        )
