"""Runs a complete scan: validate URL -> reachability -> ZAP -> custom checks -> dedupe -> score -> remediation -> save."""
import threading
import time

import requests

from . import storage
from .auth import LOGINS
from .checks import ALL_CHECKS
from .config import host_url_for, lab_target_for, normalize_url, zap_url_for
from .remediation import attach_remediation
from .scoring import deduplicate, score
from .verify import is_verified, verification_url
from .zap_client import ScanCancelled, ZapScanner, zap_engine_lock

QUICK, STANDARD, FULL = ("Quick (safe checks, ~10 s)",
                         "Standard (crawl + passive scan, ~2 min)",
                         "Full (active testing, verified sites only)")
MODES = {
    QUICK: {"zap": False, "active": False},
    STANDARD: {"zap": True, "active": False},
    FULL: {"zap": True, "active": True},
}

USER_AGENT = "HTE-VulnScanner/1.0 (+security assessment)"


class NotVerified(Exception):
    pass


def preflight(url):
    """Make sure the site answers before starting a long scan."""
    try:
        r = requests.get(url, timeout=15, headers={"User-Agent": USER_AGENT})
        return r.url
    except requests.exceptions.SSLError:
        return url  # still scannable; the transport check reports the bad certificate
    except requests.RequestException as e:
        raise RuntimeError(f"Could not reach {url}: {e.__class__.__name__}. Check the address and try again.")


def check_allowed(url, mode):
    if MODES[mode]["active"] and not is_verified(url):
        raise NotVerified(f"Full scans need proof of ownership. Publish your token at {verification_url(url)}")


def run_scan(target, mode=STANDARD, scan_id=None, log=print):
    target = normalize_url(target)
    check_allowed(target, mode)
    opts = MODES[mode]
    scan_id = scan_id or storage.create_scan(target, mode)
    t0 = time.time()

    def cancelled():
        return (storage.get_scan(scan_id) or {}).get("status") != "running"

    def progress(p, msg):
        if cancelled():
            raise ScanCancelled("Scan cancelled")
        storage.update_progress(scan_id, p, msg)
        log(f"[{p:3d}%] {msg}")

    try:
        progress(1, "Checking the site is reachable")
        preflight(target)

        findings = []
        lab = lab_target_for(target) or {}
        session, cookie = requests.Session(), None
        if lab.get("auth"):
            progress(2, "Logging in to target")
            session, cookie = LOGINS[lab["auth"]](lab["url"])

        # Custom checks run BEFORE ZAP: an active scan can leave the target slow
        # (time-based SQL injection tests keep its workers sleeping) and a lab
        # login can expire during a long scan, which made checks time out.
        session.headers["User-Agent"] = USER_AGENT
        for i, (name, check) in enumerate(ALL_CHECKS.items()):
            progress(3 + i, f"Custom check: {name}")
            for attempt in (1, 2):
                try:
                    findings += check(target, session)
                    break
                except requests.RequestException as e:
                    if attempt == 2:
                        log(f"  ! {name} failed: {e}")
                    else:
                        time.sleep(3)

        if opts["zap"]:
            zap = ZapScanner()
            if not zap.is_up():
                raise RuntimeError("ZAP engine is not running. Start it with: docker compose up -d")
            with zap_engine_lock(progress, should_abort=cancelled):
                if lab.get("auth"):  # log in again: the session may have expired while queued
                    session, cookie = LOGINS[lab["auth"]](lab["url"])
                zap_findings = zap.scan(zap_url_for(target), active=opts["active"], progress=progress,
                                        cookie=cookie, exclude=lab.get("exclude", []),
                                        ajax=lab.get("ajax", False), seeds=lab.get("seeds", []),
                                        max_minutes=15 if opts["active"] else 3,
                                        should_abort=cancelled)
            for f in zap_findings:  # show the URLs the customer knows, not Docker-internal ones
                f.url = host_url_for(f.url)
                f.extra["urls"] = [host_url_for(u) for u in f.extra.get("urls", [f.url])]
            findings += zap_findings

        findings = attach_remediation(score(deduplicate(findings)))
        storage.save_findings(scan_id, findings)
        storage.finish_scan(scan_id, "completed", f"{len(findings)} findings", round(time.time() - t0, 1))
        return scan_id, findings
    except ScanCancelled:
        if (storage.get_scan(scan_id) or {}).get("status") == "running":
            storage.finish_scan(scan_id, "cancelled", "Cancelled", round(time.time() - t0, 1))
        raise
    except Exception as e:
        storage.finish_scan(scan_id, "failed", str(e), round(time.time() - t0, 1))
        raise


def cancel_scan(scan_id):
    """Mark a scan cancelled; its worker notices within a few seconds, stops ZAP
    and leaves the queue."""
    scan = storage.get_scan(scan_id)
    if scan and scan["status"] == "running":
        storage.finish_scan(scan_id, "cancelled", "Cancelled by user", scan.get("duration_s") or 0)


def start_scan_async(target, mode):
    """Start a scan in a background thread (used by the dashboard)."""
    target = normalize_url(target)
    check_allowed(target, mode)
    scan_id = storage.create_scan(target, mode)

    def worker():
        try:
            run_scan(target, mode, scan_id=scan_id, log=lambda m: None)
        except Exception:
            pass  # error already stored on the scan row

    threading.Thread(target=worker, daemon=True).start()
    return scan_id
