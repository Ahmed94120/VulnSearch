import config  # loads .env before any os.environ read
import os
from datetime import datetime
import json
import logging
import requests
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
import ssl

from render import build_card, render_mail

BASE_DIR = config.BASE_DIR
LOG_FILE = BASE_DIR / "vulnscan.log"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
# urllib3 DEBUG logs full URLs, including the Teams webhook signature.
logging.getLogger("urllib3").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

STATE_FILE = os.environ.get("VULN_STATE_FILE", str(BASE_DIR / "alerted_cves.json"))
# One JSON line per run (what was done), read by daily_summary.py.
JOURNAL_FILE = BASE_DIR / "runs.jsonl"
# Webhook kept out of the code: env var TEAMS_WEBHOOK_URL, or this file (chmod 600).
WEBHOOK_FILE = BASE_DIR / ".teams_webhook"
# DRY_RUN=1: log and print what would be sent, send nothing, save no state.
DRY_RUN = os.environ.get("DRY_RUN") == "1"

# NOTIFY_MODE=all       (default, current behaviour) every new KEV entry is emailed.
# NOTIFY_MODE=filtered  SG criteria (vulnScore.py): email only for MATCH and TO_CHECK.
NOTIFY_MODE = os.environ.get("NOTIFY_MODE", "all")

# SMTP and recipients come only from .env (see .env.example): nothing hard-coded here.
# check_config() refuses to run when a required value is missing.
SMTP_HOST = os.environ.get("SMTP_HOST", "").strip()
SMTP_PORT_RAW = os.environ.get("SMTP_PORT", "").strip() or "25"     # empty -> 25
SMTP_PORT = int(SMTP_PORT_RAW) if SMTP_PORT_RAW.isdigit() else None  # invalid -> check_config()
SMTP_HELLO = os.environ.get("SMTP_HELLO", "").strip()
SMTP_FROM = os.environ.get("SMTP_FROM", "").strip()
# Optional: SMTP_USER set -> STARTTLS + login. Not needed with the internal relay.
SMTP_USER = os.environ.get("SMTP_USER", "").strip()
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")


def _emails(name):
    return [a.strip() for a in os.environ.get(name, "").split(",") if a.strip()]


# To of every email.
CUSTOMER_EMAILS = _emails("CUSTOMER_EMAILS")
# In copy of every email (both modes): OCD team and L1. Also the To of daily_summary.py.
CC_EMAILS = _emails("CC_EMAILS")
ONCALL_BLOCK = """Telephone Information:
Primary OnCall Number - +91 9148418803
First Level of Escalation for OnCall Number - +91 9916392561
Second Level of Escalation for OnCall Number - +91 9035173509
"""


def _cve_id(vuln):
    return vuln.get("cveID") or vuln.get("id")


def get_webhook_url():
    url = os.environ.get("TEAMS_WEBHOOK_URL")
    if url:
        return url.strip()
    if WEBHOOK_FILE.exists():
        return WEBHOOK_FILE.read_text().strip()
    return None


class ConfigError(RuntimeError):
    pass


def check_config():
    """Make the run fail, loudly, on a configuration error.

    Called first in run(), before the KEV is fetched: a missing .env line must
    fail the cron run (traceback in the cron log, failed run in runs.jsonl and
    in the daily summary), not fail every email silently one CVE at a time.
    """
    problems = []
    for name, value in (("SMTP_HOST", SMTP_HOST), ("SMTP_HELLO", SMTP_HELLO), ("SMTP_FROM", SMTP_FROM)):
        if not value:
            problems.append(f"{name} is empty")
    if SMTP_PORT is None:
        problems.append(f"SMTP_PORT is not a number ({SMTP_PORT_RAW!r})")
    if SMTP_USER and not SMTP_PASSWORD:
        problems.append("SMTP_USER is set but SMTP_PASSWORD is empty")
    if not CUSTOMER_EMAILS:
        problems.append("CUSTOMER_EMAILS is empty")
    if NOTIFY_MODE not in ("all", "filtered"):
        problems.append(f"NOTIFY_MODE must be 'all' or 'filtered' (got {NOTIFY_MODE!r})")
    if NOTIFY_MODE == "filtered" and not get_webhook_url():
        # NO_MATCH entries are reported on Teams only.
        problems.append("no Teams webhook (NOTIFY_MODE=filtered needs it for NO_MATCH)")
    # Leftovers of the test tooling: with them, the customer would never get the emails.
    for name in ("MAIL_TEST_TO", "MAIL_EML_DIR"):
        if os.environ.get(name, "").strip():
            problems.append(f"{name} is set (test setting, not supported any more): remove it")
    if problems:
        raise ConfigError("configuration error in .env: " + "; ".join(problems))
    if not get_webhook_url():
        logger.warning("no Teams webhook configured: emails only")


def load_alerted():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            alerted = set(json.load(f))
        logger.debug("loaded %d already-alerted cve(s) from %s", len(alerted), STATE_FILE)
        return alerted
    logger.warning("no state file %s yet", STATE_FILE)
    return set()


def save_alerted(alerted):
    # Atomic write: a crash mid-write must never empty the dedup history.
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(sorted(alerted), f)
    os.replace(tmp, STATE_FILE)
    logger.debug("saved %d alerted cve(s) to %s", len(alerted), STATE_FILE)


def send_teams(card, webhook_url):
    if not webhook_url:
        raise RuntimeError("Teams webhook not configured (TEAMS_WEBHOOK_URL or %s)" % WEBHOOK_FILE)
    logger.debug("POST to Teams webhook")
    r = requests.post(
        webhook_url,
        headers={"Content-Type": "application/json"},
        data=json.dumps(card),
        timeout=30,
    )
    r.raise_for_status()
    return r.status_code


def _smtp_send(subject, text, to, html=None, cc=None):
    """Raises on failure so the CVE is retried next run. `cc` defaults to CC_EMAILS."""
    cc = CC_EMAILS if cc is None else cc
    if not to:
        raise RuntimeError("no recipient")
    msg = MIMEMultipart("alternative")
    msg["From"] = SMTP_FROM
    msg["To"] = ", ".join(to)
    if cc:
        msg["Cc"] = ", ".join(cc)
    msg["Subject"] = subject
    msg.attach(MIMEText(text, "plain", "utf-8"))
    if html:
        msg.attach(MIMEText(html, "html", "utf-8"))
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
        server.ehlo(SMTP_HELLO)
        if SMTP_USER:
            server.starttls(context=ssl.create_default_context())
            server.ehlo(SMTP_HELLO)
            server.login(SMTP_USER, SMTP_PASSWORD)  # password never logged
        server.sendmail(SMTP_FROM, to + cc, msg.as_string())


def sendmail(vuln, type_cve):
    """NOTIFY_MODE=all: customer email for every new KEV entry (current behaviour)."""
    subject = f"[{vuln.get('cveID')}] - {vuln.get('vendorProject')} / {vuln.get('product')} (EXPLOITED)"
    text, html = render_mail(vuln, "This vulnerability was added to the CISA Known Exploited "
                                   "Vulnerabilities catalog: it is actively exploited in the wild.",
                             ONCALL_BLOCK)
    _smtp_send(subject, text, CUSTOMER_EMAILS, html)
    print(f"Email Sent ! ({vuln.get('cveID')})")


def sendmail_assessed(vuln):
    """NOTIFY_MODE=filtered: customer email (L1 in CC), for MATCH and TO_CHECK.

    TO_CHECK: the customer checks the criteria; the L1 only calls, no analysis.
    """
    a = vuln["assessment"]
    cid = vuln.get("cveID")
    head = f"[{cid}] - {vuln.get('vendorProject')} / {vuln.get('product')}"
    if a["status"] == "MATCH":
        subject = f"{head} (EXPLOITED - {a['type']})"
        intro = (f"This CVE was added to the CISA KEV catalog and meets the SG notification criteria "
                 f"(AV:N / AC:L / PR:N / UI:N, High impact, {a['type']}).")
    else:
        subject = f"{head} (EXPLOITED - MANUAL REVIEW REQUIRED)"
        intro = ("This CVE was added to the CISA KEV catalog, but the SG criteria could not be "
                 "evaluated automatically (e.g. not yet scored on CVE.org / NVD). "
                 "Please check it against the criteria using the steps below.")
    text, html = render_mail(vuln, intro, ONCALL_BLOCK)
    _smtp_send(subject, text, CUSTOMER_EMAILS, html)
    print(f"Email Sent ! ({cid}, {a['status']})")


def save_journal(report):
    """Append one run to runs.jsonl. Never raises: the journal must not break alerting."""
    try:
        with open(JOURNAL_FILE, "a") as f:
            f.write(json.dumps(report) + "\n")
    except Exception:
        logger.exception("Unable to write journal %s", JOURNAL_FILE)


def alert(vulns, type_cve="critical", limit=10, report=None):
    """Email + Teams for each entry not yet alerted.

    A CVE is recorded in alerted_cves.json only once its email is sent, so a
    failure is retried at the next run instead of being lost. Entries beyond
    `limit` are kept for the next run (the watermark does not pass them).
    `report` (dict, optional) receives what was done, for the journal.
    Returns the number of CVEs alerted.
    """
    report = {} if report is None else report
    report.setdefault("cves", [])
    logger.info("alert: %d vuln(s) to consider", len(vulns))
    if not vulns:
        logger.info("No vuln. No alert.")
        return 0

    alerted = load_alerted()
    new = [v for v in vulns if _cve_id(v) and _cve_id(v) not in alerted]
    logger.info("alert: %d new (not yet alerted)", len(new))
    if not new:
        logger.info("All already alerted. Skip.")
        return 0

    new.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)
    batch = new[:limit]
    report["new"], report["postponed"] = len(new), max(len(new) - limit, 0)
    if len(new) > limit:
        logger.warning("alert: %d entries postponed to next run (limit=%d)", len(new) - limit, limit)
    logger.info("alert: sending %d of %d new (limit=%d)", len(batch), len(new), limit)

    filtered = NOTIFY_MODE == "filtered"
    if filtered:
        from vulnScore import Scorer
        scorer = Scorer()

    webhook_url = get_webhook_url()
    sent = 0
    try:
        for v in batch:
            cid = _cve_id(v)

            if filtered:
                v["assessment"] = scorer.assess(v)
                logger.info("assessment %s: %s - %s", cid, v["assessment"]["status"], v["assessment"]["reason"])
            status = (v.get("assessment") or {}).get("status")
            entry = {"cve": cid, "vendor": v.get("vendorProject"), "product": v.get("product"),
                     "dateAdded": v.get("dateAdded"), "status": status,
                     "type": (v.get("assessment") or {}).get("type"),
                     "reason": (v.get("assessment") or {}).get("reason"), "email": "none", "teams": "none"}
            report["cves"].append(entry)

            if DRY_RUN:
                logger.info("DRY_RUN: would alert %s (%s) status=%s", cid, v.get("dateAdded"), status)
                print(f"DRY_RUN: {cid} | {v.get('dateAdded')} | {v.get('vendorProject')} / {v.get('product')}"
                      + (f" | {status} | {v['assessment']['reason']}" if status else ""))
                continue

            if status == "NO_MATCH":
                # No email: the Teams card is the only trace, so the CVE is recorded
                # only once Teams accepted it. On failure it is retried next run.
                logger.info("No email for %s: %s", cid, v["assessment"]["reason"])
                try:
                    http = send_teams(build_card([v], type_cve), webhook_url)
                except Exception:
                    logger.exception("Teams card failed for %s (NO_MATCH), will retry next run", cid)
                    entry["teams"] = "failed"
                    continue
                logger.info("Teams alert sent for %s. HTTP %d", cid, http)
                print(f"Teams alert sent for {cid}. HTTP {http}")
                entry["teams"] = "sent"
                alerted.add(cid)
                sent += 1
                continue

            try:
                print(f"Sending email for {cid}")
                if filtered:
                    sendmail_assessed(v)
                else:
                    sendmail(v, type_cve)
            except Exception:
                logger.exception("Email failed for %s, will retry next run", cid)
                entry["email"] = "failed"
                continue
            logger.info("Email sent for %s", cid)
            entry["email"] = "sent"

            # Email sent: never process this CVE again (no duplicate email),
            # even if the Teams card below fails.
            alerted.add(cid)
            sent += 1

            try:
                http = send_teams(build_card([v], type_cve), webhook_url)
                logger.info("Teams alert sent for %s. HTTP %d", cid, http)
                print(f"Teams alert sent for {cid}. HTTP {http}")
                entry["teams"] = "sent"
            except Exception:
                logger.exception("Teams alert failed for %s (email already sent)", cid)
                entry["teams"] = "failed"
    finally:
        if not DRY_RUN:
            save_alerted(alerted)

    return sent


def run():
    logger.info("=== run start (mode=%s, dry_run=%s) ===", NOTIFY_MODE, DRY_RUN)
    report = {"start": datetime.now().astimezone().isoformat(timespec="seconds"), "mode": NOTIFY_MODE,
              "ok": False, "error": None, "considered": 0, "new": 0, "postponed": 0, "cves": []}
    try:
        check_config()
        from vulnSearch import scan, VulnerabilityClient

        vulns, newest = scan()
        report["considered"] = len(vulns)
        alert(vulns, report=report)

        if DRY_RUN:
            logger.info("DRY_RUN: watermark not saved")
            return

        # Move the watermark only past what was actually alerted. If entries are
        # still pending (email failure, limit), keep them inside the next window.
        alerted = load_alerted()
        pending_dates = [v["dateAdded"] for v in vulns
                         if _cve_id(v) not in alerted and v.get("dateAdded")]
        watermark = min(pending_dates) if pending_dates else newest
        if watermark:
            VulnerabilityClient().save_watermark(watermark)
        logger.info("watermark set to %s (%d pending)", watermark, len(pending_dates))
        report["ok"] = True
    except Exception as e:
        logger.exception("run failed")
        report["error"] = f"{type(e).__name__}: {e}"
        raise
    finally:
        if not DRY_RUN:
            report["end"] = datetime.now().astimezone().isoformat(timespec="seconds")
            save_journal(report)
        logger.info("=== run end ===")


if __name__ == "__main__":
    run()
