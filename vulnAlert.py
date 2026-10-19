import config  # noqa: F401  (loads .env before any os.environ read)
import os
import json
import logging
import re
import requests
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
import ssl
from pathlib import Path

from render import build_card, render_mail

BASE_DIR = Path(os.environ.get("VULNSG_DIR", "/home/sysroot/VulnSG"))
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
# Webhook kept out of the code: env var TEAMS_WEBHOOK_URL, or this file (chmod 600).
WEBHOOK_FILE = BASE_DIR / ".teams_webhook"
# DRY_RUN=1: log and print what would be sent, send nothing, save no state.
DRY_RUN = os.environ.get("DRY_RUN") == "1"

# NOTIFY_MODE=all       (default, current behaviour) every new KEV entry is emailed.
# NOTIFY_MODE=filtered  SG criteria (vulnScore.py): email only for MATCH and TO_CHECK.
NOTIFY_MODE = os.environ.get("NOTIFY_MODE", "all")
# Recipients for filtered mode, comma-separated. No default on purpose.
L1_EMAILS = [a.strip() for a in os.environ.get("L1_EMAILS", "").split(",") if a.strip()]
REVIEW_EMAILS = [a.strip() for a in os.environ.get("REVIEW_EMAILS", "").split(",") if a.strip()]

# Defaults = production relay. SMTP_USER set: STARTTLS + login (e.g. Gmail on 587).
SMTP_HELLO = os.environ.get("SMTP_HELLO", "p-tvm-ctl-l-01.prod-client.itm.lan")
SMTP_FROM = os.environ.get("SMTP_FROM", "monitoring_cybertools@cybersoc.orangecyberdefense.com")
SMTP_HOST = os.environ.get("SMTP_HOST", "relay.itm.lan")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "25"))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
# MAIL_TEST_TO set: every email goes ONLY to these addresses (no customer, no BCC), subject "[TEST] ".
MAIL_TEST_TO = [a.strip() for a in os.environ.get("MAIL_TEST_TO", "").split(",") if a.strip()]
# MAIL_EML_DIR set: write each email as a .eml file in this folder instead of sending it.
MAIL_EML_DIR = os.environ.get("MAIL_EML_DIR", "").strip()


def _emails(name, default=""):
    return [a.strip() for a in os.environ.get(name, default).split(",") if a.strip()]


CUSTOMER_EMAILS = _emails("CUSTOMER_EMAILS", "GSC-VH-VULN@socgen.com")
BCC_EMAILS = _emails("BCC_EMAILS", "olivier.leung@orangecyberdefense.com,noor.mohamed@orangecyberdefense.com,"
                                   "ahmed.bouhafa@orangecyberdefense.com")
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


def build_confirm_card(vuln):
    """Separate card, own Action.Submit, so its 'wait for response' doesn't
    collide with the assign card's."""
    cid = _cve_id(vuln)
    body = [
        {
            "type": "TextBlock",
            "size": "Medium",
            "weight": "Bolder",
            "text": f"\U0001F6A8 CVSS COULD NOT BE DETERMINED, please inform that the VECTOR STRING of {cid} is unknown and they must perform a manual check. — {cid or ''}",
            "wrap": True,
        },
        {
            "type": "FactSet",
            "facts": [
                {"title": "CVE", "value": cid or ""},
                {"title": "Vendor", "value": vuln.get("vendorProject", "")},
                {"title": "Product", "value": vuln.get("product", "")},
            ],
        },
    ]

    return {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": body,
            },
        }],
    }


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


def _smtp_send(subject, text, to, html=None):
    """Raises on failure so the CVE is retried next run."""
    bcc = BCC_EMAILS
    if MAIL_TEST_TO:
        to, bcc, subject = MAIL_TEST_TO, [], "[TEST] " + subject
    msg = MIMEMultipart("alternative")
    msg["From"] = SMTP_FROM
    msg["To"] = ", ".join(to)
    msg["Subject"] = subject
    msg.attach(MIMEText(text, "plain", "utf-8"))
    if html:
        msg.attach(MIMEText(html, "html", "utf-8"))
    if MAIL_EML_DIR:
        name = re.sub(r"[^A-Za-z0-9-]+", "_", subject).strip("_")[:120] + ".eml"
        Path(MAIL_EML_DIR, name).write_text(msg.as_string())
        return
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
        server.ehlo(SMTP_HELLO)
        if SMTP_USER:
            server.starttls(context=ssl.create_default_context())
            server.ehlo(SMTP_HELLO)
            server.login(SMTP_USER, SMTP_PASSWORD or "")
        server.sendmail(SMTP_FROM, to + bcc, msg.as_string())


def sendmail(vuln, type_cve):
    """NOTIFY_MODE=all: customer email for every new KEV entry (current behaviour)."""
    subject = f"[{vuln.get('cveID')}] - {vuln.get('vendorProject')} / {vuln.get('product')} (EXPLOITED)"
    text, html = render_mail(vuln, "This vulnerability was added to the CISA Known Exploited "
                                   "Vulnerabilities catalog: it is actively exploited in the wild.",
                             ONCALL_BLOCK)
    _smtp_send(subject, text, CUSTOMER_EMAILS, html)
    print(f"Email Sent ! ({vuln.get('cveID')})")


def sendmail_assessed(vuln):
    """NOTIFY_MODE=filtered: L1 email (MATCH) or manual-review email (TO_CHECK)."""
    a = vuln["assessment"]
    cid = vuln.get("cveID")
    head = f"[{cid}] - {vuln.get('vendorProject')} / {vuln.get('product')}"
    if a["status"] == "MATCH":
        subject = f"{head} (EXPLOITED - {a['type']})"
        intro = (f"This CVE was added to the CISA KEV catalog and meets the SG notification criteria "
                 f"(AV:N / AC:L / PR:N / UI:N, High impact, {a['type']}).")
        to = L1_EMAILS
    else:
        subject = f"{head} (EXPLOITED - MANUAL REVIEW REQUIRED)"
        intro = ("This CVE was added to the CISA KEV catalog, but the SG criteria could not be "
                 "evaluated automatically. Please review it manually using the steps below.")
        to = REVIEW_EMAILS
    text, html = render_mail(vuln, intro, ONCALL_BLOCK)
    _smtp_send(subject, text, to, html)
    print(f"Email Sent ! ({cid}, {a['status']})")


def alert(vulns, type_cve="critical", limit=10):
    """Email + Teams for each entry not yet alerted.

    A CVE is recorded in alerted_cves.json only once its email is sent, so a
    failure is retried at the next run instead of being lost. Entries beyond
    `limit` are kept for the next run (the watermark does not pass them).
    Returns the number of CVEs alerted.
    """
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
    if len(new) > limit:
        logger.warning("alert: %d entries postponed to next run (limit=%d)", len(new) - limit, limit)
    logger.info("alert: sending %d of %d new (limit=%d)", len(batch), len(new), limit)

    filtered = NOTIFY_MODE == "filtered"
    if filtered and not (L1_EMAILS and REVIEW_EMAILS):
        raise RuntimeError("NOTIFY_MODE=filtered requires L1_EMAILS and REVIEW_EMAILS")
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

            if DRY_RUN:
                logger.info("DRY_RUN: would alert %s (%s) status=%s", cid, v.get("dateAdded"), status)
                print(f"DRY_RUN: {cid} | {v.get('dateAdded')} | {v.get('vendorProject')} / {v.get('product')}"
                      + (f" | {status} | {v['assessment']['reason']}" if status else ""))
                continue

            if status == "NO_MATCH":
                logger.info("No email for %s: %s", cid, v["assessment"]["reason"])
            else:
                try:
                    print(f"Sending email for {cid}")
                    if filtered:
                        sendmail_assessed(v)
                    else:
                        sendmail(v, type_cve)
                except Exception:
                    logger.exception("Email failed for %s, will retry next run", cid)
                    continue
                logger.info("Email sent for %s", cid)

            # Decision made (and email sent if any): never process this CVE again.
            alerted.add(cid)
            sent += 1

            try:
                status = send_teams(build_card([v], type_cve), webhook_url)
                logger.info("Teams alert sent for %s. HTTP %d", cid, status)
                print(f"Teams alert sent for {cid}. HTTP {status}")
            except Exception:
                logger.exception("Teams alert failed for %s (email already sent)", cid)
    finally:
        if not DRY_RUN:
            save_alerted(alerted)

    return sent


def run(product_file="/home/sysroot/VulnSG/produit_clean.csv"):
    logger.info("=== run start (product_file=%s, dry_run=%s) ===", product_file, DRY_RUN)
    try:
        from vulnSearch import scan, VulnerabilityClient

        vulns, newest = scan(product_file)
        alert(vulns)

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
    except Exception:
        logger.exception("run failed")
        raise
    finally:
        logger.info("=== run end ===")


if __name__ == "__main__":
    run()
