import config  # noqa: F401  (loads .env before any os.environ read)
import os
import json
import logging
import requests
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
from pathlib import Path

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

SMTP_HELLO = "p-tvm-ctl-l-01.prod-client.itm.lan"
SMTP_FROM = "monitoring_cybertools@cybersoc.orangecyberdefense.com"
SMTP_HOST = "relay.itm.lan"
SMTP_PORT = 25
CUSTOMER_EMAILS = ["GSC-VH-VULN@socgen.com"]
BCC_EMAILS = ["olivier.leung@orangecyberdefense.com", "noor.mohamed@orangecyberdefense.com",
              "ahmed.bouhafa@orangecyberdefense.com", "cybersoc.mru@orange.com"]
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


def _exploit_summary(vuln):
    ex = vuln.get("exploits", {})
    parts = []
    if ex.get("kev"):
        parts.append("KEV")
    if ex.get("metasploit"):
        parts.append(f"Metasploit x{len(ex['metasploit'])}")
    if ex.get("exploitdb"):
        parts.append(f"Exploit-DB x{len(ex['exploitdb'])}")
    return ", ".join(parts) if parts else "no public exploit"


CARD_HEADERS = {
    None: ("\U0001F6A8 {n} publicly exploited vuln(s)", "Attention"),
    "MATCH": ("\U0001F6A8 {n} exploited vuln(s) - SG criteria met, L1 notified", "Attention"),
    "TO_CHECK": ("⚠️ {n} exploited vuln(s) - TO CHECK, scoring not determined", "Warning"),
    "NO_MATCH": ("ℹ️ {n} exploited vuln(s) - SG criteria not met, no email", "Default"),
}


def build_card(vulns, type_cve):
    status = (vulns[0].get("assessment") or {}).get("status") if vulns else None
    title, color = CARD_HEADERS.get(status, CARD_HEADERS[None])
    body = [{
        "type": "TextBlock",
        "size": "Large",
        "weight": "Bolder",
        "color": color,
        "text": title.format(n=len(vulns)),
        "wrap": True,
    }]

    for v in vulns:
        facts = [
            {"title": "CVE", "value": _cve_id(v) or ""},
            {"title": "Vendor", "value": v.get("vendorProject", "")},
            {"title": "Product", "value": v.get("product", "")},
            {"title": "Exploit", "value": _exploit_summary(v)},
        ]
        a = v.get("assessment")
        if a:
            facts += [
                {"title": "Status", "value": a["status"]},
                {"title": "Vector", "value": a.get("vector") or "not available"},
                {"title": "Source", "value": a.get("source") or "-"},
                {"title": "Reason", "value": a.get("reason") or "-"},
            ]
        body.append({"type": "FactSet", "facts": facts})
        desc = v.get("shortDescription")
        if desc:
            body.append({
                "type": "TextBlock",
                "text": desc,
                "wrap": True,
                "spacing": "Small",
                "isSubtle": True,
            })
        cid = _cve_id(v)
        if cid:
            body.append({
                "type": "ActionSet",
                "actions": [
                    {
                        "type": "Action.OpenUrl",
                        "title": "Voir sur MITRE",
                        "url": f"https://www.cve.org/CVERecord?id={cid}",
                    },
                ],
            })

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


def _smtp_send(subject, body, to):
    """Raises on failure so the CVE is retried next run."""
    msg = MIMEMultipart()
    msg["From"] = SMTP_FROM
    msg["To"] = ", ".join(to)
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
        server.ehlo(SMTP_HELLO)
        server.sendmail(SMTP_FROM, to + BCC_EMAILS, msg.as_string())


def sendmail(vuln, type_cve):
    """NOTIFY_MODE=all: customer email for every new KEV entry (current behaviour)."""
    subject = f"[{vuln.get('cveID')}] - {vuln.get('vendorProject')} / {vuln.get('product')} (EXPLOITED)"
    body = f"{subject}\n\nDescription: {vuln.get('shortDescription', 'N/A')}\n\n{ONCALL_BLOCK}"
    _smtp_send(subject, body, CUSTOMER_EMAILS)
    print(f"Email Sent ! ({vuln.get('cveID')})")


def sendmail_assessed(vuln):
    """NOTIFY_MODE=filtered: L1 email (MATCH) or manual-review email (TO_CHECK)."""
    a = vuln["assessment"]
    cid = vuln.get("cveID")
    head = f"[{cid}] - {vuln.get('vendorProject')} / {vuln.get('product')}"
    details = (f"Description: {vuln.get('shortDescription', 'N/A')}\n"
               f"KEV date added: {vuln.get('dateAdded', 'N/A')}\n"
               f"CVSS vector: {a.get('vector') or 'not available'}\n"
               f"Source: {a.get('source') or 'N/A'}\n"
               f"Reference: https://www.cve.org/CVERecord?id={cid}\n")
    if a["status"] == "MATCH":
        subject = f"{head} (EXPLOITED - {a['type']})"
        body = (f"{subject}\n\nThis CVE was added to the CISA KEV catalog and meets the "
                f"notification criteria (AV:N / AC:L / PR:N / UI:N, High impact, {a['type']}).\n\n"
                f"{details}Vulnerability type evidence: {a.get('type_evidence')}\n\n{ONCALL_BLOCK}")
        to = L1_EMAILS
    else:
        subject = f"{head} (EXPLOITED - MANUAL REVIEW REQUIRED)"
        body = (f"{subject}\n\nThis CVE was added to the CISA KEV catalog, but the required "
                f"scoring information could not be determined automatically.\n"
                f"Reason: {a.get('reason')}\n\nPlease review it manually.\n\n{details}\n{ONCALL_BLOCK}")
        to = REVIEW_EMAILS
    _smtp_send(subject, body, to)
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
