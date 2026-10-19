"""Summarise a day of vulnAlert.py runs (read from runs.jsonl): one Teams card + one email.

The email goes to CC_EMAILS only (internal team and L1), never to the customer.

Usage:
    python3 daily_summary.py --dry               # today, print the summary, send nothing
    python3 daily_summary.py                     # today, post the card and send the email
    python3 daily_summary.py --date 2026-10-19   # another day

Read-only: does not touch alerted_cves.json / previous_run.json / runs.jsonl.
"""
import argparse
import config  # noqa: F401  (loads .env)
import json
import sys
from datetime import date

import vulnAlert
from render import build_summary_card, render_summary_mail
from vulnAlert import JOURNAL_FILE, send_teams, get_webhook_url, logger


def load_runs(day):
    """Runs started on `day` (YYYY-MM-DD, local time of the server)."""
    runs = []
    try:
        with open(JOURNAL_FILE) as f:
            for line in f:
                try:
                    run = json.loads(line)
                except ValueError:
                    logger.warning("daily_summary: unreadable journal line skipped")
                    continue
                if run.get("start", "").startswith(day):
                    runs.append(run)
    except FileNotFoundError:
        logger.warning("daily_summary: no journal %s yet", JOURNAL_FILE)
    return runs


def summarize(runs):
    # Latest outcome per CVE: an email failed at 10:00 and sent at 11:00 counts as sent.
    last = {}
    for run in runs:
        for c in run.get("cves", []):
            last[c["cve"]] = c
    cves = sorted(last.values(), key=lambda c: (c.get("dateAdded") or "", c["cve"]), reverse=True)
    hours = [r["start"][11:16] for r in runs]
    return {
        "runs": len(runs),
        "runs_ok": sum(1 for r in runs if r.get("ok")),
        "runs_failed": sum(1 for r in runs if not r.get("ok")),
        "first": min(hours) if hours else None,
        "last": max(hours) if hours else None,
        "modes": sorted({r.get("mode") for r in runs if r.get("mode")}),
        "escalated": [c for c in cves if c.get("email") == "sent"],
        "not_escalated": [c for c in cves if c.get("email") == "none"],
        "pending": [c for c in cves if c.get("email") == "failed"],
        "postponed": runs[-1].get("postponed", 0) if runs else 0,
        "teams_failed": sum(1 for c in cves if c.get("teams") == "failed"),
        "errors": [f"{r['start'][11:16]} - {r.get('error') or 'unknown error'}" for r in runs if not r.get("ok")],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--date", default=date.today().isoformat(), help="YYYY-MM-DD (default: today)")
    parser.add_argument("--dry", action="store_true", help="print the summary, send nothing")
    args = parser.parse_args()

    s = summarize(load_runs(args.date))
    if args.dry:
        print(json.dumps(s, indent=2))
        return

    # Card and email are independent: one failing must not prevent the other.
    failed = []
    try:
        webhook_url = get_webhook_url()
        if not webhook_url:
            raise RuntimeError("No Teams webhook configured (TEAMS_WEBHOOK_URL or .teams_webhook)")
        status = send_teams(build_summary_card(args.date, s), webhook_url)
        logger.info("daily_summary: card for %s sent (%d runs). HTTP %d", args.date, s["runs"], status)
        print(f"Daily summary card {args.date} sent. HTTP {status}")
    except Exception as e:
        logger.exception("daily_summary: card for %s failed", args.date)
        failed.append(f"card ({e})")
    try:
        text, html = render_summary_mail(args.date, s)
        vulnAlert._smtp_send(f"[KEV watch] Daily summary - {args.date}", text, vulnAlert.CC_EMAILS, html, cc=[])
        logger.info("daily_summary: email for %s sent to %s", args.date, vulnAlert.CC_EMAILS)
        print(f"Daily summary email {args.date} sent")
    except Exception as e:
        logger.exception("daily_summary: email for %s failed", args.date)
        failed.append(f"email ({e})")
    if failed:
        sys.exit("daily_summary failed: " + ", ".join(failed))


if __name__ == "__main__":
    main()
