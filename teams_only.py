"""One-shot: post Teams cards for KEV entries added since a date. No email, no state.

Usage:
    python3 teams_only.py --since 2026-10-17 --dry   # list only, sends nothing
    python3 teams_only.py --since 2026-10-17         # post the Teams cards
    python3 teams_only.py --since 2026-10-13 --assess        # SG criteria, cards show MATCH/TO_CHECK/NO_MATCH
    python3 teams_only.py --since 2026-10-13 --assess --dry  # same, list only

Does NOT read or write alerted_cves.json / previous_run.json: the cron job
is not affected and will not consider these CVEs as alerted (or not) because
of this script.
"""
import argparse
import sys
import time

from vulnSearch import VulnerabilityClient
from vulnAlert import build_card, send_teams, get_webhook_url, _cve_id, logger


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--since", required=True, help="YYYY-MM-DD, KEV dateAdded included")
    parser.add_argument("--dry", action="store_true", help="list only, send nothing")
    parser.add_argument("--assess", action="store_true", help="apply SG criteria (vulnScore.py) to each card")
    args = parser.parse_args()
    scorer = None
    if args.assess:
        from vulnScore import Scorer
        scorer = Scorer()

    kev = VulnerabilityClient().get_kev()
    entries = [v for v in kev.get("vulnerabilities", []) if v.get("dateAdded", "") >= args.since]
    entries.sort(key=lambda v: v.get("dateAdded", ""))
    print(f"{len(entries)} KEV entr(y/ies) since {args.since}")

    webhook_url = None if args.dry else get_webhook_url()
    if not args.dry and not webhook_url:
        sys.exit("No Teams webhook configured (TEAMS_WEBHOOK_URL or /home/sysroot/VulnSG/.teams_webhook)")

    failed = 0
    for v in entries:
        cid = _cve_id(v)
        line = f"{cid} | {v.get('dateAdded')} | {v.get('vendorProject')} / {v.get('product')}"
        if scorer:
            v["assessment"] = scorer.assess(v)
            line += f" | {v['assessment']['status']} | {v['assessment']['reason']}"
        if args.dry:
            print("DRY  " + line)
            continue
        try:
            card = build_card([v], "critical")
            if scorer:
                header = card["attachments"][0]["content"]["body"][0]
                header["text"] = "[TEST - no email sent] " + header["text"]
            status = send_teams(card, webhook_url)
            print(f"OK   {line} (HTTP {status})")
            logger.info("teams_only: Teams card sent for %s. HTTP %d", cid, status)
        except Exception as e:
            failed += 1
            print(f"FAIL {line} ({e})")
            logger.exception("teams_only: Teams card failed for %s", cid)
        time.sleep(1)  # spread the posts in the channel

    if failed:
        sys.exit(f"{failed} card(s) failed")


if __name__ == "__main__":
    main()
