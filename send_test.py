"""One-shot: test the alert content on real KEV entries added since a date. No state.

Usage:
    python3 send_test.py --since 2026-10-15 --to me@example.com --preview  # write .html/.json, send nothing
    python3 send_test.py --since 2026-10-15 --to me@example.com            # send the emails to --to only
    python3 send_test.py --since 2026-10-15 --to me@example.com --teams    # + post the Teams cards
    python3 send_test.py --since 2026-10-15 --eml ~/Downloads/eml --teams  # cards posted, emails as .eml files
    VULNSG_ENV_FILE=.env.test python3 send_test.py --since 2026-10-15     # recipients from MAIL_TEST_TO

Each entry gets the NOTIFY_MODE=all email and, unless NO_MATCH, the NOTIFY_MODE=filtered one.
Emails go ONLY to --to (MAIL_TEST_TO: no customer, no BCC, subject "[TEST] ").
With --eml, nothing is mailed: each email is written as a .eml file (real recipients
shown, unless --to is given).
Does NOT read or write alerted_cves.json / previous_run.json.
"""
import argparse
import json
import os
import sys
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--since", required=True, help="YYYY-MM-DD, KEV dateAdded included")
    parser.add_argument("--to", help="the only recipients of every email, comma-separated "
                                     "(default: MAIL_TEST_TO from the env file; required unless --eml)")
    parser.add_argument("--eml", help="write the emails as .eml files in this folder, send none")
    parser.add_argument("--preview", action="store_true", help="write files to $VULNSG_DIR/preview, send nothing")
    parser.add_argument("--teams", action="store_true", help="also post the Teams cards")
    args = parser.parse_args()
    import config  # noqa: F401  (MAIL_TEST_TO may come from the env file, e.g. VULNSG_ENV_FILE=.env.test)
    args.to = args.to or os.environ.get("MAIL_TEST_TO")
    if not (args.to or args.eml):
        parser.error("--to (or MAIL_TEST_TO) or --eml is required")
    # Must be set before vulnAlert reads its configuration.
    if args.to:
        os.environ["MAIL_TEST_TO"] = args.to
    if args.eml:
        os.makedirs(args.eml, exist_ok=True)
        os.environ["MAIL_EML_DIR"] = os.path.abspath(args.eml)

    import vulnAlert
    from render import build_card, render_mail
    from vulnScore import Scorer
    from vulnSearch import VulnerabilityClient

    kev = VulnerabilityClient().get_kev()
    entries = sorted((v for v in kev.get("vulnerabilities", []) if v.get("dateAdded", "") >= args.since),
                     key=lambda v: v.get("dateAdded", ""))
    print(f"{len(entries)} KEV entr(y/ies) since {args.since}")

    out = vulnAlert.BASE_DIR / "preview"
    if args.preview:
        out.mkdir(parents=True, exist_ok=True)
    webhook_url = vulnAlert.get_webhook_url() if args.teams and not args.preview else None
    if args.teams and not args.preview and not webhook_url:
        sys.exit("No Teams webhook configured (TEAMS_WEBHOOK_URL or .teams_webhook)")

    scorer = Scorer()
    failed = 0
    for v in entries:
        cid = vulnAlert._cve_id(v)
        plain = dict(v)  # NOTIFY_MODE=all: no assessment
        v["assessment"] = scorer.assess(v)
        status = v["assessment"]["status"]
        print(f"{cid} | {v.get('vendorProject')} / {v.get('product')} | {status}")
        try:
            if args.preview:
                for kind, item in (("all", plain), ("filtered", v)):
                    _, html = render_mail(item, f"Preview ({kind} mode).", vulnAlert.ONCALL_BLOCK)
                    (out / f"{cid}-{kind}.html").write_text(html)
                (out / f"{cid}-card.json").write_text(json.dumps(build_card([v]), indent=2))
                continue
            vulnAlert.sendmail(plain, "critical")
            if status != "NO_MATCH":
                vulnAlert.sendmail_assessed(v)
            if webhook_url:
                card = build_card([v])
                header = card["attachments"][0]["content"]["body"][0]
                header["text"] = "[TEST] " + header["text"]
                print(f"  Teams HTTP {vulnAlert.send_teams(card, webhook_url)}")
        except Exception as e:
            failed += 1
            print(f"  FAIL {cid} ({type(e).__name__}: {e})")
        time.sleep(1)

    if args.preview:
        print(f"Preview written to {out}")
    if args.eml:
        print(f"Emails written to {os.environ['MAIL_EML_DIR']}")
    if failed:
        sys.exit(f"{failed} entr(y/ies) failed")


if __name__ == "__main__":
    main()
