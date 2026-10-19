import os, sys, json, runpy
os.environ["VULNSG_DIR"] = sys.argv[1]; os.environ["TEAMS_WEBHOOK_URL"] = "https://example.invalid/hook"
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import vulnSearch, vulnAlert, smtplib
e = lambda c,d: {"cveID": c, "dateAdded": d, "vendorProject": "V", "product": "P"}
vulnSearch.VulnerabilityClient.get_kev = lambda self: {"vulnerabilities": [e("CVE-A","2026-10-18"), e("CVE-B","2026-10-17"), e("CVE-C","2026-10-16")]}
posted = []
vulnAlert.send_teams = lambda card, url: posted.append(card["attachments"][0]["content"]["body"][1]["facts"][0]["value"]) or 202
smtplib.SMTP = lambda *a, **k: (_ for _ in ()).throw(AssertionError("SMTP must not be used"))
import time; time.sleep = lambda s: None
sys.argv = ["teams_only.py"] + sys.argv[2:]
try:
    runpy.run_path(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "teams_only.py"), run_name="__main__")
except SystemExit as x:
    print("exit:", x)
print("posted:", posted, "| state files:", [f for f in os.listdir(os.environ["VULNSG_DIR"]) if f.endswith(".json")])
