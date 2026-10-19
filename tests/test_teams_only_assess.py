import os, sys, runpy
os.environ.update(VULNSG_DIR=sys.argv[1], TEAMS_WEBHOOK_URL="https://x.invalid")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import vulnSearch, vulnAlert, vulnScore, smtplib, time
time.sleep = lambda s: None
e = lambda c, d: {"cveID": c, "dateAdded": d, "vendorProject": "V", "product": "P"}
vulnSearch.VulnerabilityClient.get_kev = lambda self: {"vulnerabilities": [e("CVE-OK", "2026-10-14"), e("CVE-UIR", "2026-10-13"), e("CVE-OLD", "2026-10-08")]}
vec = {"CVE-OK": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVE-UIR": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"}
vulnScore.Scorer.fetch_cve_org = lambda self, c: {"containers": {"cna": {"metrics": [{"cvssV3_1": {"vectorString": vec[c]}}], "problemTypes": [{"descriptions": [{"cweId": "CWE-78"}]}]}}}
vulnScore.Scorer.fetch_nvd = lambda self, c: None
cards = []
vulnAlert.send_teams = lambda card, url: cards.append(card["attachments"][0]["content"]["body"][0]["text"]) or 202
smtplib.SMTP = lambda *a, **k: (_ for _ in ()).throw(AssertionError("SMTP used"))
sys.argv = ["teams_only.py", "--since", "2026-10-13", "--assess"]
import importlib; sys.modules.pop("teams_only", None)
runpy.run_path(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "teams_only.py"), run_name="__main__")
print("cards:", cards, "| state:", [f for f in os.listdir(sys.argv and os.environ["VULNSG_DIR"]) if f.endswith(".json")])
