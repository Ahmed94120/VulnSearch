import os, sys, json
env = sys.argv[1]; os.environ.update(VULNSG_DIR=env, NOTIFY_MODE="filtered", L1_EMAILS="l1@sg.test", REVIEW_EMAILS="review@sg.test", TEAMS_WEBHOOK_URL="https://x.invalid")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import vulnSearch, vulnAlert, vulnScore
vulnScore.time.sleep = lambda s: None
e = lambda c: {"cveID": c, "dateAdded": "2026-10-18", "vendorProject": "V", "product": "P", "shortDescription": "d"}
vulnSearch.VulnerabilityClient.get_kev = lambda self: {"vulnerabilities": [e("CVE-MATCH"), e("CVE-NOMATCH"), e("CVE-TOCHECK")]}
json.dump({"date_added": "2026-10-17"}, open(env + "/previous_run.json", "w"))
vec = {"CVE-MATCH": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVE-NOMATCH": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "CVE-TOCHECK": None}
vulnScore.Scorer.fetch_cve_org = lambda self, c: {"containers": {"cna": {"metrics": [{"cvssV3_1": {"vectorString": vec[c]}}] if vec[c] else [], "problemTypes": [{"descriptions": [{"cweId": "CWE-78"}]}]}}}
vulnScore.Scorer.fetch_nvd = lambda self, c: None
sent = []
vulnAlert._smtp_send = lambda subj, text, to, html=None: sent.append((to, subj))
cards = []
vulnAlert.send_teams = lambda card, url: cards.append(card["attachments"][0]["content"]["body"][0]["text"]) or 202
vulnAlert.run()
for to, subj in sent: print("MAIL", to, subj)
for c in cards: print("CARD", c)
print("alerted:", json.load(open(env + "/alerted_cves.json")))
print("watermark:", json.load(open(env + "/previous_run.json"))["date_added"])
