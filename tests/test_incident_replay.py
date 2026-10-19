import os, sys, json, importlib
env = sys.argv[1]
os.environ["VULNSG_DIR"] = env
for f in ("previous_run.json", "alerted_cves.json"):
    p = os.path.join(env, f)
    if os.path.exists(p): os.remove(p)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import vulnSearch, vulnAlert

def e(cid, d, vendor="X"):
    return {"cveID": cid, "dateAdded": d, "vendorProject": vendor, "product": "P", "shortDescription": "d"}

feeds = {
 "13/10 15h": [e("CVE-2026-104935","2026-10-13","Ivanti"), e("CVE-2015-5477","2026-10-08")],
 "13/10 16h (96951 inseree SOUS 104935)": [e("CVE-2026-104935","2026-10-13","Ivanti"), e("CVE-2026-96951","2026-10-13","Microsoft"), e("CVE-2015-5477","2026-10-08")],
 "14/10 20h": [e("CVE-2026-105134","2026-10-14"), e("CVE-2026-76519","2026-10-14","Cisco"), e("CVE-2026-105133","2026-10-14"), e("CVE-2026-0322","2026-10-14"),
               e("CVE-2026-104935","2026-10-13","Ivanti"), e("CVE-2026-96951","2026-10-13","Microsoft"), e("CVE-2015-5477","2026-10-08")],
}
current = {}
vulnSearch.VulnerabilityClient.get_kev = lambda self: {"vulnerabilities": current["feed"]}
mails = []
fail = set(os.environ.get("FAIL_MAIL","").split(","))
def fake_mail(v, t):
    if v["cveID"] in fail: raise OSError("smtp down")
    mails.append(v["cveID"])
vulnAlert.sendmail = fake_mail
vulnAlert.send_teams = lambda card, url: 202

# seed state as of 08/10, already alerted
json.dump({"date_added": "2026-10-08"}, open(os.path.join(env,"previous_run.json"),"w"))
json.dump(["CVE-2015-5477"], open(os.path.join(env,"alerted_cves.json"),"w"))

for label, feed in feeds.items():
    current["feed"] = feed
    mails.clear()
    vulnAlert.run()
    st = json.load(open(os.path.join(env,"previous_run.json")))
    print(f"{label:42s} mails={mails}  watermark={st['date_added']}")
    if label.startswith("14/10"): fail.clear()
