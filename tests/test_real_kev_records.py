import os, sys
os.environ["VULNSG_DIR"] = sys.argv[1]
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import vulnScore
from vulnScore import Scorer

# Real CVE.org data fetched on 2026-10-19 (CNA metrics, CWEs, title/description).
def rec(title, desc, metrics, cwes, state="PUBLISHED"):
    return {"cveMetadata": {"state": state}, "containers": {"cna": {
        "title": title or "", "descriptions": [{"value": desc}] if desc else [],
        "metrics": [{k: {"vectorString": v}} for m in metrics for k, v in m.items()],
        "problemTypes": [{"descriptions": [{"cweId": c} for c in cwes]}]},
        "adp": [{"providerMetadata": {"shortName": "CISA-ADP"}, "metrics": []}]}}
real = {
 "CVE-2026-21589": ("Atlassian", "2026-10-15", rec(None, None, [], [], state="REJECTED")),
 "CVE-2026-105134": ("Ahsay", "2026-10-14", rec("Ahsay AhsayCBS Replication Receiver UpdateReceivers.do os command injection", "can lead to os command injection. It is possible to launch the attack remotely.",
     [{"cvssV4_0": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P"}, {"cvssV3_1": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:P/RL:O/RC:C"}, {"cvssV2_0": "AV:N/AC:L/Au:N/C:C/I:C/A:C"}], ["CWE-78", "CWE-77"])),
 "CVE-2026-76519": ("Cisco", "2026-10-14", rec("Cisco Secure Email Gateway Arbitrary File Write Vulnerability", "A vulnerability in the Advanced Malware Protection (AMP) feature of Cisco Secure Email Gateway could allow...",
     [{"cvssV3_1": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}], ["CWE-23"])),
 "CVE-2026-105133": ("Ahsay", "2026-10-14", rec("Ahsay AhsayCBS API ApiStructsAction.java checkSysPwd improper authentication", "results in improper authentication. It is possible to initiate the attack remotely.",
     [{"cvssV4_0": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/E:P"}, {"cvssV3_1": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/E:P/RL:O/RC:C"}], ["CWE-287"])),
 "CVE-2026-0322": ("Palo Alto Networks", "2026-10-14", rec("PAN-OS: Authenticated Remote Code Execution (RCE) in the Management Interface", "A remote code execution (RCE) vulnerability in the management interface of Palo Alto Networks PAN-OS...",
     [{"cvssV4_0": "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}], ["CWE-94"])),
 "CVE-2026-104935": ("Ivanti", "2026-10-13", rec(None, "Authentication bypass by spoofing in ICS before version 25.1.3.0 allows a remote unauthenticated attacker to execute...",
     [{"cvssV3_1": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L"}], ["CWE-290"])),
 "CVE-2026-96951": ("Microsoft", "2026-10-13", rec("Windows Shell Security Feature Bypass Vulnerability", "Improper neutralization of special elements used in a command ('command injection') in Windows Shell allows an unauthorized attacker to bypass a security feature over a network.",
     [{"cvssV3_1": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C"}], ["CWE-77"])),
}
s = Scorer()
s.fetch_cve_org = lambda cid: real[cid][2]
s.fetch_nvd = lambda cid: None          # NVD not reachable from this sandbox
mail = {"MATCH": "mail L1", "TO_CHECK": "mail revue", "NO_MATCH": "aucun mail"}
for cid, (vendor, d, _) in real.items():
    r = s.assess({"cveID": cid, "vendorProject": vendor, "dateAdded": d})
    print(f"{cid:16s} {vendor:19s} {r['status']:9s} {mail[r['status']]:11s} {r['reason']}")
