import os, sys, json
os.environ["VULNSG_DIR"] = sys.argv[1]
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import vulnScore
vulnScore.time.sleep = lambda s: None
from vulnScore import Scorer, SourceError

def cveorg(vec=None, key="cvssV3_1", cwe=None, title="", desc="", adp_vec=None):
    cna = {"title": title, "descriptions": [{"value": desc}],
           "metrics": [{key: {"vectorString": vec}}] if vec else [],
           "problemTypes": [{"descriptions": [{"cweId": cwe}]}] if cwe else []}
    adp = [{"providerMetadata": {"shortName": "CISA-ADP"}, "metrics": [{"cvssV3_1": {"vectorString": adp_vec}}] if adp_vec else []}]
    return {"containers": {"cna": cna, "adp": adp}}
def nvd(vec=None, cwe=None, desc=""):
    m = {"cvssMetricV31": [{"type": "Primary", "cvssData": {"vectorString": vec}}]} if vec else {}
    return {"metrics": m, "weaknesses": [{"description": [{"value": cwe}]}] if cwe else [], "descriptions": [{"lang": "en", "value": desc}]}
DOWN = SourceError("unreachable (ConnectionError)")

cases = [
 ("CVE-2026-96951 (vrai vecteur)", cveorg("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", cwe="CWE-77", title="Windows Shell Security Feature Bypass Vulnerability"), nvd()),
 ("CVE-2026-76519 Cisco + NVD CWE-22", cveorg("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", title="Cisco Secure Email Gateway Arbitrary File Write Vulnerability"), nvd(cwe="CWE-22")),
 ("CVE-2026-76519 Cisco, aucun CWE", cveorg("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", title="Cisco Secure Email Gateway Arbitrary File Write Vulnerability"), nvd()),
 ("RCE par CWE-78", cveorg("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", cwe="CWE-78"), nvd()),
 ("Auth bypass par description", cveorg("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", desc="allows an authentication bypass via crafted header"), nvd(cwe="NVD-CWE-noinfo")),
 ("v4.0 + RCE texte", cveorg("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", key="cvssV4_0", desc="Remote code execution"), nvd()),
 ("PR:L", cveorg("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", cwe="CWE-94"), nvd()),
 ("impact faible", cveorg("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", cwe="CWE-94"), nvd()),
 ("aucun vecteur nulle part", cveorg(), nvd()),
 ("vecteur seulement chez CISA-ADP", cveorg(adp_vec="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", cwe="CWE-502"), nvd()),
 ("CVE.org down, vecteur NVD", DOWN, nvd("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", cwe="CWE-287")),
 ("les deux sources down", DOWN, DOWN),
 ("v2 seulement", cveorg("AV:N/AC:L/Au:N/C:C/I:C/A:C", key="cvssV2_0"), nvd()),
]
for label, org, nv in cases:
    s = Scorer()
    def fo(c, org=org):
        if isinstance(org, Exception): raise org
        return org
    def fn(c, nv=nv):
        if isinstance(nv, Exception): raise nv
        return nv
    s.fetch_cve_org, s.fetch_nvd = fo, fn
    r = s.assess({"cveID": "CVE-X", "shortDescription": "", "vulnerabilityName": ""})
    print(f"{label:36s} {r['status']:9s} {r['reason']}")
