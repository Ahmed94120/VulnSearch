"""CVSS sub-score and vulnerability-type assessment for KEV entries.

Implements the SG criteria (feasibility request, 19/10/2026):
  - AV:N, AC:L, PR:N, UI:N
  - at least one of C / I / A = High   (CVSS 4.0: VC / VI / VA)
  - vulnerability type is RCE or Authentication Bypass

assess() returns one of three statuses:
  MATCH     all criteria met                               -> email
  TO_CHECK  data missing / unreadable / sources unreachable -> email, manual review
  NO_MATCH  data available and criteria not met            -> no email

Sources, in this order: CVE.org (CNA, then ADP e.g. CISA-ADP), then NVD.
CVEfeed.io is not queried: no documented public API was found.
"""
import logging
import os
import re
import time

import requests

logger = logging.getLogger(__name__)

URL_CVE_ORG = "https://cveawg.mitre.org/api/cve/{cve_id}"
URL_NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY")
# NVD without a key: 5 requests / 30 s. With a key: 50 / 30 s.
NVD_MIN_INTERVAL = 0.7 if NVD_API_KEY else 6.5

# Within a source, the criteria are written in CVSS 3.x terms (C/I/A),
# so 3.1 and 3.0 are preferred; 4.0 is mapped (VC/VI/VA); 2.0 cannot be
# evaluated (no PR / UI) and is only used to explain a TO_CHECK.
CVE_ORG_KEYS = ("cvssV3_1", "cvssV3_0", "cvssV4_0")
NVD_KEYS = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40")

RCE_CWES = {
    "CWE-94",   # Code Injection
    "CWE-95",   # Eval Injection
    "CWE-77",   # Command Injection
    "CWE-78",   # OS Command Injection
    "CWE-502",  # Deserialization of Untrusted Data
    "CWE-917",  # Expression Language Injection
    "CWE-1336", # Template Injection
    "CWE-98",   # PHP Remote File Inclusion
}
AUTH_BYPASS_CWES = {
    "CWE-287",  # Improper Authentication
    "CWE-288",  # Authentication Bypass Using an Alternate Path
    "CWE-290",  # Authentication Bypass by Spoofing
    "CWE-294",  # Authentication Bypass by Capture-replay
    "CWE-302",  # Authentication Bypass by Assumed-Immutable Data
    "CWE-304",  # Missing Critical Step in Authentication
    "CWE-305",  # Authentication Bypass by Primary Weakness
    "CWE-306",  # Missing Authentication for Critical Function
    "CWE-1390", # Weak Authentication
}
# CWE values that carry no information.
NON_CWES = {"NVD-CWE-noinfo", "NVD-CWE-Other"}

RCE_PATTERNS = re.compile(
    r"remote code execution|\bRCE\b|(execute|execution of) arbitrary (code|commands?)"
    r"|arbitrary code execution|code injection|command injection",
    re.IGNORECASE,
)
AUTH_BYPASS_PATTERNS = re.compile(
    r"authentication bypass|bypass(es|ing)? (the )?authentication"
    r"|missing authentication|unauthenticated access",
    re.IGNORECASE,
)


class SourceError(Exception):
    pass


class Scorer:
    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.headers = {"Accept": "application/json", "User-Agent": "OCD-VulnSearch/1.0"}
        self._last_nvd_call = 0.0

    # ---------- Fetch ----------

    def fetch_cve_org(self, cve_id):
        try:
            r = self.session.get(URL_CVE_ORG.format(cve_id=cve_id), headers=self.headers, timeout=30)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            raise SourceError(f"CVE.org unreachable ({type(e).__name__})") from e

    def fetch_nvd(self, cve_id):
        wait = NVD_MIN_INTERVAL - (time.monotonic() - self._last_nvd_call)
        if wait > 0:
            time.sleep(wait)
        headers = dict(self.headers)
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY
        try:
            r = self.session.get(URL_NVD, params={"cveId": cve_id}, headers=headers, timeout=30)
            self._last_nvd_call = time.monotonic()
            r.raise_for_status()
            items = r.json().get("vulnerabilities", [])
            return items[0]["cve"] if items else None
        except Exception as e:
            raise SourceError(f"NVD unreachable ({type(e).__name__})") from e

    # ---------- Extract ----------

    @staticmethod
    def _cve_org_sources(record):
        """Yield (label, metrics, cwes, texts) for the CNA then each ADP container."""
        containers = (record or {}).get("containers", {})
        blocks = [("CVE.org CNA", containers.get("cna", {}))]
        for adp in containers.get("adp", []):
            name = adp.get("providerMetadata", {}).get("shortName", "ADP")
            blocks.append((f"CVE.org {name}", adp))
        for label, block in blocks:
            cwes = {d.get("cweId") for pt in block.get("problemTypes", [])
                    for d in pt.get("descriptions", []) if d.get("cweId")}
            texts = [block.get("title", "")] + [d.get("value", "") for d in block.get("descriptions", [])]
            yield label, block.get("metrics", []), cwes, texts

    @staticmethod
    def _vector_from_cve_org(metrics):
        has_v2 = False
        for key in CVE_ORG_KEYS:
            for m in metrics or []:
                vec = (m.get(key) or {}).get("vectorString")
                if vec:
                    return vec, False
        for m in metrics or []:
            if (m.get("cvssV2_0") or {}).get("vectorString"):
                has_v2 = True
        return None, has_v2

    @staticmethod
    def _nvd_source(cve):
        if not cve:
            return None, False, set(), []
        metrics = cve.get("metrics", {})
        vector = None
        for key in NVD_KEYS:
            entries = metrics.get(key, [])
            # Primary (NVD) score first, then secondary (CNA) scores.
            entries = sorted(entries, key=lambda e: e.get("type") != "Primary")
            for e in entries:
                vec = e.get("cvssData", {}).get("vectorString")
                if vec:
                    vector = vec
                    break
            if vector:
                break
        has_v2 = bool(metrics.get("cvssMetricV2"))
        cwes = {d.get("value") for w in cve.get("weaknesses", []) for d in w.get("description", [])}
        texts = [d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang", "en").startswith("en")]
        return vector, has_v2, cwes, texts

    @staticmethod
    def parse_vector(vector):
        parsed = {}
        for seg in vector.split("/"):
            k, sep, v = seg.partition(":")
            if sep:
                parsed[k.strip()] = v.strip()
        return parsed

    # ---------- Evaluate ----------

    @classmethod
    def check_subscores(cls, vector):
        """Return (ok, failed_conditions) or (None, reason) if the vector is unusable."""
        p = cls.parse_vector(vector)
        version = p.get("CVSS", "")
        if version.startswith("3."):
            impact = ("C", "I", "A")
        elif version == "4.0":
            impact = ("VC", "VI", "VA")
        else:
            return None, f"unsupported CVSS version ({vector})"

        missing = [k for k in ("AV", "AC", "PR", "UI") + impact if k not in p]
        if missing:
            return None, f"incomplete CVSS vector, missing {', '.join(missing)} ({vector})"

        failed = []
        for key, expected in (("AV", "N"), ("AC", "L"), ("PR", "N"), ("UI", "N")):
            if p[key] != expected:
                failed.append(f"{key}:{p[key]}")
        if not any(p[k] == "H" for k in impact):
            failed.append("no High impact on " + "/".join(impact))
        return not failed, failed

    @staticmethod
    def classify_type(cwes, texts):
        """Return ('RCE' | 'Authentication Bypass' | None, evidence, informative_cwes)."""
        cwes = {c for c in cwes if c and c not in NON_CWES}
        if cwes & RCE_CWES:
            return "RCE", ", ".join(sorted(cwes & RCE_CWES)), cwes
        if cwes & AUTH_BYPASS_CWES:
            return "Authentication Bypass", ", ".join(sorted(cwes & AUTH_BYPASS_CWES)), cwes
        text = " ".join(t for t in texts if t)
        m = RCE_PATTERNS.search(text)
        if m:
            return "RCE", f'description: "{m.group(0)}"', cwes
        m = AUTH_BYPASS_PATTERNS.search(text)
        if m:
            return "Authentication Bypass", f'description: "{m.group(0)}"', cwes
        return None, None, cwes

    def assess(self, kev_entry):
        """Assess one KEV entry. Never raises: any problem gives TO_CHECK."""
        cve_id = kev_entry.get("cveID")
        result = {"status": "TO_CHECK", "reason": None, "vector": None, "source": None,
                  "type": None, "type_evidence": None, "cwes": []}
        try:
            return self._assess(cve_id, kev_entry, result)
        except Exception as e:
            logger.exception("assess failed for %s", cve_id)
            result["reason"] = f"automatic assessment failed ({type(e).__name__})"
            return result

    def _assess(self, cve_id, kev_entry, result):
        errors = []
        all_cwes = set()
        texts = [kev_entry.get("vulnerabilityName", ""), kev_entry.get("shortDescription", "")]
        vector = source = None
        saw_v2 = False

        # 1. CVE.org: CNA first, then ADP containers.
        try:
            record = self.fetch_cve_org(cve_id)
            state = (record or {}).get("cveMetadata", {}).get("state")
            if state == "REJECTED":
                # Still listed in the KEV: a human must decide (ID replaced? listing error?).
                result["reason"] = "CVE record is REJECTED on CVE.org while listed in the KEV"
                return result
            for label, metrics, cwes, block_texts in self._cve_org_sources(record):
                all_cwes |= cwes
                texts += block_texts
                if vector is None:
                    vec, v2 = self._vector_from_cve_org(metrics)
                    saw_v2 |= v2
                    if vec:
                        vector, source = vec, label
        except SourceError as e:
            errors.append(str(e))

        # 2. NVD: always queried for its CWEs / description; its vector only if CVE.org had none.
        try:
            nvd_vec, v2, cwes, nvd_texts = self._nvd_source(self.fetch_nvd(cve_id))
            saw_v2 |= v2
            all_cwes |= cwes
            texts += nvd_texts
            if vector is None and nvd_vec:
                vector, source = nvd_vec, "NVD"
        except SourceError as e:
            errors.append(str(e))

        result["vector"], result["source"] = vector, source

        if vector is None:
            if errors:
                result["reason"] = "CVSS sub-scores could not be fetched: " + "; ".join(errors)
            elif saw_v2:
                result["reason"] = "only a CVSS v2 vector is published (no PR / UI sub-scores)"
            else:
                result["reason"] = "no CVSS vector published on CVE.org or NVD"
            return result

        ok, detail = self.check_subscores(vector)
        if ok is None:
            result["reason"] = detail
            return result
        if not ok:
            result["status"] = "NO_MATCH"
            result["reason"] = "CVSS criteria not met: " + ", ".join(detail)
            return result

        vtype, evidence, informative = self.classify_type(all_cwes, texts)
        result["cwes"] = sorted(informative)
        if vtype:
            result.update(status="MATCH", type=vtype, type_evidence=evidence,
                          reason=f"CVSS criteria met, {vtype} ({evidence})")
        elif informative:
            result["status"] = "NO_MATCH"
            result["reason"] = ("CVSS criteria met, but type is not RCE / Authentication Bypass "
                                f"({', '.join(sorted(informative))})")
        else:
            result["reason"] = ("CVSS criteria met, but the vulnerability type (RCE / Authentication "
                                "Bypass) could not be determined: no CWE and no explicit wording")
        return result
