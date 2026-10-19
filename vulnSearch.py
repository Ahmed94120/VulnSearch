import csv
import logging
import os
import requests
from pathlib import Path
import json
from datetime import datetime, timezone, timedelta

BASE_DIR = Path(os.environ.get("VULNSG_DIR", "/home/sysroot/VulnSG"))
STATE_FILE = BASE_DIR / "previous_run.json"
LOG_FILE = BASE_DIR / "vulnscan.log"

# KEV "dateAdded" is a bare date (no time) computed in CISA's timezone (US/Eastern).
# Re-reading one extra day absorbs the timezone shift; alerted_cves.json removes duplicates.
OVERLAP_DAYS = 1
# No state file (first run, deleted file): only look back this far, never mail the whole catalog.
FIRST_RUN_LOOKBACK_DAYS = 1

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
# urllib3 DEBUG logs full URLs, including the Teams webhook signature.
logging.getLogger("urllib3").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)


def _parse_date(value):
    return datetime.strptime(value, "%Y-%m-%d").date()


class VulnerabilityClient:
    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.headers = {
            "Accept": "application/json",
            "User-Agent": "OCD-VulnSearch/1.0",
        }

    # ---------- Sources ----------

    def get_kev(self):
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        logger.debug("GET %s", url)
        r = self.session.get(url, headers=self.headers, timeout=30)
        r.raise_for_status()
        data = r.json()
        logger.info("KEV fetched: %d entries", len(data.get("vulnerabilities", [])))
        return data

    def get_cve_record(self, cve_id):
        url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
        logger.debug("GET %s", url)
        r = self.session.get(url, headers=self.headers, timeout=30)
        r.raise_for_status()
        logger.debug("CVE record fetched: %s", cve_id)
        return r.json()

    def get_euvd(self):
        """ENISA EU Vulnerability Database, score 7-10."""
        url = "https://euvdservices.enisa.europa.eu/api/search?fromScore=7&toScore=10"
        logger.debug("GET %s", url)
        r = self.session.get(url, headers=self.headers, timeout=30)
        r.raise_for_status()
        data = r.json()
        logger.info("EUVD fetched")
        return data

    # ---------- Vector helpers ----------

    @staticmethod
    def parse_vector(vector_string):
        parsed = {}
        for seg in vector_string.split("/"):
            if ":" in seg:
                k, v = seg.split(":", 1)
                parsed[k] = v
        return parsed

    # Preference order. First match wins.
    CVSS_KEYS = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0")

    @classmethod
    def _vector_from_metrics(cls, metrics):
        """First vectorString found in a metrics[] list, by version preference."""
        if not metrics:
            return None
        for key in cls.CVSS_KEYS:
            for metric in metrics:
                block = metric.get(key)
                if block and block.get("vectorString"):
                    return block["vectorString"]
        return None

    @classmethod
    def extract_vector(cls, cve_data):
        """
        Best CVSS vector string from a CVE record.
        metrics is a LIST living at containers.cna.metrics[] and at
        containers.adp[].metrics[] (adp is itself a list). Any item may hold
        cvssV4_0 / cvssV3_1 / cvssV3_0 / cvssV2_0. CNA wins over ADP; within a
        source, newer CVSS wins. None if nothing scorable.
        """
        containers = cve_data.get("containers", {})

        # 1. CNA metrics first (authoritative source)
        vector = cls._vector_from_metrics(containers.get("cna", {}).get("metrics"))
        if vector:
            return vector

        # 2. Fallback to every ADP container (e.g. CISA-ADP on old CVEs)
        for adp in containers.get("adp", []):
            vector = cls._vector_from_metrics(adp.get("metrics"))
            if vector:
                return vector

        return None

    @classmethod
    def is_critical_vector(cls, vector):
        """True if network, low-complexity, no auth/priv, no UI, high impact.

        Handles CVSS v2, v3.0/v3.1 and v4.0. Detects version by which keys the
        vector exposes, since v2 has no leading 'CVSS:' segment.
        """
        p = cls.parse_vector(vector)

        # --- CVSS v4.0 ---  (leading segment CVSS:4.0)
        if p.get("CVSS") == "4.0":
            base_ok = (
                p.get("AV") == "N"
                and p.get("AC") == "L"
                and p.get("PR") == "N"
            )
            return base_ok

        # --- CVSS v2 ---  no 'CVSS:' key, uses 'Au' not 'PR', no 'UI'
        # metrics: AV{L,A,N} AC{H,M,L} Au{M,S,N} C/I/A{N,P,C}
        if "CVSS" not in p and "Au" in p:
            base_ok = (
                p.get("AV") == "N"
                and p.get("AC") in ("L", "M")   # v2 has no single 'low' equiv to v3
                and p.get("Au") == "N"
            )
            return base_ok

        # --- CVSS v3.0 / v3.1 ---
        base_ok = (
            p.get("AV") == "N"
            and p.get("AC") == "L"
            and p.get("PR") == "N"
        )
        return base_ok

    # ---------- Filters (not used since 16/09/2026) ----------

    def filter_by_vendor(self, vulnList, productList):
        """Keep KEV vulns matching watched vendor/product list."""
        logger.info("filter_by_vendor: %d vulns vs %d watched products", len(vulnList), len(productList))
        affected = []
        for vuln in vulnList:
            for data in productList:
                if (vuln.get("vendorProject") == data["vendor"]):
                    logger.debug("match: %s %s / %s", vuln.get("vendorProject"), vuln.get("product"), vuln.get("cveID"))
                    affected.append(vuln)
                    break
        logger.info("filter_by_vendor done: %d matched", len(affected))
        return affected

    def filter_by_metrics(self, affectedProductList):
        """Fetch each CVE record, keep only critical-vector vulns."""
        logger.info("filter_by_metrics: checking %d vulns", len(affectedProductList))
        critical = []
        not_found = []
        for vuln in affectedProductList:
            try:
                cve_data = self.get_cve_record(vuln["cveID"])
                vector = self.extract_vector(cve_data)
                if vector is None:
                    logger.debug("no vector for %s", vuln.get("cveID"))
                    not_found.append(vuln)
                    continue
                if self.is_critical_vector(vector):
                    logger.info("critical: %s vector=%s", vuln.get("cveID"), vector)
                    vuln["vectorString"] = vector
                    critical.append(vuln)
                else:
                    logger.debug("not critical: %s vector=%s", vuln.get("cveID"), vector)
            except Exception as e:
                logger.error("Error %s: %s", vuln.get("cveID"), e)
                not_found.append(vuln)
        logger.info("filter_by_metrics done: %d critical", len(critical))
        return {"critical": critical, "not_found": not_found}

    # ---------- State ----------

    def load_state(self):
        if not STATE_FILE.exists():
            return {}
        try:
            with open(STATE_FILE) as f:
                return json.load(f)
        except Exception:
            logger.exception("Unable to read state file")
            return {}

    def save_watermark(self, date_added):
        """Store the KEV date the next run starts from (minus OVERLAP_DAYS).

        Called by vulnAlert.run() AFTER alerting, never before: if alerting
        fails, the watermark does not move and the entries are retried.
        """
        state = {
            "date_added": date_added,
            "last_run": datetime.now(timezone.utc).isoformat(),
        }
        try:
            tmp = STATE_FILE.with_suffix(".json.tmp")
            with open(tmp, "w") as f:
                json.dump(state, f, indent=4)
            os.replace(tmp, STATE_FILE)
        except Exception:
            logger.exception("Unable to save state file")

    def get_new_kev_entries(self, vulnerabilities):
        """
        Return KEV entries added since the previous run, by date only.

        We never stop on the last processed CVE ID: CISA does not keep same-day
        entries in insertion order. On 2026-10-13, CVE-2026-96951 was inserted
        BELOW CVE-2026-104935 (already processed), and the old "break on
        last_cve" logic never read it. Order in the feed must not matter.
        Duplicates caused by the overlap are removed by alerted_cves.json.
        """
        state = self.load_state()
        date_added = state.get("date_added")

        if date_added:
            cutoff = _parse_date(date_added) - timedelta(days=OVERLAP_DAYS)
        else:
            cutoff = datetime.now(timezone.utc).date() - timedelta(days=FIRST_RUN_LOOKBACK_DAYS)
            logger.warning("No previous state found, looking back to %s only", cutoff)

        new_entries = []
        for vuln in vulnerabilities:
            try:
                if _parse_date(vuln["dateAdded"]) >= cutoff:
                    new_entries.append(vuln)
            except (KeyError, TypeError, ValueError):
                # Fail-open: an unreadable date must not hide a KEV entry.
                logger.warning("Unreadable dateAdded for %s: %r, kept",
                               vuln.get("cveID"), vuln.get("dateAdded"))
                new_entries.append(vuln)

        logger.info("Found %d KEV entries added since %s", len(new_entries), cutoff)
        return new_entries


def load_products(product_file):
    logger.debug("loading product list from %s", product_file)
    products = []
    with open(product_file) as f:
        reader = csv.DictReader(f, delimiter=";")
        for row in reader:
            products.append({
                "vendor": row["Editor/Manufacturer"],
                "product": row["Software/Firmware"],
            })
    logger.info("loaded %d watched products from %s", len(products), product_file)
    return products


def scan(product_file="/home/sysroot/VulnSG/produit_clean.csv"):
    """Return (entries to consider, newest dateAdded in the catalog).

    Does NOT save the watermark: vulnAlert.run() does it once alerting is done.
    """
    logger.info("=== scan start (product_file=%s) ===", product_file)
    client = VulnerabilityClient()

    kev = client.get_kev()
    all_vulns = kev.get("vulnerabilities", [])
    logger.info("KEV total: %d", len(all_vulns))

    vulns = client.get_new_kev_entries(all_vulns)
    logger.info("New KEV entries: %d", len(vulns))
    print(f"New KEV entries: {len(vulns)}")

    # Stop filtering on vendor (08/06/2026)
    # products = load_products(product_file)
    # affected = client.filter_by_vendor(vulns, products)

    # Stop filter on vector string (16/09/2026)
    # cve_result = client.filter_by_metrics(vulns)

    newest = max((v["dateAdded"] for v in all_vulns if v.get("dateAdded")), default=None)

    logger.info("=== scan end ===")
    return vulns, newest


if __name__ == "__main__":
    # Read-only: shows what the next run would consider, saves nothing.
    entries, newest = scan()
    for v in entries:
        print(f"{v['cveID']} | {v.get('dateAdded')} | {v.get('vendorProject')} {v.get('product')}")
    print(f"Newest dateAdded in catalog: {newest}")
