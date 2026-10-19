import config  # loads .env before any os.environ read
import logging
import os
import requests
import json
from datetime import datetime, timezone, timedelta

BASE_DIR = config.BASE_DIR
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


def scan():
    """Return (entries to consider, newest dateAdded in the catalog).

    Does NOT save the watermark: vulnAlert.run() does it once alerting is done.
    """
    logger.info("=== scan start ===")
    client = VulnerabilityClient()

    kev = client.get_kev()
    all_vulns = kev.get("vulnerabilities", [])
    logger.info("KEV total: %d", len(all_vulns))

    vulns = client.get_new_kev_entries(all_vulns)
    logger.info("New KEV entries: %d", len(vulns))
    print(f"New KEV entries: {len(vulns)}")

    # Vendor filter removed on 08/06/2026, vector filter on 16/09/2026: every
    # new KEV entry is returned. The SG criteria live in vulnScore.py.

    newest = max((v["dateAdded"] for v in all_vulns if v.get("dateAdded")), default=None)

    logger.info("=== scan end ===")
    return vulns, newest


if __name__ == "__main__":
    # Read-only: shows what the next run would consider, saves nothing.
    entries, newest = scan()
    for v in entries:
        print(f"{v['cveID']} | {v.get('dateAdded')} | {v.get('vendorProject')} {v.get('product')}")
    print(f"Newest dateAdded in catalog: {newest}")
