"""server.engine - Scanner engine connecting cached security feeds to homebom_core.

Loads:
- CISA KEV catalog (cisa_kev.json)
- FIRST EPSS scores (epss.csv.gz)
- NVD 2.0 CVE records (server/data/nvd_cache/)

Evaluates all home devices with defensive three-state logic and priority ranking.
"""

import csv
import gzip
import json
import sys
from pathlib import Path
from typing import Any

# Ensure packages/homebom-core is in sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
CORE_DIR = REPO_ROOT / "packages" / "homebom-core"
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from homebom_core.match import match_device_vulnerabilities
from homebom_core.rank import DeviceRiskProfile, rank_device, sort_ranked_devices

DATA_DIR = Path(__file__).resolve().parent / "data"
NVD_CACHE_DIR = DATA_DIR / "nvd_cache"
KEV_PATH = DATA_DIR / "cisa_kev.json"
EPSS_PATH = DATA_DIR / "epss.csv.gz"

# In-memory cache for loaded feed dictionaries to maintain fast, responsive queries
_KEV_CATALOG: dict[str, Any] | None = None
_EPSS_SCORES: dict[str, float] | None = None


def get_kev_catalog() -> dict[str, Any]:
    """Load cached CISA KEV catalog."""
    global _KEV_CATALOG
    if _KEV_CATALOG is not None:
        return _KEV_CATALOG

    if not KEV_PATH.exists():
        return {}

    with open(KEV_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    _KEV_CATALOG = {v["cveID"]: v for v in data.get("vulnerabilities", [])}
    return _KEV_CATALOG


def get_epss_scores() -> dict[str, float]:
    """Load cached FIRST EPSS scores from compressed CSV."""
    global _EPSS_SCORES
    if _EPSS_SCORES is not None:
        return _EPSS_SCORES

    if not EPSS_PATH.exists():
        return {}

    scores: dict[str, float] = {}
    with gzip.open(EPSS_PATH, "rt", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if row and row[0].startswith("CVE-"):
                try:
                    scores[row[0]] = float(row[1])
                except (ValueError, IndexError):
                    continue
    _EPSS_SCORES = scores
    return _EPSS_SCORES


def safe_filename_for_cpe(cpe: str) -> str:
    """Derive deterministic filename for a CPE in nvd_cache."""
    clean = cpe.replace("cpe:2.3:", "").replace(":", "_").replace("*", "ANY").replace("/", "_")
    return f"{clean}.json"


def get_nvd_records_for_cpe(cpe: str) -> list[dict[str, Any]]:
    """Retrieve cached NVD records for a given CPE."""
    cache_file = NVD_CACHE_DIR / safe_filename_for_cpe(cpe)
    if not cache_file.exists():
        # Also check if prefix match exists
        cpe_prefix = "_".join(cpe.split(":")[:5]).replace("cpe:2.3:", "")
        for candidate_file in NVD_CACHE_DIR.glob(f"*{cpe_prefix}*.json"):
            try:
                with open(candidate_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return data.get("vulnerabilities", [])
            except (json.JSONDecodeError, OSError):
                pass
        return []

    try:
        with open(cache_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("vulnerabilities", [])
    except (json.JSONDecodeError, OSError):
        return []


def evaluate_single_device(device: dict[str, Any]) -> DeviceRiskProfile:
    """Evaluate vulnerabilities and calculate risk profile for a single device."""
    cpe = device.get("cpe", "")
    firmware = device.get("firmware", "")
    dev_id = device.get("id", "unknown")
    name = device.get("name", "Unknown Device")
    model = device.get("model", "Unknown Model")

    kev_catalog = get_kev_catalog()
    epss_scores = get_epss_scores()
    nvd_vulns = get_nvd_records_for_cpe(cpe)

    overall_state, findings = match_device_vulnerabilities(
        device_firmware=firmware,
        device_cpe=cpe,
        nvd_vulnerabilities=nvd_vulns,
        kev_catalog=kev_catalog,
        epss_scores=epss_scores,
    )

    return rank_device(
        device_id=dev_id,
        device_name=name,
        model=model,
        firmware=firmware,
        cpe=cpe,
        overall_status=overall_state,
        findings=findings,
    )


def scan_all_devices(devices: list[dict[str, Any]]) -> list[DeviceRiskProfile]:
    """Scan and rank all provided devices."""
    profiles = [evaluate_single_device(d) for d in devices]
    return sort_ranked_devices(profiles)
