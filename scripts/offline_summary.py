#!/usr/bin/env python3
"""scripts/offline_summary.py - Print offline summary table of seeded devices and vulnerability stats.

Reads strictly from local cache (server/data/) with zero network requests.
Prints: Device -> Model -> Firmware -> CVE Count -> KEV Count -> Max EPSS -> Risk Tier
"""

import csv
import gzip
import json
import sys
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "server" / "data"
NVD_CACHE_DIR = DATA_DIR / "nvd_cache"


def safe_filename_for_cpe(cpe: str) -> str:
    clean = cpe.replace("cpe:2.3:", "").replace(":", "_").replace("*", "ANY").replace("/", "_")
    return f"{clean}.json"


def load_kev_set() -> set[str]:
    kev_path = DATA_DIR / "cisa_kev.json"
    if not kev_path.exists():
        return set()
    with open(kev_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {v["cveID"] for v in data.get("vulnerabilities", []) if "cveID" in v}


def load_epss_map() -> dict[str, float]:
    epss_path = DATA_DIR / "epss.csv.gz"
    if not epss_path.exists():
        return {}
    epss_map = {}
    with gzip.open(epss_path, "rt", encoding="utf-8") as f:
        reader = csv.reader(f)
        # Skip header lines if present
        for row in reader:
            if not row or row[0].startswith("#") or row[0] == "cve":
                continue
            if len(row) >= 2:
                try:
                    epss_map[row[0]] = float(row[1])
                except ValueError:
                    continue
    return epss_map


def main():
    devices_path = DATA_DIR / "devices.json"
    if not devices_path.exists():
        print(f"[ERROR] devices.json not found at {devices_path}")
        sys.exit(1)

    with open(devices_path, "r", encoding="utf-8") as f:
        devices = json.load(f)

    kev_set = load_kev_set()
    epss_map = load_epss_map()

    print("\n" + "=" * 105)
    print(" " * 32 + "HomeBOM Offline Vulnerability Summary")
    print("=" * 105)
    header = f"{'ID':<9} {'Device Name':<25} {'Model':<20} {'Firmware':<22} {'CVEs':<6} {'KEV':<5} {'Max EPSS':<10}"
    print(header)
    print("-" * 105)

    total_cves = 0
    total_kev = 0

    for dev in devices:
        dev_id = dev.get("id", "N/A")
        name = dev.get("name", "Unknown")[:24]
        model = dev.get("model", "Unknown")[:19]
        fw = dev.get("firmware", "Unknown")[:21]
        cpe = dev.get("cpe", "")

        cache_file = NVD_CACHE_DIR / safe_filename_for_cpe(cpe) if cpe else None
        cve_ids = []
        if cache_file and cache_file.exists():
            with open(cache_file, "r", encoding="utf-8") as f:
                nvd_data = json.load(f)
            for item in nvd_data.get("vulnerabilities", []):
                cid = item.get("cve", {}).get("id")
                if cid:
                    cve_ids.append(cid)

        cve_count = len(cve_ids)
        kev_count = sum(1 for cid in cve_ids if cid in kev_set)
        max_epss = max((epss_map.get(cid, 0.0) for cid in cve_ids), default=0.0)

        total_cves += cve_count
        total_kev += kev_count

        epss_str = f"{max_epss:.4f}" if max_epss > 0 else "0.0000"
        print(
            f"{dev_id:<9} {name:<25} {model:<20} {fw:<22} {cve_count:<6} {kev_count:<5} {epss_str:<10}"
        )

    print("-" * 105)
    print(f"Total Seeded Devices: {len(devices)}")
    print(f"Total Cached Device-Associated CVEs: {total_cves}")
    print(f"Total CISA KEV Actively Exploited CVEs: {total_kev}")
    print(f"Total CISA KEV Catalog Size: {len(kev_set)} entries")
    print(f"Total FIRST EPSS Bulk Database: {len(epss_map):,} scores loaded")
    print("=" * 105 + "\n")


if __name__ == "__main__":
    main()
