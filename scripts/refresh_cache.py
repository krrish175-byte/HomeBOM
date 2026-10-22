#!/usr/bin/env python3
"""scripts/refresh_cache.py - Download and cache vulnerability feeds for offline operation.

Feeds:
1. CISA KEV (Known Exploited Vulnerabilities) JSON feed
2. FIRST EPSS (Exploit Prediction Scoring System) bulk scores (CSV.gz)
3. NVD API 2.0 vulnerability records per device CPE (cached under server/data/nvd_cache/)

After running this script, HomeBOM operates 100% offline.
"""

import argparse
import gzip
import json
import os
import time
import urllib.parse
from pathlib import Path

import httpx
from dotenv import load_dotenv

load_dotenv()

DATA_DIR = Path(__file__).resolve().parent.parent / "server" / "data"
NVD_CACHE_DIR = DATA_DIR / "nvd_cache"

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

NVD_API_KEY = os.getenv("NVD_API_KEY")


def safe_filename_for_cpe(cpe: str) -> str:
    """Convert CPE string to a safe, deterministic filename."""
    clean = cpe.replace("cpe:2.3:", "").replace(":", "_").replace("*", "ANY").replace("/", "_")
    return f"{clean}.json"


def refresh_cisa_kev() -> bool:
    print("[1/3] Downloading CISA KEV feed...")
    try:
        resp = httpx.get(CISA_KEV_URL, timeout=60.0)
        resp.raise_for_status()
        data = resp.json()
        out_path = DATA_DIR / "cisa_kev.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        count = len(data.get("vulnerabilities", []))
        print(f"  ✓ Saved CISA KEV feed ({count} vulnerabilities) to {out_path.name}")
        return True
    except Exception as e:  # noqa: BLE001
        print(f"  ✗ Failed downloading CISA KEV: {e}")
        return False


def refresh_epss() -> bool:
    print("[2/3] Downloading FIRST EPSS bulk scores...")
    try:
        resp = httpx.get(EPSS_URL, follow_redirects=True, timeout=120.0)
        resp.raise_for_status()
        out_path = DATA_DIR / "epss.csv.gz"
        with open(out_path, "wb") as f:
            f.write(resp.content)
        size_mb = len(resp.content) / (1024 * 1024)
        print(f"  ✓ Saved FIRST EPSS bulk scores ({size_mb:.2f} MB compressed) to {out_path.name}")

        # Extract snapshot date from header line 1
        epss_date = "unknown"
        epss_ts = "unknown"
        with gzip.open(out_path, "rt", encoding="utf-8") as gz:
            line1 = gz.readline().strip()
            for part in line1.split(","):
                if "score_date:" in part:
                    epss_ts = part.split("score_date:")[-1]
                    epss_date = epss_ts.split("T")[0]

        meta_path = DATA_DIR / "metadata.json"
        with open(meta_path, "w", encoding="utf-8") as mf:
            json.dump({
                "epss_score_date": epss_date,
                "epss_score_timestamp": epss_ts,
                "as_of_string": f"as of {epss_date}",
            }, mf, indent=2)
        print(f"  ✓ Recorded EPSS snapshot date ({epss_date}) in {meta_path.name}")
        return True
    except Exception as e:  # noqa: BLE001
        print(f"  ✗ Failed downloading EPSS: {e}")
        return False


def get_target_cpes() -> list[str]:
    devices_path = DATA_DIR / "devices.json"
    if not devices_path.exists():
        print(f"  [WARN] {devices_path} not found, using default candidate CPE list")
        return [
            "cpe:2.3:o:tp-link:archer_ax21_firmware:*:*:*:*:*:*:*:*",
            "cpe:2.3:o:dlink:dcs-2530l_firmware:*:*:*:*:*:*:*:*",
            "cpe:2.3:o:hikvision:ds-7608ni-k1_firmware:*:*:*:*:*:*:*:*",
            "cpe:2.3:o:asus:gt-ac2900_firmware:*:*:*:*:*:*:*:*",
            "cpe:2.3:o:amazon:echo_dot_firmware:*:*:*:*:*:*:*:*",
            "cpe:2.3:o:amazon:ring_video_doorbell_firmware:*:*:*:*:*:*:*:*",
            "cpe:2.3:o:amazon:fire_os:*:*:*:*:*:*:*:*",
            "cpe:2.3:o:tuya:smart_plug_firmware:*:*:*:*:*:*:*:*",
        ]

    with open(devices_path, "r", encoding="utf-8") as f:
        devices = json.load(f)
    return [d["cpe"] for d in devices if d.get("cpe")]


def fetch_nvd_for_cpe(cpe: str, client: httpx.Client) -> dict:
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    # If CPE ends with wildcards or contains *, use virtualMatchString prefix
    # NVD API 2.0 returns 404 for wildcards under cpeName, but supports virtualMatchString
    base_cpe = cpe.split(":*:")[0].rstrip(":*")
    query_param = "virtualMatchString" if ("*" in cpe or len(cpe.split(":")) <= 6) else "cpeName"
    url = f"{NVD_API_URL}?{query_param}={urllib.parse.quote(base_cpe if query_param == 'virtualMatchString' else cpe)}"

    for attempt in range(3):
        try:
            resp = client.get(url, headers=headers, timeout=40.0)
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code == 404:
                # No vulnerabilities found in NVD for this criteria
                return {"resultsPerPage": 0, "startIndex": 0, "totalResults": 0, "vulnerabilities": []}
            if resp.status_code in (403, 429, 503):
                wait_sec = 6.0 * (attempt + 1)
                print(f"    Rate limit or status {resp.status_code}, backing off {wait_sec}s...")
                time.sleep(wait_sec)
                continue
            resp.raise_for_status()
        except Exception as e:
            if attempt == 2:
                print(f"    Failed after 3 attempts: {e}")
                raise
            time.sleep(2.0)
    return {"resultsPerPage": 0, "startIndex": 0, "totalResults": 0, "vulnerabilities": []}


def refresh_nvd() -> bool:
    print("[3/3] Querying and caching NVD records per device CPE...")
    NVD_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cpes = get_target_cpes()

    with httpx.Client() as client:
        for idx, cpe in enumerate(cpes, 1):
            filename = safe_filename_for_cpe(cpe)
            cache_file = NVD_CACHE_DIR / filename
            print(f"  [{idx}/{len(cpes)}] Querying NVD for: {cpe}")
            try:
                data = fetch_nvd_for_cpe(cpe, client)
                with open(cache_file, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
                vuln_count = data.get("totalResults", len(data.get("vulnerabilities", [])))
                print(f"      ✓ Cached {vuln_count} CVEs to {filename}")
            except Exception as e:  # noqa: BLE001
                print(f"      ✗ Error fetching {cpe}: {e}")
            # Respect NVD public rate limit (sleep 6s without key, 0.6s with key)
            sleep_time = 0.6 if NVD_API_KEY else 6.0
            time.sleep(sleep_time)
    return True


def main():
    parser = argparse.ArgumentParser(description="Refresh HomeBOM offline vulnerability feeds")
    parser.add_argument("--kev-only", action="store_true", help="Refresh only CISA KEV")
    parser.add_argument("--epss-only", action="store_true", help="Refresh only FIRST EPSS")
    parser.add_argument("--nvd-only", action="store_true", help="Refresh only NVD CPE cache")
    parser.add_argument("--skip-nvd", action="store_true", help="Skip NVD queries")
    args = parser.parse_args()

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    if args.kev_only:
        refresh_cisa_kev()
        return
    if args.epss_only:
        refresh_epss()
        return
    if args.nvd_only:
        refresh_nvd()
        return

    refresh_cisa_kev()
    refresh_epss()
    if not args.skip_nvd:
        refresh_nvd()
    print("\n[COMPLETE] All vulnerability feeds successfully cached in server/data/.")


if __name__ == "__main__":
    main()
