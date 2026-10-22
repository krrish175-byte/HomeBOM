#!/usr/bin/env python3
"""Build server/data/cpe_index.json from cached NVD configurations and devices.json.

Zero MCP / AWS imports. Produces a curated candidate index for add_device resolution.
"""

import json
import re
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "server" / "data"
CACHE_DIR = DATA_DIR / "nvd_cache"

VENDOR_NAMES = {
    "tp-link": "TP-Link",
    "dlink": "D-Link",
    "asus": "ASUS",
    "amazon": "Amazon",
    "hikvision": "Hikvision",
    "tuya": "Tuya",
}


def build_cpe_index():
    firmware_cpes = set()

    # Seeded devices
    with open(DATA_DIR / "devices.json", "r", encoding="utf-8") as f:
        seeded = json.load(f)
        for dev in seeded:
            if dev["cpe"].startswith("cpe:2.3:o:"):
                firmware_cpes.add(dev["cpe"])

    # From NVD cache files
    for cache_file in CACHE_DIR.glob("*.json"):
        with open(cache_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            for cfg in cve.get("configurations", []):
                for node in cfg.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        crit = match.get("criteria", "")
                        if crit.startswith("cpe:2.3:o:"):
                            firmware_cpes.add(crit)

    # Group by (vendor, base_product)
    grouped = {}
    for cpe in sorted(firmware_cpes):
        tokens = cpe.split(":")
        if len(tokens) < 5:
            continue
        vendor = tokens[3]
        prod = tokens[4]
        clean_prod = re.sub(r"_firmware$", "", prod, flags=re.IGNORECASE)
        key = (vendor, clean_prod)
        if key not in grouped:
            grouped[key] = []
        grouped[key].append(cpe)

    index_entries = []
    # Match seeded devices first to preserve exact models and categories
    seeded_by_cpe_prefix = {}
    for d in seeded:
        prefix = ":".join(d["cpe"].split(":")[:5])
        seeded_by_cpe_prefix[prefix] = d

    for (vendor, base_prod), cpe_list in sorted(grouped.items()):
        # Canonical CPE: prefer wildcard
        wildcards = [c for c in cpe_list if ":*:*:*:*:*:*:*:*" in c]
        canonical_cpe = wildcards[0] if wildcards else cpe_list[0]

        prefix = f"cpe:2.3:o:{vendor}:{base_prod}_firmware"
        seeded_match = seeded_by_cpe_prefix.get(prefix) or seeded_by_cpe_prefix.get(
            f"cpe:2.3:o:{vendor}:{base_prod}"
        )

        vendor_title = (
            seeded_match["vendor"]
            if seeded_match
            else VENDOR_NAMES.get(vendor, vendor.capitalize())
        )
        if seeded_match:
            product_title = seeded_match["model"]
            category = seeded_match.get("category", "iot")
            canonical_cpe = seeded_match["cpe"]
        else:
            product_title = base_prod.replace("-", " ").replace("_", " ").upper()
            if "router" in base_prod or "ax" in base_prod or "ac" in base_prod:
                category = "router"
            elif "camera" in base_prod or "dcs" in base_prod:
                category = "camera"
            elif "doorbell" in base_prod:
                category = "doorbell"
            elif "echo" in base_prod:
                category = "smart_speaker"
            elif "plug" in base_prod:
                category = "smart_plug"
            elif "nvr" in base_prod or "ni-k1" in base_prod or "ni-q" in base_prod:
                category = "nvr"
            else:
                category = "iot"

        # Generate search keywords
        clean_tokens = [
            vendor.lower(),
            vendor_title.lower(),
            base_prod.lower(),
            product_title.lower(),
            category.lower(),
        ]
        # Split tokens by space and punctuation
        keywords = set()
        for tok in clean_tokens:
            for sub in re.split(r"[\s\-_/]+", tok):
                if len(sub) >= 2:
                    keywords.add(sub)

        index_entries.append(
            {
                "cpe": canonical_cpe,
                "vendor": vendor_title,
                "product": product_title,
                "category": category,
                "vendor_key": vendor,
                "model_key": base_prod,
                "keywords": sorted(keywords),
            }
        )

    out_file = DATA_DIR / "cpe_index.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(index_entries, f, indent=2)

    print(f"Generated {out_file.name} with {len(index_entries)} candidate devices.")


if __name__ == "__main__":
    build_cpe_index()
