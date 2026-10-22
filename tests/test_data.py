"""Tests for Phase 1 data layer: cached feeds, devices.json, and offline summary."""

import json
from pathlib import Path

from scripts.offline_summary import load_epss_map, load_kev_set, safe_filename_for_cpe

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "server" / "data"
NVD_CACHE_DIR = DATA_DIR / "nvd_cache"


def test_devices_json_schema_and_rules():
    """Verify devices.json conforms to hackathon rules."""
    devices_path = DATA_DIR / "devices.json"
    assert devices_path.exists(), "server/data/devices.json is missing!"

    with open(devices_path, "r", encoding="utf-8") as f:
        devices = json.load(f)

    # Must have 6-8 devices
    assert 6 <= len(devices) <= 8, f"Expected 6-8 devices, got {len(devices)}"

    has_unparseable = False
    for dev in devices:
        assert "id" in dev
        assert "name" in dev
        assert "model" in dev
        assert "firmware" in dev
        assert "cpe" in dev

        # Rule 2: Devices must resolve to FIRMWARE CPEs (cpe:2.3:o:...), never hardware CPEs (h:)
        assert dev["cpe"].startswith("cpe:2.3:o:"), (
            f"Device '{dev['name']}' has CPE '{dev['cpe']}' which is not a firmware CPE (cpe:2.3:o:...)!"
        )

        if "???" in dev["firmware"] or "CUSTOM" in dev["firmware"]:
            has_unparseable = True

    assert has_unparseable, "devices.json must include at least 1 device with an unparseable firmware string"


def test_cisa_kev_cache():
    """Verify CISA KEV feed is present, valid, and populated."""
    kev_path = DATA_DIR / "cisa_kev.json"
    assert kev_path.exists(), "server/data/cisa_kev.json is missing!"

    kev_set = load_kev_set()
    assert len(kev_set) > 1000, f"Expected >1000 KEV entries, got {len(kev_set)}"
    # Verify known KEV items are present
    assert "CVE-2023-1389" in kev_set
    assert "CVE-2020-25078" in kev_set
    assert "CVE-2021-36260" in kev_set


def test_epss_cache():
    """Verify FIRST EPSS bulk CSV.gz is present and parseable."""
    epss_path = DATA_DIR / "epss.csv.gz"
    assert epss_path.exists(), "server/data/epss.csv.gz is missing!"

    epss_map = load_epss_map()
    assert len(epss_map) > 100_000, f"Expected >100k EPSS entries, got {len(epss_map)}"
    assert "CVE-2023-1389" in epss_map
    assert epss_map["CVE-2023-1389"] > 0.90


def test_nvd_cache_for_all_devices():
    """Verify every seeded device has a cached NVD JSON file on disk."""
    devices_path = DATA_DIR / "devices.json"
    with open(devices_path, "r", encoding="utf-8") as f:
        devices = json.load(f)

    for dev in devices:
        cpe = dev["cpe"]
        filename = safe_filename_for_cpe(cpe)
        cache_path = NVD_CACHE_DIR / filename
        assert cache_path.exists(), f"Missing cached NVD JSON for {cpe} at {cache_path}"

        with open(cache_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            assert "vulnerabilities" in data or "totalResults" in data
