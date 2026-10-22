"""tests/test_golden_truth.py - Strict test asserting all CVE, EPSS, and KEV findings come from cached feeds.

User Condition 5:
Assert that every CVE ID, EPSS value, and KEV flag is read from the cache files,
not hardcoded literals in code.
"""

import csv
import gzip
import json
from pathlib import Path

from homebom_core.match import match_device_vulnerabilities
from homebom_core.rank import rank_device, sort_ranked_devices

DATA_DIR = Path(__file__).resolve().parent.parent / "server" / "data"
NVD_CACHE_DIR = DATA_DIR / "nvd_cache"


def safe_filename_for_cpe(cpe: str) -> str:
    clean = cpe.replace("cpe:2.3:", "").replace(":", "_").replace("*", "ANY").replace("/", "_")
    return f"{clean}.json"


def test_every_cve_epss_kev_is_ground_truth_from_cache():
    """Verify that every finding in the seeded devices matches cached files exactly."""
    # 1. Load ground truth feeds directly
    with open(DATA_DIR / "cisa_kev.json", "r", encoding="utf-8") as f:
        kev_raw = json.load(f)
    kev_catalog = {v["cveID"]: v for v in kev_raw["vulnerabilities"]}

    epss_scores = {}
    with gzip.open(DATA_DIR / "epss.csv.gz", "rt", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if row and row[0].startswith("CVE-"):
                epss_scores[row[0]] = float(row[1])

    with open(DATA_DIR / "devices.json", "r", encoding="utf-8") as f:
        devices = json.load(f)

    # 2. Evaluate all seeded devices
    ranked_profiles = []
    for dev in devices:
        cpe = dev["cpe"]
        cache_file = NVD_CACHE_DIR / safe_filename_for_cpe(cpe)
        assert cache_file.exists(), f"NVD cache file missing for CPE {cpe}: {cache_file}"

        with open(cache_file, "r", encoding="utf-8") as f:
            nvd_data = json.load(f)
        nvd_vulns = nvd_data.get("vulnerabilities", [])

        overall_state, findings = match_device_vulnerabilities(
            device_firmware=dev["firmware"],
            device_cpe=cpe,
            nvd_vulnerabilities=nvd_vulns,
            kev_catalog=kev_catalog,
            epss_scores=epss_scores,
        )

        # Assert every finding strictly reflects the cached files
        for finding in findings:
            cid = finding.cve_id
            
            # Ground truth KEV check
            expected_in_kev = cid in kev_catalog
            assert finding.in_kev == expected_in_kev, (
                f"Finding {cid} in_kev={finding.in_kev} does not match cache={expected_in_kev}"
            )

            # Ground truth EPSS check
            expected_epss = epss_scores.get(cid, 0.0)
            assert abs(finding.epss_score - expected_epss) < 1e-5, (
                f"Finding {cid} EPSS={finding.epss_score} does not match cache={expected_epss}"
            )

            # Ground truth EoL check
            if expected_in_kev:
                short_desc = kev_catalog[cid].get("shortDescription", "").lower()
                expected_eol = "end-of-life" in short_desc or "end-of-service" in short_desc
                assert finding.eol == expected_eol, (
                    f"Finding {cid} EoL={finding.eol} does not match KEV description: '{short_desc}'"
                )

        profile = rank_device(
            device_id=dev["id"],
            device_name=dev["name"],
            model=dev["model"],
            firmware=dev["firmware"],
            cpe=cpe,
            overall_status=overall_state,
            findings=findings,
        )
        ranked_profiles.append(profile)

    # Sort profiles
    sorted_profiles = sort_ranked_devices(ranked_profiles)
    assert len(sorted_profiles) == 8

    # 3. Assert tier classifications for each device
    profile_by_id = {p.device_id: p for p in sorted_profiles}

    # dev-001 (TP-Link Archer AX21): affected + KEV -> fix_now
    assert profile_by_id["dev-001"].tier == "fix_now"
    assert profile_by_id["dev-001"].overall_status == "affected"
    assert any(f.cve_id == "CVE-2023-1389" for f in profile_by_id["dev-001"].findings)

    # dev-002 (D-Link DCS-2530L): affected + KEV -> fix_now, is_eol=True
    assert profile_by_id["dev-002"].tier == "fix_now"
    assert profile_by_id["dev-002"].is_eol is True
    assert "replace" in profile_by_id["dev-002"].fix_steps.lower()
    assert "replace" in profile_by_id["dev-002"].spoken_summary.lower()

    # dev-003 (TP-Link TL-WA855RE): affected + KEV -> fix_now, is_eol=True
    assert profile_by_id["dev-003"].tier == "fix_now"
    assert profile_by_id["dev-003"].is_eol is True
    assert "replace" in profile_by_id["dev-003"].fix_steps.lower()

    # dev-004 (ASUS GT-AC2900): affected + KEV -> fix_now, is_eol=True
    assert profile_by_id["dev-004"].tier == "fix_now"
    assert profile_by_id["dev-004"].is_eol is True

    # dev-005 (Echo Dot): unknown because firmware is semver while NVD CPEs are date-based
    assert profile_by_id["dev-005"].tier == "unknown"
    assert "I can't verify" in profile_by_id["dev-005"].spoken_summary

    # dev-006 (Ring Video Doorbell): not_affected
    assert profile_by_id["dev-006"].tier == "not_affected"
    assert "no known vulnerabilities in public databases" in profile_by_id["dev-006"].spoken_summary
    assert "safe" not in profile_by_id["dev-006"].spoken_summary.lower()

    # dev-007 (Fire TV Stick): not_affected
    assert profile_by_id["dev-007"].tier == "not_affected"
    assert "no known vulnerabilities in public databases" in profile_by_id["dev-007"].spoken_summary
    assert "safe" not in profile_by_id["dev-007"].spoken_summary.lower()

    # dev-008 (Porch Smart Plug): unknown
    assert profile_by_id["dev-008"].tier == "unknown"
    assert "I can't verify" in profile_by_id["dev-008"].spoken_summary


def test_epss_metadata_snapshot_date():
    """User Condition 4: Verify metadata.json contains the EPSS file snapshot date."""
    meta_path = DATA_DIR / "metadata.json"
    assert meta_path.exists(), "server/data/metadata.json is missing!"

    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)

    assert "epss_score_date" in meta
    assert "as_of_string" in meta
    assert meta["epss_score_date"] == "2026-10-21"
    assert meta["as_of_string"] == "as of 2026-10-21"
