"""packages/homebom-core/tests/test_hbom.py - CycloneDX 1.6 HBOM and embedded VEX tests.

Validates:
- Full adherence to official CycloneDX 1.6 JSON Schema (via cyclonedx-python-lib JsonValidator)
- Top-level device components with nested firmware components (version + cpe)
- Stable bom-refs across devices, firmware, and vulnerabilities
- Embedded VEX:
  - affected + KEV -> analysis.state: exploitable
  - not_affected -> 0 vulnerability entries
  - unknown candidates -> analysis.state: in_triage
  - affects array points to firmware component bom-ref
- Component eol properties derived from KEV text
- Short spoken summary (<= 3 sentences, no CVE IDs)
"""

import json
from pathlib import Path

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonValidator
from homebom_core.hbom import generate_cyclonedx_hbom, generate_hbom_spoken_summary
from homebom_core.match import match_device_vulnerabilities
from homebom_core.rank import rank_device

REPO_ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = REPO_ROOT / "server" / "data"
NVD_CACHE_DIR = DATA_DIR / "nvd_cache"


def _safe_filename_for_cpe(cpe: str) -> str:
    clean = cpe.replace("cpe:2.3:", "").replace(":", "_").replace("*", "ANY").replace("/", "_")
    return f"{clean}.json"


def _build_seeded_profiles():
    with open(DATA_DIR / "devices.json", "r", encoding="utf-8") as f:
        devices = json.load(f)
    with open(DATA_DIR / "cisa_kev.json", "r", encoding="utf-8") as f:
        kev_data = json.load(f)
    kev_catalog = {v["cveID"]: v for v in kev_data["vulnerabilities"]}

    import csv
    import gzip

    epss_scores = {}
    with gzip.open(DATA_DIR / "epss.csv.gz", "rt", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if row and row[0].startswith("CVE-"):
                epss_scores[row[0]] = float(row[1])

    profiles = []
    for dev in devices:
        cpe = dev["cpe"]
        cache_file = NVD_CACHE_DIR / _safe_filename_for_cpe(cpe)
        nvd_vulns = []
        if cache_file.exists():
            with open(cache_file, "r", encoding="utf-8") as f:
                nvd_vulns = json.load(f).get("vulnerabilities", [])

        overall, findings = match_device_vulnerabilities(
            device_firmware=dev["firmware"],
            device_cpe=cpe,
            nvd_vulnerabilities=nvd_vulns,
            kev_catalog=kev_catalog,
            epss_scores=epss_scores,
        )
        p = rank_device(
            device_id=dev["id"],
            device_name=dev["name"],
            model=dev["model"],
            firmware=dev["firmware"],
            cpe=cpe,
            overall_status=overall,
            findings=findings,
        )
        profiles.append(p)
    return profiles


def test_cyclonedx_1_6_official_schema_validation():
    """Phase 4 Requirement: Validate every export against official CycloneDX 1.6 schema."""
    profiles = _build_seeded_profiles()
    bom = generate_cyclonedx_hbom(
        profiles,
        serial_uuid="12345678-1234-5678-1234-567812345678",
        timestamp="2026-10-22T00:00:00Z",
    )

    validator = JsonValidator(SchemaVersion.V1_6)
    json_str = json.dumps(bom, indent=2)
    err = validator.validate_str(json_str)
    assert err is None, f"CycloneDX 1.6 schema validation failed: {err}"


def test_cyclonedx_components_structure_and_eol():
    """Verify one device component per device with nested firmware component and eol property."""
    profiles = _build_seeded_profiles()
    bom = generate_cyclonedx_hbom(profiles)

    components = bom.get("components", [])
    assert len(components) == 8, f"Expected 8 device components, got {len(components)}"

    firmware_refs = set()
    for comp in components:
        assert comp["type"] == "device"
        dev_ref = comp["bom-ref"]
        assert dev_ref.startswith("device-dev-")

        # Must have eol property
        dev_props = {p["name"]: p["value"] for p in comp.get("properties", [])}
        assert "homebom:eol" in dev_props
        assert dev_props["homebom:eol"] in ("true", "false")

        # Must contain nested firmware component
        sub_comps = comp.get("components", [])
        assert len(sub_comps) == 1
        fw = sub_comps[0]
        assert fw["type"] == "firmware"
        fw_ref = fw["bom-ref"]
        assert fw_ref.startswith("firmware-dev-")
        firmware_refs.add(fw_ref)

        assert "version" in fw
        assert "cpe" in fw
        assert fw["cpe"].startswith("cpe:2.3:o:")

        fw_props = {p["name"]: p["value"] for p in fw.get("properties", [])}
        assert "homebom:eol" in fw_props

    # Verify specific EoL flags
    comp_by_id = {c["bom-ref"]: c for c in components}
    # dev-002 (DCS-2530L), dev-003 (TL-WA855RE), dev-004 (GT-AC2900) are EoL
    assert (
        next(
            p["value"]
            for p in comp_by_id["device-dev-002"]["properties"]
            if p["name"] == "homebom:eol"
        )
        == "true"
    )
    assert (
        next(
            p["value"]
            for p in comp_by_id["device-dev-003"]["properties"]
            if p["name"] == "homebom:eol"
        )
        == "true"
    )
    assert (
        next(
            p["value"]
            for p in comp_by_id["device-dev-004"]["properties"]
            if p["name"] == "homebom:eol"
        )
        == "true"
    )
    # dev-001 (AX21) is NOT EoL
    assert (
        next(
            p["value"]
            for p in comp_by_id["device-dev-001"]["properties"]
            if p["name"] == "homebom:eol"
        )
        == "false"
    )


def test_cyclonedx_vulnerabilities_and_vex_states():
    """Verify VEX analysis states and affects targets."""
    profiles = _build_seeded_profiles()
    bom = generate_cyclonedx_hbom(profiles)

    vulns = bom.get("vulnerabilities", [])
    assert len(vulns) > 0

    # 1. Affected + KEV devices must have analysis.state == "exploitable"
    exploitable_vulns = [v for v in vulns if v.get("analysis", {}).get("state") == "exploitable"]
    exploitable_ids = {v["id"] for v in exploitable_vulns}
    assert "CVE-2023-1389" in exploitable_ids  # AX21
    assert "CVE-2020-25078" in exploitable_ids  # DCS-2530L
    assert "CVE-2020-25079" in exploitable_ids  # DCS-2530L
    assert "CVE-2020-24363" in exploitable_ids  # WA855RE
    assert "CVE-2021-32030" in exploitable_ids  # GT-AC2900

    # 2. Unknown candidates must have analysis.state == "in_triage"
    triage_vulns = [v for v in vulns if v.get("analysis", {}).get("state") == "in_triage"]
    triage_ids = {v["id"] for v in triage_vulns}
    assert "CVE-2018-11567" in triage_ids  # Echo Dot
    assert "CVE-2021-37436" in triage_ids  # Echo Dot
    assert "CVE-2022-25809" in triage_ids  # Echo Dot

    # 3. not_affected devices emit no vulnerability entries
    # Ring Doorbell (dev-006) and TV Stick (dev-007) must have 0 entries in affects
    for v in vulns:
        affects_refs = [a["ref"] for a in v.get("affects", [])]
        assert "firmware-dev-006" not in affects_refs
        assert "firmware-dev-007" not in affects_refs
        # Every affect ref must point to a valid firmware component
        for ref in affects_refs:
            assert ref.startswith("firmware-dev-")


def test_export_hbom_spoken_summary():
    """Verify plain-language voice summary for export_hbom."""
    profiles = _build_seeded_profiles()
    bom = generate_cyclonedx_hbom(profiles)
    spoken = generate_hbom_spoken_summary(profiles, bom)

    assert "CycloneDX" in spoken
    assert "8 devices" in spoken
    assert "actively exploited" in spoken
    assert "triage" in spoken
    # Voice rules: max 3 sentences, no CVE IDs
    sentences = [s.strip() for s in spoken.split(".") if s.strip()]
    assert len(sentences) <= 3
    assert "CVE-" not in spoken
