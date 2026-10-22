"""Unit tests for homebom_core matching, EoL detection, ranking, and phrasing rules."""

from homebom_core.cpe import is_valid_firmware_cpe, parse_cpe
from homebom_core.match import (
    VulnerabilityFinding,
    is_eol_vulnerability,
)
from homebom_core.rank import (
    determine_device_tier,
    generate_device_spoken_text,
    generate_fix_steps,
    rank_device,
    sort_ranked_devices,
)


def test_firmware_cpe_rule():
    """Rule 2: Devices must resolve to firmware CPEs (part == 'o'), not hardware CPEs ('h')."""
    assert is_valid_firmware_cpe("cpe:2.3:o:tp-link:archer_ax21_firmware:*:*:*:*:*:*:*:*") is True
    assert is_valid_firmware_cpe("cpe:2.3:h:tp-link:archer_ax21:-:*:*:*:*:*:*:*") is False

    parsed = parse_cpe("cpe:2.3:o:dlink:dcs-2530l_firmware:1.05:*:*:*:*:*:*:*")
    assert parsed.is_firmware is True
    assert parsed.vendor == "dlink"
    assert parsed.product == "dcs-2530l_firmware"


def test_eol_detection_from_kev_text():
    """User condition 2: Derive eol boolean by searching KEV shortDescription for 'end-of-life' or 'end-of-service'."""
    # Matches "end-of-life"
    kev_eol = {
        "shortDescription": "This device contains a vulnerability. The impacted products could be end-of-life (EoL)."
    }
    assert is_eol_vulnerability(kev_eol) is True

    # Matches "end-of-service"
    kev_eos = {"shortDescription": "Device is end-of-service and no patches will be released."}
    assert is_eol_vulnerability(kev_eos) is True

    # No EoL mention
    kev_active = {
        "shortDescription": "TP-Link Archer AX21 command injection vulnerability allows RCE. Apply vendor updates."
    }
    assert is_eol_vulnerability(kev_active) is False


def test_phrasing_and_remediation_rules():
    """User condition 2 & 3: Phrasing rules for EoL, zero-CVE, and unknown devices."""
    # 1. EoL devices must say 'replace' in both get_fix_steps and spoken text
    # Condition 4: use 'actively exploited' for KEV, and 'critical' only if CVSS >= 9.0. Never call 7.5 critical.
    spoken_eol_75 = generate_device_spoken_text(
        "Backyard Camera", "fix_now", is_eol=True, max_cvss=7.5
    )
    assert "critical" not in spoken_eol_75.lower(), f"Never call a 7.5 critical: {spoken_eol_75}"
    assert "actively exploited" in spoken_eol_75.lower()
    assert "replace" in spoken_eol_75.lower()

    spoken_eol_98 = generate_device_spoken_text(
        "Gaming Router", "fix_now", is_eol=True, max_cvss=9.8
    )
    assert "critical" in spoken_eol_98.lower(), f"CVSS 9.8 can be called critical: {spoken_eol_98}"
    assert "actively exploited" in spoken_eol_98.lower()
    assert "replace" in spoken_eol_98.lower()

    fix_eol = generate_fix_steps("Backyard Camera", "fix_now", is_eol=True)
    assert "replace" in fix_eol.lower(), f"Fix steps must say 'replace': {fix_eol}"

    # 2. Zero-CVE devices speak as 'no known vulnerabilities in public databases', never 'safe'
    spoken_clean = generate_device_spoken_text("Front Doorbell", "not_affected", is_eol=False)
    assert "no known vulnerabilities in public databases" in spoken_clean
    assert "safe" not in spoken_clean.lower()

    # 3. unknown speaks as "I can't verify this one"
    spoken_unknown = generate_device_spoken_text("Porch Smart Plug", "unknown", is_eol=False)
    assert "I can't verify" in spoken_unknown
    assert "safe" not in spoken_unknown.lower()


def test_priority_ranking_order_kev_and_epss():
    """Rule 4: Prioritize by active exploitation (KEV) and EPSS probability, NOT raw CVSS."""
    # Device A: CVSS 9.8, but not in KEV, low EPSS 0.01 -> fix_soon
    dev_a = VulnerabilityFinding(
        cve_id="CVE-LOW-EPSS",
        status="affected",
        cvss_score=9.8,
        cvss_vector=None,
        epss_score=0.01,
        in_kev=False,
        eol=False,
        description="",
        criteria_matched=None,
    )
    assert determine_device_tier("affected", [dev_a]) == "fix_soon"

    # Device B: CVSS 7.5, in CISA KEV, high EPSS 0.97 -> fix_now
    dev_b = VulnerabilityFinding(
        cve_id="CVE-KEV-EXPLOITED",
        status="affected",
        cvss_score=7.5,
        cvss_vector=None,
        epss_score=0.97,
        in_kev=True,
        eol=True,
        description="",
        criteria_matched=None,
    )
    assert determine_device_tier("affected", [dev_b]) == "fix_now"

    # Profile generation and sorting
    profile_a = rank_device(
        "dev-a", "Device A", "Model A", "1.0", "cpe:2.3:o:a:a:*:*:*:*:*:*:*:*", "affected", [dev_a]
    )
    profile_b = rank_device(
        "dev-b", "Device B", "Model B", "1.0", "cpe:2.3:o:b:b:*:*:*:*:*:*:*:*", "affected", [dev_b]
    )

    # Even though dev_a has higher CVSS (9.8 vs 7.5), dev_b is KEV-listed so must rank first!
    sorted_profiles = sort_ranked_devices([profile_a, profile_b])
    assert sorted_profiles[0].device_id == "dev-b"
    assert sorted_profiles[1].device_id == "dev-a"
    assert sorted_profiles[0].tier == "fix_now"
    assert sorted_profiles[1].tier == "fix_soon"
