"""Unit tests for homebom_core.versions: messy string extraction, like-with-like matching, and boundary rules."""

from homebom_core.versions import (
    extract_version_info,
    match_firmware_range,
)


def test_messy_firmware_extraction():
    """Test version extraction across 10 real-world messy firmware strings."""
    cases = [
        ("1.1.2 Build 20220624", (1, 1, 2), 20220624, False, False),
        ("1.0.0 Build 200508", (1, 0, 0), 200508, False, False),
        ("1.05.00", (1, 5, 0), None, False, False),
        ("3.0.0.4.386.41700", (3, 0, 0, 4, 386, 41700), None, False, False),
        ("Amazon FireOS 7.5.8.2", (7, 5, 8, 2), None, False, False),
        ("3.4.7", (3, 4, 7), None, False, False),
        ("FireOS 7.6.6.9", (7, 6, 6, 9), None, False, False),
        ("V4.30.215 build 210101", (4, 30, 215), 210101, False, False),
        ("2018-04-27", None, 20180427, True, False),
        ("CUSTOM-BETA-REV-???", None, None, False, True),
    ]

    for fw_str, exp_tuple, exp_build, exp_date_only, exp_unparseable in cases:
        info = extract_version_info(fw_str)
        assert info.version_tuple == exp_tuple, (
            f"Failed tuple for '{fw_str}': {info.version_tuple} != {exp_tuple}"
        )
        assert info.build_token == exp_build, (
            f"Failed build for '{fw_str}': {info.build_token} != {exp_build}"
        )
        assert info.is_date_only == exp_date_only, f"Failed is_date_only for '{fw_str}'"
        assert info.is_unparseable == exp_unparseable, f"Failed is_unparseable for '{fw_str}'"


def test_compare_like_with_like_date_tokens():
    """User condition 1: Compare like with like.

    If range bound is a single 6-8 digit token ('200731'), compare it against
    the build-date token extracted from firmware ('Build 200508').
    If formats are incompatible (e.g. no build token), return None (unknown).
    """
    # 1. TL-WA855RE '1.0.0 Build 200508' vs '200731' -> affected
    res1 = match_firmware_range("1.0.0 Build 200508", version_end_excluding="200731")
    assert res1 == "affected", f"Expected affected, got {res1}"

    # 2. '1.0.0 Build 200901' vs '200731' -> not_affected
    res2 = match_firmware_range("1.0.0 Build 200901", version_end_excluding="200731")
    assert res2 == "not_affected", f"Expected not_affected, got {res2}"

    # 3. '1.0.0' with no build token vs '200731' -> unknown
    res3 = match_firmware_range("1.0.0", version_end_excluding="200731")
    assert res3 == "unknown", f"Expected unknown for incompatible formats, got {res3}"


def test_boundary_rule_version_end_excluding():
    """User condition 1: AX21 '1.1.4 Build 20230219' -> not_affected (equals versionEndExcluding).

    In accordance with NVD's vulnerability range data, versionEndExcluding defines the first
    patched/fixed version and is strictly exclusive. A version equal to versionEndExcluding
    is NOT affected.
    """
    # TP-Link Archer AX21 CVE-2023-1389: versionEndExcluding is '1.1.4'
    # Version 1.1.2 is affected (< 1.1.4)
    assert match_firmware_range("1.1.2 Build 20220624", version_end_excluding="1.1.4") == "affected"

    # Version 1.1.4 is NOT affected (equal to boundary)
    assert (
        match_firmware_range("1.1.4 Build 20230219", version_end_excluding="1.1.4")
        == "not_affected"
    )

    # Version 1.1.5 is NOT affected (> boundary)
    assert (
        match_firmware_range("1.1.5 Build 20230501", version_end_excluding="1.1.4")
        == "not_affected"
    )


def test_boundary_rule_version_end_including():
    """Test boundary rule for versionEndIncluding (inclusive)."""
    # D-Link DCS-2530L CVE-2020-25078: versionEndIncluding is '1.05.05'
    assert match_firmware_range("1.05.00", version_end_including="1.05.05") == "affected"
    assert match_firmware_range("1.05.05", version_end_including="1.05.05") == "affected"
    assert match_firmware_range("1.06.01", version_end_including="1.05.05") == "not_affected"


def test_start_and_end_ranges():
    """Test ranges with both start and end bounds."""
    # [1.0.0, 2.0.0)
    assert (
        match_firmware_range(
            "0.9.9", version_start_including="1.0.0", version_end_excluding="2.0.0"
        )
        == "not_affected"
    )
    assert (
        match_firmware_range(
            "1.0.0", version_start_including="1.0.0", version_end_excluding="2.0.0"
        )
        == "affected"
    )
    assert (
        match_firmware_range(
            "1.5.0", version_start_including="1.0.0", version_end_excluding="2.0.0"
        )
        == "affected"
    )
    assert (
        match_firmware_range(
            "2.0.0", version_start_including="1.0.0", version_end_excluding="2.0.0"
        )
        == "not_affected"
    )


def test_unparseable_firmware_returns_unknown():
    """Rule 3: Unparseable firmware string must always evaluate to unknown, never safe."""
    res = match_firmware_range("CUSTOM-BETA-REV-???", version_end_excluding="1.1.4")
    assert res == "unknown", "Unparseable firmware must evaluate to 'unknown'"
