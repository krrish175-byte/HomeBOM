"""tests/test_bedrock.py - Unit and integration tests for AWS Bedrock Converse API.

Validates:
1. Mocked client success for scan phrasing, device phrasing, and CPE resolution.
2. Forced failures:
   - Generic exception / ClientError -> falls back to deterministic template
   - Network timeout (ConnectTimeoutError / ReadTimeoutError) -> falls back to template
   - Missing credentials (NoCredentialsError) -> falls back to template
3. Output validator rejecting bad cases and falling back to template:
   - CVE ID present
   - Word 'safe' present
   - More than 3 sentences
   - Hallucinated number not in input
   - 'critical' when max_cvss < 9.0
   - 'update' for an EoL device
4. CPE resolver:
   - Valid numeric candidate ID returned -> resolves candidate
   - Numeric ID not in candidate list -> rejected, asks user
   - Free-form string -> rejected, never accepted as CPE
5. Phrasing source tagging ('bedrock' vs 'template') across tool responses.
"""

from unittest.mock import MagicMock

from botocore.exceptions import ClientError, ConnectTimeoutError, NoCredentialsError

from server.bedrock import (
    generate_spoken_device_phrasing,
    generate_spoken_scan_phrasing,
    resolve_cpe_with_bedrock,
    validate_phrasing_output,
)


def _make_mock_client_response(text: str) -> MagicMock:
    """Build a mock boto3 client returning specific text from converse()."""
    mock = MagicMock()
    mock.converse.return_value = {
        "output": {
            "message": {
                "role": "assistant",
                "content": [{"text": text}],
            }
        },
        "stopReason": "end_turn",
        "usage": {"inputTokens": 50, "outputTokens": 30, "totalTokens": 80},
    }
    return mock


def test_bedrock_converse_success_mocked():
    """Verify successful Bedrock Converse API call returns Bedrock text and phrasing_source='bedrock'."""
    scan_input = {
        "total_devices": 8,
        "fix_now": 4,
        "fix_soon": 0,
        "low": 0,
        "unknown": 1,
        "not_affected": 3,
        "eol_devices": 3,
        "as_of": "as of 2026-10-21",
    }
    mock_text = (
        "I scanned 8 devices as of 2026-10-21. "
        "4 devices have actively exploited vulnerabilities needing immediate attention. "
        "3 discontinued devices must be replaced."
    )
    mock_client = _make_mock_client_response(mock_text)

    spoken, source = generate_spoken_scan_phrasing(
        scan_summary=scan_input,
        max_cvss=8.8,
        is_eol=True,
        template_fallback="Template Fallback Text",
        client_override=mock_client,
    )

    assert spoken == mock_text
    assert source == "bedrock"
    assert mock_client.converse.called

    # Also test device phrasing
    dev_input = {
        "device_name": "Living Room Router",
        "model": "Archer AX21",
        "is_eol": False,
        "max_cvss": 8.8,
    }
    dev_mock_text = "Living Room Router has an actively exploited issue that needs an update."
    dev_client = _make_mock_client_response(dev_mock_text)
    dev_spoken, dev_source = generate_spoken_device_phrasing(
        device_summary=dev_input,
        max_cvss=8.8,
        is_eol=False,
        template_fallback="Template Device Text",
        client_override=dev_client,
    )
    assert dev_spoken == dev_mock_text
    assert dev_source == "bedrock"


def test_bedrock_forced_failures():
    """Verify forced failures (exception, timeout, missing credentials) fall back to template."""
    scan_input = {"total_devices": 8, "fix_now": 4, "as_of": "2026-10-21"}
    fallback_text = "Deterministic Template Fallback"

    # 1. Forced ClientError exception
    client_err = MagicMock()
    client_err.converse.side_effect = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "User not authorized"}},
        "Converse",
    )
    spoken, source = generate_spoken_scan_phrasing(
        scan_summary=scan_input,
        max_cvss=8.8,
        is_eol=False,
        template_fallback=fallback_text,
        client_override=client_err,
    )
    assert spoken == fallback_text
    assert source == "template"

    # 2. Forced network ConnectTimeoutError
    client_timeout = MagicMock()
    client_timeout.converse.side_effect = ConnectTimeoutError(
        endpoint_url="https://bedrock-runtime.us-east-1.amazonaws.com"
    )
    spoken, source = generate_spoken_scan_phrasing(
        scan_summary=scan_input,
        max_cvss=8.8,
        is_eol=False,
        template_fallback=fallback_text,
        client_override=client_timeout,
    )
    assert spoken == fallback_text
    assert source == "template"

    # 3. Forced NoCredentialsError
    client_nocreds = MagicMock()
    client_nocreds.converse.side_effect = NoCredentialsError()
    spoken, source = generate_spoken_scan_phrasing(
        scan_summary=scan_input,
        max_cvss=8.8,
        is_eol=False,
        template_fallback=fallback_text,
        client_override=client_nocreds,
    )
    assert spoken == fallback_text
    assert source == "template"


def test_validator_rejects_cve_id():
    """Validator must reject output containing a CVE ID and fall back to template."""
    scan_input = {"total_devices": 8, "fix_now": 1}
    bad_text = "Your router is affected by CVE-2023-1389 and needs remediation."

    is_valid, reason = validate_phrasing_output(bad_text, scan_input, max_cvss=8.8, is_eol=False)
    assert is_valid is False
    assert reason == "contains_cve_id"

    # Test through generator
    client = _make_mock_client_response(bad_text)
    spoken, source = generate_spoken_scan_phrasing(
        scan_summary=scan_input,
        max_cvss=8.8,
        is_eol=False,
        template_fallback="Template fallback",
        client_override=client,
    )
    assert spoken == "Template fallback"
    assert source == "template"


def test_validator_rejects_word_safe():
    """Validator must reject output containing the word 'safe' and fall back to template."""
    scan_input = {"total_devices": 8, "not_affected": 8}
    bad_text = "I scanned 8 devices and your home is safe."

    is_valid, reason = validate_phrasing_output(bad_text, scan_input, max_cvss=0.0, is_eol=False)
    assert is_valid is False
    assert reason == "contains_word_safe"

    client = _make_mock_client_response(bad_text)
    spoken, source = generate_spoken_scan_phrasing(
        scan_summary=scan_input,
        max_cvss=0.0,
        is_eol=False,
        template_fallback="Template fallback",
        client_override=client,
    )
    assert spoken == "Template fallback"
    assert source == "template"


def test_validator_rejects_more_than_three_sentences():
    """Validator must reject output containing more than 3 sentences."""
    scan_input = {"total_devices": 8, "fix_now": 1}
    bad_text = (
        "I scanned 8 devices today. "
        "One device needs attention. "
        "It has a vulnerability. "
        "Please check your companion app for details."
    )

    is_valid, reason = validate_phrasing_output(bad_text, scan_input, max_cvss=8.8, is_eol=False)
    assert is_valid is False
    assert reason == "exceeds_max_sentences"

    client = _make_mock_client_response(bad_text)
    spoken, source = generate_spoken_scan_phrasing(
        scan_summary=scan_input,
        max_cvss=8.8,
        is_eol=False,
        template_fallback="Template fallback",
        client_override=client,
    )
    assert spoken == "Template fallback"
    assert source == "template"


def test_validator_rejects_hallucinated_numbers():
    """Validator must reject numbers not present in the structured input data."""
    scan_input = {"total_devices": 8, "fix_now": 4, "as_of": "2026-10-21"}
    # 99 is not in the input data
    bad_text = "I scanned 8 devices and found 99 issues needing your attention."

    is_valid, reason = validate_phrasing_output(bad_text, scan_input, max_cvss=8.8, is_eol=False)
    assert is_valid is False
    assert "hallucinated_number" in reason

    client = _make_mock_client_response(bad_text)
    spoken, source = generate_spoken_scan_phrasing(
        scan_summary=scan_input,
        max_cvss=8.8,
        is_eol=False,
        template_fallback="Template fallback",
        client_override=client,
    )
    assert spoken == "Template fallback"
    assert source == "template"


def test_validator_rejects_critical_when_cvss_below_nine():
    """Validator must reject 'critical' when max_cvss < 9.0."""
    scan_input = {"total_devices": 8, "fix_now": 1}
    bad_text = "I found a critical issue on your network router."

    # max_cvss is 8.8 (< 9.0) -> must be rejected
    is_valid, reason = validate_phrasing_output(bad_text, scan_input, max_cvss=8.8, is_eol=False)
    assert is_valid is False
    assert reason == "critical_cvss_below_threshold"

    # But if max_cvss >= 9.0 -> allowed!
    good_valid, good_reason = validate_phrasing_output(
        bad_text, scan_input, max_cvss=9.8, is_eol=False
    )
    assert good_valid is True
    assert good_reason is None


def test_validator_rejects_update_for_eol_device():
    """Validator must reject 'update' for an EoL device (must say replace)."""
    device_input = {"device_name": "Camera", "model": "DCS-2530L", "is_eol": True}
    bad_text = "Please update your security camera immediately."

    is_valid, reason = validate_phrasing_output(bad_text, device_input, max_cvss=8.8, is_eol=True)
    assert is_valid is False
    assert reason == "update_for_eol_device"

    # If is_eol is False -> 'update' is allowed
    good_valid, good_reason = validate_phrasing_output(
        bad_text, device_input, max_cvss=8.8, is_eol=False
    )
    assert good_valid is True
    assert good_reason is None


def test_cpe_resolver_with_bedrock():
    """Verify Bedrock candidate resolution: accepts valid ID, rejects invalid ID, never accepts free-form CPE."""
    # 1. Success: Bedrock returns valid numeric candidate ID 0
    mock_success = _make_mock_client_response('{"selected_id": 0, "clarification_question": null}')
    candidate, q, source = resolve_cpe_with_bedrock(
        model="Archer AX21",
        name="Router",
        client_override=mock_success,
    )
    assert candidate is not None
    assert candidate["vendor"] == "TP-Link"
    assert "AX21" in candidate["product"] or "ax21" in candidate["cpe"]
    assert q is None
    assert source == "bedrock"

    # 2. Rejection: Bedrock returns an ID that isn't in the list (e.g. 999)
    mock_invalid_id = _make_mock_client_response(
        '{"selected_id": 999, "clarification_question": "Did you mean AX21?"}'
    )
    candidate, q, source = resolve_cpe_with_bedrock(
        model="Unknown Gadget",
        name="Gadget",
        client_override=mock_invalid_id,
    )
    assert candidate is None
    assert q is not None
    assert source == "bedrock"

    # 3. Rejection: Bedrock returns free-form CPE string instead of integer ID
    mock_freeform = _make_mock_client_response(
        '{"selected_id": "cpe:2.3:o:fake:cpe:1.0", "clarification_question": null}'
    )
    candidate, q, source = resolve_cpe_with_bedrock(
        model="Fake Model",
        name="Fake",
        client_override=mock_freeform,
    )
    # Must never accept free-form CPE string
    assert candidate is None
    assert q is not None
    assert source == "bedrock"

    # 4. Fallback on exception: falls back to template heuristic
    mock_error = MagicMock()
    mock_error.converse.side_effect = Exception("AWS Timeout")
    candidate, q, source = resolve_cpe_with_bedrock(
        model="Archer AX21",
        name="Router",
        client_override=mock_error,
    )
    assert candidate is not None
    assert source == "template"
