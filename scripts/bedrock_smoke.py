#!/usr/bin/env python3
"""scripts/bedrock_smoke.py - Real AWS Bedrock Converse API smoke test.

Usage:
  # With AWS credentials configured:
  export AWS_REGION=us-east-1
  export BEDROCK_MODEL_ID=us.anthropic.claude-3-haiku-20240307-v1:0
  uv run python scripts/bedrock_smoke.py

  # Without credentials (offline verification):
  uv run python scripts/bedrock_smoke.py
"""

import json
import sys
from pathlib import Path

# Add repo root and core package to sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "packages" / "homebom-core"))

from server.bedrock import (
    create_bedrock_client,
    generate_spoken_scan_phrasing,
    get_aws_region,
    get_bedrock_model_id,
    validate_phrasing_output,
)
from server.engine import scan_all_devices
from server.storage import get_all_devices, get_epss_metadata


def run_smoke_test():
    model_id = get_bedrock_model_id()
    region = get_aws_region()

    print("=" * 70)
    print(" HomeBOM - AWS Bedrock Converse API Smoke Test")
    print("=" * 70)
    print(f"Target Model:   {model_id}")
    print(f"Target Region:  {region}")
    print("Timeouts:       connect=4s, read=4s, retries=0")
    print("Inference:      temperature=0.0, maxTokens=150")
    print("-" * 70)

    # 1. Build payload by executing real home scanning code
    devices = get_all_devices()
    profiles = scan_all_devices(devices)
    epss_meta = get_epss_metadata()
    as_of_str = epss_meta.get("as_of_string", "as of 2026-10-21")

    # 2. Print per-device tiers
    print("Per-Device Tiers & Status from Real Scanner:")
    for p in profiles:
        print(
            f"  • [{p.device_id}] {p.device_name:25s} ({p.model:18s}) "
            f"-> tier: {p.tier:12s} status: {p.overall_status:12s} eol: {p.is_eol!s:5s} "
            f"max_cvss: {p.max_cvss:<4.1f} max_epss: {p.max_epss:<6.4f} "
            f"cves: {p.vulnerabilities_count}"
        )
    print("-" * 70)

    fix_now_count = sum(1 for p in profiles if p.tier == "fix_now")
    fix_soon_count = sum(1 for p in profiles if p.tier == "fix_soon")
    low_count = sum(1 for p in profiles if p.tier == "low")
    unknown_count = sum(1 for p in profiles if p.tier == "unknown")
    not_affected_count = sum(1 for p in profiles if p.tier == "not_affected")
    eol_count = sum(1 for p in profiles if p.is_eol)
    max_cvss = max((p.max_cvss for p in profiles), default=0.0)

    # Real structured input payload dynamically calculated from scan_all_devices
    real_scan_summary = {
        "total_devices": len(profiles),
        "fix_now": fix_now_count,
        "fix_soon": fix_soon_count,
        "low": low_count,
        "unknown": unknown_count,
        "not_affected": not_affected_count,
        "eol_devices": eol_count,
        "as_of": as_of_str,
    }

    if fix_now_count > 0:
        if eol_count > 0:
            deterministic_template = (
                f"I scanned {len(profiles)} devices {as_of_str}. "
                f"{fix_now_count} devices have actively exploited vulnerabilities needing immediate attention, "
                f"including {eol_count} discontinued models that must be replaced. "
                f"The remaining devices have no known vulnerabilities or need version verification."
            )
        else:
            deterministic_template = (
                f"I scanned {len(profiles)} devices {as_of_str}. "
                f"{fix_now_count} devices have actively exploited vulnerabilities that need immediate firmware updates. "
                f"The other devices currently have no known vulnerabilities in public databases."
            )
    elif fix_soon_count > 0:
        deterministic_template = (
            f"I scanned {len(profiles)} devices {as_of_str}. "
            f"{fix_soon_count} devices have high-risk vulnerabilities that should be patched soon. "
            f"The remaining devices have no known vulnerabilities in public databases."
        )
    elif unknown_count > 0:
        deterministic_template = (
            f"I scanned {len(profiles)} devices {as_of_str}. "
            f"No urgent vulnerabilities were found, though {unknown_count} devices could not be verified against known databases. "
            f"The rest have no known vulnerabilities in public databases."
        )
    else:
        deterministic_template = (
            f"I scanned {len(profiles)} devices {as_of_str}. "
            f"All devices currently have no known vulnerabilities in public databases."
        )

    print("Real Scan Input Payload:")
    print(json.dumps(real_scan_summary, indent=2))
    print("-" * 70)

    print("Attempting Bedrock Converse API invocation...")
    live_failed = False
    try:
        client = create_bedrock_client()
        system_prompt = (
            "You are HomeBOM, a smart-home security assistant on Alexa. "
            "You provide spoken responses summarizing home scan results.\n"
            "MANDATORY RULES:\n"
            "1. Use ONLY the facts provided in the input JSON below.\n"
            "2. Maximum 3 sentences.\n"
            "3. Never add, assume, or invent vulnerabilities or devices.\n"
            "4. NEVER say the word 'safe'.\n"
            "5. NEVER read CVE IDs.\n"
            "6. For discontinued or end-of-life (EoL) devices, you MUST say they must be replaced; never say update for them.\n"
            "7. Only use the word 'critical' if max_cvss is 9.0 or higher.\n"
            "8. Respond with plain conversational text only. No markdown, no bullet points."
        )
        user_message = (
            f"Here is the verified scan summary:\n"
            f"{json.dumps(real_scan_summary, indent=2)}\n\n"
            f"Please summarize this for voice playback in at most 3 sentences."
        )

        raw_response = client.converse(
            modelId=model_id,
            system=[{"text": system_prompt}],
            messages=[{"role": "user", "content": [{"text": user_message}]}],
            inferenceConfig={"temperature": 0.0, "maxTokens": 150},
        )

        print("\n>>> RAW BEDROCK CONVERSE RESPONSE:")
        print(json.dumps(raw_response, indent=2, default=str))

        output_text = (
            raw_response.get("output", {})
            .get("message", {})
            .get("content", [{}])[0]
            .get("text", "")
            .strip()
        )
        print(f'\nExtracted Text: "{output_text}"')

        is_valid, reason = validate_phrasing_output(
            output_text,
            input_data=real_scan_summary,
            max_cvss=max_cvss,
            is_eol=eol_count > 0,
        )
        print(f"Output Validator Passed: {is_valid} (reason: {reason})")

    except Exception as exc:  # noqa: BLE001 - Diagnostic display for real smoke script
        print(f"\n[Bedrock API Notice] Live call did not proceed: {type(exc).__name__}: {exc}")
        print("LIVE CALL FAILED, USING TEMPLATE")
        live_failed = True

    # Complete fallback pipeline function test
    spoken, source = generate_spoken_scan_phrasing(
        scan_summary=real_scan_summary,
        max_cvss=max_cvss,
        is_eol=eol_count > 0,
        template_fallback=deterministic_template,
    )

    print("-" * 70)
    print(f"Final Spoken Output (phrasing_source: '{source}'):")
    print(f'"{spoken}"')
    print("=" * 70)

    if live_failed:
        print("Smoke test finished with non-zero status because live Bedrock call failed.")
        sys.exit(1)
    else:
        print("Smoke test completed successfully.")


if __name__ == "__main__":
    run_smoke_test()
