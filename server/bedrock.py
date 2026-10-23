"""server.bedrock - AWS Bedrock Converse API integration with strict validation and deterministic fallbacks.

Enforces:
- Region and model configuration from environment (BEDROCK_MODEL_ID, AWS_REGION).
- Timeout: 4s connect, 4s read, 0 retries.
- Converse API invocation with temperature 0.0 and short max tokens.
- Phrasing:
  - Input is strictly the structured scan/device result.
  - Prompt: only provided facts, max 3 sentences, no invented vulnerabilities,
    never say 'safe', never read CVE IDs, say 'replace' for EoL devices.
- Output Validator:
  - Rejects text containing a CVE ID.
  - Rejects text containing the word 'safe'.
  - Rejects text with more than 3 sentences.
  - Rejects text containing a number not in the input.
  - Rejects text with 'critical' when max_cvss < 9.0.
  - Rejects text with 'update' for an EoL device.
  - On rejection: falls back deterministically to template.
- CPE Candidate Resolution:
  - Passes candidates from cpe_index.json with numeric integer IDs.
  - Bedrock returns an integer ID or a clarifying question.
  - Verifies the returned ID exists in the candidate list, otherwise asks user.
  - Never accepts a free-form CPE string.
- Every Bedrock call has a deterministic template fallback returning:
  phrasing_source: 'bedrock' | 'template'
"""

import json
import logging
import os
import re
from typing import Any

import boto3
from botocore.config import Config

from .storage import load_cpe_index, resolve_candidate_cpe

logger = logging.getLogger(__name__)

# Configurable defaults
DEFAULT_MODEL_ID = "us.anthropic.claude-3-haiku-20240307-v1:0"
DEFAULT_REGION = "us-east-1"

# Word-to-digit mapping for number validation (up to twenty)
WORD_TO_DIGIT = {
    "zero": "0",
    "one": "1",
    "two": "2",
    "three": "3",
    "four": "4",
    "five": "5",
    "six": "6",
    "seven": "7",
    "eight": "8",
    "nine": "9",
    "ten": "10",
    "eleven": "11",
    "twelve": "12",
    "thirteen": "13",
    "fourteen": "14",
    "fifteen": "15",
    "sixteen": "16",
    "seventeen": "17",
    "eighteen": "18",
    "nineteen": "19",
    "twenty": "20",
}


def get_bedrock_model_id() -> str:
    """Read Bedrock model ID from environment or return default."""
    return os.environ.get("BEDROCK_MODEL_ID") or DEFAULT_MODEL_ID


def get_aws_region() -> str:
    """Read AWS region from environment or return default."""
    return os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or DEFAULT_REGION


def create_bedrock_client(client_override: Any = None) -> Any:
    """Create a boto3 bedrock-runtime client configured with 4s timeouts and 0 retries."""
    if client_override is not None:
        return client_override

    cfg = Config(
        connect_timeout=4,
        read_timeout=4,
        retries={"max_attempts": 0},
    )
    return boto3.client(
        "bedrock-runtime",
        region_name=get_aws_region(),
        config=cfg,
    )


def extract_numbers_from_input(input_data: Any) -> set[str]:
    """Recursively extract all numeric tokens and floats from input data structure."""
    raw_str = json.dumps(input_data)
    allowed: set[str] = set()

    for match in re.findall(r"\b\d+(?:\.\d+)?\b", raw_str):
        allowed.add(match)
        try:
            val = float(match)
            if val.is_integer():
                allowed.add(str(int(val)))
            else:
                allowed.add(str(val))
        except ValueError:
            pass

    return allowed


def count_sentences(text: str) -> int:
    """Count sentences in text, ignoring decimals and version strings."""
    cleaned = re.sub(r"\b\d+\.\d+\b", "NUM", text)
    sentences = [s.strip() for s in re.split(r"[.!?]+(?:\s+|$)", cleaned) if s.strip()]
    return len(sentences)


def validate_phrasing_output(
    text: str,
    input_data: dict[str, Any],
    max_cvss: float = 0.0,
    is_eol: bool = False,
) -> tuple[bool, str | None]:
    """Validate Bedrock generated phrasing before returning.

    Rejection conditions:
    1. Text contains a CVE ID (e.g. CVE-2023-1389).
    2. Text contains the word 'safe'.
    3. Text contains more than 3 sentences.
    4. Text contains a number not present in the input.
    5. Text contains 'critical' when max_cvss < 9.0.
    6. Text contains 'update' for an EoL device.
    """
    if not text or not text.strip():
        return False, "empty_text"

    # 1. CVE ID check
    if re.search(r"\bCVE-\d{4}-\d{4,7}\b", text, re.IGNORECASE):
        return False, "contains_cve_id"

    # 2. Word 'safe' check
    if re.search(r"\bsafe\b", text, re.IGNORECASE):
        return False, "contains_word_safe"

    # 3. Sentence count <= 3
    if count_sentences(text) > 3:
        return False, "exceeds_max_sentences"

    # 4. Numbers check: every number in text must be present in input_data
    allowed_numbers = extract_numbers_from_input(input_data)

    # Check word numbers (e.g. "three")
    words = re.findall(r"[a-zA-Z]+", text.lower())
    for w in words:
        if w in WORD_TO_DIGIT:
            digit = WORD_TO_DIGIT[w]
            if digit not in allowed_numbers:
                return False, f"hallucinated_number_word_{w}"

    # Check digit numbers (e.g. "8", "4.0", "99")
    for num_str in re.findall(r"\b\d+(?:\.\d+)?\b", text):
        if num_str not in allowed_numbers:
            try:
                val = float(num_str)
                check = str(int(val)) if val.is_integer() else str(val)
                if check not in allowed_numbers:
                    return False, f"hallucinated_number_{num_str}"
            except ValueError:
                return False, f"hallucinated_number_{num_str}"

    # 5. 'critical' check when max_cvss < 9.0
    if max_cvss < 9.0 and re.search(r"\bcritical\b", text, re.IGNORECASE):
        return False, "critical_cvss_below_threshold"

    # 6. 'update' check for EoL device
    if is_eol and re.search(r"\bupdate(?:s|d|ing)?\b", text, re.IGNORECASE):
        return False, "update_for_eol_device"

    return True, None


def generate_spoken_scan_phrasing(
    scan_summary: dict[str, Any],
    max_cvss: float,
    is_eol: bool,
    template_fallback: str,
    client_override: Any = None,
) -> tuple[str, str]:
    """Generate spoken phrasing for scan_home via Bedrock Converse API with template fallback.

    Returns:
        (spoken_text, phrasing_source) where phrasing_source is 'bedrock' or 'template'.
    """
    model_id = get_bedrock_model_id()
    from server.limiter import global_bedrock_budget

    if not global_bedrock_budget.allow_call():
        logger.info("Bedrock hourly call limit reached; falling back to template scan phrasing.")
        return template_fallback, "template"

    try:
        client = create_bedrock_client(client_override)
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
            f"{json.dumps(scan_summary, indent=2)}\n\n"
            f"Please summarize this for voice playback in at most 3 sentences."
        )

        response = client.converse(
            modelId=model_id,
            system=[{"text": system_prompt}],
            messages=[{"role": "user", "content": [{"text": user_message}]}],
            inferenceConfig={"temperature": 0.0, "maxTokens": 150},
        )

        output_content = response.get("output", {}).get("message", {}).get("content", [])
        if not output_content or "text" not in output_content[0]:
            logger.warning("Bedrock converse response had no text content.")
            return template_fallback, "template"

        generated_text = output_content[0]["text"].strip()

        # Run output validator
        is_valid, reason = validate_phrasing_output(
            generated_text,
            input_data=scan_summary,
            max_cvss=max_cvss,
            is_eol=is_eol,
        )

        if is_valid:
            return generated_text, "bedrock"
        else:
            logger.warning(
                "Bedrock phrasing rejected by validator (%s): %s", reason, generated_text
            )
            return template_fallback, "template"

    except Exception as exc:  # noqa: BLE001 - Resilient fallback for any AWS/network failure
        logger.info("Bedrock converse failed (%s); falling back to template.", exc)
        return template_fallback, "template"


def generate_spoken_device_phrasing(
    device_summary: dict[str, Any],
    max_cvss: float,
    is_eol: bool,
    template_fallback: str,
    client_override: Any = None,
) -> tuple[str, str]:
    """Generate spoken phrasing for explain_risk via Bedrock Converse API with template fallback.

    Returns:
        (spoken_text, phrasing_source) where phrasing_source is 'bedrock' or 'template'.
    """
    model_id = get_bedrock_model_id()
    from server.limiter import global_bedrock_budget

    if not global_bedrock_budget.allow_call():
        logger.info("Bedrock hourly call limit reached; falling back to template device phrasing.")
        return template_fallback, "template"

    try:
        client = create_bedrock_client(client_override)
        system_prompt = (
            "You are HomeBOM, a smart-home security assistant on Alexa. "
            "Explain the security risk of a specific device for voice playback.\n"
            "MANDATORY RULES:\n"
            "1. Use ONLY the facts provided in the input JSON below.\n"
            "2. Maximum 3 sentences.\n"
            "3. Never add, assume, or invent vulnerabilities.\n"
            "4. NEVER say the word 'safe'.\n"
            "5. NEVER read CVE IDs.\n"
            "6. If the device is end-of-life (is_eol=true), you MUST say it must be replaced; never say update for it.\n"
            "7. Only use the word 'critical' if max_cvss is 9.0 or higher.\n"
            "8. Respond with plain conversational text only."
        )
        user_message = (
            f"Here is the device risk details:\n"
            f"{json.dumps(device_summary, indent=2)}\n\n"
            f"Please explain the risk in at most 3 sentences."
        )

        response = client.converse(
            modelId=model_id,
            system=[{"text": system_prompt}],
            messages=[{"role": "user", "content": [{"text": user_message}]}],
            inferenceConfig={"temperature": 0.0, "maxTokens": 150},
        )

        output_content = response.get("output", {}).get("message", {}).get("content", [])
        if not output_content or "text" not in output_content[0]:
            return template_fallback, "template"

        generated_text = output_content[0]["text"].strip()

        is_valid, reason = validate_phrasing_output(
            generated_text,
            input_data=device_summary,
            max_cvss=max_cvss,
            is_eol=is_eol,
        )

        if is_valid:
            return generated_text, "bedrock"
        else:
            logger.warning("Bedrock device phrasing rejected (%s): %s", reason, generated_text)
            return template_fallback, "template"

    except Exception as exc:  # noqa: BLE001 - Resilient fallback for any AWS/network failure
        logger.info("Bedrock device phrasing failed (%s); falling back to template.", exc)
        return template_fallback, "template"


def resolve_cpe_with_bedrock(
    model: str,
    name: str = "",
    client_override: Any = None,
) -> tuple[dict[str, Any] | None, str | None, str]:
    """Resolve device CPE using Bedrock candidate selection with deterministic heuristic fallback.

    Rule D.3:
    - Candidate list with numeric IDs passed to Bedrock.
    - Model returns an ID or a clarifying question.
    - Verify returned ID exists in the list, otherwise ask the user.
    - Never accept a free-form CPE string.

    Returns:
        (best_candidate, clarification_question, phrasing_source)
    """
    # Deterministic heuristic resolution for baseline/fallback
    template_best, template_closest = resolve_candidate_cpe(model, name)

    # Build candidate pool: use closest candidates if found, or top relevant from index
    all_index = load_cpe_index()
    candidates_to_present: list[dict[str, Any]] = []

    if template_closest:
        candidates_to_present = template_closest
    else:
        # Filter by vendor or tokens
        q_tokens = set(re.findall(r"[a-z0-9]+", f"{name} {model}".lower()))
        matched = []
        for c in all_index:
            c_tokens = set(c.get("keywords", []))
            if q_tokens.intersection(c_tokens):
                matched.append(c)
        candidates_to_present = matched[:5] if matched else all_index[:5]

    # Map with integer IDs
    candidate_map: dict[int, dict[str, Any]] = {
        i: cand for i, cand in enumerate(candidates_to_present)
    }

    formatted_candidates = [
        {
            "id": i,
            "vendor": cand.get("vendor", ""),
            "product": cand.get("product", ""),
            "category": cand.get("category", ""),
        }
        for i, cand in candidate_map.items()
    ]

    model_id = get_bedrock_model_id()
    from server.limiter import global_bedrock_budget

    if not global_bedrock_budget.allow_call():
        logger.info("Bedrock hourly call limit reached; falling back to heuristic candidate resolver.")
        if template_best:
            return template_best, None, "template"
        cand_names = [f"{c['vendor']} {c['product']}" for c in template_closest]
        q = (
            f"I couldn't match '{model}' to a verified firmware model in my security database. "
            f"Did you mean one of these: {', '.join(cand_names)}?"
            if cand_names
            else f"I couldn't find a matching firmware definition for '{model}'. Could you check the label on your device?"
        )
        return None, q, "template"

    try:
        client = create_bedrock_client(client_override)
        system_prompt = (
            "You are a device identification assistant for smart-home security. "
            "Your job is to match a user's device name and model to exactly one candidate in the candidate list.\n"
            "MANDATORY RULES:\n"
            "1. If there is a confident match, output its integer 'id' in 'selected_id'.\n"
            "2. If there is no confident match or if multiple candidates are plausible, set 'selected_id' to null and write a polite 'clarification_question' asking the user for clarification.\n"
            "3. You must NEVER invent or output a CPE string.\n"
            '4. Respond ONLY with a valid JSON object: {"selected_id": <int or null>, "clarification_question": <string or null>}.'
        )
        user_message = (
            f"User Device Request:\n"
            f"- Device Name: {name}\n"
            f"- Device Model: {model}\n\n"
            f"Candidate List:\n"
            f"{json.dumps(formatted_candidates, indent=2)}\n"
        )

        response = client.converse(
            modelId=model_id,
            system=[{"text": system_prompt}],
            messages=[{"role": "user", "content": [{"text": user_message}]}],
            inferenceConfig={"temperature": 0.0, "maxTokens": 100},
        )

        output_content = response.get("output", {}).get("message", {}).get("content", [])
        if not output_content or "text" not in output_content[0]:
            # Fall back to template
            if template_best:
                return template_best, None, "template"
            cand_names = [f"{c['vendor']} {c['product']}" for c in template_closest]
            question = (
                f"I couldn't match '{model}' to a verified model. Did you mean one of these: {', '.join(cand_names)}?"
                if cand_names
                else f"I couldn't find a matching model for '{model}'. Could you check the label?"
            )
            return None, question, "template"

        raw_text = output_content[0]["text"].strip()
        # Parse JSON from model
        # Remove potential markdown code blocks
        clean_json_str = re.sub(
            r"^```(?:json)?\s*|\s*```$", "", raw_text, flags=re.MULTILINE
        ).strip()
        parsed = json.loads(clean_json_str)

        selected_id = parsed.get("selected_id")
        clarification_q = parsed.get("clarification_question")

        # Verify returned ID exists in the candidate list
        if isinstance(selected_id, int) and selected_id in candidate_map:
            # Verified ID match from pre-indexed candidate list!
            return candidate_map[selected_id], None, "bedrock"
        else:
            # Model returned null, invalid ID, or clarification question
            q = (
                clarification_q
                or f"I couldn't match '{model}' to a verified model in my database. Could you specify the exact model number?"
            )
            return None, q, "bedrock"

    except Exception as exc:  # noqa: BLE001 - Resilient fallback for any AWS/network failure
        logger.info("Bedrock CPE resolution failed (%s); falling back to heuristic template.", exc)
        if template_best:
            return template_best, None, "template"
        cand_names = [f"{c['vendor']} {c['product']}" for c in template_closest]
        q = (
            f"I couldn't match '{model}' to a verified firmware model in my security database. "
            f"Did you mean one of these: {', '.join(cand_names)}?"
            if cand_names
            else f"I couldn't find a matching firmware definition for '{model}'. Could you check the label on your device?"
        )
        return None, q, "template"
