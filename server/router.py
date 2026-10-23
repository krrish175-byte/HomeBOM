"""server.router - Tool intent routing via AWS Bedrock Converse API with deterministic keyword fallback.

Enforces:
- Real MCP tool discovery (tools matching the MCP server's registered tools).
- Bedrock tool selection via Converse API with temperature=0.0 and short max tokens.
- Deterministic keyword router fallback when Bedrock is unavailable, credentials absent, or times out.
- Reports `routed_by`: 'bedrock' | 'keywords'.
- Zero crashes in offline environments.
"""

import json
import logging
import re
from typing import Any

from .bedrock import create_bedrock_client, get_bedrock_model_id

logger = logging.getLogger(__name__)

# Canonical 6 MCP tools
VALID_TOOLS = {
    "list_devices",
    "add_device",
    "scan_home",
    "explain_risk",
    "get_fix_steps",
    "export_hbom",
}


def route_with_keywords(query: str) -> tuple[str, dict[str, Any]]:
    """Deterministic keyword-based intent router for voice queries and demo phrasings."""
    q = query.lower().strip()

    # 1. Export HBOM / CycloneDX / VEX
    if any(k in q for k in ["export", "bill of materials", "hbom", "cyclonedx", "vex", "bom"]):
        return "export_hbom", {}

    # 2. Add device
    if any(
        k in q
        for k in [
            "add device",
            "add a device",
            "add new",
            "add my",
            "register device",
            "connect device",
        ]
    ):
        return "add_device", {"name": "New Device", "model": "Unknown", "firmware": "1.0.0"}

    # 2. Fix steps / remediation for a specific device
    if any(
        k in q
        for k in [
            "how do i fix",
            "how to fix",
            "fix the",
            "fix steps",
            "remediate",
            "patch the",
            "update the",
            "what should i do about",
            "how can i fix",
        ]
    ):
        dev = "router"
        for candidate in [
            "tv stick",
            "camera",
            "router",
            "extender",
            "doorbell",
            "echo",
            "plug",
            "tv",
            "stick",
        ]:
            if candidate in q:
                dev = candidate
                break
        return "get_fix_steps", {"device": dev}

    # 3. List devices / inventory
    if any(
        k in q
        for k in [
            "what devices",
            "list devices",
            "show devices",
            "inventory",
            "which devices",
            "all devices",
        ]
    ):
        return "list_devices", {}

    # 4. Device name or category mentioned (e.g. "how safe is my router", "is my camera ok", "tell me about my router")
    device_candidates = [
        "tv stick",
        "router",
        "camera",
        "extender",
        "doorbell",
        "echo",
        "plug",
        "tv",
        "stick",
    ]
    for candidate in device_candidates:
        if re.search(rf"\b{re.escape(candidate)}\b", q):
            return "explain_risk", {"device": candidate}

    # Also handle general explain risk triggers
    if any(
        k in q
        for k in [
            "tell me about",
            "why is",
            "explain",
            "risk on",
            "about my",
            "status of",
            "check my",
            "details on",
            "info on",
        ]
    ):
        return "explain_risk", {"device": "router"}

    # 5. Whole-home scan / fix first / overall home safety
    if any(
        k in q
        for k in [
            "how safe",
            "fix first",
            "what first",
            "scan home",
            "scan my home",
            "security scan",
            "audit home",
            "threats",
            "safe is my home",
            "how safe is",
        ]
    ):
        return "scan_home", {}

    # Default fallback to whole-home security scan
    return "scan_home", {}


def route_with_bedrock(
    query: str,
    tools_definitions: list[dict[str, Any]],
    client_override: Any = None,
) -> tuple[str, dict[str, Any]] | None:
    """Attempt to route user query to an MCP tool using Bedrock Converse API.

    Returns:
        (tool_name, tool_args) or None if Bedrock fails or credentials missing.
    """
    from server.limiter import global_bedrock_budget

    if not global_bedrock_budget.allow_call():
        logger.info("Bedrock hourly call limit reached; falling back to keyword router.")
        return None

    model_id = get_bedrock_model_id()
    allowed_tool_names = {t.get("name") for t in tools_definitions} if tools_definitions else VALID_TOOLS
    try:
        client = create_bedrock_client(client_override)
        system_prompt = (
            "You are an intent classifier and tool selector for HomeBOM, an Alexa+ smart home security assistant. "
            "Given the user query, select exactly one tool from the list of available tools and extract its arguments.\n"
            "MANDATORY RULES:\n"
            '1. Output ONLY a valid JSON object: {"tool": "<tool_name>", "args": {<key>: <value>}}.\n'
            "2. Tool name MUST be one of: list_devices, add_device, scan_home, explain_risk, get_fix_steps, export_hbom.\n"
            "3. If query mentions a specific device or device category (e.g. router, camera, extender, echo, doorbell, tv stick, plug), choose explain_risk or get_fix_steps (if asking how to fix).\n"
            "4. If query asks about overall home safety without specifying a device (e.g., 'how safe is my home'), choose scan_home.\n"
            "5. Do not include markdown or explanations outside the JSON."
        )

        formatted_tools = [
            {
                "name": t.get("name"),
                "description": t.get("description", "").splitlines()[0],
                "inputSchema": t.get("inputSchema"),
            }
            for t in tools_definitions
        ]

        user_message = (
            f"Available Tools:\n"
            f"{json.dumps(formatted_tools, indent=2)}\n\n"
            f'User Query: "{query}"\n'
            f"Select the best tool and arguments."
        )

        response = client.converse(
            modelId=model_id,
            system=[{"text": system_prompt}],
            messages=[{"role": "user", "content": [{"text": user_message}]}],
            inferenceConfig={"temperature": 0.0, "maxTokens": 100},
        )

        output_content = response.get("output", {}).get("message", {}).get("content", [])
        if not output_content or "text" not in output_content[0]:
            return None

        raw_text = output_content[0]["text"].strip()
        clean_json = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw_text, flags=re.MULTILINE).strip()
        parsed = json.loads(clean_json)

        tool_name = parsed.get("tool")
        args = parsed.get("args", {})

        if tool_name in allowed_tool_names and tool_name in VALID_TOOLS and isinstance(args, dict):
            return tool_name, args

        return None

    except Exception as exc:  # noqa: BLE001 - Resilient fallback to keyword routing
        logger.info("Bedrock tool routing did not proceed (%s); using keyword router.", exc)
        return None


def route_user_query(
    query: str,
    tools_definitions: list[dict[str, Any]] | None = None,
    client_override: Any = None,
) -> tuple[str, dict[str, Any], str]:
    """Route user query with Bedrock tool selection, falling back to deterministic keywords.

    Returns:
        (tool_name, tool_args, routed_by) where routed_by is 'bedrock' or 'keywords'.
    """
    tools = tools_definitions or []

    # Attempt Bedrock routing if tools provided
    if tools:
        bedrock_result = route_with_bedrock(query, tools, client_override=client_override)
        if bedrock_result is not None:
            tool_name, args = bedrock_result
            return tool_name, args, "bedrock"

    # Deterministic keyword fallback
    tool_name, args = route_with_keywords(query)
    return tool_name, args, "keywords"
