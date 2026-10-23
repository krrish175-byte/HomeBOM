"""server.web - Web application routes and real Streamable HTTP MCP client.

Implements Phase 7:
- Serves single-page web UI (`GET /`, `GET /static/...`)
- Device inventory endpoint with real-time risk tiers (`GET /api/devices`)
- Chat routing endpoint acting as a real MCP client (`POST /api/chat`):
  - Connects to the server's `/mcp` endpoint over Streamable HTTP with Bearer auth.
  - Dynamically discovers real tools from `session.list_tools()`.
  - Routes user intent with Bedrock (falls back to deterministic keywords).
  - Invokes routed MCP tool via `session.call_tool()`.
  - Returns structured output, spoken text, routed_by ('bedrock' | 'keywords'),
    and phrasing_source ('bedrock' | 'template').
- 100% resilient and functional offline with no AWS credentials.
"""

import json
import logging
import os
from pathlib import Path

import httpx
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse

from server.auth import get_configured_api_key
from server.engine import scan_all_devices
from server.router import route_user_query
from server.storage import get_all_devices, get_epss_metadata

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).resolve().parent / "static"


async def home_page(request: Request) -> HTMLResponse:
    """Serve the single-page application index.html."""
    index_file = STATIC_DIR / "index.html"
    if not index_file.exists():
        return HTMLResponse("<h1>HomeBOM UI loading...</h1>", status_code=200)
    content = index_file.read_text(encoding="utf-8")
    return HTMLResponse(content, status_code=200)


async def devices_endpoint(request: Request) -> JSONResponse:
    """Return all devices ranked by risk tier and security attributes."""
    try:
        devices = get_all_devices()
        profiles = scan_all_devices(devices)
        epss_meta = get_epss_metadata()

        device_cards = []
        for p in profiles:
            device_cards.append(
                {
                    "device_id": p.device_id,
                    "name": p.device_name,
                    "model": p.model,
                    "firmware": p.firmware,
                    "cpe": p.cpe,
                    "tier": p.tier,
                    "overall_status": p.overall_status,
                    "is_eol": p.is_eol,
                    "max_cvss": p.max_cvss,
                    "max_epss": p.max_epss,
                    "vulnerabilities_count": p.vulnerabilities_count,
                    "unverified_candidates": p.unverified_candidates,
                    "spoken_summary": p.spoken_summary,
                    "fix_steps": p.fix_steps,
                }
            )

        return JSONResponse(
            {
                "status": "success",
                "total_devices": len(device_cards),
                "epss_as_of": epss_meta.get("as_of_string", "as of 2026-10-21"),
                "devices": device_cards,
            }
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("Error retrieving device profiles: %s", exc)
        return JSONResponse({"status": "error", "message": str(exc)}, status_code=500)


async def chat_endpoint(request: Request) -> JSONResponse:
    """Handle chat queries by connecting as a real MCP client over Streamable HTTP."""
    try:
        payload = await request.json()
    except Exception:  # noqa: BLE001
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    message = (payload.get("message") or "").strip()
    if not message:
        return JSONResponse({"error": "Query message cannot be empty"}, status_code=400)

    # Abuse Limit 1: Max query length 300 chars
    MAX_QUERY_LENGTH = 300
    if len(message) > MAX_QUERY_LENGTH:
        return JSONResponse(
            {"error": f"Query length exceeds maximum limit of {MAX_QUERY_LENGTH} characters"},
            status_code=400,
        )

    # Abuse Limit 2: Per-IP rate limiting (10 queries / minute)
    from server.limiter import global_ip_limiter

    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()
    else:
        client_ip = request.client.host if request.client else "127.0.0.1"

    if not global_ip_limiter.is_allowed(client_ip):
        return JSONResponse(
            {"error": "Rate limit exceeded. Maximum 10 queries per minute per IP."},
            status_code=429,
        )

    # Determine server host/port and target URL
    server_port = request.url.port or int(os.environ.get("PORT", "8000"))
    server_host = request.url.hostname or "127.0.0.1"
    server_url = f"http://{server_host}:{server_port}/mcp"

    # Retrieve configured API key for MCP transport
    try:
        api_key, _ = get_configured_api_key()
    except Exception:  # noqa: BLE001
        api_key = os.environ.get("HOMEBOM_API_KEY", "")

    headers: dict[str, str] = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    try:
        # Establish a real Streamable HTTP MCP client session
        async with (
            httpx.AsyncClient(headers=headers, timeout=20.0) as http_client,
            streamable_http_client(server_url, http_client=http_client) as (r, w, _),
            ClientSession(r, w) as session,
        ):
            await session.initialize()

            # 1. Discover registered tools dynamically from MCP server
            tools_result = await session.list_tools()
            tools_list = [
                {
                    "name": t.name,
                    "description": t.description,
                    "inputSchema": t.inputSchema,
                }
                for t in tools_result.tools
            ]

            # In HOMEBOM_PUBLIC_DEMO mode: filter add_device out of the tool list the router sees
            from server.storage import is_public_demo_mode

            if is_public_demo_mode():
                tools_list = [t for t in tools_list if t["name"] != "add_device"]

            # 2. Tool routing: Bedrock with deterministic keyword fallback
            tool_name, tool_args, routed_by = route_user_query(
                message, tools_definitions=tools_list
            )

            # Defensive guard: If add_device was selected in public demo mode, block execution
            if is_public_demo_mode() and tool_name == "add_device":
                return JSONResponse(
                    {
                        "query": message,
                        "tool_called": "add_device",
                        "tool_args": tool_args,
                        "routed_by": routed_by,
                        "phrasing_source": "template",
                        "spoken": "Adding devices is disabled in public demo mode.",
                        "result": {
                            "status": "disabled",
                            "spoken": "Adding devices is disabled in public demo mode.",
                            "phrasing_source": "template",
                        },
                    }
                )

            # 3. Call the chosen tool on the real MCP server
            call_res = await session.call_tool(tool_name, tool_args)
            raw_text = call_res.content[0].text if call_res.content else "{}"
            tool_data = json.loads(raw_text)

            spoken = tool_data.get("spoken", "")
            phrasing_source = tool_data.get("phrasing_source", "template")

            return JSONResponse(
                {
                    "query": message,
                    "tool_called": tool_name,
                    "tool_args": tool_args,
                    "routed_by": routed_by,
                    "phrasing_source": phrasing_source,
                    "spoken": spoken,
                    "result": tool_data,
                }
            )

    except Exception as exc:
        logger.exception("Error executing MCP client call for '%s'", message)
        return JSONResponse(
            {
                "status": "error",
                "message": f"MCP execution error: {type(exc).__name__}: {exc}",
                "query": message,
            },
            status_code=500,
        )
