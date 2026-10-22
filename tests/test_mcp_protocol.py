"""tests/test_mcp_protocol.py - End-to-end MCP protocol tests over Streamable HTTP.

Validates:
- Streamable HTTP transport and MCP protocol version (2025-11-25)
- Constant-time HMAC authentication with fail-closed behavior
- HTTP 401 rejection on missing or invalid keys
- Exactly six tools listed with LLM routing docstrings
- Tool execution for list_devices, scan_home, explain_risk, get_fix_steps, export_hbom
- add_device without matching candidate returns clarifying question, never invents CPE
- add_device with valid candidate persists atomically to user_devices.json
"""

import asyncio
import json
import os
import socket

import httpx
import pytest
import uvicorn
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client

from server.auth import get_configured_api_key
from server.main import app
from server.storage import USER_DEVICES_PATH

TEST_KEY = "test-secret-api-key-homebom-2026"


def find_free_port() -> int:
    """Find a free TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(autouse=True)
def clean_user_devices():
    """Ensure user_devices.json does not leak between tests."""
    if USER_DEVICES_PATH.exists():
        USER_DEVICES_PATH.unlink()
    yield
    if USER_DEVICES_PATH.exists():
        USER_DEVICES_PATH.unlink()


@pytest.fixture
def test_env():
    """Set HOMEBOM_API_KEY for the duration of a test."""
    old_key = os.environ.get("HOMEBOM_API_KEY")
    old_noauth = os.environ.get("HOMEBOM_DEV_NOAUTH")
    os.environ["HOMEBOM_API_KEY"] = TEST_KEY
    os.environ.pop("HOMEBOM_DEV_NOAUTH", None)
    app.reset()
    yield TEST_KEY
    if old_key is not None:
        os.environ["HOMEBOM_API_KEY"] = old_key
    else:
        os.environ.pop("HOMEBOM_API_KEY", None)
    if old_noauth is not None:
        os.environ["HOMEBOM_DEV_NOAUTH"] = old_noauth
    else:
        os.environ.pop("HOMEBOM_DEV_NOAUTH", None)
    app.reset()


@pytest.fixture
async def running_server(test_env):
    """Run HomeBOM server on an ephemeral port in the background."""
    app.reset()
    port = find_free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    await asyncio.sleep(0.4)
    server_url = f"http://127.0.0.1:{port}/mcp"
    try:
        yield server_url
    finally:
        server.should_exit = True
        await task
        app.reset()


def test_auth_fail_closed_mechanics():
    """Requirement 1: Server refuses to start if HOMEBOM_API_KEY is unset unless HOMEBOM_DEV_NOAUTH=1."""
    old_key = os.environ.get("HOMEBOM_API_KEY")
    old_noauth = os.environ.get("HOMEBOM_DEV_NOAUTH")
    os.environ.pop("HOMEBOM_API_KEY", None)
    os.environ.pop("HOMEBOM_DEV_NOAUTH", None)
    try:
        # Unset -> must raise RuntimeError
        with pytest.raises(
            RuntimeError, match="HOMEBOM_API_KEY environment variable is not configured"
        ):
            get_configured_api_key()

        # HOMEBOM_DEV_NOAUTH=1 -> allows starting without key
        os.environ["HOMEBOM_DEV_NOAUTH"] = "1"
        key, noauth = get_configured_api_key()
        assert key is None
        assert noauth is True
    finally:
        if old_key is not None:
            os.environ["HOMEBOM_API_KEY"] = old_key
        else:
            os.environ.pop("HOMEBOM_API_KEY", None)
        if old_noauth is not None:
            os.environ["HOMEBOM_DEV_NOAUTH"] = old_noauth
        else:
            os.environ.pop("HOMEBOM_DEV_NOAUTH", None)


@pytest.mark.asyncio
async def test_auth_rejection_http_401(running_server):
    """Requirement 1: Requests with missing or invalid keys are rejected with HTTP 401."""
    # 1. Missing Authorization header
    async with httpx.AsyncClient() as client:
        resp = await client.post(running_server, json={})
        assert resp.status_code == 401
        data = resp.json()
        assert "error" in data
        assert "Unauthorized" in data["error"]

    # 2. Wrong Authorization key
    async with httpx.AsyncClient(headers={"Authorization": "Bearer wrong-key"}) as client:
        resp = await client.post(running_server, json={})
        assert resp.status_code == 401

    # 3. Wrong X-API-Key
    async with httpx.AsyncClient(headers={"X-API-Key": "wrong-key"}) as client:
        resp = await client.post(running_server, json={})
        assert resp.status_code == 401


@pytest.mark.asyncio
async def test_list_tools_exactly_six_and_routing_descriptions(running_server):
    """Requirement 6 & 7: Exactly six tools listed, with descriptions formatted for LLM routing."""
    async with (
        httpx.AsyncClient(headers={"Authorization": f"Bearer {TEST_KEY}"}) as http_client,
        streamable_http_client(running_server, http_client=http_client) as (r, w, _),
        ClientSession(r, w) as session,
    ):
        await session.initialize()
        tools_result = await session.list_tools()
        tool_dict = {t.name: t for t in tools_result.tools}

        expected_tools = {
            "list_devices",
            "add_device",
            "scan_home",
            "explain_risk",
            "get_fix_steps",
            "export_hbom",
        }
        assert set(tool_dict.keys()) == expected_tools, (
            f"Expected exactly 6 tools {expected_tools}, got {set(tool_dict.keys())}"
        )

        # Check LLM routing descriptions
        for name, tool in tool_dict.items():
            desc = tool.description or ""
            assert "When to use:" in desc, f"Tool '{name}' missing 'When to use:' in description"
            assert "When NOT to use:" in desc, (
                f"Tool '{name}' missing 'When NOT to use:' in description"
            )
            assert "Example user phrasings:" in desc, (
                f"Tool '{name}' missing 'Example user phrasings:' in description"
            )


@pytest.mark.asyncio
async def test_mcp_tools_execution_and_voice_rules(running_server):
    """Requirement 4 & 7: Test calling each tool with valid auth and verify structured and voice output."""
    async with (
        httpx.AsyncClient(headers={"Authorization": f"Bearer {TEST_KEY}"}) as http_client,
        streamable_http_client(running_server, http_client=http_client) as (r, w, _),
        ClientSession(r, w) as session,
    ):
        await session.initialize()

        # 1. list_devices
        res = await session.call_tool("list_devices", {})
        data = json.loads(res.content[0].text)
        assert data["total_devices"] == 8
        assert len(data["devices"]) == 8
        assert "spoken" in data
        assert "inventory" in data["spoken"].lower()

        # 2. scan_home (includes "as of <EPSS date>")
        res = await session.call_tool("scan_home", {})
        data = json.loads(res.content[0].text)
        assert "epss_as_of" in data
        assert data["epss_as_of"] == "as of 2026-10-21"
        assert "as of 2026-10-21" in data["spoken"]
        assert data["summary"]["fix_now"] >= 1
        assert "replace" in data["spoken"].lower()  # EoL devices present -> says replace

        # 3. explain_risk for affected device
        res = await session.call_tool("explain_risk", {"device": "Living Room Router"})
        data = json.loads(res.content[0].text)
        assert data["tier"] == "fix_now"
        assert data["overall_status"] == "affected"
        assert "CVE-" not in data["spoken"]  # Never read CVE IDs aloud

        # explain_risk for clean device (must say "no known vulnerabilities in public databases", never "safe")
        res = await session.call_tool("explain_risk", {"device": "Ring Video Doorbell Pro"})
        data = json.loads(res.content[0].text)
        assert data["tier"] == "not_affected"
        assert "no known vulnerabilities in public databases" in data["spoken"]
        assert "safe" not in data["spoken"].lower()

        # explain_risk for unknown device (must say "I can't verify")
        res = await session.call_tool("explain_risk", {"device": "Amazon Echo Dot"})
        data = json.loads(res.content[0].text)
        assert data["tier"] == "unknown"
        assert "I can't verify" in data["spoken"]

        # 4. get_fix_steps for EoL device (must say "replace")
        res = await session.call_tool("get_fix_steps", {"device": "Backyard Security Camera"})
        data = json.loads(res.content[0].text)
        assert data["action"] == "replace"
        assert data["is_eol"] is True
        assert "replace" in data["spoken"].lower()

        # 5. export_hbom stub (status: not_implemented)
        res = await session.call_tool("export_hbom", {})
        data = json.loads(res.content[0].text)
        assert data["status"] == "not_implemented"
        assert "CycloneDX" in data["bom_format"]
        assert "Phase 4" in data["message"]


@pytest.mark.asyncio
async def test_add_device_without_candidate_returns_question_not_cpe(running_server):
    """Requirement 3 & 7: add_device with no candidate returns a clarifying question, never a CPE."""
    async with (
        httpx.AsyncClient(headers={"Authorization": f"Bearer {TEST_KEY}"}) as http_client,
        streamable_http_client(running_server, http_client=http_client) as (r, w, _),
        ClientSession(r, w) as session,
    ):
        await session.initialize()

        res = await session.call_tool(
            "add_device",
            {
                "name": "my router",
                "model": "SuperUnknown-Model-9999",
                "firmware": "1.0.0",
            },
        )
        data = json.loads(res.content[0].text)
        assert data["status"] == "clarification_needed"
        assert "question" in data
        assert "?" in data["question"]
        assert "spoken" in data
        # Crucial assertion: never invents or returns a CPE
        assert "cpe" not in data
        assert not USER_DEVICES_PATH.exists()


@pytest.mark.asyncio
async def test_add_device_atomic_persistence(running_server):
    """Requirement 2 & 3: add_device with valid candidate resolves from index and persists atomically."""
    async with (
        httpx.AsyncClient(headers={"Authorization": f"Bearer {TEST_KEY}"}) as http_client,
        streamable_http_client(running_server, http_client=http_client) as (r, w, _),
        ClientSession(r, w) as session,
    ):
        await session.initialize()

        # Add a device that matches an indexed product (DCS-2530L)
        res = await session.call_tool(
            "add_device",
            {
                "name": "Basement Camera",
                "model": "DCS-2530L",
                "firmware": "1.05.00",
            },
        )
        data = json.loads(res.content[0].text)
        assert data["status"] == "added"
        assert data["device"]["cpe"] == "cpe:2.3:o:dlink:dcs-2530l_firmware:*:*:*:*:*:*:*:*"
        assert data["device"]["vendor"] == "D-Link"

        # Verify user_devices.json was persisted
        assert USER_DEVICES_PATH.exists()
        saved = json.loads(USER_DEVICES_PATH.read_text(encoding="utf-8"))
        assert len(saved) == 1
        assert saved[0]["name"] == "Basement Camera"

        # Verify list_devices reflects the newly persisted device (8 seeded + 1 user = 9)
        list_res = await session.call_tool("list_devices", {})
        list_data = json.loads(list_res.content[0].text)
        assert list_data["total_devices"] == 9
        assert any(d["name"] == "Basement Camera" for d in list_data["devices"])
