"""tests/test_public_hardening.py - Public-demo mode, abuse limits, and API key containment tests.

Validates Requirements 1, 2, and 3:
1. HOMEBOM_PUBLIC_DEMO=1 mode:
   - /api/chat cannot call add_device (filtered out of tool list seen by router).
   - User-device writes are disabled entirely (save_user_devices raises error).
   - Inventory is always strictly the 8 seeded devices at startup.
2. Abuse limits on /api/chat:
   - Per-IP rate limit (10 requests / minute) returning HTTP 429 on exceedance.
   - Max query length 300 characters returning HTTP 400.
   - Hard cap on Bedrock calls per process per hour with automatic fallback to keywords/templates.
   - No CORS: Access-Control-Allow-Origin header is never sent.
3. API key containment:
   - Secret API key never reaches the browser (greps static assets and all /api responses).
"""

import asyncio
import socket
from pathlib import Path

import httpx
import pytest
import uvicorn

from server.limiter import BedrockHourlyBudget, global_bedrock_budget, global_ip_limiter
from server.main import app
from server.router import route_user_query
from server.storage import (
    get_all_devices,
    is_public_demo_mode,
    load_user_devices,
    save_user_devices,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
CANARY_KEY = "CANARY-SECRET-KEY-999-DO-NOT-LEAK-TO-BROWSER"


def find_free_port() -> int:
    """Find a free TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
async def hardened_server(tmp_path, monkeypatch):
    """Run server with CANARY_KEY and clean state."""
    monkeypatch.setenv("HOMEBOM_API_KEY", CANARY_KEY)
    test_user_devices = tmp_path / "user_devices.json"
    monkeypatch.setenv("HOMEBOM_USER_DEVICES_PATH", str(test_user_devices))
    global_ip_limiter.reset()
    global_bedrock_budget.reset()

    app.reset()
    port = find_free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    await asyncio.sleep(0.4)

    base_url = f"http://127.0.0.1:{port}"
    try:
        yield base_url
    finally:
        server.should_exit = True
        await task
        app.reset()
        global_ip_limiter.reset()
        global_bedrock_budget.reset()
        if test_user_devices.exists():
            test_user_devices.unlink()


# ============================================================================
# Requirement 1: HOMEBOM_PUBLIC_DEMO=1 mode
# ============================================================================
def test_public_demo_storage_guards(monkeypatch):
    """Requirement 1: In public demo mode, user writes are disabled and inventory is strictly 8 seeded devices."""
    monkeypatch.setenv("HOMEBOM_PUBLIC_DEMO", "1")
    assert is_public_demo_mode() is True

    # User devices load returns empty list
    assert load_user_devices() == []

    # get_all_devices returns exactly 8 seeded devices
    devices = get_all_devices()
    assert len(devices) == 8

    # save_user_devices raises RuntimeError
    with pytest.raises(RuntimeError, match="User-device writes are disabled in public demo mode"):
        save_user_devices([{"id": "dev-hack", "name": "Fake Device"}])


@pytest.mark.asyncio
async def test_public_demo_filters_add_device_from_chat(hardened_server, monkeypatch):
    """Requirement 1: In public demo mode, /api/chat cannot call add_device and tool is filtered."""
    monkeypatch.setenv("HOMEBOM_PUBLIC_DEMO", "1")

    async with httpx.AsyncClient(base_url=hardened_server, timeout=15.0) as client:
        # User attempts to add a device via chat
        resp = await client.post(
            "/api/chat",
            json={"message": "add my TP-Link router running firmware 1.1.2"},
        )
        assert resp.status_code == 200
        data = resp.json()

        # Tool called must NOT be add_device (or if defensive fallback tripped, disabled)
        assert data.get("tool_called") != "add_device" or data.get("result", {}).get("status") == "disabled"
        assert "disabled in public demo mode" in data.get("spoken", "") or "disabled in public demo mode" in data.get("result", {}).get("spoken", "") or data.get("tool_called") == "scan_home"

        # Verify device inventory count remained exactly 8
        dev_resp = await client.get("/api/devices")
        assert dev_resp.status_code == 200
        assert len(dev_resp.json()["devices"]) == 8


# ============================================================================
# Requirement 2: Abuse limits on /api/chat
# ============================================================================
@pytest.mark.asyncio
async def test_max_query_length_enforced(hardened_server):
    """Requirement 2: Query length capped at 300 characters."""
    async with httpx.AsyncClient(base_url=hardened_server, timeout=10.0) as client:
        # 300 characters is allowed
        valid_query = "a" * 300
        resp = await client.post("/api/chat", json={"message": valid_query})
        assert resp.status_code == 200

        # 301 characters is rejected
        long_query = "a" * 301
        resp = await client.post("/api/chat", json={"message": long_query})
        assert resp.status_code == 400
        data = resp.json()
        assert "exceeds maximum limit of 300" in data.get("error", "")


@pytest.mark.asyncio
async def test_per_ip_rate_limiting(hardened_server):
    """Requirement 2: 10 queries per minute per IP limit; 11th request receives HTTP 429."""
    global_ip_limiter.reset()

    async with httpx.AsyncClient(base_url=hardened_server, timeout=15.0) as client:
        # First 10 requests should succeed
        for i in range(10):
            resp = await client.post("/api/chat", json={"message": f"ping {i}"})
            assert resp.status_code == 200, f"Request {i+1} failed with status {resp.status_code}"

        # 11th request must be rejected with HTTP 429 Too Many Requests
        resp_blocked = await client.post("/api/chat", json={"message": "ping 11"})
        assert resp_blocked.status_code == 429
        data = resp_blocked.json()
        assert "Rate limit exceeded" in data.get("error", "")

    global_ip_limiter.reset()


def test_bedrock_hourly_budget_hard_cap_and_fallback():
    """Requirement 2: Hard cap on Bedrock calls per process per hour with automatic fallback."""
    budget = BedrockHourlyBudget(max_calls_per_hour=3)
    assert budget.allow_call() is True
    assert budget.allow_call() is True
    assert budget.allow_call() is True
    # 4th call exceeds budget
    assert budget.allow_call() is False
    assert budget.is_exceeded() is True


def test_router_falls_back_when_bedrock_budget_exceeded(monkeypatch):
    """Requirement 2: Router automatically falls back to keywords when Bedrock budget is exceeded."""
    global_bedrock_budget.reset()
    # Saturate budget
    global_bedrock_budget.calls = [1e12] * global_bedrock_budget.max_calls
    assert global_bedrock_budget.is_exceeded() is True

    # Call router: should immediately fall back to keywords with no error
    tool, _args, routed_by = route_user_query(
        "how safe is my home",
        tools_definitions=[{"name": "scan_home", "description": "Scan", "inputSchema": {}}],
    )
    assert tool == "scan_home"
    assert routed_by == "keywords"

    global_bedrock_budget.reset()


@pytest.mark.asyncio
async def test_no_cors_headers_present(hardened_server):
    """Requirement 2: No CORS headers (e.g. Access-Control-Allow-Origin) on responses."""
    async with httpx.AsyncClient(base_url=hardened_server, timeout=10.0) as client:
        # GET /api/devices
        resp = await client.get("/api/devices")
        assert "access-control-allow-origin" not in resp.headers

        # POST /api/chat
        chat_resp = await client.post("/api/chat", json={"message": "how safe is my home"})
        assert "access-control-allow-origin" not in chat_resp.headers


# ============================================================================
# Requirement 3: API key never reaches the browser
# ============================================================================
@pytest.mark.asyncio
async def test_api_key_never_reaches_browser(hardened_server):
    """Requirement 3: Confirm the API key never reaches the browser (grep static assets & /api responses)."""
    async with httpx.AsyncClient(base_url=hardened_server, timeout=15.0) as client:
        # 1. HTML index page
        resp_index = await client.get("/")
        assert CANARY_KEY not in resp_index.text
        for h, v in resp_index.headers.items():
            assert CANARY_KEY not in h and CANARY_KEY not in v

        # 2. Static CSS
        resp_css = await client.get("/static/styles.css")
        assert CANARY_KEY not in resp_css.text

        # 3. Static JS
        resp_js = await client.get("/static/app.js")
        assert CANARY_KEY not in resp_js.text

        # 4. GET /api/devices response
        resp_devices = await client.get("/api/devices")
        assert CANARY_KEY not in resp_devices.text

        # 5. POST /api/chat responses for all 5 demo phrasings
        queries = [
            "how safe is my home",
            "what should I fix first",
            "tell me about my router",
            "how do I fix the camera",
            "export my home bill of materials",
        ]
        for q in queries:
            chat_resp = await client.post("/api/chat", json={"message": q})
            assert chat_resp.status_code == 200
            assert CANARY_KEY not in chat_resp.text
            for h, v in chat_resp.headers.items():
                assert CANARY_KEY not in h and CANARY_KEY not in v

        # 6. Verify filesystem static assets do not contain the key
        static_dir = REPO_ROOT / "server" / "static"
        for asset_file in static_dir.glob("*"):
            if asset_file.is_file():
                content = asset_file.read_text(encoding="utf-8")
                assert CANARY_KEY not in content
