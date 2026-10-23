"""tests/test_frontend_api.py - HTTP and End-to-End API tests for Phase 7 Single-Page Web App.

Validates:
- Static asset serving (GET /, GET /static/styles.css, GET /static/app.js)
- Device inventory endpoint (GET /api/devices) returning devices ranked by tier
- Real MCP client execution over Streamable HTTP (/api/chat)
- Tool routing & phrasing badges: 'routed by: bedrock | keywords', 'phrasing: bedrock | template'
- Five mandatory demo phrasings:
  1. "how safe is my home" -> scan_home
  2. "what should I fix first" -> scan_home
  3. "tell me about my router" -> explain_risk
  4. "how do I fix the camera" -> get_fix_steps (with 'replace' for EoL)
  5. "export my home bill of materials" -> export_hbom (CycloneDX 1.6 HBOM)
- Resilient 100% offline operation without AWS credentials.
"""

import asyncio
import socket
from pathlib import Path

import httpx
import pytest
import uvicorn
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonValidator

from server.main import app

REPO_ROOT = Path(__file__).resolve().parent.parent
TEST_API_KEY = "test-phase7-web-api-key"


def find_free_port() -> int:
    """Find a free TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
async def web_server(tmp_path, monkeypatch):
    """Launch the HomeBOM server with web UI and MCP client on an ephemeral port."""
    monkeypatch.setenv("HOMEBOM_API_KEY", TEST_API_KEY)
    test_user_devices = tmp_path / "user_devices.json"
    monkeypatch.setenv("HOMEBOM_USER_DEVICES_PATH", str(test_user_devices))

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
        if test_user_devices.exists():
            test_user_devices.unlink()


@pytest.mark.asyncio
async def test_static_assets_served(web_server):
    """Test that the single-page HTML and static assets load successfully."""
    async with httpx.AsyncClient(base_url=web_server, timeout=10.0) as client:
        # 1. HTML index
        resp = await client.get("/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers.get("content-type", "")
        html = resp.text
        assert "HomeBOM" in html
        assert 'id="mic-btn"' in html
        assert 'id="text-input"' in html
        assert 'id="transcript-container"' in html
        assert 'id="device-cards-grid"' in html
        assert 'id="chip-scan"' in html

        # 2. CSS
        css_resp = await client.get("/static/styles.css")
        assert css_resp.status_code == 200
        assert "text/css" in css_resp.headers.get("content-type", "")
        assert "--tier-fix-now" in css_resp.text

        # 3. JS
        js_resp = await client.get("/static/app.js")
        assert js_resp.status_code == 200
        assert "SpeechRecognition" in js_resp.text
        assert "speechSynthesis" in js_resp.text


@pytest.mark.asyncio
async def test_api_devices_ranked_by_tier(web_server):
    """Test GET /api/devices returns all 8 devices ranked with security attributes."""
    async with httpx.AsyncClient(base_url=web_server, timeout=10.0) as client:
        resp = await client.get("/api/devices")
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("status") == "success"
        assert data.get("total_devices") == 8
        assert "epss_as_of" in data

        devices = data.get("devices", [])
        assert len(devices) == 8

        # Ensure all tiers are represented correctly
        tiers = {d["tier"] for d in devices}
        assert "fix_now" in tiers
        assert "unknown" in tiers
        assert "not_affected" in tiers

        # Verify D-Link DCS-2530L (EoL camera)
        camera = next((d for d in devices if d["model"] == "DCS-2530L"), None)
        assert camera is not None
        assert camera["tier"] == "fix_now"
        assert camera["is_eol"] is True
        assert camera["vulnerabilities_count"] == 2


@pytest.mark.asyncio
async def test_demo_phrasing_1_how_safe_is_my_home(web_server):
    """Demo Phrasing 1: 'how safe is my home' -> scan_home tool."""
    async with httpx.AsyncClient(base_url=web_server, timeout=20.0) as client:
        resp = await client.post("/api/chat", json={"message": "how safe is my home"})
        assert resp.status_code == 200
        data = resp.json()

        assert data["query"] == "how safe is my home"
        assert data["tool_called"] == "scan_home"
        assert data["routed_by"] in ("bedrock", "keywords")
        assert data["phrasing_source"] in ("bedrock", "template")

        spoken = data.get("spoken", "")
        assert len(spoken) > 0
        assert "8 devices" in spoken or "scanned" in spoken
        assert "CVE-" not in spoken  # Never read CVE IDs
        assert " safe" not in spoken.lower() or "safe is my home" in spoken.lower()
        assert "safe." not in spoken.lower()  # Never claim safe


@pytest.mark.asyncio
async def test_demo_phrasing_2_what_should_i_fix_first(web_server):
    """Demo Phrasing 2: 'what should I fix first' -> scan_home tool prioritizing urgent fixes."""
    async with httpx.AsyncClient(base_url=web_server, timeout=20.0) as client:
        resp = await client.post("/api/chat", json={"message": "what should I fix first"})
        assert resp.status_code == 200
        data = resp.json()

        assert data["tool_called"] == "scan_home"
        assert data["routed_by"] in ("bedrock", "keywords")
        assert data["phrasing_source"] in ("bedrock", "template")
        assert len(data.get("spoken", "")) > 0


@pytest.mark.asyncio
async def test_demo_phrasing_3_tell_me_about_my_router(web_server):
    """Demo Phrasing 3: 'tell me about my router' -> explain_risk tool."""
    async with httpx.AsyncClient(base_url=web_server, timeout=20.0) as client:
        resp = await client.post("/api/chat", json={"message": "tell me about my router"})
        assert resp.status_code == 200
        data = resp.json()

        assert data["tool_called"] == "explain_risk"
        assert "device" in data["tool_args"]
        assert data["routed_by"] in ("bedrock", "keywords")
        assert data["phrasing_source"] in ("bedrock", "template")

        spoken = data.get("spoken", "")
        assert len(spoken) > 0
        assert "CVE-" not in spoken
        assert "Router" in spoken or "router" in spoken


@pytest.mark.asyncio
async def test_demo_phrasing_4_how_do_i_fix_the_camera(web_server):
    """Demo Phrasing 4: 'how do I fix the camera' -> get_fix_steps tool (EoL device says 'replace')."""
    async with httpx.AsyncClient(base_url=web_server, timeout=20.0) as client:
        resp = await client.post("/api/chat", json={"message": "how do I fix the camera"})
        assert resp.status_code == 200
        data = resp.json()

        assert data["tool_called"] == "get_fix_steps"
        assert "device" in data["tool_args"]
        assert data["routed_by"] in ("bedrock", "keywords")
        assert data["phrasing_source"] in ("bedrock", "template")

        spoken = data.get("spoken", "")
        # D-Link camera is EoL -> MUST include 'replace'
        assert "replace" in spoken.lower(), f"EoL camera fix steps must say replace: {spoken}"


@pytest.mark.asyncio
async def test_demo_phrasing_5_export_my_home_bill_of_materials(web_server):
    """Demo Phrasing 5: 'export my home bill of materials' -> export_hbom (CycloneDX 1.6 HBOM)."""
    import json

    async with httpx.AsyncClient(base_url=web_server, timeout=20.0) as client:
        resp = await client.post("/api/chat", json={"message": "export my home bill of materials"})
        assert resp.status_code == 200
        data = resp.json()

        assert data["tool_called"] == "export_hbom"
        assert data["routed_by"] in ("bedrock", "keywords")
        assert data["phrasing_source"] in ("bedrock", "template")

        spoken = data.get("spoken", "")
        assert "CycloneDX" in spoken or "Bill of Materials" in spoken or "Hardware" in spoken
        assert "CVE-" not in spoken

        # Validate CycloneDX 1.6 JSON
        bom = data.get("result", {}).get("bom")
        assert bom is not None
        assert bom["bomFormat"] == "CycloneDX"
        assert bom["specVersion"] == "1.6"
        assert len(bom["components"]) == 8
        assert len(bom["vulnerabilities"]) > 0

        # Validate against official CycloneDX schema
        validator = JsonValidator(SchemaVersion.V1_6)
        err = validator.validate_str(json.dumps(bom))
        assert err is None, f"Schema validation error: {err}"


@pytest.mark.asyncio
async def test_demo_phrasing_how_safe_is_my_router(web_server):
    """Bug fix verification: 'how safe is my router' -> explain_risk (not scan_home), explaining both routers."""
    async with httpx.AsyncClient(base_url=web_server, timeout=20.0) as client:
        resp = await client.post("/api/chat", json={"message": "how safe is my router"})
        assert resp.status_code == 200
        data = resp.json()

        assert data["tool_called"] == "explain_risk"
        assert data["tool_args"].get("device") == "router"
        assert data["routed_by"] in ("bedrock", "keywords")

        spoken = data.get("spoken", "")
        assert len(spoken) > 0
        assert "CVE-" not in spoken
        # Must explain both routers in one spoken answer
        assert "2 routers" in spoken or "two routers" in spoken or ("Living Room Router" in spoken and "Gaming Router" in spoken)
        # Gaming Router is discontinued / EoL -> must say replace
        assert "replace" in spoken.lower()
        # Living Room Router needs firmware update
        assert "update" in spoken.lower()


@pytest.mark.asyncio
async def test_demo_phrasing_is_my_camera_ok(web_server):
    """Category query verification: 'is my camera ok' -> explain_risk for camera (EoL says replace)."""
    async with httpx.AsyncClient(base_url=web_server, timeout=20.0) as client:
        resp = await client.post("/api/chat", json={"message": "is my camera ok"})
        assert resp.status_code == 200
        data = resp.json()

        assert data["tool_called"] == "explain_risk"
        assert data["tool_args"].get("device") == "camera"
        assert data["routed_by"] in ("bedrock", "keywords")

        spoken = data.get("spoken", "")
        assert len(spoken) > 0
        assert "CVE-" not in spoken
        # D-Link camera is EoL -> must say replace
        assert "replace" in spoken.lower()


@pytest.mark.asyncio
async def test_chat_empty_or_invalid_query_handling(web_server):
    """Test defensive error handling on invalid queries."""
    async with httpx.AsyncClient(base_url=web_server, timeout=10.0) as client:
        # Empty string
        resp = await client.post("/api/chat", json={"message": ""})
        assert resp.status_code == 400

        # Missing body
        resp = await client.post("/api/chat", content=b"invalid json")
        assert resp.status_code == 400

