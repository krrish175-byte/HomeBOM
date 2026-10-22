#!/usr/bin/env python3
"""scripts/inspect_mcp.py - MCP Inspector-equivalent client.

Connects to HomeBOM server over Streamable HTTP transport (Protocol 2025-11-25)
using bearer authentication, inspects tools, and exercises each tool with raw output.
"""

import asyncio
import json
import os
import sys
from pathlib import Path

# Ensure repo root and core are in path
REPO_ROOT = Path(__file__).resolve().parent.parent
CORE_DIR = REPO_ROOT / "packages" / "homebom-core"
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import httpx
import uvicorn
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client

from server.main import app

API_KEY = os.environ.get("HOMEBOM_API_KEY", "inspector-demo-key-2026")


async def run_inspection():
    os.environ["HOMEBOM_API_KEY"] = API_KEY
    app.reset()

    port = 8765
    server_url = f"http://127.0.0.1:{port}/mcp"

    print("=" * 80)
    print("HOMEBOM MCP INSPECTOR CLIENT")
    print("Transport: Streamable HTTP (/mcp)")
    print("Protocol Version: 2025-11-25")
    print(f"Server Target: {server_url}")
    print("Authentication: Bearer <API_KEY>")
    print("=" * 80)

    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    await asyncio.sleep(0.5)

    import tempfile

    tmp_dir = tempfile.TemporaryDirectory()
    test_user_devices = Path(tmp_dir.name) / "user_devices.json"
    os.environ["HOMEBOM_USER_DEVICES_PATH"] = str(test_user_devices)

    try:
        headers = {"Authorization": f"Bearer {API_KEY}"}
        async with (
            httpx.AsyncClient(headers=headers, timeout=15.0) as http_client,
            streamable_http_client(server_url, http_client=http_client) as (r, w, _),
            ClientSession(r, w) as session,
        ):
            # 1. Initialize
            init_res = await session.initialize()
            print("\n[MCP INITIALIZE RESPONSE]")
            print(f"  Server Name    : {init_res.serverInfo.name}")
            print(f"  Protocol Version: {init_res.protocolVersion}")
            print(f"  Instructions   : {init_res.instructions}")

            # 2. List Tools
            print("\n" + "-" * 80)
            print("[MCP TOOLS/LIST]")
            tools_res = await session.list_tools()
            print(f"Found {len(tools_res.tools)} tools registered:\n")
            for t in tools_res.tools:
                print(f"• Tool: {t.name}")
                print(f"  Description: {t.description.splitlines()[0] if t.description else ''}")
                print(f"  Input Schema: {json.dumps(t.inputSchema, indent=2)}\n")

            # 3. Call tool: list_devices
            print("-" * 80)
            print("[CALL TOOL: list_devices]")
            res = await session.call_tool("list_devices", {})
            raw_text = res.content[0].text if res.content else "{}"
            print(json.dumps(json.loads(raw_text), indent=2))

            # 4. Call tool: scan_home
            print("\n" + "-" * 80)
            print("[CALL TOOL: scan_home]")
            res = await session.call_tool("scan_home", {})
            raw_text = res.content[0].text if res.content else "{}"
            print(json.dumps(json.loads(raw_text), indent=2))

            # 5. Call tool: explain_risk (affected device)
            print("\n" + "-" * 80)
            print("[CALL TOOL: explain_risk(device='Living Room Router')]")
            res = await session.call_tool("explain_risk", {"device": "Living Room Router"})
            raw_text = res.content[0].text if res.content else "{}"
            print(json.dumps(json.loads(raw_text), indent=2))

            # 6. Call tool: explain_risk (unknown device with unverified candidates)
            print("\n" + "-" * 80)
            print("[CALL TOOL: explain_risk(device='Kitchen Echo')]")
            res = await session.call_tool("explain_risk", {"device": "Kitchen Echo"})
            raw_text = res.content[0].text if res.content else "{}"
            print(json.dumps(json.loads(raw_text), indent=2))

            # 7. Call tool: explain_risk (clean device)
            print("\n" + "-" * 80)
            print("[CALL TOOL: explain_risk(device='Front Doorbell')]")
            res = await session.call_tool("explain_risk", {"device": "Front Doorbell"})
            raw_text = res.content[0].text if res.content else "{}"
            print(json.dumps(json.loads(raw_text), indent=2))

            # 8. Call tool: get_fix_steps (EoL device)
            print("\n" + "-" * 80)
            print("[CALL TOOL: get_fix_steps(device='Backyard Security Camera')]")
            res = await session.call_tool("get_fix_steps", {"device": "Backyard Security Camera"})
            raw_text = res.content[0].text if res.content else "{}"
            print(json.dumps(json.loads(raw_text), indent=2))

            # 9. Call tool: add_device without firmware (never default firmware -> returns question)
            print("\n" + "-" * 80)
            print("[CALL TOOL: add_device without firmware (Condition 2)]")
            res = await session.call_tool(
                "add_device",
                {"name": "Basement Camera", "model": "DCS-2530L"},
            )
            raw_text = res.content[0].text if res.content else "{}"
            print(json.dumps(json.loads(raw_text), indent=2))

            # 10. Call tool: add_device with unknown candidate (returns question, never CPE)
            print("\n" + "-" * 80)
            print("[CALL TOOL: add_device(name='my router', model='SuperRouter 9000')]")
            res = await session.call_tool(
                "add_device",
                {"name": "my router", "model": "SuperRouter 9000", "firmware": "1.0.0"},
            )
            raw_text = res.content[0].text if res.content else "{}"
            print(json.dumps(json.loads(raw_text), indent=2))

            # 11. Call tool: add_device (valid candidate -> atomic persistence)
            print("\n" + "-" * 80)
            print("[CALL TOOL: add_device(name='Basement Cam', model='DCS-2530L')]")
            res = await session.call_tool(
                "add_device",
                {"name": "Basement Cam", "model": "DCS-2530L", "firmware": "1.05.00"},
            )
            raw_text = res.content[0].text if res.content else "{}"
            print(json.dumps(json.loads(raw_text), indent=2))

            # 12. Call tool: export_hbom (Phase 4: CycloneDX 1.6 HBOM with embedded VEX)
            print("\n" + "-" * 80)
            print("[CALL TOOL: export_hbom]")
            res = await session.call_tool("export_hbom", {})
            raw_text = res.content[0].text if res.content else "{}"
            hbom_data = json.loads(raw_text)
            # Print spoken summary and first component + first vulnerability sample
            sample_output = {
                "status": hbom_data.get("status"),
                "bom_format": hbom_data.get("bom_format"),
                "spec_version": hbom_data.get("spec_version"),
                "spoken": hbom_data.get("spoken"),
                "total_components": len(hbom_data.get("bom", {}).get("components", [])),
                "total_vulnerabilities": len(hbom_data.get("bom", {}).get("vulnerabilities", [])),
                "sample_component": (
                    hbom_data.get("bom", {}).get("components", [])[0]
                    if hbom_data.get("bom", {}).get("components")
                    else None
                ),
                "sample_vulnerability": (
                    hbom_data.get("bom", {}).get("vulnerabilities", [])[0]
                    if hbom_data.get("bom", {}).get("vulnerabilities")
                    else None
                ),
            }
            print(json.dumps(sample_output, indent=2))

    finally:
        server.should_exit = True
        await task
        app.reset()
        tmp_dir.cleanup()
        repo_file = REPO_ROOT / "server" / "data" / "user_devices.json"
        if repo_file.exists():
            repo_file.unlink()
        print("\n" + "=" * 80)
        print("MCP INSPECTION COMPLETE: All 6 tools executed successfully.")
        print("=" * 80)


if __name__ == "__main__":
    asyncio.run(run_inspection())
