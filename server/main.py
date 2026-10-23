"""server.main - HomeBOM Alexa+ FastMCP Streamable HTTP Server.

Exposes exactly six MCP tools:
1. list_devices
2. add_device
3. scan_home
4. explain_risk
5. get_fix_steps
6. export_hbom

Enforces:
- Streamable HTTP transport (stateless_http=True, json_response=True)
- Protocol version 2025-11-25
- Bearer / API key authentication via AuthMiddleware (hmac.compare_digest)
- Fail closed if HOMEBOM_API_KEY is unset unless HOMEBOM_DEV_NOAUTH=1
- Read-only seeded devices, atomic writes for user devices
- Dynamic CPE resolution (never invent CPEs)
- Plain-language voice outputs (max 3 sentences, no CVE IDs, "as of <date>", "replace" for EoL)
"""

import os
import sys
from pathlib import Path
from typing import Any

# Ensure repo root and homebom-core are in sys.path so direct execution succeeds
REPO_ROOT = Path(__file__).resolve().parent.parent
CORE_DIR = REPO_ROOT / "packages" / "homebom-core"
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from homebom_core.hbom import generate_cyclonedx_hbom, generate_hbom_spoken_summary
from mcp.server.fastmcp import FastMCP

from server.auth import AuthMiddleware, get_configured_api_key
from server.bedrock import (
    generate_spoken_device_phrasing,
    generate_spoken_scan_phrasing,
    resolve_cpe_with_bedrock,
)
from server.engine import evaluate_single_device, scan_all_devices
from server.storage import (
    find_all_devices_by_query,
    find_device_by_query,
    get_all_devices,
    get_epss_metadata,
    is_public_demo_mode,
    load_user_devices,
    save_user_devices,
)


def create_mcp_server() -> FastMCP:
    """Factory to create a FastMCP server instance and register all six tools."""
    server = FastMCP(
        "HomeBOM",
        instructions=(
            "HomeBOM is a smart-home security assistant that monitors device firmware against "
            "real-world vulnerability feeds (CISA KEV, FIRST EPSS, NVD 2.0) and CycloneDX 1.6 HBOM standards."
        ),
        stateless_http=True,
        json_response=True,
        streamable_http_path="/mcp",
    )

    # ------------------------------------------------------------------------
    # Tool 1: list_devices
    # ------------------------------------------------------------------------
    @server.tool()
    def list_devices() -> dict[str, Any]:
        """Retrieve the inventory of all smart-home devices currently registered in the home.

        When to use:
          Use when the user asks what devices are connected, asks to see their smart-home inventory,
          or wants to check which gadgets are being monitored by HomeBOM.

        When NOT to use:
          Do NOT use when the user asks about security status, safety risks, or for vulnerability scanning
          (use scan_home instead), or when asking how to fix a specific device (use get_fix_steps).

        Example user phrasings:
          - 'Alexa, what devices do I have?'
          - 'Show me my smart home inventory.'
          - 'Which devices are connected to HomeBOM?'
        """
        devices = get_all_devices()
        total = len(devices)

        if total == 0:
            spoken = "You currently have no devices registered in your home inventory."
        elif total == 1:
            spoken = f"You have 1 device registered: {devices[0]['name']}."
        else:
            sample_names = [d["name"] for d in devices[:3]]
            sample_str = ", ".join(sample_names)
            spoken = (
                f"You have {total} devices in your home inventory, including {sample_str}. "
                f"You can ask me 'how safe is my home' to run a security scan."
            )

        return {
            "total_devices": total,
            "devices": devices,
            "spoken": spoken,
            "phrasing_source": "template",
        }

    # ------------------------------------------------------------------------
    # Tool 2: add_device
    # ------------------------------------------------------------------------
    @server.tool()
    def add_device(name: str, model: str, firmware: str | None = None) -> dict[str, Any]:
        """Register a new smart-home device into the inventory by matching its model against verified firmware CPE definitions.

        When to use:
          Use when the user wants to add, register, or connect a new device with its brand/model and firmware version.

        When NOT to use:
          Do NOT use if the user is asking to inspect, scan, or explain an existing device (use scan_home or explain_risk).

        Example user phrasings:
          - 'Alexa, add my TP-Link router running firmware 1.1.2.'
          - 'Register a new smart plug in the living room.'
          - 'Add my D-Link security camera model DCS-2530L.'
        """
        clean_name = name.strip() if name else "Device"
        clean_model = model.strip() if model else ""

        if is_public_demo_mode():
            return {
                "status": "disabled",
                "question": "Adding devices is disabled in public demo mode.",
                "spoken": "Device registration is disabled in public demo mode.",
                "phrasing_source": "template",
            }

        # Condition 2: add_device must never default firmware.
        if firmware is None or not firmware.strip():
            return {
                "status": "clarification_needed",
                "question": f"What firmware version is {clean_name} running? Please provide the version number from device settings or the companion app.",
                "spoken": f"What firmware version is {clean_name} running? Please tell me the version number so I can check it for vulnerabilities.",
                "phrasing_source": "template",
            }

        clean_firmware = firmware.strip()

        # Resolve against pre-indexed candidates using Bedrock (with deterministic fallback)
        best_candidate, clarification_q, phrasing_source = resolve_cpe_with_bedrock(
            clean_model,
            clean_name,
        )

        if best_candidate is None:
            return {
                "status": "clarification_needed",
                "question": clarification_q,
                "spoken": clarification_q,
                "phrasing_source": phrasing_source,
            }

        # Match confirmed -> Persist atomically to user_devices.json
        user_devices = load_user_devices()
        new_id = f"dev-user-{len(user_devices) + 1:03d}"
        new_device = {
            "id": new_id,
            "name": clean_name,
            "vendor": best_candidate["vendor"],
            "model": best_candidate["product"],
            "category": best_candidate.get("category", "iot"),
            "firmware": clean_firmware,
            "cpe": best_candidate["cpe"],
        }
        user_devices.append(new_device)
        save_user_devices(user_devices)

        spoken = (
            f"Added {clean_name} ({best_candidate['product']}) with firmware {clean_firmware} "
            f"to your home inventory."
        )
        return {
            "status": "added",
            "device": new_device,
            "spoken": spoken,
            "phrasing_source": phrasing_source,
        }

    # ------------------------------------------------------------------------
    # Tool 3: scan_home
    # ------------------------------------------------------------------------
    @server.tool()
    def scan_home() -> dict[str, Any]:
        """Perform a full home security scan across all registered devices, evaluating firmware against CISA KEV, FIRST EPSS, and NVD 2.0 vulnerability data.

        When to use:
          Use when the user asks 'how safe is my home?', asks for a security audit,
          asks if any devices are vulnerable or hacked, or wants an overall threat assessment.

        When NOT to use:
          Do NOT use when the user only asks to list devices without assessing security (use list_devices),
          or when asking specifically about how to fix a single device (use get_fix_steps).

        Example user phrasings:
          - 'Alexa, how safe is my home?'
          - 'Scan my devices for security issues.'
          - 'Are any of my smart home gadgets vulnerable?'
        """
        devices = get_all_devices()
        profiles = scan_all_devices(devices)
        epss_meta = get_epss_metadata()
        as_of_str = epss_meta.get("as_of_string", "as of 2026-10-21")

        fix_now_count = sum(1 for p in profiles if p.tier == "fix_now")
        fix_soon_count = sum(1 for p in profiles if p.tier == "fix_soon")
        low_count = sum(1 for p in profiles if p.tier == "low")
        unknown_count = sum(1 for p in profiles if p.tier == "unknown")
        not_affected_count = sum(1 for p in profiles if p.tier == "not_affected")
        eol_count = sum(1 for p in profiles if p.is_eol)

        # Voice phrasing: plain language, max 3 sentences, zero CVE IDs, says "replace" for EoL
        # Rule 4: use 'actively exploited' for KEV, and 'critical' only if CVSS >= 9.0
        if fix_now_count > 0:
            if eol_count > 0:
                template_spoken = (
                    f"I scanned {len(profiles)} devices {as_of_str}. "
                    f"{fix_now_count} devices have actively exploited vulnerabilities needing immediate attention, "
                    f"including {eol_count} discontinued models that must be replaced. "
                    f"The remaining devices have no known vulnerabilities or need version verification."
                )
            else:
                template_spoken = (
                    f"I scanned {len(profiles)} devices {as_of_str}. "
                    f"{fix_now_count} devices have actively exploited vulnerabilities that need immediate firmware updates. "
                    f"The other devices currently have no known vulnerabilities in public databases."
                )
        elif fix_soon_count > 0:
            template_spoken = (
                f"I scanned {len(profiles)} devices {as_of_str}. "
                f"{fix_soon_count} devices have high-risk vulnerabilities that should be patched soon. "
                f"The remaining devices have no known vulnerabilities in public databases."
            )
        elif unknown_count > 0:
            template_spoken = (
                f"I scanned {len(profiles)} devices {as_of_str}. "
                f"No urgent vulnerabilities were found, though {unknown_count} devices could not be verified against known databases. "
                f"The rest have no known vulnerabilities in public databases."
            )
        else:
            template_spoken = (
                f"I scanned {len(profiles)} devices {as_of_str}. "
                f"All devices currently have no known vulnerabilities in public databases."
            )

        max_cvss = max((p.max_cvss for p in profiles), default=0.0)
        has_eol = eol_count > 0
        scan_summary_input = {
            "total_devices": len(profiles),
            "fix_now": fix_now_count,
            "fix_soon": fix_soon_count,
            "low": low_count,
            "unknown": unknown_count,
            "not_affected": not_affected_count,
            "eol_devices": eol_count,
            "as_of": as_of_str,
        }

        spoken, phrasing_source = generate_spoken_scan_phrasing(
            scan_summary=scan_summary_input,
            max_cvss=max_cvss,
            is_eol=has_eol,
            template_fallback=template_spoken,
        )

        device_summaries = []
        for p in profiles:
            device_summaries.append(
                {
                    "id": p.device_id,
                    "name": p.device_name,
                    "model": p.model,
                    "firmware": p.firmware,
                    "tier": p.tier,
                    "overall_status": p.overall_status,
                    "is_eol": p.is_eol,
                    "max_epss": round(p.max_epss, 4),
                    "max_cvss": round(p.max_cvss, 1),
                    "vulnerabilities_count": p.vulnerabilities_count,
                    "unverified_candidates": p.unverified_candidates,
                    "spoken_summary": p.spoken_summary,
                    "fix_steps": p.fix_steps,
                }
            )

        return {
            "epss_as_of": as_of_str,
            "summary": {
                "total_devices": len(profiles),
                "fix_now": fix_now_count,
                "fix_soon": fix_soon_count,
                "low": low_count,
                "unknown": unknown_count,
                "not_affected": not_affected_count,
                "eol_devices": eol_count,
            },
            "devices": device_summaries,
            "spoken": spoken,
            "phrasing_source": phrasing_source,
        }

    # ------------------------------------------------------------------------
    # Tool 4: explain_risk
    # ------------------------------------------------------------------------
    @server.tool()
    def explain_risk(device: str) -> dict[str, Any]:
        """Provide a plain-language explanation of security risks and vulnerabilities for a specific smart-home device.

        When to use:
          Use when the user asks why a specific device is risky, asks what's wrong with their camera or router,
          or wants details on a specific device's safety.

        When NOT to use:
          Do NOT use for whole-home scans across all devices (use scan_home),
          or when the user is asking for remediation steps on how to resolve the risk (use get_fix_steps).

        Example user phrasings:
          - 'Alexa, why is my router unsafe?'
          - 'Explain the risk on my security camera.'
          - 'Is my Ring doorbell safe?'
        """
        matching_devices = find_all_devices_by_query(device)
        if not matching_devices:
            return {
                "error": "device_not_found",
                "device_query": device,
                "spoken": f"I couldn't find a device matching '{device}' in your home inventory.",
                "phrasing_source": "template",
            }

        if len(matching_devices) == 1:
            dev = matching_devices[0]
            profile = evaluate_single_device(dev)
            device_summary_input = {
                "device_name": profile.device_name,
                "model": profile.model,
                "firmware": profile.firmware,
                "tier": profile.tier,
                "overall_status": profile.overall_status,
                "is_eol": profile.is_eol,
                "max_cvss": round(profile.max_cvss, 1),
                "max_epss": round(profile.max_epss, 4),
                "vulnerabilities_count": profile.vulnerabilities_count,
                "unverified_candidates": profile.unverified_candidates,
            }
            spoken, phrasing_source = generate_spoken_device_phrasing(
                device_summary=device_summary_input,
                max_cvss=profile.max_cvss,
                is_eol=profile.is_eol,
                template_fallback=profile.spoken_summary,
            )

            return {
                "device_id": profile.device_id,
                "device_name": profile.device_name,
                "model": profile.model,
                "firmware": profile.firmware,
                "cpe": profile.cpe,
                "tier": profile.tier,
                "overall_status": profile.overall_status,
                "is_eol": profile.is_eol,
                "max_cvss": round(profile.max_cvss, 1),
                "max_epss": round(profile.max_epss, 4),
                "vulnerabilities_count": profile.vulnerabilities_count,
                "unverified_candidates": profile.unverified_candidates,
                "spoken": spoken,
                "phrasing_source": phrasing_source,
            }

        # Multiple matching devices (e.g. two routers in inventory)
        profiles = [evaluate_single_device(d) for d in matching_devices]
        device_explanations = []
        for p in profiles:
            if p.tier == "fix_now":
                if p.is_eol:
                    device_explanations.append(
                        f"the {p.device_name} has actively exploited vulnerabilities and is discontinued so it should be replaced"
                    )
                else:
                    device_explanations.append(
                        f"the {p.device_name} has an actively exploited vulnerability needing an immediate firmware update"
                    )
            elif p.tier == "fix_soon":
                device_explanations.append(
                    f"the {p.device_name} has high-risk vulnerabilities that should be patched soon"
                )
            elif p.tier == "unknown":
                device_explanations.append(
                    f"the {p.device_name} could not be verified against known databases"
                )
            else:
                device_explanations.append(
                    f"the {p.device_name} currently has no known vulnerabilities in public databases"
                )

        spoken = (
            f"You have {len(profiles)} {device}s in your home. "
            f"Specifically, {'; '.join(device_explanations)}."
        )

        return {
            "device_query": device,
            "count": len(profiles),
            "devices": [
                {
                    "device_id": p.device_id,
                    "device_name": p.device_name,
                    "model": p.model,
                    "firmware": p.firmware,
                    "cpe": p.cpe,
                    "tier": p.tier,
                    "overall_status": p.overall_status,
                    "is_eol": p.is_eol,
                    "max_cvss": round(p.max_cvss, 1),
                    "max_epss": round(p.max_epss, 4),
                    "vulnerabilities_count": p.vulnerabilities_count,
                    "unverified_candidates": p.unverified_candidates,
                }
                for p in profiles
            ],
            "spoken": spoken,
            "phrasing_source": "template",
        }

    # ------------------------------------------------------------------------
    # Tool 5: get_fix_steps
    # ------------------------------------------------------------------------
    @server.tool()
    def get_fix_steps(device: str) -> dict[str, Any]:
        """Provide concise, actionable remediation instructions for a specific device.

        When to use:
          Use when the user asks how to fix a device, how to patch an issue,
          or what they should do about a vulnerable gadget.

        When NOT to use:
          Do NOT use when the user is asking why the device is vulnerable (use explain_risk),
          or when asking for a full security scan (use scan_home).

        Example user phrasings:
          - 'Alexa, how do I fix my router?'
          - 'What should I do about the vulnerable camera?'
          - 'How can I update my smart plug?'
        """
        dev = find_device_by_query(device)
        if not dev:
            return {
                "error": "device_not_found",
                "device_query": device,
                "spoken": f"I couldn't find a device matching '{device}' in your home inventory.",
                "phrasing_source": "template",
            }

        profile = evaluate_single_device(dev)

        if profile.is_eol:
            action = "replace"
        elif profile.tier in ("fix_now", "fix_soon", "low"):
            action = "update"
        elif profile.tier == "unknown":
            action = "check"
        else:
            action = "none"

        return {
            "device_id": profile.device_id,
            "device_name": profile.device_name,
            "action": action,
            "is_eol": profile.is_eol,
            "fix_steps": profile.fix_steps,
            "spoken": profile.fix_steps,
            "phrasing_source": "template",
        }

    # ------------------------------------------------------------------------
    # Tool 6: export_hbom
    # ------------------------------------------------------------------------
    @server.tool()
    def export_hbom() -> dict[str, Any]:
        """Export a CycloneDX 1.6 Hardware Bill of Materials (HBOM) with embedded VEX records for all home devices.

        When to use:
          Use when the user or an auditor requests a CycloneDX BOM, an HBOM export,
          a software/hardware inventory report, or VEX security attestation.

        When NOT to use:
          Do NOT use for voice answers about home safety (use scan_home),
          or for simple device listings (use list_devices).

        Example user phrasings:
          - 'Alexa, export my home hardware bill of materials.'
          - 'Generate a CycloneDX HBOM for my home devices.'
          - 'Download my smart home VEX report.'
        """
        devices = get_all_devices()
        profiles = scan_all_devices(devices)
        bom = generate_cyclonedx_hbom(profiles)
        spoken = generate_hbom_spoken_summary(profiles, bom)
        return {
            "status": "success",
            "bom_format": "CycloneDX",
            "spec_version": "1.6",
            "bom": bom,
            "spoken": spoken,
            "phrasing_source": "template",
        }

    return server


# ============================================================================
# ASGI App Construction with Fail-Closed Authentication & Web UI
# ============================================================================
from starlette.applications import Starlette
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from server.web import STATIC_DIR, chat_endpoint, devices_endpoint, home_page


def create_app() -> AuthMiddleware:
    """Create ASGI application with web interface and MCP Streamable HTTP transport."""
    api_key, dev_noauth = get_configured_api_key()
    server = create_mcp_server()
    mcp_app = server.streamable_http_app()

    routes = [
        Route("/", home_page, methods=["GET"]),
        Route("/api/chat", chat_endpoint, methods=["POST"]),
        Route("/api/devices", devices_endpoint, methods=["GET"]),
        Mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static"),
        Mount("", app=mcp_app),
    ]

    starlette_app = Starlette(
        routes=routes,
        lifespan=mcp_app.router.lifespan_context,
    )
    return AuthMiddleware(starlette_app, api_key=api_key, dev_noauth=dev_noauth)


class LazyApp:
    """Lazy ASGI app wrapper that evaluates auth config on invocation or startup."""

    def __init__(self) -> None:
        self._app: AuthMiddleware | None = None

    def get_inner(self) -> AuthMiddleware:
        if self._app is None:
            self._app = create_app()
        return self._app

    def reset(self) -> None:
        self._app = None

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            # Use fresh app instance for every server lifecycle to prevent closed session manager re-use
            app = create_app()
            self._app = app
            await app(scope, receive, send)
            return

        app = self.get_inner()
        await app(scope, receive, send)


app = LazyApp()

if __name__ == "__main__":
    import uvicorn

    # Enforce auth configuration check before launching
    get_configured_api_key()

    port = int(os.environ.get("PORT", "8000"))
    host = os.environ.get("HOST", "127.0.0.1")
    print(f"Starting HomeBOM MCP Server on http://{host}:{port}/mcp (Streamable HTTP)")
    uvicorn.run("server.main:app", host=host, port=port, log_level="info")
