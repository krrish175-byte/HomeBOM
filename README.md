# HomeBOM

> **"Alexa, how safe is my home?"**  
> An Alexa+ Model Context Protocol (MCP) server and vulnerability intelligence engine for smart-home devices. Matches device firmware against real-world vulnerability feeds (CISA KEV, FIRST EPSS, NVD 2.0), delivers voice-optimized spoken summaries, and exports CycloneDX 1.6 Hardware BOMs (HBOM) with embedded VEX.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![MCP Spec: 2025-11-25+](https://img.shields.io/badge/MCP%20Spec-2025--11--25+-brightgreen.svg)](https://modelcontextprotocol.io/)
[![CycloneDX 1.6](https://img.shields.io/badge/CycloneDX-1.6%20HBOM%20%2B%20VEX-orange.svg)](https://cyclonedx.org/)

---

## 1. What It Is

HomeBOM bridges consumer smart-home security and enterprise-grade software supply chain security. When a homeowner asks *"Alexa, how safe is my home?"*, HomeBOM:
1. **Scans device inventory**: Audits firmware across home routers, extenders, security cameras, smart speakers, doorbells, and plugs.
2. **Matches real ground-truth vulnerabilities**: Evaluates firmware version strings against official NVD 2.0 match criteria, CISA Known Exploited Vulnerabilities (KEV), and FIRST EPSS exploit probabilities.
3. **Speaks plain-language advice**: Generates concise spoken answers (max 3 sentences) that never read raw CVE IDs aloud, never call devices "safe", prioritize actively exploited threats, and instruct owners to replace end-of-life (EoL) hardware.
4. **Exports CycloneDX 1.6 Hardware BOM (HBOM)**: Generates an official CycloneDX 1.6 JSON document linking devices to firmware components and embedded Vulnerability Exploitability eXchange (VEX) records.

---

## 2. Architecture

```text
       +-------------------------------------------------------------------+
       |                     Simulated Voice Web UI                        |
       |  (Microphone Web Speech API, Text Box Fallback, SpeechSynthesis)  |
       +-------------------------------------------------------------------+
                                         |
                                         | POST /api/chat (JSON)
                                         v
       +-------------------------------------------------------------------+
       |                      HomeBOM Web Gateway                          |
       |  - Real MCP Client over Streamable HTTP (session.call_tool)       |
       |  - Per-IP rate limiting (10 req/min) & 300 char query cap         |
       |  - Public demo mode filter (HOMEBOM_PUBLIC_DEMO=1)                |
       +-------------------------------------------------------------------+
                     |                                         |
                     | Intent Routing                          | Streamable HTTP (/mcp)
                     v                                         | Bearer Auth
       +----------------------------+                          v
       |       Tool Router          |        +-----------------------------------+
       |  - Bedrock Converse API    |        |        HomeBOM MCP Server         |
       |  - Deterministic Keywords  |        |      (FastMCP, 6 Core Tools)      |
       |  - Hourly Budget Guard     |        +-----------------------------------+
       +----------------------------+                          |
                                                               v
                                             +-----------------------------------+
                                             |       homebom-core Library        |
                                             |  - Pure Python (Zero MCP, No AWS) |
                                             |  - CPE 2.3 & Version Comparator   |
                                             |  - 4-Tier Risk Ranker             |
                                             |  - CycloneDX 1.6 HBOM + VEX       |
                                             +-----------------------------------+
                                                               |
                                                               v
                                             +-----------------------------------+
                                             |      Ground Truth Feed Cache      |
                                             |  - CISA KEV (as of 2026-10-21)    |
                                             |  - FIRST EPSS (as of 2026-10-21)  |
                                             |  - NVD 2.0 CVE/CPE Records        |
                                             +-----------------------------------+
```

---

## 3. Ground Truth Vulnerability Data

HomeBOM strictly enforces a **no-hallucination policy**. Every finding, score, and state decision traces directly to official security feeds cached in `server/data/`:

| Feed | Source | Snapshot Date | Purpose |
| :--- | :--- | :--- | :--- |
| **CISA KEV** | Cybersecurity & Infrastructure Security Agency | **as of 2026-10-21** | Identifies actively exploited vulnerabilities in the wild (`tier: fix_now`). |
| **FIRST EPSS** | Forum of Incident Response and Security Teams | **as of 2026-10-21** | Provides daily empirical exploit probability scores (0.0 to 1.0). |
| **NVD 2.0** | National Institute of Standards and Technology | **as of 2026-10-21** | Official CVE descriptions, CVSS v3.1 base scores/vectors, and CPE configurations. |

### Sample Home Inventory (8 Devices)
The inventory in `server/data/devices.json` represents a typical smart home, audited against real CVE records:

1. **Living Room Router** (`dev-001`, TP-Link Archer AX21, firmware `1.1.2 Build 20220624`): Vulnerable to `CVE-2023-1389` (CISA KEV, command injection, CVSS 8.8, EPSS 0.99999). Evaluated as **`fix_now`**.
2. **Backyard Security Camera** (`dev-002`, D-Link DCS-2530L, firmware `1.05.00`): Vulnerable to `CVE-2020-25078` and `CVE-2020-25079` (CISA KEV, password disclosure, CVSS 8.8, EPSS 0.97511). Hardware is discontinued/EoL. Evaluated as **`fix_now` (EoL: Replace)**.
3. **Wi-Fi Range Extender** (`dev-003`, TP-Link TL-WA855RE, firmware `1.0.0 Build 200508`): Vulnerable to `CVE-2020-24363` (CISA KEV, factory reset bypass, CVSS 8.8, EPSS 0.22187). Discontinued. Evaluated as **`fix_now` (EoL: Replace)**.
4. **Gaming Router** (`dev-004`, ASUS ROG GT-AC2900, firmware `3.0.0.4.386.41700`): Vulnerable to `CVE-2021-32030` (CISA KEV, command execution, CVSS 9.8 Critical, EPSS 0.99393). Discontinued. Evaluated as **`fix_now` (Critical, EoL: Replace)**.
5. **Kitchen Echo** (`dev-005`, Amazon Echo Dot 5th Gen, firmware `Amazon FireOS 7.5.8.2`): Semver string cannot be compared against NVD date-based CPE bounds. Defensive Rule 3 evaluates as **`unknown`** with 3 unverified candidates in triage.
6. **Front Doorbell** (`dev-006`, Amazon / Ring Video Doorbell Pro, firmware `3.4.7`): Exact CPE exists in NVD with zero known vulnerabilities. Evaluated as **`not_affected`**.
7. **Living Room TV Stick** (`dev-007`, Amazon Fire TV Stick 4K, firmware `FireOS 7.6.6.9`): Exact CPE exists in NVD with zero known vulnerabilities. Evaluated as **`not_affected`**.
8. **Porch Smart Plug** (`dev-008`, Generic IoT Wi-Fi Smart Plug, firmware `CUSTOM-BETA-REV-???`): Unparseable firmware format. Defensive Rule 3 evaluates as **`unknown`**.

---

## 4. How Hackathon Requirements Are Met

| Requirement | Implementation Details | Primary Source Files | Verification Tests |
| :--- | :--- | :--- | :--- |
| **1. Streamable HTTP MCP Server** | FastMCP server running Protocol 2025-11-25 over Streamable HTTP at `/mcp` with Bearer auth. | [`server/main.py`](file:///Users/krrishbiswas/Desktop/HomeBOM/server/main.py)<br>[`server/auth.py`](file:///Users/krrishbiswas/Desktop/HomeBOM/server/auth.py) | [`tests/test_mcp_protocol.py`](file:///Users/krrishbiswas/Desktop/HomeBOM/tests/test_mcp_protocol.py) |
| **2. Six Core MCP Tools** | `list_devices`, `add_device`, `scan_home`, `explain_risk`, `get_fix_steps`, `export_hbom`. | [`server/main.py`](file:///Users/krrishbiswas/Desktop/HomeBOM/server/main.py) | [`tests/test_mcp_protocol.py`](file:///Users/krrishbiswas/Desktop/HomeBOM/tests/test_mcp_protocol.py) |
| **3. Ground Truth Matching & Priority Ranking** | Firmware-only CPE matching (`cpe:2.3:o`), version bounds parsing, 4-tier risk prioritization based on CISA KEV and EPSS. | [`packages/homebom-core/homebom_core/match.py`](file:///Users/krrishbiswas/Desktop/HomeBOM/packages/homebom-core/homebom_core/match.py)<br>[`packages/homebom-core/homebom_core/rank.py`](file:///Users/krrishbiswas/Desktop/HomeBOM/packages/homebom-core/homebom_core/rank.py) | [`tests/test_golden_truth.py`](file:///Users/krrishbiswas/Desktop/HomeBOM/tests/test_golden_truth.py)<br>[`packages/homebom-core/tests/test_match_rank.py`](file:///Users/krrishbiswas/Desktop/HomeBOM/packages/homebom-core/tests/test_match_rank.py) |
| **4. Voice Phrasing & Spoken Text Rules** | Max 3 sentences, no CVE IDs spoken, never say "safe", replace for EoL, "actively exploited" for KEV, "critical" only if CVSS >= 9.0. | [`packages/homebom-core/homebom_core/rank.py`](file:///Users/krrishbiswas/Desktop/HomeBOM/packages/homebom-core/homebom_core/rank.py)<br>[`server/bedrock.py`](file:///Users/krrishbiswas/Desktop/HomeBOM/server/bedrock.py) | [`tests/test_bedrock.py`](file:///Users/krrishbiswas/Desktop/HomeBOM/tests/test_bedrock.py) |
| **5. CycloneDX 1.6 HBOM with Embedded VEX** | Full schema-valid CycloneDX 1.6 HBOM linking devices to firmware components, VEX states (`exploitable`, `in_triage`), ratings, and EoL properties. | [`packages/homebom-core/homebom_core/hbom.py`](file:///Users/krrishbiswas/Desktop/HomeBOM/packages/homebom-core/homebom_core/hbom.py) | [`packages/homebom-core/tests/test_hbom.py`](file:///Users/krrishbiswas/Desktop/HomeBOM/packages/homebom-core/tests/test_hbom.py) |
| **6. Pure Open Source Core Library** | Standalone MIT library with zero MCP and zero AWS imports. | [`packages/homebom-core/`](file:///Users/krrishbiswas/Desktop/HomeBOM/packages/homebom-core/) | [`packages/homebom-core/tests/test_imports.py`](file:///Users/krrishbiswas/Desktop/HomeBOM/packages/homebom-core/tests/test_imports.py) |
| **7. AWS Bedrock & Deterministic Resilience** | Bedrock Converse API (`claude-3-haiku`) for intent routing and phrasing with automatic local fallback pipelines. | [`server/bedrock.py`](file:///Users/krrishbiswas/Desktop/HomeBOM/server/bedrock.py)<br>[`server/router.py`](file:///Users/krrishbiswas/Desktop/HomeBOM/server/router.py) | [`tests/test_bedrock.py`](file:///Users/krrishbiswas/Desktop/HomeBOM/tests/test_bedrock.py)<br>[`scripts/bedrock_smoke.py`](file:///Users/krrishbiswas/Desktop/HomeBOM/scripts/bedrock_smoke.py) |
| **8. Single-Page Web Frontend** | Vanilla CSS dark-mode UI with Web Speech API input, speech synthesis output, ranked device cards, and transcript badges. | [`server/static/`](file:///Users/krrishbiswas/Desktop/HomeBOM/server/static/)<br>[`server/web.py`](file:///Users/krrishbiswas/Desktop/HomeBOM/server/web.py) | [`tests/test_frontend_api.py`](file:///Users/krrishbiswas/Desktop/HomeBOM/tests/test_frontend_api.py) |
| **9. Public Demo Hardening & Abuse Protection** | `HOMEBOM_PUBLIC_DEMO=1` mode disabling device writes, per-IP rate limiting (10/min), 300 char query cap, Bedrock hourly budget, no CORS, and strict API key containment. | [`server/limiter.py`](file:///Users/krrishbiswas/Desktop/HomeBOM/server/limiter.py)<br>[`server/web.py`](file:///Users/krrishbiswas/Desktop/HomeBOM/server/web.py) | [`tests/test_public_hardening.py`](file:///Users/krrishbiswas/Desktop/HomeBOM/tests/test_public_hardening.py) |

---

## 5. End-of-Life (EoL) Logic

Firmware security differs fundamentally from cloud software: once an embedded device reaches End-of-Life, manufacturers discontinue patches. Recommending a "firmware update" for an EoL device provides false security.

- **Detection**: HomeBOM scans the official CISA KEV catalog short description for strings matching `"end-of-life"` or `"end-of-service"`.
- **Enforcement**:
  1. The device risk profile sets `is_eol = True`.
  2. CycloneDX 1.6 HBOM sets `"homebom:eol": "true"`.
  3. Spoken text and remediation steps (`get_fix_steps`) strictly state that the device is discontinued and **must be replaced**.

---

## 6. Running Locally

### Prerequisites
- Python 3.12+
- `uv` package manager (`curl -LsSf https://astral.sh/uv/install.sh | sh`)

### Setup & Testing
```bash
# 1. Clone repository
git clone https://github.com/krrish175-byte/HomeBOM.git
cd HomeBOM

# 2. Sync dependencies
uv sync --extra dev

# 3. Run all 57 tests
uv run pytest -v

# 4. Check code formatting and linting
uv run ruff check .
```

### Launch Local Server
```bash
# Start server with local dev authentication bypass
export HOMEBOM_DEV_NOAUTH=1
uv run python -m server.main

# Or start with a specific API key
export HOMEBOM_API_KEY="my-secret-key"
uv run python -m server.main
```
Open **`http://127.0.0.1:8000`** in your browser to interact with the voice-driven Single-Page Application.

### Run Verification Scripts
```bash
# Verify offline Bedrock Converse fallback
uv run python scripts/bedrock_smoke.py

# Inspect all 6 MCP tools over Streamable HTTP
uv run python scripts/inspect_mcp.py

# Verify deployed/running service via curl
BASE_URL="http://127.0.0.1:8000" HOMEBOM_API_KEY="my-secret-key" ./scripts/smoke_deployed.sh
```

---

## 7. Container & AWS App Runner Deployment

HomeBOM includes containerization files for production cloud hosting:
- **`Dockerfile`**: Slim Debian Bookworm (`python:3.12-slim`), non-root user (`appuser:10001`), pre-bundled feeds and static assets, binding to `0.0.0.0` inside container with dynamic `$PORT`.
- **`apprunner.yaml`**: AWS App Runner configuration template.
- **`deploy/iam_bedrock_policy.json`**: Minimal IAM policy allowing `bedrock:InvokeModel` only.

---

## 8. Limitations & Scope

- **Simulated Voice Frontend**: HomeBOM provides a simulated voice interface in the browser using the W3C Web Speech API (`webkitSpeechRecognition`) and `window.speechSynthesis` connecting as a real MCP client over Streamable HTTP. It does **not** claim live production Alexa+ certified hardware device fleet integration or proprietary Alexa Skills Kit accounts.
- **Offline Cached Data**: Demonstration feeds reflect ground truth as of **2026-10-21**. Live deployments can refresh feeds periodically via `scripts/refresh_cache.py`.

---

## 9. License

This project is licensed under the [MIT License](LICENSE).  
The `packages/homebom-core` library is independently licensed under the [MIT License](packages/homebom-core/LICENSE).