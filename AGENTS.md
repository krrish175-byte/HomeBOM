# AGENTS.md - Developer & Agent Operating Manual for HomeBOM

Welcome to **HomeBOM**. This file outlines repository guidelines, architectural constraints, testing expectations, and domain rules for both human developers and autonomous AI agents.

---

## 1. Project Overview & Hackathon Constraints
- **Primary Mission**: Alexa+ MCP server answering *"Alexa, how safe is my home?"*
- **Core Pillars**:
  1. Smart-home device inventory (router, camera, smart plug, Echo, Ring, Fire TV stick).
  2. Matching firmware against **real** vulnerability data (CISA KEV, FIRST EPSS, NVD 2.0).
  3. Short, spoken, plain-language answers optimized for voice interfaces (no CVE IDs read aloud).
  4. CycloneDX 1.6 Hardware BOM (HBOM) export with embedded VEX (Vulnerability Exploitability eXchange).
  5. 100% offline demo capability using pre-cached feeds.

---

## 2. Hard Architectural Rules

### Rule 1: Zero MCP & Zero AWS Imports in `homebom-core`
- `packages/homebom-core/` is a pure, independent, MIT-licensed Python library.
- It contains only CPE resolution, firmware version extraction, vulnerability matching, risk ranking, and CycloneDX HBOM generation.
- Never add `mcp`, `boto3`, or AWS SDK imports to `homebom-core`.

### Rule 2: Ground Truth Vulnerability Data
- **Never invent or fabricate** CVEs, CPEs, firmware versions, CVSS/EPSS scores, or KEV statuses.
- Every finding in seed data or scan output must trace back directly to CISA KEV or NVD feeds.
- Devices must resolve to **firmware CPEs** (`cpe:2.3:o:...`), not hardware CPEs (`h:`).

### Rule 3: Defensive Three-State Logic
- Matching evaluates to: `affected`, `not_affected`, or `unknown`.
- `unknown` must **never** be reported as safe.

### Rule 4: Priority Ranking
- Prioritize by active exploitation and probability, not raw CVSS:
  1. `fix_now`: `affected` + listed on CISA KEV.
  2. `fix_soon`: `affected` and (`EPSS >= 0.10` or `CVSS >= 9.0`).
  3. `low`: other `affected` devices.
  4. `not_affected` / `unknown`.

### Rule 5: Resilience & Fallbacks
- Every AWS Bedrock Converse API invocation must have a deterministic template fallback.
- If Bedrock is down or credentials are absent, the application must run completely offline without crashing.

---

## 3. Tech Stack & Commands
- **Python**: 3.12 managed via `uv`
- **Linting & Formatting**: `uv run ruff check .` and `uv run ruff format .`
- **Testing**: `uv run pytest`
- **Environment Sync**: `uv sync --extra dev`

---

## 4. MCP Server & Tools
The MCP server exposes exactly six tools:
1. `list_devices()`
2. `add_device(name, model, firmware)`
3. `scan_home()`
4. `explain_risk(device)`
5. `get_fix_steps(device)`
6. `export_hbom()`

All tools return structured data AND a `spoken` string (maximum 3 plain-language sentences).
