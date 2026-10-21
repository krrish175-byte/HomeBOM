# HomeBOM Hackathon Friction & Developer Experience Log

This document tracks all developer friction, SDK limitations, API bugs, and workarounds encountered during the development of HomeBOM for the Amazon Developer Hackathon (Alexa+ Track, AWS Builder, Open Source Challenges).

---

## Tooling & SDK Summary

| Tool / SDK | Purpose in Project | What Worked Well | Pain Points / Snags |
| :--- | :--- | :--- | :--- |
| **uv** (v0.11.x) | Workspace & virtualenv management | Blazing fast syncs, native workspace member support (`tool.uv.workspace`) | Requires explicit package target specification when root package isn't named matching folder |
| **mcp** (Python SDK) | FastMCP server, Streamable HTTP transport | FastMCP provides straightforward decorator syntax for tools and built-in SSE/Streamable HTTP support | MCP 2.x breaking change completely removed `mcp.server.fastmcp` (renamed to `MCPServer`), breaking `stateless_http` parameters. Pinned to `mcp>=1.3.0,<2`. |
| **boto3 / Bedrock** | Amazon Bedrock Converse API integration | Converse API provides unified message schema and temperature=0 support | Requires fallback path for local offline development or environments lacking IAM credentials |
| **cyclonedx-python-lib** | CycloneDX 1.6 Hardware BOM + VEX export | Official support for CycloneDX spec and validation models | Type-strict models require precise nesting of components, services, and vulnerabilities |

---

## Snag Entries

### Snag #001: Hatchling editable build failed on root workspace package
- **Date**: 2026-10-21
- **Task**: Phase 0 repository initialization and `uv sync`
- **Steps**:
  1. Configured root `pyproject.toml` with `[project] name = "homebom"`.
  2. Ran `uv sync --python 3.12`.
- **Expected**: `uv` and `hatchling` detect root workspace without requiring a `homebom/` subfolder.
- **Actual**: `ValueError: Unable to determine which files to ship inside the wheel using the following heuristics... no directory that matches the name of your project (homebom)`.
- **Severity**: Low
- **Workaround**: Added `server/__init__.py` and configured `[tool.hatch.build.targets.wheel] packages = ["server"]` in `pyproject.toml`.
- **Suggestion**: In multi-package workspaces where the root acts as a service or application runner rather than a library wheel, Hatchling or uv should support virtual / non-packaged roots seamlessly.

---

### Snag #002: MCP 2.x broke `FastMCP` import and configuration parameters
- **Date**: 2026-10-21
- **Task**: Phase 0 FastMCP dependency resolution
- **Steps**:
  1. Default dependency `mcp>=1.3.0` resolved to `mcp==2.3.0`.
  2. Attempted to import `mcp.server.fastmcp.FastMCP`.
- **Expected**: `FastMCP` available with `stateless_http=True`, `json_response=True`, `streamable_http_path="/mcp"`.
- **Actual**: `ModuleNotFoundError: No module named 'mcp.server.fastmcp'. This is mcp 2.x, where FastMCP was renamed to MCPServer...`
- **Severity**: Medium
- **Workaround**: Pinned root dependency to `"mcp>=1.3.0,<2"` (specifically resolving to `1.30.0`), which contains the exact FastMCP Streamable HTTP implementation specified by the hackathon requirements.
- **Suggestion**: SDK major version transitions should maintain a backward-compatibility aliasing layer or deprecation warnings before hard removal of top-level modules.
