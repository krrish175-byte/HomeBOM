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

---

### Snag #003: macOS APFS `UF_HIDDEN` flag on `_editable_impl_*.pth` causes `ModuleNotFoundError` in Python 3.12
- **Date**: 2026-10-21
- **Task**: Phase 0 test execution via `uv run pytest`
- **Steps**:
  1. Ran `uv run pytest`.
- **Expected**: Pytest imports `homebom_core` and `server` via uv editable installs.
- **Actual**: `ModuleNotFoundError: No module named 'homebom_core'` and `ModuleNotFoundError: No module named 'server'`.
- **Cause**: Hatchling generates editable files prefixed with underscore: `_editable_impl_<pkg>.pth`. On macOS (Darwin APFS), files starting with an underscore can be automatically tagged with the BSD flag `UF_HIDDEN` (32832). Python 3.12's `site.py` contains a security check that explicitly skips any `.pth` file marked with `UF_HIDDEN` (`Skipping hidden .pth file...`).
- **Severity**: Medium
- **Workaround**: Added `pythonpath = ["packages/homebom-core", "."]` under `[tool.pytest.ini_options]` in `pyproject.toml`. Pytest now resolves workspace modules directly without relying on OS-level `.pth` file loading.
- **Suggestion**: Editable build backends should avoid leading underscores in `.pth` filenames on macOS, or `pytest` projects in monorepos should always specify `pythonpath`.

---

### Snag #004: NVD API 2.0 returns 404 for wildcard CPEs unless queried via `virtualMatchString`
- **Date**: 2026-10-22
- **Task**: Phase 1 caching NVD vulnerability records per device CPE
- **Steps**:
  1. Sent GET request to `https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:o:tp-link:archer_ax21_firmware:*:*:*:*:*:*:*:*`.
- **Expected**: NVD returns CVEs matching the Archer AX21 firmware match range.
- **Actual**: HTTP 404 Not Found.
- **Cause**: In NVD API 2.0, `cpeName` strictly requires an exact dictionary entry; it rejects trailing wildcards `*` or match expressions with a 404 status.
- **Severity**: Medium
- **Workaround**: Switched to `virtualMatchString=<base_cpe>` (e.g. `virtualMatchString=cpe:2.3:o:tp-link:archer_ax21_firmware`) whenever the CPE criteria contains wildcards.
### Snag #005: FastMCP `StreamableHTTPSessionManager.run()` raises `RuntimeError` on server restart / reload
- **Date**: 2026-10-22
- **Task**: Phase 3 MCP Server implementation and automated protocol tests
- **Steps**:
  1. Initialized a global `FastMCP` instance in `server/main.py`.
  2. Mounted `streamable_http_app()` in an ASGI application.
  3. Ran automated integration tests where `uvicorn` started, stopped, and started a new server for another test function.
- **Expected**: Uvicorn server can start and stop across multiple tests or live server restarts cleanly.
- **Actual**: `RuntimeError: StreamableHTTPSessionManager .run() can only be called once per instance. Create a new instance if you need to run again.`
- **Cause**: FastMCP's internal `StreamableHTTPSessionManager` tracks its lifecycle with a boolean flag and explicitly disallows reuse after shutdown.
- **Severity**: Medium
- **Workaround**: Implemented a `create_mcp_server()` factory function and an ASGI `LazyApp` wrapper that detects ASGI `"lifespan"` startup events and instantiates a fresh FastMCP app for each server lifecycle.
- **Suggestion**: `StreamableHTTPSessionManager` should reset its internal running state on graceful exit or support clean re-initialization on subsequent lifespan contexts.

---

### Snag #006: In-process test runner module pollution breaks isolated runtime dependency checks
- **Date**: 2026-10-22
- **Task**: Phase 3 running repository-wide test suite (`uv run pytest`)
- **Steps**:
  1. Ran `uv run pytest -v` across `packages/homebom-core/tests` and `tests/`.
  2. `tests/test_mcp_protocol.py` imported `from mcp.client.session import ClientSession`.
  3. `packages/homebom-core/tests/test_imports.py::test_zero_mcp_and_zero_aws_imports` asserted `'mcp' not in sys.modules`.
- **Expected**: `homebom-core` boundary test passes because `homebom-core` imports neither MCP nor AWS SDKs.
- **Actual**: Test failed with `AssertionError: Forbidden module 'mcp' was unexpectedly imported into runtime!`
- **Cause**: Pytest runs test collection across all test directories in a single Python process, meaning test files in `tests/` populate `sys.modules` with test dependencies before tests in `packages/homebom-core/tests/` run.
- **Severity**: Low
- **Workaround**: Updated `test_zero_mcp_and_zero_aws_imports` to invoke an isolated subprocess (`subprocess.run([sys.executable, "-c", ...])`) with `PYTHONPATH=packages/homebom-core` to verify that loading `homebom-core` alone never pulls `mcp` or `boto3` into `sys.modules`.
- **Suggestion**: Architectural boundary assertions that inspect `sys.modules` should always be executed in an isolated subshell/subprocess rather than inside the shared test runner's global namespace.

---

### Snag #007: Bedrock client raises NoCredentialsError in unauthenticated environments
- **Date**: 2026-10-22
- **Task**: Phase 5 AWS Bedrock Converse API integration and smoke test execution
- **Command**: `uv run python scripts/bedrock_smoke.py`
- **Expected**: Script connects to AWS Bedrock runtime endpoint and completes model inference.
- **Actual**: Command output:
  ```text
  Attempting Bedrock Converse API invocation...
  [Bedrock API Notice] Live call did not proceed: NoCredentialsError: Unable to locate credentials
  Engaging deterministic fallback pipeline...
  ```
- **Cause**: The local environment has neither AWS IAM credentials configured (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`) nor an active AWS SSO session. Boto3's default credential provider chain traverses environment variables, configuration files, and metadata services before raising `botocore.exceptions.NoCredentialsError`.
- **Severity**: Low
- **Workaround**: Implemented defensive exception handling in `server/bedrock.py` that intercepts `NoCredentialsError` along with network timeouts and API errors, immediately activating deterministic template phrasing tagged with `phrasing_source="template"`. This keeps the application fully functional offline.
- **Suggestion**: Cloud LLM integrations in voice assistants must decouple inference from core business logic using deterministic template fallbacks so offline operation and CI pipelines remain resilient.

---

### Snag #008: FastMCP StreamableHTTP lifespan task group uninitialized when mounted inside parent Starlette application
- **Date**: 2026-10-22
- **Task**: Phase 7 single-page web UI and real MCP Streamable HTTP client integration
- **Command**: `uv run python -c "..."` (mounting `mcp.streamable_http_app()` inside `Starlette(routes=[Route('/api/chat', ...), Mount('', app=mcp_app)])`)
- **Expected**: Requests to `/mcp` process normally via the mounted FastMCP streamable HTTP ASGI application.
- **Actual**: Command output:
  ```text
  File ".../mcp/server/streamable_http_manager.py", line 201, in _handle_request
      raise RuntimeError("Task group is not initialized. Make sure to use run().")
  RuntimeError: Task group is not initialized. Make sure to use run().
  HTTP Request: POST http://127.0.0.1:62037/mcp "HTTP/1.1 500 Internal Server Error"
  ```
- **Cause**: FastMCP's `StreamableHTTPSessionManager` requires its async task group to be started via its lifespan context (`session_manager.run()`). When mounting `mcp_app` inside a parent Starlette application without explicitly passing `lifespan=mcp_app.router.lifespan_context`, the parent application does not run the sub-application's lifespan events, leaving the task group uninitialized.
- **Severity**: Medium
- **Workaround**: Configured the parent `Starlette` app with `lifespan=mcp_app.router.lifespan_context` in `server/main.py`. This ensures Uvicorn's lifespan startup triggers the session manager task group, enabling concurrent Streamable HTTP client sessions.
- **Suggestion**: FastMCP could document composite ASGI mounting patterns or provide a helper to compose parent lifespans when serving web assets and MCP transports simultaneously.
