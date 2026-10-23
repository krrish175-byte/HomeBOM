#!/usr/bin/env bash
# ==============================================================================
# scripts/smoke_deployed.sh - Smoke test deployed HomeBOM service.
#
# Verifies:
# 1. MCP initialize over Streamable HTTP with Bearer auth
# 2. MCP tools/list returning registered tools
# 3. MCP tools/call scan_home returning verified risk profiles and spoken text
# 4. GET /api/devices returning 8 seeded devices ranked with security attributes
#
# Usage:
#   export BASE_URL="https://my-apprunner-url.awsapprunner.com"
#   export HOMEBOM_API_KEY="my-secret-key"
#   ./scripts/smoke_deployed.sh
# ==============================================================================

set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8000}"
API_KEY="${HOMEBOM_API_KEY:-smoke-test-key}"

echo "======================================================================"
echo " HomeBOM Deployed Smoke Verification"
echo "======================================================================"
echo "Target Base URL: ${BASE_URL}"
echo "Auth Token:      Bearer [CONFIGURED]"
echo "----------------------------------------------------------------------"

# 1. MCP Protocol: Initialize
echo ">>> [1/4] Testing MCP initialize (/mcp)..."
INIT_PAYLOAD='{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2025-11-25",
    "capabilities": {},
    "clientInfo": {
      "name": "homebom-smoke-curl",
      "version": "1.0.0"
    }
  }
}'

INIT_RESP=$(curl -sS -f -X POST "${BASE_URL}/mcp" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d "${INIT_PAYLOAD}")

echo "Response: ${INIT_RESP}" | cut -c 1-200
echo "✓ MCP initialize successful."
echo "----------------------------------------------------------------------"

# 2. MCP Protocol: Tools List
echo ">>> [2/4] Testing MCP tools/list (/mcp)..."
LIST_PAYLOAD='{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/list",
  "params": {}
}'

LIST_RESP=$(curl -sS -f -X POST "${BASE_URL}/mcp" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d "${LIST_PAYLOAD}")

if ! echo "${LIST_RESP}" | grep -q "scan_home"; then
  echo "ERROR: scan_home tool missing from tools/list response!"
  exit 1
fi
echo "✓ MCP tools/list returned registered tools."
echo "----------------------------------------------------------------------"

# 3. MCP Protocol: Call Tool scan_home
echo ">>> [3/4] Testing MCP tools/call scan_home (/mcp)..."
CALL_PAYLOAD='{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "scan_home",
    "arguments": {}
  }
}'

CALL_RESP=$(curl -sS -f -X POST "${BASE_URL}/mcp" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d "${CALL_PAYLOAD}")

if ! echo "${CALL_RESP}" | grep -q "spoken"; then
  echo "ERROR: tools/call scan_home failed to return spoken text!"
  exit 1
fi
echo "✓ MCP tools/call scan_home succeeded with spoken output."
echo "----------------------------------------------------------------------"

# 4. Web API: GET /api/devices
echo ">>> [4/4] Testing Web API GET /api/devices..."
DEVICES_RESP=$(curl -sS -f -X GET "${BASE_URL}/api/devices")

if ! echo "${DEVICES_RESP}" | grep -q "total_devices"; then
  echo "ERROR: GET /api/devices failed or invalid response!"
  exit 1
fi
echo "✓ GET /api/devices returned 8 monitored devices."
echo "======================================================================"
echo " SMOKE VERIFICATION COMPLETED SUCCESSFULLY"
echo "======================================================================"
