"""server.auth - Authentication middleware and API key validation.

Enforces:
- API key read from HOMEBOM_API_KEY
- Constant-time comparison with hmac.compare_digest
- Reject missing or incorrect keys with HTTP 401
- Fail closed: Refuse to start if HOMEBOM_API_KEY is unset unless HOMEBOM_DEV_NOAUTH=1
- Never logs the API key
"""

import hmac
import os
from typing import Any


def get_configured_api_key() -> tuple[str | None, bool]:
    """Retrieve the API key and no-auth flag from the environment.

    Fail-closed policy: If HOMEBOM_API_KEY is unset and HOMEBOM_DEV_NOAUTH != "1",
    raises RuntimeError to refuse server startup.
    Never logs the key.
    """
    dev_noauth = os.environ.get("HOMEBOM_DEV_NOAUTH", "").strip() == "1"
    api_key = os.environ.get("HOMEBOM_API_KEY", "").strip()

    if not api_key:
        if dev_noauth:
            return (None, True)
        raise RuntimeError(
            "HOMEBOM_API_KEY environment variable is not configured. "
            "Server refuses to start. (Set HOMEBOM_DEV_NOAUTH=1 for local development without authentication)."
        )

    return (api_key, dev_noauth)


def verify_token(token: str | None, expected_key: str | None, dev_noauth: bool = False) -> bool:
    """Verify an authentication token using constant-time comparison."""
    if dev_noauth:
        return True
    if not token or not expected_key:
        return False
    return hmac.compare_digest(token, expected_key)


class AuthMiddleware:
    """ASGI Middleware to validate API keys on every incoming HTTP request."""

    def __init__(self, app: Any, api_key: str | None, dev_noauth: bool = False) -> None:
        self.app = app
        self.api_key = api_key
        self.dev_noauth = dev_noauth

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        if self.dev_noauth:
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        auth_header = headers.get(b"authorization", b"").decode("utf-8", errors="ignore").strip()
        x_api_key = headers.get(b"x-api-key", b"").decode("utf-8", errors="ignore").strip()

        token = ""
        if auth_header.lower().startswith("bearer "):
            token = auth_header[7:].strip()
        elif auth_header:
            token = auth_header
        elif x_api_key:
            token = x_api_key

        if not verify_token(token, self.api_key, self.dev_noauth):
            body = b'{"error": "Unauthorized: Missing or invalid authentication token"}'
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode("ascii")),
                    ],
                }
            )
            await send(
                {
                    "type": "http.response.body",
                    "body": body,
                }
            )
            return

        await self.app(scope, receive, send)
