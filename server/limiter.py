"""server.limiter - Abuse prevention, rate limiting, and Bedrock call budget controls.

Enforces:
- Per-IP rate limiting on public endpoints (default: 10 requests / minute)
- Maximum query character limit (default: 300 characters)
- Process-level hourly budget for AWS Bedrock Converse API calls (default: 50 / hour)
- Automatic fallback to keywords and templates when Bedrock budget is exceeded
"""

import os
import time
from collections import defaultdict


class IPRateLimiter:
    """Sliding-window in-memory rate limiter per client IP address."""

    def __init__(self, max_requests: int = 10, window_seconds: float = 60.0) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, ip: str) -> bool:
        """Check if an incoming request from `ip` is within the rate limit."""
        now = time.time()
        cutoff = now - self.window_seconds
        # Retain only timestamps within the sliding window
        history = [t for t in self.requests[ip] if t > cutoff]
        if len(history) >= self.max_requests:
            self.requests[ip] = history
            return False

        history.append(now)
        self.requests[ip] = history
        return True

    def reset(self) -> None:
        """Reset all rate limiter tracking."""
        self.requests.clear()


class BedrockHourlyBudget:
    """Tracks and caps Bedrock API calls per process per hour."""

    def __init__(self, max_calls_per_hour: int | None = None) -> None:
        if max_calls_per_hour is None:
            raw_env = os.environ.get("BEDROCK_MAX_CALLS_PER_HOUR", "50")
            try:
                self.max_calls = int(raw_env)
            except ValueError:
                self.max_calls = 50
        else:
            self.max_calls = max_calls_per_hour

        self.window_seconds = 3600.0
        self.calls: list[float] = []

    def allow_call(self) -> bool:
        """Return True if under hourly budget and record the call; False if budget exceeded."""
        now = time.time()
        cutoff = now - self.window_seconds
        self.calls = [t for t in self.calls if t > cutoff]
        if len(self.calls) >= self.max_calls:
            return False

        self.calls.append(now)
        return True

    def is_exceeded(self) -> bool:
        """Check if hourly budget is currently exceeded without recording a call."""
        now = time.time()
        cutoff = now - self.window_seconds
        valid_calls = [t for t in self.calls if t > cutoff]
        return len(valid_calls) >= self.max_calls

    def reset(self) -> None:
        """Reset hourly call tracking."""
        self.calls.clear()


# Global singleton instances
global_ip_limiter = IPRateLimiter(max_requests=10, window_seconds=60.0)
global_bedrock_budget = BedrockHourlyBudget()
