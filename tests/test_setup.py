"""Tests for repository-wide setup, environment, and fallback mechanics."""

import os

import server
from scripts.bedrock_hello import check_bedrock


def test_server_package_imports():
    """Verify server package imports cleanly."""
    assert server is not None


def test_bedrock_hello_fallback_runs():
    """Verify scripts/bedrock_hello.py runs gracefully even without AWS credentials."""
    # Temporarily ensure no AWS credentials in env to force fallback execution path
    old_id = os.environ.pop("AWS_ACCESS_KEY_ID", None)
    old_sec = os.environ.pop("AWS_SECRET_ACCESS_KEY", None)
    try:
        # check_bedrock() should return False (or True if configured) without throwing an uncaught exception
        res = check_bedrock()
        assert isinstance(res, bool)
    finally:
        if old_id:
            os.environ["AWS_ACCESS_KEY_ID"] = old_id
        if old_sec:
            os.environ["AWS_SECRET_ACCESS_KEY"] = old_sec
