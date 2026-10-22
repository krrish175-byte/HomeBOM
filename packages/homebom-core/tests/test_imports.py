"""Tests for homebom-core package integrity and dependency boundaries."""

import sys

import homebom_core


def test_package_version():
    """Verify homebom_core imports and has a valid version."""
    assert hasattr(homebom_core, "__version__")
    assert homebom_core.__version__ == "0.1.0"


def test_zero_mcp_and_zero_aws_imports():
    """Hard requirement: packages/homebom-core must have ZERO MCP and ZERO AWS imports."""
    forbidden_modules = ["mcp", "boto3", "botocore", "fastmcp"]

    # Check already imported modules in sys.modules
    for mod in forbidden_modules:
        assert mod not in sys.modules, (
            f"Forbidden module '{mod}' was unexpectedly imported into runtime!"
        )

    # Verify that homebom-core source code itself never references forbidden packages
    import inspect
    import os

    core_dir = os.path.dirname(inspect.getfile(homebom_core))
    for root, _, files in os.walk(core_dir):
        for f in files:
            if f.endswith(".py"):
                path = os.path.join(root, f)
                with open(path, "r", encoding="utf-8") as py_file:
                    content = py_file.read()
                    for forbidden in [
                        "import mcp",
                        "from mcp",
                        "import boto3",
                        "from boto3",
                        "import botocore",
                    ]:
                        assert forbidden not in content, (
                            f"Violation in {path}: found forbidden import statement '{forbidden}'"
                        )
