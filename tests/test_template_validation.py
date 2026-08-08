"""Tests validating project structure and configuration.

These ensure the pyproject.toml, Cargo.toml, and CI layout are correct for a
project whose production code is Rust and whose Python env is scripting-only.
"""

from __future__ import annotations

import tomllib
from pathlib import Path


def test_pyproject_toml_structure() -> None:
    """pyproject.toml describes a scripting env, not an installable package."""
    pyproject_file = Path("pyproject.toml")
    assert pyproject_file.exists(), "pyproject.toml should exist"

    with open(pyproject_file, "rb") as f:
        content = tomllib.load(f)

    # Required sections for the scripting environment
    assert "project" in content, "Missing [project] section"
    assert "tool" in content, "Missing [tool] section"

    # No build-system: there is no Python package to build (server is pure Rust)
    assert "build-system" not in content, "Should not declare a build-system (no Python package; server is Rust)"

    # Scripting project name
    assert content["project"]["name"] == "vaultwarden-mcp-scripts", "Python env should be the scripting project, not the server package"

    # No fastmcp / Python MCP SDK — the MCP server is Rust (rmcp)
    deps = content["project"].get("dependencies", [])
    assert not any("fastmcp" in d.lower() for d in deps), "Should not depend on fastmcp (MCP server is Rust)"
    assert not any(d.startswith("mcp") for d in deps), "Should not depend on the Python mcp package"


def test_cargo_toml_uses_rmcp() -> None:
    """native/Cargo.toml uses modelcontextprotocol/rust-sdk (rmcp) + vaultwarden-cli."""
    cargo_file = Path("native/Cargo.toml")
    assert cargo_file.exists(), "native/Cargo.toml should exist"

    with open(cargo_file, "rb") as f:
        content = tomllib.load(f)

    deps = content["dependencies"]
    assert "rmcp" in deps, "Should use rmcp (modelcontextprotocol/rust-sdk)"
    assert "vaultwarden-cli" in deps, "Should use vaultwarden-cli for vault operations"

    # CalVer version (YYYY.MM.N)
    version = content["package"]["version"]
    parts = version.split(".")
    assert len(parts) == 3, f"Version should be CalVer (YYYY.MM.N), got: {version}"
    year = parts[0]
    assert len(year) == 4, f"Version year should be 4 digits, got: {version}"
    assert year.startswith("20"), f"Version year should start with '20', got: {version}"


def test_pytest_configuration() -> None:
    """Pytest is configured with testpaths (no coverage/asyncio — sync structural tests)."""
    with open(Path("pyproject.toml"), "rb") as f:
        content = tomllib.load(f)

    pytest_config = content.get("tool", {}).get("pytest", {}).get("ini_options", {})
    assert "testpaths" in pytest_config, "testpaths should be configured"
    assert pytest_config["testpaths"] == ["tests"], f"testpaths should be ['tests'], got: {pytest_config['testpaths']}"

    # No coverage threshold and no asyncio mode — these were test-client config
    # that no longer applies to a sync structural test suite.
    assert "tool" not in content or "pytest-cov" not in content["tool"], "Should not configure pytest-cov (no coverage target package)"


def test_binary_exists_in_release_workflow() -> None:
    """CI builds a Rust binary via cargo, not a Python wheel."""
    workflow_file = Path(".github/workflows/release.yml")
    assert workflow_file.exists(), "release.yml workflow should exist"
    content = workflow_file.read_text(encoding="utf-8")

    assert "cargo build" in content or "cargo release" in content, "CI should use cargo build for Rust binary"
    assert "maturin" not in content, "CI should not use maturin (no Python wheels)"
