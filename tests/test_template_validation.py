"""Tests validating project structure and configuration.

These ensure the pyproject.toml, Cargo.toml, and project layout are correct.
"""

from __future__ import annotations

import tomllib
from pathlib import Path


def test_pyproject_toml_structure() -> None:
    """Test that pyproject.toml has the correct structure for a pure-Python testing layer."""
    pyproject_file = Path("pyproject.toml")
    assert pyproject_file.exists(), "pyproject.toml should exist"

    with open(pyproject_file, "rb") as f:
        content = tomllib.load(f)

    # Verify required sections
    assert "project" in content, "Missing [project] section"
    assert "build-system" in content, "Missing [build-system] section"
    assert "tool" in content, "Missing [tool] section"

    # Verify project metadata
    assert "name" in content["project"], "Missing project name"
    assert content["project"]["name"] == "vaultwarden-mcp"

    # Verify no maturin/pyo3 dependencies (server is pure Rust)
    build_deps = content["build-system"]["requires"]
    assert not any("maturin" in d for d in build_deps), "Should not use maturin (server is pure Rust binary)"

    # Verify dependencies include FastMCP for testing
    deps = content["project"]["dependencies"]
    assert any("fastmcp" in d.lower() for d in deps), "FastMCP should be a dependency for test client"

    # Verify no 'mcp' dependency (we use rmcp in Rust, not Python MCP SDK)
    assert not any(d.startswith("mcp") for d in deps), "Should not depend on Python mcp package"


def test_cargo_toml_uses_rmcp() -> None:
    """Test that native/Cargo.toml uses the modelcontextprotocol/rust-sdk (rmcp)."""
    cargo_file = Path("native/Cargo.toml")
    assert cargo_file.exists(), "native/Cargo.toml should exist"

    with open(cargo_file, "rb") as f:
        content = tomllib.load(f)

    deps = content["dependencies"]
    assert "rmcp" in deps, "Should use rmcp (modelcontextprotocol/rust-sdk)"
    assert "vaultwarden-cli" in deps, "Should use vaultwarden-cli for vault operations"

    # Verify version is CalVer format (YYYY.MM.N)
    version = content["package"]["version"]
    parts = version.split(".")
    assert len(parts) == 3, f"Version should be CalVer (YYYY.MM.N), got: {version}"
    year = parts[0]
    assert len(year) == 4, f"Version year should be 4 digits, got: {version}"
    assert year.startswith("20"), f"Version year should start with '20', got: {version}"


def test_pytest_configuration() -> None:
    """Test that pytest is configured for async testing with coverage threshold."""
    pyproject_file = Path("pyproject.toml")
    with open(pyproject_file, "rb") as f:
        content = tomllib.load(f)

    pytest_config = content.get("tool", {}).get("pytest", {}).get("ini_options", {})
    assert "testpaths" in pytest_config, "testpaths should be configured"
    mode = str(pytest_config.get("asyncio_mode", "")).lower()
    assert mode in ("auto", "strict"), f"asyncio_mode should be 'auto' or 'strict' for async tests, got: {mode}"

    # Verify coverage threshold
    pytest_cov = content.get("tool", {}).get("pytest-cov", {})
    assert "fail_under" in pytest_cov, "fail_under should be set"
    assert pytest_cov["fail_under"] == 80, f"Coverage threshold should be 80%, got: {pytest_cov['fail_under']}"


def test_binary_exists_in_release_workflow() -> None:
    """Test that CI is configured to build a Rust binary (not Python wheel)."""
    workflow_file = Path(".github/workflows/release.yml")
    assert workflow_file.exists(), "release.yml workflow should exist"
    content = workflow_file.read_text(encoding="utf-8")

    # Should use cargo build, not maturin build or uv build
    assert "cargo build" in content or "cargo release" in content, "CI should use cargo build for Rust binary"
    assert "maturin" not in content, "CI should not use maturin (no Python wheels)"
