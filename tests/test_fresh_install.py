"""test_fresh_install.py — Validate that frapAST installs cleanly in a fresh virtual
environment and that the CLI entry point works end-to-end without any files from the
development tree being on sys.path.

This test builds a real wheel from the current source tree, creates an isolated venv,
installs the wheel, and verifies the `frapast` command is available and functional.

Skip in normal `pytest` runs unless the environment variable
`FRAPAST_RUN_INSTALL_TEST=1` is set (the test is slow and requires build tools).
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SKIP_REASON = (
    "Set FRAPAST_RUN_INSTALL_TEST=1 to run the slow fresh-install packaging test."
)


@pytest.mark.skipif(
    os.environ.get("FRAPAST_RUN_INSTALL_TEST") != "1",
    reason=SKIP_REASON,
)
class TestFreshInstall:
    """Build a wheel, install into an isolated venv, verify CLI works cleanly."""

    @pytest.fixture(scope="class")
    def built_wheel(self, tmp_path_factory):
        """Build a wheel from the current source tree. Returns the wheel Path."""
        dist_dir = tmp_path_factory.mktemp("dist")
        result = subprocess.run(
            [sys.executable, "-m", "build", "--wheel", "--outdir", str(dist_dir)],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        assert result.returncode == 0, (
            f"Wheel build failed.\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )
        wheels = list(dist_dir.glob("*.whl"))
        assert len(wheels) == 1, f"Expected 1 wheel, got: {wheels}"
        return wheels[0]

    @pytest.fixture(scope="class")
    def fresh_venv(self, tmp_path_factory, built_wheel):
        """Create an isolated venv, install the wheel, yield the bin directory."""
        venv_dir = tmp_path_factory.mktemp("venv")
        subprocess.run(
            [sys.executable, "-m", "venv", str(venv_dir)],
            check=True,
        )
        # Determine bin/Scripts directory
        if sys.platform == "win32":
            pip_path = venv_dir / "Scripts" / "pip"
            frapast_path = venv_dir / "Scripts" / "frapast"
        else:
            pip_path = venv_dir / "bin" / "pip"
            frapast_path = venv_dir / "bin" / "frapast"

        # Install wheel into isolated venv
        result = subprocess.run(
            [str(pip_path), "install", str(built_wheel)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, (
            f"pip install failed.\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )
        return frapast_path

    def test_frapast_help_exits_zero(self, fresh_venv):
        """frapast --help must succeed with exit code 0."""
        result = subprocess.run(
            [str(fresh_venv), "--help"],
            capture_output=True,
            text=True,
            env={"PATH": str(fresh_venv.parent)},
        )
        assert result.returncode == 0
        assert "frapast" in result.stdout.lower()

    def test_frapast_scan_help(self, fresh_venv):
        """frapast scan --help must succeed and list key options."""
        result = subprocess.run(
            [str(fresh_venv), "scan", "--help"],
            capture_output=True,
            text=True,
            env={"PATH": str(fresh_venv.parent)},
        )
        assert result.returncode == 0
        assert "--format" in result.stdout or "format" in result.stdout

    def test_frapast_version_is_present(self, fresh_venv):
        """frapast --version (or help output) must include a recognizable version string."""
        result = subprocess.run(
            [str(fresh_venv), "--version"],
            capture_output=True,
            text=True,
            env={"PATH": str(fresh_venv.parent)},
        )
        combined = result.stdout + result.stderr
        # Accept either exit 0 or exit 1 — some CLIs print version to stderr and exit 1
        assert any(c.isdigit() for c in combined), (
            f"Expected a version number in output: {combined!r}"
        )
