from pathlib import Path

import _test_bootstrap  # noqa: F401

from vuln_swarm.core.config import Settings
from vuln_swarm.git.github import GitHubIntegrator


def test_git_command_uses_github_token_for_authenticated_git_operations(tmp_path: Path) -> None:
    settings = Settings(
        GITHUB_TOKEN="secret-token",
        VULN_SWARM_DATA_DIR=str(tmp_path / ".data"),
        CHROMA_DIR=str(tmp_path / ".data" / "chroma"),
    )
    integrator = GitHubIntegrator(settings)

    command = integrator._git_command(["push", "origin", "feature"])

    assert command[:3] == ["git", "-c", command[2]]
    assert "extraheader=AUTHORIZATION: basic " in command[2]
    assert command[3:] == ["push", "origin", "feature"]


def test_git_command_skips_auth_header_without_token(tmp_path: Path) -> None:
    settings = Settings(
        GITHUB_TOKEN="",
        VULN_SWARM_DATA_DIR=str(tmp_path / ".data"),
        CHROMA_DIR=str(tmp_path / ".data" / "chroma"),
    )
    integrator = GitHubIntegrator(settings)

    assert integrator._git_command(["status", "--porcelain"]) == ["git", "status", "--porcelain"]
