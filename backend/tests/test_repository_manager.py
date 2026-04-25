from pathlib import Path

import _test_bootstrap  # noqa: F401

from vuln_swarm.core.config import Settings
from vuln_swarm.git.repository import RepositoryManager


def test_clone_command_uses_github_token_for_github_https_urls(tmp_path: Path) -> None:
    settings = Settings(
        GITHUB_TOKEN="secret-token",
        VULN_SWARM_DATA_DIR=str(tmp_path / ".data"),
        CHROMA_DIR=str(tmp_path / ".data" / "chroma"),
    )
    manager = RepositoryManager(settings)
    command = manager._clone_command(
        "https://github.com/acme/platform.git",
        tmp_path / "repo",
        branch="main",
    )

    assert command[:3] == ["git", "-c", command[2]]
    assert "extraheader=AUTHORIZATION: basic " in command[2]
    assert command[3:] == [
        "clone",
        "--depth",
        "1",
        "--branch",
        "main",
        "https://github.com/acme/platform.git",
        str(tmp_path / "repo"),
    ]


def test_clone_command_skips_auth_header_without_token(tmp_path: Path) -> None:
    settings = Settings(
        GITHUB_TOKEN="",
        VULN_SWARM_DATA_DIR=str(tmp_path / ".data"),
        CHROMA_DIR=str(tmp_path / ".data" / "chroma"),
    )
    manager = RepositoryManager(settings)
    command = manager._clone_command(
        "https://github.com/acme/platform.git",
        tmp_path / "repo",
    )

    assert command == [
        "git",
        "clone",
        "--depth",
        "1",
        "https://github.com/acme/platform.git",
        str(tmp_path / "repo"),
    ]
