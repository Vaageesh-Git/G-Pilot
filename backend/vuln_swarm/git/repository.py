from __future__ import annotations

import base64
import subprocess
from pathlib import Path

from vuln_swarm.core.config import Settings
from vuln_swarm.schemas import ScanRepoRequest


class RepositoryPreparationError(RuntimeError):
    pass


class RepositoryManager:
    def __init__(self, settings: Settings):
        self.settings = settings

    def prepare(self, run_id: str, request: ScanRepoRequest) -> Path:
        destination = self.settings.worktrees_dir / run_id / "repo"
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            return destination
            
        self._clone(request.clone_url, destination, branch=request.branch)
        
        if request.forked_repository and request.forked_repository != request.github_repository:
            upstream_url = f"https://github.com/{request.github_repository}.git"
            self._git(destination, ["remote", "add", "upstream", upstream_url])
            if request.commit_sha:
                self._git(destination, ["fetch", "upstream", request.commit_sha])
            else:
                self._git(destination, ["fetch", "upstream", request.branch or "main"])
                
        if request.commit_sha:
            self._git(destination, ["checkout", request.commit_sha])
        return destination

    def commit_sha(self, repo_path: Path) -> str | None:
        try:
            result = self._git(repo_path, ["rev-parse", "HEAD"])
        except RepositoryPreparationError:
            return None
        return result.stdout.strip() or None

    def has_changes(self, repo_path: Path) -> bool:
        result = self._git(repo_path, ["status", "--porcelain"], allow_failure=True)
        return bool(result.stdout.strip())

    def _clone(self, source: str, destination: Path, *, branch: str | None = None) -> None:
        command = self._clone_command(source, destination, branch=branch)
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise RepositoryPreparationError(result.stderr.strip() or "git clone failed")

    def _clone_command(self, source: str, destination: Path, *, branch: str | None = None) -> list[str]:
        command = ["git"]
        if self.settings.github_token and source.startswith("https://github.com/"):
            auth = base64.b64encode(f"x-access-token:{self.settings.github_token}".encode()).decode()
            command.extend(
                [
                    "-c",
                    f"http.https://github.com/.extraheader=AUTHORIZATION: basic {auth}",
                ]
            )
        command.extend(["clone", "--depth", "1"])
        if branch:
            command.extend(["--branch", branch])
        command.extend([source, str(destination)])
        return command

    def _git(
        self,
        repo_path: Path,
        args: list[str],
        *,
        allow_failure: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            ["git", *args],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0 and not allow_failure:
            raise RepositoryPreparationError(result.stderr.strip() or f"git {' '.join(args)} failed")
        return result
