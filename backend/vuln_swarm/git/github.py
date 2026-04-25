from __future__ import annotations

import base64
import re
import subprocess
from pathlib import Path

import httpx

from vuln_swarm.core.config import Settings


class GitHubIntegrationError(RuntimeError):
    pass


class GitHubIntegrator:
    def __init__(self, settings: Settings):
        self.settings = settings

    async def commit_and_create_pr(
        self,
        *,
        repo_path: Path,
        github_repository: str | None,
        branch_name: str,
        base_branch: str | None,
        title: str,
        body: str,
        fork_owner: str | None = None,
    ) -> str | None:
        if not self.settings.github_token:
            raise GitHubIntegrationError("GITHUB_TOKEN is required for PR automation")
        repository = github_repository or self._repository_from_remote(repo_path)
        if not repository:
            raise GitHubIntegrationError("Could not determine GitHub repository owner/name")
        base = base_branch or self.settings.github_default_base_branch
        self._git(repo_path, ["checkout", "-B", branch_name])
        self._git(repo_path, ["add", "-A"])
        status = self._git(repo_path, ["status", "--porcelain"])
        if not status.stdout.strip():
            return None
        self._git(repo_path, ["commit", "-m", title])
        self._git(repo_path, ["push", "origin", branch_name, "--force-with-lease"])
        pr_head = f"{fork_owner}:{branch_name}" if fork_owner else branch_name
        return await self._create_pr(repository=repository, head=pr_head, base=base, title=title, body=body)

    async def create_fork(self, repository: str) -> tuple[str, str]:
        if not self.settings.github_token:
            raise GitHubIntegrationError("GITHUB_TOKEN is required for forking automation")
        url = f"https://api.github.com/repos/{repository}/forks"
        headers = self._headers()
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(url, headers=headers)
            response.raise_for_status()
            payload = response.json()
            fork_full_name = payload["full_name"]
            fork_owner = payload["owner"]["login"]
            
            import asyncio
            for _ in range(15):
                check = await client.get(f"https://api.github.com/repos/{fork_full_name}", headers=headers)
                if check.status_code == 200:
                    break
                await asyncio.sleep(2)
        return fork_full_name, fork_owner

    async def create_issue(self, *, repository: str, title: str, body: str) -> str:
        if not self.settings.github_token:
            raise GitHubIntegrationError("GITHUB_TOKEN is required for issue automation")
        url = f"https://api.github.com/repos/{repository}/issues"
        headers = self._headers()
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(url, headers=headers, json={"title": title, "body": body})
            response.raise_for_status()
            payload = response.json()
        return payload["html_url"]

    async def _create_pr(
        self,
        *,
        repository: str,
        head: str,
        base: str,
        title: str,
        body: str,
    ) -> str:
        url = f"https://api.github.com/repos/{repository}/pulls"
        headers = self._headers()
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                url,
                headers=headers,
                json={"title": title, "head": head, "base": base, "body": body},
            )
            response.raise_for_status()
            payload = response.json()
        return payload["html_url"]

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.settings.github_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _repository_from_remote(self, repo_path: Path) -> str | None:
        result = self._git(repo_path, ["remote", "get-url", "origin"], allow_failure=True)
        remote = result.stdout.strip()
        patterns = [
            r"github\.com[:/](?P<repo>[^/]+/[^/.]+)(?:\.git)?$",
            r"https://[^/]*github\.com/(?P<repo>[^/]+/[^/.]+)(?:\.git)?$",
        ]
        for pattern in patterns:
            match = re.search(pattern, remote)
            if match:
                return match.group("repo")
        return None

    def _git(
        self,
        repo_path: Path,
        args: list[str],
        *,
        allow_failure: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            self._git_command(args),
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0 and not allow_failure:
            raise GitHubIntegrationError(result.stderr.strip() or f"git {' '.join(args)} failed")
        return result

    def _git_command(self, args: list[str]) -> list[str]:
        command = ["git"]
        if self.settings.github_token:
            auth = base64.b64encode(f"x-access-token:{self.settings.github_token}".encode()).decode()
            command.extend(
                [
                    "-c",
                    f"http.https://github.com/.extraheader=AUTHORIZATION: basic {auth}",
                ]
            )
        command.extend(args)
        return command
