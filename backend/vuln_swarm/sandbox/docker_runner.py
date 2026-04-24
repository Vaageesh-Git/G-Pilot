from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

from vuln_swarm.core.config import Settings
from vuln_swarm.schemas import ExploitResult, TestResult


class DockerSandbox:
    def __init__(self, settings: Settings):
        self.settings = settings

    def run_exploit(
        self,
        *,
        run_id: str,
        vulnerability_id: str,
        repo_path: Path,
        script: str,
        language: str = "python",
    ) -> ExploitResult:
        script_dir = self.settings.runs_dir / run_id / "exploits"
        script_dir.mkdir(parents=True, exist_ok=True)
        extension = {"python": "py", "bash": "sh", "node": "js"}.get(language, "txt")
        script_path = script_dir / f"{vulnerability_id}.{extension}"
        script_path.write_text(script, encoding="utf-8")

        if language == "python":
            command = ["python", f"/runner/{script_path.name}"]
        elif language == "bash":
            command = ["bash", f"/runner/{script_path.name}"]
        elif language == "node":
            command = ["node", f"/runner/{script_path.name}"]
        else:
            return ExploitResult(
                vulnerability_id=vulnerability_id,
                executed=False,
                success=False,
                reason=f"Unsupported exploit language: {language}",
            )

        started = time.monotonic()
        try:
            completed = self._docker_run(repo_path, script_dir, command)
        except FileNotFoundError:
            return ExploitResult(
                vulnerability_id=vulnerability_id,
                executed=False,
                success=False,
                reason="Docker CLI is not installed or not on PATH.",
            )
        except subprocess.TimeoutExpired as exc:
            return ExploitResult(
                vulnerability_id=vulnerability_id,
                executed=True,
                success=False,
                stdout=(exc.stdout or b"").decode(errors="ignore") if isinstance(exc.stdout, bytes) else str(exc.stdout or ""),
                stderr="Sandbox execution timed out.",
                duration_ms=int((time.monotonic() - started) * 1000),
            )
        duration_ms = int((time.monotonic() - started) * 1000)
        return ExploitResult(
            vulnerability_id=vulnerability_id,
            executed=True,
            success=completed.returncode == 0,
            exit_code=completed.returncode,
            stdout=completed.stdout[-4000:],
            stderr=completed.stderr[-4000:],
            duration_ms=duration_ms,
        )

    def run_test_command(self, repo_path: Path, command: list[str]) -> TestResult:
        started = time.monotonic()
        try:
            completed = self._docker_run(repo_path, None, command, writable_repo=True)
        except FileNotFoundError:
            return self._host_test_result(
                repo_path,
                command,
                started=started,
                reason="Docker CLI not installed; ran tests on the host instead.",
            )
        except subprocess.TimeoutExpired as exc:
            return TestResult(
                command=" ".join(command),
                passed=False,
                stdout=(exc.stdout or b"").decode(errors="ignore") if isinstance(exc.stdout, bytes) else str(exc.stdout or ""),
                stderr="Sandbox test command timed out.",
                duration_ms=int((time.monotonic() - started) * 1000),
            )
        if completed.returncode != 0 and self._docker_unavailable(completed.stderr):
            return self._host_test_result(
                repo_path,
                command,
                started=started,
                reason="Docker daemon unavailable; ran tests on the host instead.",
            )
        return TestResult(
            command=" ".join(command),
            passed=completed.returncode == 0,
            exit_code=completed.returncode,
            stdout=completed.stdout[-4000:],
            stderr=completed.stderr[-4000:],
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    def _docker_run(
        self,
        repo_path: Path,
        runner_path: Path | None,
        command: list[str],
        *,
        writable_repo: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        docker_command = [
            "docker",
            "run",
            "--rm",
            "--cpus",
            self.settings.sandbox_cpus,
            "--memory",
            self.settings.sandbox_memory,
            "--security-opt",
            "no-new-privileges",
        ]
        if self.settings.sandbox_network_disabled:
            docker_command.extend(["--network", "none"])
        repo_mode = "rw" if writable_repo else "ro"
        docker_command.extend(["-v", f"{repo_path.resolve()}:/workspace:{repo_mode}", "-w", "/workspace"])
        if runner_path is not None:
            docker_command.extend(["-v", f"{runner_path.resolve()}:/runner:ro"])
        docker_command.append(self.settings.sandbox_docker_image)
        docker_command.extend(command)
        return subprocess.run(
            docker_command,
            check=False,
            capture_output=True,
            text=True,
            timeout=self.settings.sandbox_timeout_seconds,
        )

    def _host_test_result(
        self,
        repo_path: Path,
        command: list[str],
        *,
        started: float,
        reason: str,
    ) -> TestResult:
        try:
            completed = self._run_host_command(repo_path, command)
        except FileNotFoundError as exc:
            return TestResult(
                command=" ".join(command),
                passed=False,
                stderr=f"{reason}\nHost test runner unavailable: {exc}".strip(),
                duration_ms=int((time.monotonic() - started) * 1000),
            )
        stderr = "\n".join(part for part in (reason, completed.stderr[-4000:]) if part).strip()
        return TestResult(
            command=" ".join(command),
            passed=completed.returncode == 0,
            exit_code=completed.returncode,
            stdout=completed.stdout[-4000:],
            stderr=stderr,
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    def _run_host_command(self, repo_path: Path, command: list[str]) -> subprocess.CompletedProcess[str]:
        host_command = command[:]
        if host_command and host_command[0] in {"python", "python3"}:
            host_command[0] = sys.executable
        return subprocess.run(
            host_command,
            cwd=repo_path,
            check=False,
            capture_output=True,
            text=True,
            timeout=self.settings.sandbox_timeout_seconds,
        )

    def _docker_unavailable(self, stderr: str) -> bool:
        message = stderr.lower()
        return any(
            token in message
            for token in (
                "docker api",
                "cannot connect to the docker daemon",
                "error during connect",
                "connect: no such file or directory",
            )
        )
