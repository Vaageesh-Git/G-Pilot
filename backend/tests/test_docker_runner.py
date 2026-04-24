import subprocess
from pathlib import Path

import _test_bootstrap  # noqa: F401

from vuln_swarm.core.config import Settings
from vuln_swarm.sandbox.docker_runner import DockerSandbox


def test_run_test_command_falls_back_to_host_when_docker_is_unavailable(
    tmp_path: Path,
    monkeypatch,
) -> None:
    sandbox = DockerSandbox(Settings(VULN_SWARM_DATA_DIR=str(tmp_path / ".data")))

    def fake_docker_run(*args, **kwargs) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            ["docker", "run"],
            1,
            stdout="",
            stderr=(
                "failed to connect to the docker API at unix:///tmp/docker.sock; "
                "connect: no such file or directory"
            ),
        )

    def fake_host_run(repo_path: Path, command: list[str]) -> subprocess.CompletedProcess[str]:
        assert repo_path == tmp_path
        assert command == ["python", "-m", "pytest", "-q"]
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    monkeypatch.setattr(sandbox, "_docker_run", fake_docker_run)
    monkeypatch.setattr(sandbox, "_run_host_command", fake_host_run)

    result = sandbox.run_test_command(tmp_path, ["python", "-m", "pytest", "-q"])

    assert result.passed is True
    assert "host instead" in result.stderr
