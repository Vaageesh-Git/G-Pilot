from importlib import metadata
from pathlib import Path
import subprocess

import _test_bootstrap  # noqa: F401

from vuln_swarm.agents.patcher import DeterministicPatchApplier
from vuln_swarm.schemas import Evidence, Severity, Vulnerability


def test_patcher_replaces_yaml_load(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text("import yaml\nvalue = yaml.load(data)\n", encoding="utf-8")
    vulnerability = Vulnerability(
        id="TRB-002-test",
        vuln_id="TRB-002",
        title="Unsafe yaml.load",
        category="Trust Boundary",
        cwe="CWE-502",
        severity=Severity.critical,
        description="Unsafe YAML",
        affected_files=["app.py"],
        evidence=[Evidence(file_path="app.py", detector="test", confidence=1.0)],
    )
    fix = DeterministicPatchApplier().apply(repo_path=tmp_path, vulnerability=vulnerability, citations=[])
    assert fix.status == "applied"
    assert "yaml.safe_load(data)" in source.read_text(encoding="utf-8")


def test_patcher_compiles_requirements_with_hashes(tmp_path: Path, monkeypatch) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "demo"
version = "0.1.0"
dependencies = ["requests"]
""".strip()
        + "\n",
        encoding="utf-8",
    )
    vulnerability = Vulnerability(
        id="DEP-003-test",
        vuln_id="DEP-003",
        title="Unpinned Dependency Version",
        category="Dependency",
        cwe="CWE-1357",
        severity=Severity.medium,
        description="Floating dependency",
        affected_files=["requirements.txt"],
        evidence=[Evidence(file_path="requirements.txt", detector="test", confidence=1.0)],
    )
    commands: list[list[str]] = []

    def fake_run(
        command: list[str],
        *,
        cwd: Path,
        check: bool,
        capture_output: bool,
        text: bool,
    ) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        output_file = Path(command[command.index("--output-file") + 1])
        output_file.write_text(
            "requests==2.32.3 \\\n"
            "    --hash=sha256:abc123 \\\n"
            "    --hash=sha256:def456\n",
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr("vuln_swarm.agents.patcher.subprocess.run", fake_run)
    patcher = DeterministicPatchApplier(python_executable="/tmp/fake-python")

    first_fix = patcher.apply(repo_path=tmp_path, vulnerability=vulnerability, citations=[])
    second_fix = patcher.apply(
        repo_path=tmp_path,
        vulnerability=vulnerability.model_copy(update={"id": "DEP-004-test", "vuln_id": "DEP-004"}),
        citations=[],
    )

    assert first_fix.status == "applied"
    assert second_fix.status == "applied"
    assert len(commands) == 1
    assert commands[0][:4] == ["/tmp/fake-python", "-m", "piptools", "compile"]
    assert "--generate-hashes" in commands[0]
    assert "requests==2.32.3" in requirements.read_text(encoding="utf-8")


def test_patcher_falls_back_to_pypi_metadata_locking(tmp_path: Path, monkeypatch) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "demo"
version = "0.1.0"
dependencies = ["requests"]
""".strip()
        + "\n",
        encoding="utf-8",
    )
    vulnerability = Vulnerability(
        id="DEP-003-test",
        vuln_id="DEP-003",
        title="Unpinned Dependency Version",
        category="Dependency",
        cwe="CWE-1357",
        severity=Severity.medium,
        description="Floating dependency",
        affected_files=["requirements.txt"],
        evidence=[Evidence(file_path="requirements.txt", detector="test", confidence=1.0)],
    )

    def fake_run(
        command: list[str],
        *,
        cwd: Path,
        check: bool,
        capture_output: bool,
        text: bool,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            command,
            1,
            stdout="",
            stderr="No module named piptools",
        )

    class FakeResponse:
        def __init__(self, payload: dict):
            self._payload = payload

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return self._payload

    def fake_get(url: str, *, follow_redirects: bool, timeout: float) -> FakeResponse:
        assert follow_redirects is True
        assert timeout == 10.0
        if url.endswith("/requests/json"):
            return FakeResponse(
                {
                    "releases": {
                        "2.32.3": [
                            {"digests": {"sha256": "abc123"}},
                            {"digests": {"sha256": "def456"}},
                        ]
                    }
                }
            )
        raise AssertionError(f"Unexpected URL: {url}")

    monkeypatch.setattr("vuln_swarm.agents.patcher.subprocess.run", fake_run)
    monkeypatch.setattr("vuln_swarm.agents.patcher.shutil.which", lambda _: None)
    monkeypatch.setattr("vuln_swarm.agents.patcher.httpx.get", fake_get)
    monkeypatch.setattr("vuln_swarm.agents.patcher.metadata.version", lambda _: (_ for _ in ()).throw(metadata.PackageNotFoundError()))

    fix = DeterministicPatchApplier(python_executable="/tmp/fake-python").apply(
        repo_path=tmp_path,
        vulnerability=vulnerability,
        citations=[],
    )

    assert fix.status == "applied"
    assert "PyPI release metadata" in (fix.notes or "")
    contents = requirements.read_text(encoding="utf-8")
    assert "requests==2.32.3" in contents
    assert "--hash=sha256:abc123" in contents
    assert "--hash=sha256:def456" in contents
