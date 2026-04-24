from __future__ import annotations

import json
from pathlib import Path


def detect_test_commands(repo_path: Path) -> list[list[str]]:
    commands: list[list[str]] = []
    if _has_pytest_targets(repo_path):
        commands.append(["python", "-m", "pytest", "-q"])
    package_json = repo_path / "package.json"
    if package_json.exists():
        try:
            package = json.loads(package_json.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            package = {}
        scripts = package.get("scripts", {}) if isinstance(package, dict) else {}
        if "test" in scripts:
            commands.append(["npm", "test"])
    if (repo_path / "go.mod").exists():
        commands.append(["go", "test", "./..."])
    return commands[:3]


def _has_pytest_targets(repo_path: Path) -> bool:
    if any((repo_path / name).exists() for name in ("pytest.ini", "conftest.py", "tests", "test")):
        return True

    pyproject = repo_path / "pyproject.toml"
    if pyproject.exists():
        text = pyproject.read_text(encoding="utf-8", errors="ignore")
        if "[tool.pytest" in text:
            return True

    return any(repo_path.rglob("test_*.py")) or any(repo_path.rglob("*_test.py"))
