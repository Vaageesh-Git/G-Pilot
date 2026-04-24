from pathlib import Path

from vuln_swarm.agents.testing import detect_test_commands


def test_detect_test_commands_ignores_plain_pyproject(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'demo'\nversion = '0.1.0'\n", encoding="utf-8")

    commands = detect_test_commands(tmp_path)

    assert ["python", "-m", "pytest", "-q"] not in commands


def test_detect_test_commands_picks_up_pytest_layout(tmp_path: Path) -> None:
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_sample.py").write_text("def test_ok():\n    assert True\n", encoding="utf-8")

    commands = detect_test_commands(tmp_path)

    assert ["python", "-m", "pytest", "-q"] in commands
