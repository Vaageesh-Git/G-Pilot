from pathlib import Path

from vuln_swarm.core.config import Settings
from vuln_swarm.scanner.static import StaticAnalyzer


def test_static_scanner_detects_yaml_and_eval(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        """
import yaml

def load_config(data):
    return yaml.load(data)

def parse_expr(expr):
    return eval(expr)
""",
        encoding="utf-8",
    )
    scanner = StaticAnalyzer(Settings(VULN_SWARM_DATA_DIR=str(tmp_path / ".data")))
    report = scanner.scan(tmp_path)
    ids = {finding.vuln_id for finding in report}
    assert "TRB-002" in ids
    assert "TRB-001" in ids


def test_static_scanner_detects_dependency_pinning(tmp_path: Path) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests>=2.0\nfastapi==0.115.0\n", encoding="utf-8")
    scanner = StaticAnalyzer(Settings(VULN_SWARM_DATA_DIR=str(tmp_path / ".data")))
    report = scanner.scan(tmp_path)
    ids = {finding.vuln_id for finding in report}
    assert "DEP-003" in ids
    assert "DEP-004" in ids


def test_static_scanner_accepts_piptools_multiline_hashes(tmp_path: Path) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text(
        "requests==2.32.3 \\\n"
        "    --hash=sha256:abc123 \\\n"
        "    --hash=sha256:def456\n",
        encoding="utf-8",
    )
    scanner = StaticAnalyzer(Settings(VULN_SWARM_DATA_DIR=str(tmp_path / ".data")))
    report = scanner.scan(tmp_path)
    ids = {finding.vuln_id for finding in report}
    assert "DEP-003" not in ids
    assert "DEP-004" not in ids
