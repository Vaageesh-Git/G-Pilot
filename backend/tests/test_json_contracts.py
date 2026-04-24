import pytest

import _test_bootstrap  # noqa: F401

from vuln_swarm.core.json_utils import StrictJsonError, validate_agent_json
from vuln_swarm.schemas import ScanRepoRequest, VulnerabilityReport


def test_vulnerability_report_rejects_extra_keys() -> None:
    raw = """
    {
      "run_id": "abc",
      "repository": "repo",
      "summary": "ok",
      "vulnerabilities": [],
      "unexpected": true
    }
    """
    with pytest.raises(StrictJsonError):
        validate_agent_json(raw, VulnerabilityReport)


def test_vulnerability_report_accepts_strict_json() -> None:
    raw = """
    {
      "run_id": "abc",
      "repository": "repo",
      "summary": "ok",
      "vulnerabilities": []
    }
    """
    report = validate_agent_json(raw, VulnerabilityReport)
    assert report.run_id == "abc"


def test_scan_repo_request_normalizes_github_url() -> None:
    request = ScanRepoRequest(github_repository="https://github.com/acme/platform.git")
    assert request.github_repository == "acme/platform"
    assert request.clone_url == "https://github.com/acme/platform.git"


def test_scan_repo_request_rejects_non_github_shape() -> None:
    with pytest.raises(ValueError):
        ScanRepoRequest(github_repository="not-a-repo")
