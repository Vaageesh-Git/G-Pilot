import _test_bootstrap  # noqa: F401

from vuln_swarm.agents.agent_c import ValidationAgent
from vuln_swarm.schemas import FixReport, Severity, Vulnerability


def test_validation_feedback_groups_repeated_residuals() -> None:
    residual = [
        Vulnerability(
            id=f"dep-{index}",
            vuln_id="DEP-003" if index % 2 else "DEP-004",
            title="Dependency finding",
            category="Dependency",
            cwe="CWE-1357",
            severity=Severity.medium,
            description="Residual dependency finding",
            affected_files=["requirements.txt"],
        )
        for index in range(1, 7)
    ]
    fix_report = FixReport(run_id="run-1", retry_count=0, status="patched", summary="ok")

    feedback = ValidationAgent._feedback(None, residual, fix_report)

    assert "DEP-003 in requirements.txt (3 occurrences)" in feedback
    assert "DEP-004 in requirements.txt (3 occurrences)" in feedback
