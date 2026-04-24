from __future__ import annotations

from typing import TypedDict

from vuln_swarm.schemas import (
    FixReport,
    ScanRepoRequest,
    TraceEvent,
    ValidationReport,
    ValidationStatus,
    VulnerabilityReport,
)


class SwarmState(TypedDict, total=False):
    run_id: str
    request: ScanRepoRequest
    repository_path: str
    repository: str
    commit_sha: str | None
    vulnerability_report: VulnerabilityReport
    fix_report: FixReport
    validation_report: ValidationReport
    validation_status: ValidationStatus
    retry_count: int
    max_retry_count: int
    remediation_feedback: str | None
    trace: list[TraceEvent]
    errors: list[str]
