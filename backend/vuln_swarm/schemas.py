from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
import re
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class JobStatus(StrEnum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    retrying = "retrying"
    cancelled = "cancelled"


class ValidationStatus(StrEnum):
    pending = "pending"
    fixed = "fixed"
    not_fixed = "not_fixed"
    needs_human = "needs_human"
    failed = "failed"


class AgentName(StrEnum):
    agent_a = "agent_a"
    agent_b = "agent_b"
    agent_c = "agent_c"


class Evidence(StrictModel):
    file_path: str
    line_start: int | None = None
    line_end: int | None = None
    code_excerpt: str | None = None
    detector: str
    confidence: float = Field(ge=0.0, le=1.0)


class RagCitation(StrictModel):
    collection: Literal["vulnerabilities", "exploits", "fixes"]
    document_id: str
    source: str
    score: float | None = None
    excerpt: str


class ExploitScript(StrictModel):
    vulnerability_id: str
    language: Literal["python", "bash", "node"] = "python"
    script: str
    expected_signal: str
    sandbox_safe: bool = True


class ExploitResult(StrictModel):
    vulnerability_id: str
    executed: bool
    success: bool
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    duration_ms: int | None = None
    reason: str | None = None


class Vulnerability(StrictModel):
    id: str
    vuln_id: str
    title: str
    category: str
    cwe: str | None = None
    severity: Severity
    description: str
    affected_files: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    exploit_pattern: str | None = None
    exploit_script: ExploitScript | None = None
    exploit_result: ExploitResult | None = None
    rag_citations: list[RagCitation] = Field(default_factory=list)
    remediation_hint: str | None = None


class VulnerabilityReport(StrictModel):
    run_id: str
    repository: str
    commit_sha: str | None = None
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    scanner_version: str = "0.1.0"
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    summary: str


class TestResult(StrictModel):
    command: str
    passed: bool
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    duration_ms: int | None = None


class PatchOperation(StrictModel):
    file_path: str
    operation: Literal["replace", "insert_after", "append", "manual_required"]
    original: str | None = None
    replacement: str | None = None
    rationale: str
    applied: bool = False


class AppliedFix(StrictModel):
    vulnerability_id: str
    file_path: str
    strategy: str
    operations: list[PatchOperation] = Field(default_factory=list)
    rag_citations: list[RagCitation] = Field(default_factory=list)
    status: Literal["applied", "manual_required", "failed"]
    notes: str | None = None


class FixReport(StrictModel):
    run_id: str
    retry_count: int
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    fixes: list[AppliedFix] = Field(default_factory=list)
    files_changed: list[str] = Field(default_factory=list)
    tests: list[TestResult] = Field(default_factory=list)
    history_purge_required: bool = False
    status: Literal["patched", "partial", "failed", "no_vulnerabilities"]
    summary: str


class ValidationReport(StrictModel):
    run_id: str
    retry_count: int
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    validation_status: ValidationStatus
    fixed: bool
    residual_vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    compared_vulnerability_ids: list[str] = Field(default_factory=list)
    tests: list[TestResult] = Field(default_factory=list)
    pr_url: str | None = None
    feedback_to_remediation: str | None = None
    rag_citations: list[RagCitation] = Field(default_factory=list)
    summary: str


class ScanRepoRequest(StrictModel):
    github_repository: str = Field(description="GitHub repository in owner/repo form")
    branch: str | None = None
    commit_sha: str | None = None
    base_branch: str | None = None
    create_pr: bool = False
    full_scan: bool = True
    max_retry_count: int | None = Field(default=None, ge=0, le=10)
    metadata: dict[str, Any] = Field(default_factory=dict)
    forked_repository: str | None = None
    fork_owner: str | None = None

    @field_validator("github_repository")
    @classmethod
    def normalize_github_repository(cls, value: str) -> str:
        cleaned = value.strip()
        cleaned = re.sub(r"^https?://github\.com/", "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"^git@github\.com:", "", cleaned, flags=re.IGNORECASE)
        cleaned = cleaned.removesuffix(".git").strip("/")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", cleaned):
            raise ValueError("github_repository must be in owner/repo form")
        return cleaned

    @property
    def clone_url(self) -> str:
        if self.forked_repository:
            return f"https://github.com/{self.forked_repository}.git"
        return f"https://github.com/{self.github_repository}.git"


class ScanRepoResponse(StrictModel):
    id: str
    status: JobStatus
    status_url: str
    report_url: str


class TraceEvent(StrictModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    agent: AgentName | None = None
    step: str
    status: str
    message: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class PipelineStatus(StrictModel):
    id: str
    status: JobStatus
    current_step: str | None = None
    created_at: datetime
    updated_at: datetime
    retry_count: int = 0
    validation_status: ValidationStatus = ValidationStatus.pending
    trace: list[TraceEvent] = Field(default_factory=list)
    error: str | None = None


class ReportResponse(StrictModel):
    id: str
    status: JobStatus
    request: ScanRepoRequest
    vulnerability_report: VulnerabilityReport | None = None
    fix_report: FixReport | None = None
    validation_report: ValidationReport | None = None
    trace: list[TraceEvent] = Field(default_factory=list)
    error: str | None = None


class JobRecord(StrictModel):
    id: str = Field(default_factory=lambda: uuid4().hex)
    request: ScanRepoRequest
    status: JobStatus = JobStatus.queued
    current_step: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    retry_count: int = 0
    validation_status: ValidationStatus = ValidationStatus.pending
    repository_path: str | None = None
    vulnerability_report: VulnerabilityReport | None = None
    fix_report: FixReport | None = None
    validation_report: ValidationReport | None = None
    trace: list[TraceEvent] = Field(default_factory=list)
    error: str | None = None

    def to_status(self) -> PipelineStatus:
        return PipelineStatus(
            id=self.id,
            status=self.status,
            current_step=self.current_step,
            created_at=self.created_at,
            updated_at=self.updated_at,
            retry_count=self.retry_count,
            validation_status=self.validation_status,
            trace=self.trace[-50:],
            error=self.error,
        )

    def to_report(self) -> ReportResponse:
        return ReportResponse(
            id=self.id,
            status=self.status,
            request=self.request,
            vulnerability_report=self.vulnerability_report,
            fix_report=self.fix_report,
            validation_report=self.validation_report,
            trace=self.trace,
            error=self.error,
        )
