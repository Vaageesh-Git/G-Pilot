from __future__ import annotations

from collections import Counter
from pathlib import Path

from vuln_swarm.core.config import Settings
from vuln_swarm.git.github import GitHubIntegrationError, GitHubIntegrator
from vuln_swarm.rag.vector_store import ChromaKnowledgeBase
from vuln_swarm.scanner.static import StaticAnalyzer
from vuln_swarm.schemas import (
    FixReport,
    ValidationReport,
    ValidationStatus,
    Vulnerability,
    VulnerabilityReport,
)


class ValidationAgent:
    def __init__(
        self,
        *,
        settings: Settings,
        scanner: StaticAnalyzer,
        knowledge_base: ChromaKnowledgeBase,
        github: GitHubIntegrator,
    ):
        self.settings = settings
        self.scanner = scanner
        self.knowledge_base = knowledge_base
        self.github = github

    async def run(
        self,
        *,
        run_id: str,
        repo_path: Path,
        original_report: VulnerabilityReport,
        fix_report: FixReport,
        retry_count: int,
        create_pr: bool,
        github_repository: str,
        base_branch: str | None,
        fork_owner: str | None = None,
    ) -> ValidationReport:
        rescanned = self.scanner.scan(repo_path)
        residual = self._match_residual(original_report.vulnerabilities, rescanned)
        tests_passed = all(test.passed for test in fix_report.tests)
        fixed = not residual and tests_passed
        citations = self.knowledge_base.retrieve(
            "fixes",
            "how to verify patch fixed vulnerability and reject naive remediation",
            top_k=4,
        )
        pr_url: str | None = None
        feedback: str | None = None
        status = ValidationStatus.fixed if fixed else ValidationStatus.not_fixed

        if fixed and create_pr:
            try:
                pr_url = await self.github.commit_and_create_pr(
                    repo_path=repo_path,
                    github_repository=github_repository,
                    branch_name=f"fix/vuln-swarm-{run_id[:8]}",
                    base_branch=base_branch,
                    title=f"Fix security findings from Vuln-Swarm run {run_id[:8]}",
                    body=build_pr_body(original_report, fix_report),
                    fork_owner=fork_owner,
                )
            except GitHubIntegrationError as exc:
                feedback = f"Fix validated, but PR automation failed: {exc}"
                status = ValidationStatus.needs_human

        if not fixed:
            feedback = self._feedback(residual, fix_report)

        return ValidationReport(
            run_id=run_id,
            retry_count=retry_count,
            validation_status=status,
            fixed=fixed,
            residual_vulnerabilities=residual,
            compared_vulnerability_ids=[vulnerability.id for vulnerability in original_report.vulnerabilities],
            tests=fix_report.tests,
            pr_url=pr_url,
            feedback_to_remediation=feedback,
            rag_citations=citations,
            summary=(
                "Validation passed; no original vulnerabilities were rediscovered."
                if fixed
                else f"Validation failed; {len(residual)} residual vulnerabilities remain."
            ),
        )

    def _match_residual(
        self,
        original: list[Vulnerability],
        rescanned: list[Vulnerability],
    ) -> list[Vulnerability]:
        original_keys = {
            (vuln.vuln_id, file_path)
            for vuln in original
            for file_path in vuln.affected_files
        }
        return [
            vuln
            for vuln in rescanned
            if any((vuln.vuln_id, file_path) in original_keys for file_path in vuln.affected_files)
        ]

    def _feedback(self, residual: list[Vulnerability], fix_report: FixReport) -> str:
        grouped = Counter((v.vuln_id, tuple(v.affected_files)) for v in residual)
        residual_text = ", ".join(
            f"{vuln_id} in {', '.join(file_paths)}"
            + (f" ({count} occurrences)" if count > 1 else "")
            for (vuln_id, file_paths), count in grouped.items()
        )
        failed_tests = [test.command for test in fix_report.tests if not test.passed]
        parts = []
        if residual_text:
            parts.append(f"Residual findings remain: {residual_text}.")
        if failed_tests:
            parts.append(f"Failing tests: {', '.join(failed_tests)}.")
        if not parts:
            parts.append("Patch did not satisfy validation criteria; review Agent C citations.")
        return " ".join(parts)


def build_pr_body(original_report: VulnerabilityReport, fix_report: FixReport) -> str:
    vuln_lines = "\n".join(
        f"- `{vulnerability.vuln_id}` {vulnerability.title}: {', '.join(vulnerability.affected_files)}"
        for vulnerability in original_report.vulnerabilities
    )
    test_lines = "\n".join(
        f"- `{test.command}`: {'passed' if test.passed else 'failed'}"
        for test in fix_report.tests
    ) or "- No test command detected."
    history_note = (
        "\n\nSecret history purge is required. Rotate affected credentials and rewrite git history."
        if fix_report.history_purge_required
        else ""
    )
    return f"""Automated security remediation generated by Vuln-Swarm.

## Findings

{vuln_lines or "- No findings."}

## Tests

{test_lines}
{history_note}
"""
