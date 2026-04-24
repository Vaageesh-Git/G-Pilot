from __future__ import annotations

import asyncio
from pathlib import Path

from vuln_swarm.agents.patcher import DeterministicPatchApplier, LlmPatchPlan
from vuln_swarm.agents.testing import detect_test_commands
from vuln_swarm.core.config import Settings
from vuln_swarm.core.llm import GroqJsonClient, LlmUnavailableError
from vuln_swarm.rag.vector_store import ChromaKnowledgeBase
from vuln_swarm.sandbox.docker_runner import DockerSandbox
from vuln_swarm.schemas import AppliedFix, FixReport, PatchOperation, TestResult, VulnerabilityReport


class RemediationAgent:
    def __init__(
        self,
        *,
        settings: Settings,
        knowledge_base: ChromaKnowledgeBase,
        sandbox: DockerSandbox,
        llm: GroqJsonClient,
    ):
        self.settings = settings
        self.knowledge_base = knowledge_base
        self.sandbox = sandbox
        self.llm = llm
        self.patcher = DeterministicPatchApplier()

    async def run(
        self,
        *,
        run_id: str,
        repo_path: Path,
        report: VulnerabilityReport,
        retry_count: int,
        feedback: str | None = None,
    ) -> FixReport:
        if not report.vulnerabilities:
            return FixReport(
                run_id=run_id,
                retry_count=retry_count,
                fixes=[],
                files_changed=[],
                tests=[],
                status="no_vulnerabilities",
                summary="No remediation was required.",
            )

        fixes: list[AppliedFix] = []
        for vulnerability in report.vulnerabilities:
            citations = self.knowledge_base.retrieve(
                "fixes",
                f"{vulnerability.vuln_id} {vulnerability.title} {vulnerability.remediation_hint or ''}",
                top_k=3,
            )
            fixes.append(
                self.patcher.apply(repo_path=repo_path, vulnerability=vulnerability, citations=citations)
            )

        manual_fixes = [fix for fix in fixes if fix.status == "manual_required"]
        if manual_fixes and self.llm.enabled:
            llm_operations = await self._plan_llm_operations(report, manual_fixes, feedback)
            applied_operations = self.patcher.apply_llm_operations(repo_path=repo_path, operations=llm_operations)
            fixes.extend(self._llm_operations_to_fixes(applied_operations))

        tests = await self._run_tests(repo_path)
        files_changed = sorted(
            {
                operation.file_path
                for fix in fixes
                for operation in fix.operations
                if operation.applied and operation.file_path
            }
        )
        applied_count = sum(1 for fix in fixes if fix.status == "applied")
        status = "patched" if applied_count and applied_count == len(report.vulnerabilities) else "partial"
        if not applied_count:
            status = "failed"
        history_purge_required = any(vuln.vuln_id.startswith("SEC-") for vuln in report.vulnerabilities)
        return FixReport(
            run_id=run_id,
            retry_count=retry_count,
            fixes=fixes,
            files_changed=files_changed,
            tests=tests,
            history_purge_required=history_purge_required,
            status=status,  # type: ignore[arg-type]
            summary=f"Applied {applied_count} deterministic or LLM-guided fix groups; {len(manual_fixes)} required escalation.",
        )

    async def _plan_llm_operations(
        self,
        report: VulnerabilityReport,
        manual_fixes: list[AppliedFix],
        feedback: str | None,
    ) -> list[PatchOperation]:
        payload = {
            "vulnerability_report": report.model_dump(mode="json"),
            "manual_fix_groups": [fix.model_dump(mode="json") for fix in manual_fixes],
            "validator_feedback": feedback,
            "constraints": [
                "Return exact original/replacement snippets only.",
                "Do not rewrite unrelated files.",
                "Prefer AST-preserving minimal changes.",
                "Mark operation as manual_required if exact replacement cannot be guaranteed.",
            ],
        }
        try:
            plan = await self.llm.complete_json(
                system_prompt="You are Agent B, a security remediation engineer.",
                user_payload=payload,
                output_model=LlmPatchPlan,
                schema_name="LlmPatchPlan",
            )
        except (LlmUnavailableError, Exception):
            return []
        return plan.operations

    def _llm_operations_to_fixes(self, operations: list[PatchOperation]) -> list[AppliedFix]:
        grouped: dict[str, list[PatchOperation]] = {}
        for operation in operations:
            grouped.setdefault(operation.file_path, []).append(operation)
        return [
            AppliedFix(
                vulnerability_id="llm-planned",
                file_path=file_path,
                strategy="groq-exact-patch-plan",
                operations=file_operations,
                status="applied" if any(operation.applied for operation in file_operations) else "manual_required",
                notes="Patch operations generated in a single Groq call for cost control.",
            )
            for file_path, file_operations in grouped.items()
        ]

    async def _run_tests(self, repo_path: Path) -> list[TestResult]:
        commands = detect_test_commands(repo_path)
        tests: list[TestResult] = []
        for command in commands:
            tests.append(await asyncio.to_thread(self.sandbox.run_test_command, repo_path, command))
        return tests
