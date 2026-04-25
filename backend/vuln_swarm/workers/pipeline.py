from __future__ import annotations

import traceback
from pathlib import Path

from vuln_swarm.agents.agent_a import OffensiveSecurityAgent
from vuln_swarm.agents.agent_b import RemediationAgent
from vuln_swarm.agents.agent_c import ValidationAgent
from vuln_swarm.core.config import Settings
from vuln_swarm.core.llm import GeminiJsonClient
from vuln_swarm.core.logging import get_logger
from vuln_swarm.git.github import GitHubIntegrator
from vuln_swarm.git.repository import RepositoryManager
from vuln_swarm.orchestration.graph import SwarmGraph
from vuln_swarm.rag.vector_store import ChromaKnowledgeBase
from vuln_swarm.sandbox.docker_runner import DockerSandbox
from vuln_swarm.scanner.static import StaticAnalyzer
from vuln_swarm.schemas import JobStatus, TraceEvent, ValidationStatus
from vuln_swarm.storage.job_store import JobStore

logger = get_logger(__name__)


class PipelineRunner:
    def __init__(self, *, settings: Settings, store: JobStore):
        self.settings = settings
        self.store = store
        self.repository_manager = RepositoryManager(settings)
        self.knowledge_base = ChromaKnowledgeBase(settings, base_dir=Path(__file__).resolve().parents[3])
        self.scanner = StaticAnalyzer(settings)
        self.sandbox = DockerSandbox(settings)
        self.llm = GeminiJsonClient(settings)
        self.github = GitHubIntegrator(settings)

    async def run(self, job_id: str) -> None:
        try:
            record = self.store.get(job_id)
            self.store.append_trace(
                job_id,
                TraceEvent(step="prepare", status="running", message="Preparing repository worktree."),
                status=JobStatus.running,
                current_step="prepare",
            )

            if record.request.create_pr:
                forked_repo, fork_owner = await self.github.create_fork(record.request.github_repository)
                record.request.forked_repository = forked_repo
                record.request.fork_owner = fork_owner
                self.store.update(job_id, lambda item: (
                    setattr(item.request, "forked_repository", forked_repo),
                    setattr(item.request, "fork_owner", fork_owner),
                ))

            repo_path = self.repository_manager.prepare(job_id, record.request)
            commit_sha = self.repository_manager.commit_sha(repo_path) or record.request.commit_sha
            self.store.update(
                job_id,
                lambda item: setattr(item, "repository_path", str(repo_path)),
            )
            self.store.append_trace(
                job_id,
                TraceEvent(step="rag", status="running", message="Ensuring Chroma knowledge collections are ready."),
                status=JobStatus.running,
                current_step="rag",
            )
            counts = self.knowledge_base.ingest(force=False)
            self.store.append_trace(
                job_id,
                TraceEvent(step="rag", status="completed", message="Knowledge base ready.", metadata=counts),
                status=JobStatus.running,
                current_step="agent_a",
            )

            graph = SwarmGraph(
                agent_a=OffensiveSecurityAgent(
                    settings=self.settings,
                    scanner=self.scanner,
                    knowledge_base=self.knowledge_base,
                    sandbox=self.sandbox,
                    llm=self.llm,
                ),
                agent_b=RemediationAgent(
                    settings=self.settings,
                    knowledge_base=self.knowledge_base,
                    sandbox=self.sandbox,
                    llm=self.llm,
                ),
                agent_c=ValidationAgent(
                    settings=self.settings,
                    scanner=self.scanner,
                    knowledge_base=self.knowledge_base,
                    github=self.github,
                ),
                trace_callback=self._trace(job_id),
            )
            max_retry_count = record.request.max_retry_count
            if max_retry_count is None:
                max_retry_count = self.settings.max_retry_count
            final_state = await graph.ainvoke(
                {
                    "run_id": job_id,
                    "request": record.request,
                    "repository_path": str(repo_path),
                    "repository": record.request.github_repository,
                    "commit_sha": commit_sha,
                    "retry_count": record.retry_count,
                    "max_retry_count": max_retry_count,
                    "validation_status": ValidationStatus.pending,
                    "errors": [],
                }
            )
            self._persist_final_state(job_id, final_state)
        except Exception as exc:
            logger.exception("Pipeline failed", extra={"run_id": job_id})
            error_message = f"{exc}\n{traceback.format_exc(limit=8)}"
            self.store.update(
                job_id,
                lambda item: (
                    setattr(item, "status", JobStatus.failed),
                    setattr(item, "current_step", "failed"),
                    setattr(item, "error", error_message),
                ),
            )

    async def retry(self, job_id: str) -> None:
        self.store.update(
            job_id,
            lambda item: (
                setattr(item, "status", JobStatus.retrying),
                setattr(item, "error", None),
                setattr(item, "current_step", "retry"),
            ),
        )
        await self.run(job_id)

    def _persist_final_state(self, job_id: str, state: dict) -> None:
        def mutate(record) -> None:
            record.vulnerability_report = state.get("vulnerability_report")
            record.fix_report = state.get("fix_report")
            record.validation_report = state.get("validation_report")
            record.retry_count = state.get("retry_count", record.retry_count)
            record.validation_status = state.get("validation_status", record.validation_status)
            record.current_step = "completed"
            record.status = JobStatus.completed
            record.error = None

        self.store.update(job_id, mutate)

    def _trace(self, job_id: str):
        async def callback(
            event: TraceEvent,
            status: JobStatus | None = None,
            current_step: str | None = None,
        ) -> None:
            self.store.append_trace(job_id, event, status=status, current_step=current_step)

        return callback
