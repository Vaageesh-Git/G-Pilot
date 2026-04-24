from __future__ import annotations

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from vuln_swarm.api.dependencies import get_runner, get_store, settings_dependency
from vuln_swarm.core.config import Settings
from vuln_swarm.core.logging import configure_logging
from vuln_swarm.rag.vector_store import ChromaKnowledgeBase
from vuln_swarm.schemas import (
    JobStatus,
    PipelineStatus,
    ReportResponse,
    ScanRepoRequest,
    ScanRepoResponse,
    TraceEvent,
)
from vuln_swarm.storage.job_store import JobNotFoundError, JobStore
from vuln_swarm.workers.pipeline import PipelineRunner

configure_logging()


def create_app() -> FastAPI:
    app = FastAPI(
        title="Vuln-Swarm API",
        version="0.1.0",
        description="Multi-agent security automation with LangGraph, ChromaDB, Docker, and GitHub PR automation.",
    )

    settings = settings_dependency()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.resolved_cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": settings.app_name}

    @app.post("/scan-repo", response_model=ScanRepoResponse, status_code=202)
    async def scan_repo(
        request: ScanRepoRequest,
        background_tasks: BackgroundTasks,
        store: JobStore = Depends(get_store),
        runner: PipelineRunner = Depends(get_runner),
    ) -> ScanRepoResponse:
        record = store.create(request)
        store.append_trace(
            record.id,
            TraceEvent(step="queued", status="queued", message="Scan request accepted."),
            status=JobStatus.queued,
            current_step="queued",
        )
        background_tasks.add_task(runner.run, record.id)
        return ScanRepoResponse(
            id=record.id,
            status=JobStatus.queued,
            status_url=f"/status/{record.id}",
            report_url=f"/report/{record.id}",
        )

    @app.get("/status/{job_id}", response_model=PipelineStatus)
    async def status(job_id: str, store: JobStore = Depends(get_store)) -> PipelineStatus:
        try:
            return store.get(job_id).to_status()
        except JobNotFoundError:
            raise HTTPException(status_code=404, detail="Job not found") from None

    @app.get("/report/{job_id}", response_model=ReportResponse)
    async def report(job_id: str, store: JobStore = Depends(get_store)) -> ReportResponse:
        try:
            return store.get(job_id).to_report()
        except JobNotFoundError:
            raise HTTPException(status_code=404, detail="Job not found") from None

    @app.post("/retry/{job_id}", response_model=PipelineStatus, status_code=202)
    async def retry(
        job_id: str,
        background_tasks: BackgroundTasks,
        store: JobStore = Depends(get_store),
        runner: PipelineRunner = Depends(get_runner),
    ) -> PipelineStatus:
        try:
            record = store.get(job_id)
        except JobNotFoundError:
            raise HTTPException(status_code=404, detail="Job not found") from None
        if record.status == JobStatus.running:
            raise HTTPException(status_code=409, detail="Job is already running")
        store.append_trace(
            job_id,
            TraceEvent(step="retry", status="queued", message="Retry requested."),
            status=JobStatus.retrying,
            current_step="retry",
        )
        background_tasks.add_task(runner.retry, job_id)
        return store.get(job_id).to_status()

    @app.get("/knowledge/stats")
    async def knowledge_stats(settings: Settings = Depends(settings_dependency)) -> dict[str, int]:
        return ChromaKnowledgeBase(settings).stats()

    return app


app = create_app()
