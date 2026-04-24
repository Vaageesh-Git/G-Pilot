from __future__ import annotations

from functools import lru_cache

from vuln_swarm.core.config import Settings, get_settings
from vuln_swarm.storage.job_store import JobStore
from vuln_swarm.workers.pipeline import PipelineRunner


@lru_cache
def get_store() -> JobStore:
    settings = get_settings()
    return JobStore(settings.runs_dir)


@lru_cache
def get_runner() -> PipelineRunner:
    settings = get_settings()
    return PipelineRunner(settings=settings, store=get_store())


def settings_dependency() -> Settings:
    return get_settings()
