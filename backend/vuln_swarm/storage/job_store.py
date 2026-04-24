from __future__ import annotations

import json
import os
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from vuln_swarm.schemas import JobRecord, JobStatus, ScanRepoRequest, TraceEvent


class JobNotFoundError(KeyError):
    pass


class JobStore:
    def __init__(self, runs_dir: Path):
        self.runs_dir = runs_dir
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    def create(self, request: ScanRepoRequest) -> JobRecord:
        record = JobRecord(request=request)
        self.save(record)
        return record

    def get(self, job_id: str) -> JobRecord:
        path = self._path(job_id)
        if not path.exists():
            raise JobNotFoundError(job_id)
        with self._lock:
            return JobRecord.model_validate_json(path.read_text(encoding="utf-8"))

    def save(self, record: JobRecord) -> None:
        record.updated_at = datetime.now(UTC)
        path = self._path(record.id)
        path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = path.with_suffix(".tmp")
        payload = record.model_dump_json(indent=2)
        with self._lock:
            temp_path.write_text(payload, encoding="utf-8")
            os.replace(temp_path, path)

    def update(self, job_id: str, mutator: Callable[[JobRecord], None]) -> JobRecord:
        with self._lock:
            record = self.get(job_id)
            mutator(record)
            self.save(record)
            return record

    def append_trace(
        self,
        job_id: str,
        event: TraceEvent,
        *,
        status: JobStatus | None = None,
        current_step: str | None = None,
    ) -> JobRecord:
        def mutate(record: JobRecord) -> None:
            record.trace.append(event)
            if status is not None:
                record.status = status
            if current_step is not None:
                record.current_step = current_step

        return self.update(job_id, mutate)

    def list_recent(self, limit: int = 50) -> list[JobRecord]:
        records: list[JobRecord] = []
        for path in sorted(self.runs_dir.glob("*.json"), reverse=True):
            try:
                records.append(JobRecord.model_validate_json(path.read_text(encoding="utf-8")))
            except (json.JSONDecodeError, ValueError):
                continue
            if len(records) >= limit:
                break
        return records

    def _path(self, job_id: str) -> Path:
        safe_id = "".join(ch for ch in job_id if ch.isalnum() or ch in {"-", "_"})
        return self.runs_dir / f"{safe_id}.json"
