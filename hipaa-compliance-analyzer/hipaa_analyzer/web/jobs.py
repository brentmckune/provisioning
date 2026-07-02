"""In-memory job manager: one background thread per analysis run.

Jobs live for the duration of the server process. The rendered report and
raw JSON are also written to the job's working directory so they survive
as files, but the GUI reads from memory.
"""

from __future__ import annotations

import secrets
import threading
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from ..models import AnalysisResult


@dataclass
class OrgInfo:
    name: str = ""
    org_type: str = ""
    contact_name: str = ""
    contact_email: str = ""


@dataclass
class Job:
    id: str
    org: OrgInfo
    directory: Path
    files: list[str] = field(default_factory=list)
    status: str = "queued"  # queued | running | done | error
    message: str = "Queued"
    error: Optional[str] = None
    result: Optional[AnalysisResult] = None
    report_md: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    finished_at: Optional[datetime] = None


class JobManager:
    def __init__(self):
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def create(self, org: OrgInfo, directory: Path, files: list[str]) -> Job:
        job = Job(id=secrets.token_urlsafe(12), org=org, directory=directory, files=files)
        with self._lock:
            self._jobs[job.id] = job
        return job

    def get(self, job_id: str) -> Optional[Job]:
        with self._lock:
            return self._jobs.get(job_id)

    def all(self) -> list[Job]:
        with self._lock:
            return sorted(self._jobs.values(), key=lambda j: j.created_at, reverse=True)

    def set_message(self, job: Job, message: str) -> None:
        job.message = message

    def run_in_background(self, job: Job, target) -> None:
        """Run `target(job)` in a daemon thread, tracking status and errors."""

        def wrapper():
            job.status = "running"
            try:
                target(job)
                job.status = "done"
                job.message = "Complete"
            except Exception as e:  # surface any failure in the UI
                job.status = "error"
                job.error = f"{type(e).__name__}: {e}"
                job.message = "Failed"
                traceback.print_exc()
            finally:
                job.finished_at = datetime.now()

        threading.Thread(target=wrapper, daemon=True).start()
