"""Base local SQLite de transiciones; no debe subirse a GitHub."""
from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Job:
    job_id: str
    source_path: str
    state: str = "DISCOVERED"
    processing_path: str = ""
    target_path: str = ""
    score: int | None = None
    sha256: str = ""
    error: str = ""
    created_at: str = ""
    updated_at: str = ""

    @classmethod
    def create(cls, source_path: Path | str) -> "Job":
        return cls(uuid.uuid4().hex, str(source_path), created_at=_now(), updated_at=_now())


class StateDB:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path), timeout=30)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("""CREATE TABLE IF NOT EXISTS jobs (
            job_id TEXT PRIMARY KEY, source_path TEXT NOT NULL,
            state TEXT NOT NULL, processing_path TEXT NOT NULL,
            target_path TEXT NOT NULL, score INTEGER, sha256 TEXT NOT NULL,
            error TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        )""")
        self.conn.commit()

    def save_job(self, job: Job) -> Job:
        job = replace(job, updated_at=_now())
        self.conn.execute("""INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(job_id) DO UPDATE SET
            state=excluded.state, processing_path=excluded.processing_path,
            target_path=excluded.target_path, score=excluded.score,
            sha256=excluded.sha256, error=excluded.error,
            updated_at=excluded.updated_at""", (
            job.job_id, job.source_path, job.state, job.processing_path,
            job.target_path, job.score, job.sha256, job.error,
            job.created_at or _now(), job.updated_at))
        self.conn.commit()
        return job

    def recent_jobs(self, limit: int = 30) -> list[Job]:
        cur = self.conn.execute("""SELECT job_id, source_path, state, processing_path,
            target_path, score, sha256, error, created_at, updated_at
            FROM jobs ORDER BY updated_at DESC LIMIT ?""", (max(0, min(int(limit), 1000)),))
        return [Job(*row) for row in cur.fetchall()]

    def close(self) -> None:
        self.conn.close()
