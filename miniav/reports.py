from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from .core.models import ScanResult
from .state import Job


def safe_name(name: str, limit: int = 120) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in name)[:limit] or "unnamed"


def write_scan_report(result: ScanResult, job: Job, reports_root: Path, decision: str, reason: str) -> Path:
    now = datetime.now()
    day = reports_root / now.strftime("%Y-%m-%d")
    day.mkdir(parents=True, exist_ok=True)
    original = Path(job.source_path).name
    short = result.sha256[:12] if result.sha256 else job.job_id[:12]
    out = day / f"{now.strftime('%H%M%S_%f')}_{safe_name(original)}_{short}.json"
    payload = {
        "job": {
            "job_id": job.job_id,
            "source_path": job.source_path,
            "processing_path": result.path,
            "decision": decision,
            "decision_reason": reason,
        },
        "scan": result.to_dict(),
    }
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return out
