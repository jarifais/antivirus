"""Handoff conservador: Incoming -> Processing -> Clean/Quarantine/Error."""
from __future__ import annotations

import os
import uuid
from pathlib import Path

from .core.policy import decide
from .core.scanner import scan_file
from .reports import write_scan_report
from .state import Job, StateDB


def _new_destination(folder: Path, name: str) -> Path:
    # Evitar sobrescribir un fichero ya presente.
    for _ in range(20):
        destination = folder / f"{uuid.uuid4().hex}_{name}"
        if not destination.exists():
            return destination
    raise RuntimeError("No se pudo crear un nombre de destino único")


def process_one(source: Path, roles: dict[str, Path], cfg: dict,
                db: StateDB, reports_root: Path) -> Job:
    source = Path(source)
    incoming = roles["incoming_dir"]
    try:
        resolved = source.resolve(strict=True)
        if source.is_symlink() or not resolved.is_file() or incoming not in resolved.parents:
            raise ValueError("El archivo debe ser regular y estar dentro de Incoming")
    except OSError as exc:
        raise ValueError("Origen inaccesible") from exc

    job = db.save_job(Job.create(resolved))
    processing: Path | None = None
    result = None
    action = "ERROR"
    reason = "Fallo antes del análisis"
    try:
        processing = _new_destination(roles["processing_dir"], resolved.name)
        os.replace(resolved, processing)
        job.processing_path = str(processing)
        job.state = "PROCESSING"
        job = db.save_job(job)
        result = scan_file(processing, cfg)
        policy = decide(
            result, suspicious_threshold=int(cfg.get("suspicious_score", 45)),
            review_action=str(cfg.get("review_action", "quarantine")))
        action, reason = policy.action, policy.reason
        job.sha256, job.score = result.sha256, result.score
        # Antes de autorizar CLEAN: confirmar que no hubo ERROR, ni bloqueo, ni informe incoherente.
        if action == "CLEAN" and (not result.analysis_complete or result.error or result.errors):
            action, reason = "ERROR", "Análisis incompleto; denegada liberación"
        dest_key = {"CLEAN": "clean_dir", "QUARANTINED": "quarantine_dir",
                    "ERROR": "error_dir"}[action]
        target = _new_destination(roles[dest_key], resolved.name)
        os.replace(processing, target)
        processing = None
        job.target_path = str(target)
        job.state = action
        job = db.save_job(job)
    except Exception as exc:
        action, reason = "ERROR", f"{type(exc).__name__}: {exc}"
        job.error = reason
        if processing is not None and processing.exists():
            try:
                fallback = _new_destination(roles["error_dir"], resolved.name)
                os.replace(processing, fallback)
                job.target_path = str(fallback)
            except OSError as move_exc:
                job.error += f"; no se pudo mover a AV_Error: {move_exc}"
        job.state = "ERROR"
        job = db.save_job(job)
    if result is not None:
        try:
            write_scan_report(result, job, reports_root, action, reason)
        except OSError as exc:
            job.error = f"{job.error}; reporte: {exc}".strip("; ")
            job = db.save_job(job)
    return job
