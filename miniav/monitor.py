"""Monitor por polling: procesa únicamente archivos observados como estables."""
from __future__ import annotations

import time
from pathlib import Path

from .config import validate_config
from .pipeline import process_one
from .state import Job, StateDB


def iter_candidates(incoming: Path, cfg: dict):
    walk = incoming.rglob("*") if bool(cfg.get("recursive", True)) else incoming.iterdir()
    ignored = tuple(str(e).lower() for e in cfg.get("ignore_extensions", []))
    for path in walk:
        try:
            if path.is_symlink() or not path.is_file():
                continue
            if path.name.lower().endswith(ignored) or path.name.startswith("."):
                continue
            yield path
        except OSError:
            continue


def run_monitor(cfg: dict, db_path: Path, reports_root: Path,
                *, once: bool = False, max_cycles: int | None = None) -> list[Job]:
    roles = validate_config(cfg, create_outputs=True)
    db = StateDB(db_path)
    seen: dict[Path, tuple[int, int, float]] = {}
    finished: list[Job] = []
    cycle = 0
    try:
        while True:
            cycle += 1
            now = time.monotonic()
            candidates = list(iter_candidates(roles["incoming_dir"], cfg))
            current = set(candidates)
            for path in list(seen):
                if path not in current:
                    del seen[path]
            for path in candidates:
                try:
                    stat = path.stat()
                    if stat.st_size == 0:
                        continue  # aún puede estar escribiéndose
                    previous = seen.get(path)
                    if previous is None or previous[:2] != (stat.st_size, stat.st_mtime_ns):
                        seen[path] = (stat.st_size, stat.st_mtime_ns, now)
                        continue
                    if now - previous[2] < float(cfg.get("stable_seconds", 10.0)):
                        continue
                    finished.append(process_one(path, roles, cfg, db, reports_root))
                    seen.pop(path, None)
                except (OSError, ValueError):
                    seen.pop(path, None)
            if once and max_cycles is None:
                # Una pasada completa de estabilidad, sin servicio perpetuo.
                if not candidates or not seen:
                    return finished
            if max_cycles is not None and cycle >= max_cycles:
                return finished
            time.sleep(max(0.1, float(cfg.get("poll_seconds", 2.0))))
    finally:
        db.close()
