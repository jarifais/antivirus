"""Capa de operaciones sobre volumen; las transferencias deben ser atómicas."""
from __future__ import annotations

import os
from pathlib import Path


def atomic_move_same_volume(src: Path, dst: Path) -> None:
    if src.stat().st_dev != dst.parent.stat().st_dev:
        raise ValueError("Se requiere el mismo volumen para un handoff atómico")
    if dst.exists():
        raise FileExistsError(str(dst))
    os.replace(src, dst)
