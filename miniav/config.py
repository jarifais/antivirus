"""Configuración del gatekeeper; reconstruido al no disponer del ZIP original."""
from __future__ import annotations

import json
import os
from pathlib import Path

DEFAULT_CONFIG = {
    "incoming_dir": "", "processing_dir": "", "clean_dir": "",
    "quarantine_dir": "", "error_dir": "", "recursive": True,
    "poll_seconds": 2.0, "stable_seconds": 10.0, "reconcile_seconds": 60.0,
    "ignore_extensions": [".part", ".part.met", ".tmp", ".temp", ".crdownload", ".download"],
    "suspicious_score": 45, "review_action": "quarantine",
    "max_archive_depth": 4, "max_archive_entries": 5000,
    "max_uncompressed_bytes": 2147483648, "max_member_bytes": 536870912,
    "max_expansion_ratio": 250.0, "yara_timeout_seconds": 15,
    "scan_timeout_seconds": 600,
}

def load_config(path: Path) -> dict:
    cfg = DEFAULT_CONFIG.copy()
    if path.is_file():
        obj = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(obj, dict):
            raise ValueError("La configuración debe ser un objeto JSON")
        cfg.update(obj)
    return cfg

def save_config(path: Path, cfg: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temp, path)

def default_pipeline_paths(incoming: Path) -> dict[str, str]:
    base = incoming.resolve().parent
    return {
        "processing_dir": str(base / "AV_Processing"),
        "clean_dir": str(base / "AV_Clean"),
        "quarantine_dir": str(base / "AV_Quarantine"),
        "error_dir": str(base / "AV_Error"),
    }

def common_emule_incoming_dirs() -> list[Path]:
    home = Path.home()
    guesses = [home / "Downloads" / "eMule" / "Incoming",
               home / "eMule" / "Incoming"]
    for variable in ("PROGRAMFILES", "PROGRAMFILES(X86)"):
        value = os.environ.get(variable)
        if value:
            guesses.append(Path(value) / "eMule" / "Incoming")
    return [p for p in guesses if p.is_dir()]

def validate_config(cfg: dict, *, create_outputs: bool = False) -> dict[str, Path]:
    fields = ("incoming_dir", "processing_dir", "clean_dir", "quarantine_dir", "error_dir")
    paths: dict[str, Path] = {}
    for key in fields:
        value = cfg.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"Falta ruta obligatoria: {key}")
        paths[key] = Path(value).expanduser().resolve()
    incoming = paths["incoming_dir"]
    if not incoming.is_dir():
        raise ValueError("Incoming no existe")
    norms = [os.path.normcase(str(p)) for p in paths.values()]
    if len(set(norms)) != len(norms):
        raise ValueError("Las cinco carpetas deben ser distintas")
    for name, p in paths.items():
        if name != "incoming_dir" and (p in incoming.parents or incoming in p.parents):
            raise ValueError("Las carpetas de salida no pueden contener Incoming ni estar dentro de ella")
    for a_name, a in paths.items():
        for b_name, b in paths.items():
            if a_name != b_name and (a in b.parents or b in a.parents):
                raise ValueError("No se admiten carpetas de roles anidadas")
    if create_outputs:
        for key in fields[1:]:
            paths[key].mkdir(parents=True, exist_ok=True)
    source_dev = incoming.stat().st_dev
    for key in fields[1:]:
        p = paths[key]
        existing = p
        while not existing.exists() and existing != existing.parent:
            existing = existing.parent
        if existing.stat().st_dev != source_dev:
            raise ValueError(f"{key} debe estar en el mismo volumen que Incoming")
        if p.exists() and not p.is_dir():
            raise ValueError(f"{key} no es una carpeta")
    if str(cfg.get("review_action", "quarantine")).lower() != "quarantine":
        raise ValueError("Solo se admite review_action=quarantine en esta reconstrucción")
    if not 0 <= int(cfg.get("suspicious_score", 45)) <= 100:
        raise ValueError("Umbral sospechoso fuera de rango")
    for key in ("max_archive_depth", "max_archive_entries", "max_uncompressed_bytes", "max_member_bytes"):
        if int(cfg.get(key, 0)) < 1:
            raise ValueError(f"Límite inválido: {key}")
    if float(cfg.get("max_expansion_ratio", 0)) <= 1:
        raise ValueError("max_expansion_ratio debe ser > 1")
    return paths
