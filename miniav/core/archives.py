"""Inspección ZIP en memoria, sin extracción ni ejecución de miembros."""
from __future__ import annotations

import hashlib
import io
import zipfile
from pathlib import Path

from .filetypes import ACTIVE_EXTENSIONS, DECOY_EXTENSIONS, detect_type
from .models import Finding, NestedResult
from .policy import verdict


def inspect_zip(
    path: Path, *, depth: int = 0, max_depth: int = 4,
    max_entries: int = 5000, max_uncompressed: int = 2147483648,
    max_member: int = 536870912, max_ratio: float = 250.0,
    _data: bytes | None = None, _budget: list[int] | None = None,
) -> tuple[list[Finding], list[NestedResult], list[str]]:
    findings: list[Finding] = []
    nested: list[NestedResult] = []
    errors: list[str] = []
    if depth >= max_depth:
        return findings, nested, ["Profundidad ZIP máxima alcanzada"]
    budget = _budget if _budget is not None else [0]
    source = io.BytesIO(_data) if _data is not None else path
    try:
        with zipfile.ZipFile(source) as archive:
            members = archive.infolist()
            if len(members) > max_entries:
                return findings, nested, ["ZIP excede el límite de entradas"]
            for info in members:
                if info.is_dir():
                    continue
                budget[0] += info.file_size
                if budget[0] > max_uncompressed or info.file_size > max_member:
                    errors.append(f"Límite de descompresión: {info.filename[:100]}")
                    break
                if info.file_size > 0 and info.file_size / max(1, info.compress_size) > max_ratio:
                    errors.append(f"Ratio de expansión excedido: {info.filename[:100]}")
                    break
                if info.flag_bits & 1:
                    findings.append(Finding("ZIP_ENCRYPTED", "high", 80, "Miembro ZIP cifrado",
                                            "archives", info.filename[:120], True))
                    continue
                try:
                    with archive.open(info, "r") as stream:
                        contents = stream.read(max_member + 1)
                        if len(contents) > max_member or len(contents) != info.file_size:
                            raise ValueError("tamaño ZIP inconsistente")
                except (RuntimeError, ValueError, EOFError, OSError, zipfile.BadZipFile) as exc:
                    errors.append(f"Lectura ZIP fallida: {info.filename[:100]}: {type(exc).__name__}")
                    break
                name = Path(info.filename.replace("\\", "/")).name
                parts = name.lower().split(".")
                ext = "." + parts[-1] if len(parts) > 1 else ""
                active = ext.lstrip(".") in ACTIVE_EXTENSIONS
                decoy = len(parts) > 2 and parts[-2] in DECOY_EXTENSIONS and active
                detected = detect_type(contents[:65536], Path(name))
                child_findings: list[Finding] = []
                if active:
                    child_findings.append(Finding("ARCHIVE_ACTIVE", "high", 55, "Código activo dentro del ZIP",
                                                   "archives", info.filename[:120], True))
                if decoy:
                    child_findings.append(Finding("ARCHIVE_DOUBLE_EXT", "high", 85, "Doble extensión engañosa",
                                                   "archives", info.filename[:120], True))
                if info.filename.startswith(("/", "\\")) or ".." in info.filename.replace("\\", "/").split("/"):
                    child_findings.append(Finding("ARCHIVE_TRAVERSAL", "high", 85, "Ruta relativa peligrosa",
                                                   "archives", info.filename[:120], True))
                nested.append(NestedResult(
                    internal_path=info.filename[:240], size=info.file_size,
                    sha256=hashlib.sha256(contents).hexdigest(),
                    detected_type=detected, score=min(100, sum(f.score for f in child_findings)),
                    verdict=verdict(min(100, sum(f.score for f in child_findings))),
                    analysis_complete=True, findings=child_findings))
                if detected == "ZIP container":
                    extra_findings, extra_nested, extra_errors = inspect_zip(
                        path, depth=depth + 1, max_depth=max_depth,
                        max_entries=max_entries, max_uncompressed=max_uncompressed,
                        max_member=max_member, max_ratio=max_ratio,
                        _data=contents, _budget=budget)
                    findings.extend(extra_findings)
                    nested.extend(extra_nested)
                    errors.extend(extra_errors)
                elif detected in {"RAR container", "7-Zip container", "TAR container",
                                  "GZIP stream", "BZIP2 stream", "XZ stream"}:
                    errors.append("Contenedor anidado sin parser fiable")
                if errors:
                    break
    except (zipfile.BadZipFile, EOFError, OSError, ValueError, RuntimeError) as exc:
        errors.append(f"ZIP inválido: {type(exc).__name__}: {str(exc)[:120]}")
    return findings, nested, errors
