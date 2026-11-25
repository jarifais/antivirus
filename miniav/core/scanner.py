"""Reconstrucción prudente del scanner estático MiniAntivirus v0.3.0.

No afirma equivalencia binaria con el código original ni sustituye a un AV comercial.
"""
from __future__ import annotations

import hashlib
import math
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from miniav import __version__, POLICY_VERSION
from .archives import inspect_zip
from .pe import PEFormatError, inspect_pe
from .indicators import load_catalog, scan_indicators
from .scripts import ScriptInspectionError, inspect_script
from .filetypes import ACTIVE_EXTENSIONS, DECOY_EXTENSIONS, EXECUTABLE_EXTENSIONS, SCRIPT_EXTENSIONS, detect_type
from .models import Finding, ScanResult
from .policy import verdict
from .yara_engine import rules_version, scan_yara, yara_capability

SAMPLE_BYTES = 65536
READ_CHUNK = 1024 * 1024


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    size = len(data)
    return -sum((count / size) * math.log2(count / size) for count in counts if count)


def scan_file(path: Path | str, config: dict | None = None,
              rules_dir: Path | None = None) -> ScanResult:
    cfg = config or {}
    p = Path(path)
    now = datetime.now(timezone.utc).isoformat()
    findings: list[Finding] = []
    errors: list[str] = []
    nested = []
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()  # compatibilidad de informes; no se usa para seguridad
    md5 = hashlib.md5()  # compatibilidad de informes; no se usa para seguridad
    raw = b""
    size = 0
    suffix = p.suffix.lower()
    detected = "Unknown/binary"
    yara_matches: list[str] = []
    pe_details = None
    script_details = None
    indicator_catalog = None
    trusted_pe = False
    trusted_script = False
    complete = True
    start = time.monotonic()
    yara_ok, yara_reason = yara_capability()
    if rules_dir is None:
        rules_dir = Path(__file__).resolve().parents[1] / "rules"
    rules_ver = rules_version(rules_dir)
    try:
        if p.is_symlink() or not p.is_file():
            raise ValueError("No se analiza un enlace simbólico ni una ruta que no sea archivo regular")
        before = p.stat()
        size = before.st_size
        with p.open("rb") as stream:
            while True:
                data = stream.read(READ_CHUNK)
                if not data:
                    break
                if len(raw) < SAMPLE_BYTES:
                    raw += data[:SAMPLE_BYTES - len(raw)]
                sha256.update(data)
                sha1.update(data)
                md5.update(data)
                if time.monotonic() - start > float(cfg.get("scan_timeout_seconds", 600)):
                    raise TimeoutError("Tiempo máximo de análisis excedido")
        after = p.stat()
        if (before.st_size, before.st_mtime_ns, before.st_ino) != (
                after.st_size, after.st_mtime_ns, after.st_ino):
            raise RuntimeError("Archivo modificado durante el análisis")
        detected = detect_type(raw, p)
        parts = p.name.lower().split(".")
        ext = parts[-1] if len(parts) > 1 else ""
        is_active = ext in ACTIVE_EXTENSIONS or suffix in SCRIPT_EXTENSIONS or suffix in EXECUTABLE_EXTENSIONS
        if len(parts) > 2 and parts[-2] in DECOY_EXTENSIONS and ext in ACTIVE_EXTENSIONS:
            findings.append(Finding("DOUBLE_EXTENSION", "high", 90,
                                    "Doble extensión para disimular un ejecutable", "filenames",
                                    p.name, True))
        if detected == "PE/Windows executable":
            try:
                pe = inspect_pe(p)
                catalog = load_catalog()
                indicator_catalog = {"version": catalog["version"], "sha256": catalog["sha256"]}
                findings.extend(scan_indicators(catalog, "pe_import", pe.imports))
                imported = {entry.rsplit("!", 1)[-1].lower() for entry in pe.imports}
                suspicious_apis = sorted(imported.intersection({
                    "virtualallocex", "writeprocessmemory",
                    "createremotethread", "ntmapviewofsection",
                }))
                rwx_sections = [s["name"] for s in pe.sections
                                if s["writable"] and s["executable"]]
                pe_details = {
                    "bits": pe.bits, "machine": pe.machine,
                    "sections": len(pe.sections),
                    "rwx_sections": rwx_sections,
                    "import_count": len(pe.imports),
                    "suspicious_imports": suspicious_apis,
                    "signature_present_unverified": pe.signature_present,
                    "overlay_bytes": pe.overlay_bytes,
                }
                if rwx_sections:
                    findings.append(Finding(
                        "PE_RWX_SECTION", "high", 85,
                        "Sección PE ejecutable y escribible", "pe",
                        location=",".join(rwx_sections), blocking=True))
                if len(suspicious_apis) >= 2:
                    findings.append(Finding(
                        "PE_INJECTION_APIS", "high", 70,
                        "Combinación de imports relacionada con inyección",
                        "pe", blocking=True, metadata={"imports": suspicious_apis}))
                if pe.overlay_bytes > 65536 and pe.overlay_bytes > size * 0.25 and not pe.signature_present:
                    findings.append(Finding(
                        "PE_LARGE_OVERLAY", "medium", 20,
                        "Overlay de tamaño relevante", "pe"))
                approved = cfg.get("trusted_executable_sha256", [])
                if not isinstance(approved, list) or any(
                    not isinstance(value, str) or len(value) != 64 or
                    any(ch not in "0123456789abcdefABCDEF" for ch in value)
                    for value in approved
                ):
                    raise ValueError("trusted_executable_sha256 debe contener hashes SHA-256")
                trusted_pe = sha256.hexdigest() in {value.lower() for value in approved}
                if not trusted_pe:
                    findings.append(Finding(
                        "PE_REVIEW_REQUIRED", "info", 20,
                        "Ejecutable PE desconocido: revisión, no implica malware", "pe"))
            except PEFormatError as exc:
                errors.append(f"PE malformado: {exc}")
        elif suffix in EXECUTABLE_EXTENSIONS:
            errors.append("Extensión ejecutable sin formato PE reconocido")
        if suffix in SCRIPT_EXTENSIONS and detected != "PE/Windows executable":
            allowed_script = cfg.get("trusted_script_sha256", [])
            if not isinstance(allowed_script, list) or any(
                not isinstance(value, str) or len(value) != 64 or
                any(ch not in "0123456789abcdefABCDEF" for ch in value)
                for value in allowed_script
            ):
                raise ValueError("trusted_script_sha256 debe contener hashes SHA-256")
            try:
                script_limit = int(cfg.get("max_script_bytes", 1048576))
                if not 1 <= script_limit <= 16777216:
                    raise ValueError("max_script_bytes fuera de límites")
                if size > script_limit:
                    raise ScriptInspectionError("El script excede el límite inspeccionable")
                script_info = inspect_script(p.read_bytes(), max_size=script_limit)
                catalog = load_catalog()
                indicator_catalog = {"version": catalog["version"], "sha256": catalog["sha256"]}
                trusted_script = sha256.hexdigest() in {v.lower() for v in allowed_script}
                script_details = {"encoding": script_info.encoding,
                                  "inspected_bytes": size,
                                  "trusted_sha256": trusted_script}
                findings.extend(script_info.findings)
                if not trusted_script:
                    findings.append(Finding(
                        "SCRIPT_REVIEW_REQUIRED", "info", 20,
                        "Script desconocido: revisión sin afirmar malware",
                        "scripts"))
            except ScriptInspectionError as exc:
                errors.append(f"Script no inspeccionable: {exc}")
        elif is_active and detected != "PE/Windows executable":
            findings.append(Finding("ACTIVE_FILE", "medium", 50,
                                    "Tipo activo: revisión antes de liberar", "filetypes"))
        if detected in {"PE/Windows executable", "ELF executable/object", "Mach-O executable/object"}:
            if (detected == "PE/Windows executable" and suffix not in EXECUTABLE_EXTENSIONS) or not is_active:
                findings.append(Finding("MISMATCH_EXECUTABLE", "high", 85,
                                        "Ejecutable con extensión inesperada", "filetypes",
                                        p.name, True))
            if _entropy(raw) > 7.4:
                findings.append(Finding("HIGH_ENTROPY_EXECUTABLE", "medium", 20,
                                        "Entropía elevada en ejecutable", "heuristics"))
        if detected == "Text/script-like file" and suffix not in SCRIPT_EXTENSIONS:
            # For non-script extensions, preserve a low-cost indicator only.
            small = raw.lower()
            if b"-encodedcommand" in small or b"powershell -enc" in small:
                findings.append(Finding("ENCODED_POWERSHELL", "high", 75,
                                        "Indicador textual PowerShell codificado",
                                        "heuristics", blocking=True))
        if detected == "ZIP container" or suffix == ".zip":
            more, nested, archive_errors = inspect_zip(
                p, max_depth=int(cfg.get("max_archive_depth", 4)),
                max_entries=int(cfg.get("max_archive_entries", 5000)),
                max_uncompressed=int(cfg.get("max_uncompressed_bytes", 2147483648)),
                max_member=int(cfg.get("max_member_bytes", 536870912)),
                max_ratio=float(cfg.get("max_expansion_ratio", 250.0)))
            findings.extend(more)
            errors.extend(archive_errors)
        elif detected in {"RAR container", "7-Zip container", "TAR container",
                          "GZIP stream", "BZIP2 stream", "XZ stream"} or suffix in {
                          ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"}:
            errors.append("No existe parser completo para este contenedor")
        if rules_ver != "none" and yara_ok:
            yara_matches, yara_err = scan_yara(p, rules_dir,
                                               int(cfg.get("yara_timeout_seconds", 15)))
            if yara_err:
                errors.append(yara_err)
            for match in yara_matches:
                findings.append(Finding("YARA_MATCH", "high", 80,
                                        f"Coincidencia YARA: {match}", "yara", blocking=True))
        final_stat = p.stat()
        if (before.st_size, before.st_mtime_ns, before.st_ino) != (
            final_stat.st_size, final_stat.st_mtime_ns, final_stat.st_ino):
            errors.append("Archivo cambiado durante el análisis estructural")
    except Exception as exc:
        errors.append(f"{type(exc).__name__}: {exc}")
    if errors:
        complete = False
    raw_score = sum(f.score for f in findings) + sum(n.score for n in nested)
    score = min(100, raw_score)
    return ScanResult(
        scan_id=uuid.uuid4().hex, path=str(p), size=size,
        sha256=sha256.hexdigest() if size or raw else "",
        sha1=sha1.hexdigest() if size or raw else "",
        md5=md5.hexdigest() if size or raw else "",
        extension=suffix, detected_type=detected,
        entropy=round(_entropy(raw), 4), findings=findings,
        score=score, raw_score=raw_score, verdict=verdict(score),
        yara_matches=yara_matches, analysis_complete=complete, errors=errors,
        nested_results=nested, capabilities={
            "yara": yara_ok, "yara_detail": yara_reason,
            "zip": True, "rar": False, "7z": False, "deep_pe": False,
            "ml": False, "reconstructed": True,
            "pe": pe_details, "trusted_sha256": trusted_pe,
            "script": script_details, "trusted_script_sha256": trusted_script,
            "indicator_catalog": indicator_catalog,
        }, engine_version=__version__, policy_version=POLICY_VERSION,
        rules_version=rules_ver, scanned_at=now,
        error="; ".join(errors) if errors else None)
