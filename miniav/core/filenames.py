"""Conservative filename spoofing indicators, without renaming or executing files.

Normalization is ONLY for detection, never used as a filesystem path.
This module does not prove malware infection or exhaust Unicode confusables.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from .filetypes import ACTIVE_EXTENSIONS, DECOY_EXTENSIONS, EXECUTABLE_EXTENSIONS, SCRIPT_EXTENSIONS
from .models import Finding

# Unicode display controls which can reverse or reorder what an operator sees.
_BIDI = set("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
# Dot-like characters not all mapped by Unicode compatibility normalization.
_DOTS = str.maketrans({"\u3002": ".", "\uff61": ".", "\u2024": ".", "\ufe52": "."})
# Conservative subset of Unicode confusables inside extension tokens only.
_EXTENSION_CONFUSABLES = str.maketrans({
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0445": "x", "\u0443": "y", "\u043a": "k",
    "\u043c": "m", "\u0442": "t", "\u0432": "b", "\u043d": "h",
    "\u0456": "i", "\u0458": "j", "\u04cf": "l",
    "\u03b1": "a", "\u03b5": "e", "\u03bf": "o", "\u03c1": "p",
    "\u03c7": "x", "\u03ba": "k", "\u03b9": "i", "\u03bd": "v",
})
_ACTIVE = ACTIVE_EXTENSIONS | {x.lstrip(".") for x in EXECUTABLE_EXTENSIONS | SCRIPT_EXTENSIONS}
_DECOY = DECOY_EXTENSIONS | {
    "csv", "html", "htm", "odt", "ods", "odp", "svg", "md", "log", "eml",
}


@dataclass(frozen=True)
class FilenameInspection:
    effective_suffix: str
    findings: tuple[Finding, ...]


def inspect_filename(filename: str) -> FilenameInspection:
    """Identify deceptive filenames without using normalized names as paths.

    Literal matching is intentionally bounded. A clean result from this
    function is NOT a conclusion that the file contents are trustworthy.
    """
    if not isinstance(filename, str) or not filename or filename in {".", ".."}:
        raise ValueError("Invalid filename")
    original = filename
    has_bidi = any(ch in _BIDI for ch in original)
    has_format = any(unicodedata.category(ch) == "Cf" for ch in original)
    has_dotlookalike = any(ch in "\u3002\uff61\u2024\ufe52\uff0e" for ch in original)
    original_normalized = unicodedata.normalize("NFKC", original).translate(_DOTS)
    normalized = "".join(
        c for c in original_normalized if unicodedata.category(c) != "Cf"
    ).rstrip(" .").casefold()
    pieces = [part.strip(" ") for part in normalized.split(".")]
    # Apply a small, documented confusable map to extension tokens only.
    tokens = [p.translate(_EXTENSION_CONFUSABLES) for p in pieces]
    active = len(tokens) > 1 and tokens[-1] in _ACTIVE
    decoy = len(tokens) > 2 and tokens[-2] in _DECOY
    effective_suffix = "." + tokens[-1] if len(tokens) > 1 and tokens[-1] else ""
    label = repr(original)[:200]
    findings: list[Finding] = []

    def report(code: str, points: int, message: str, *, block: bool) -> None:
        findings.append(Finding(
            code, "high" if points >= 45 else "medium", points, message,
            "filenames", label, block,
        ))

    if active and decoy:
        report("DOUBLE_EXTENSION", 90,
               "Extensión de documento seguida de una extensión activa",
               block=True)
    elif active and len(tokens) > 2:
        report("FILENAME_MULTI_EXT_ACTIVE", 20,
               "Nombre con varias extensiones y extensión activa final",
               block=False)

    if has_bidi:
        report("FILENAME_BIDI_CONTROL", 75,
               "Controles bidireccionales capaces de alterar el orden visual",
               block=True)

    if has_format and not has_bidi:
        report("FILENAME_INVISIBLE_FORMAT", 75 if active else 20,
               "Caracteres de formato invisibles en el nombre",
               block=bool(active))

    if has_dotlookalike:
        report("FILENAME_UNICODE_DOT", 75 if active else 20,
               "Separador Unicode visualmente parecido a un punto",
               block=bool(active))

    if original != original.rstrip(" ."):
        report("FILENAME_TRAILING_DOT_SPACE", 75 if active else 20,
               "Puntos o espacios finales que Windows puede interpretar de forma distinta",
               block=bool(active))

    if active and tokens[-1] != pieces[-1]:
        report("FILENAME_CONFUSABLE_EXTENSION", 75,
               "Extensión visualmente confusable con una activa", block=True)

    if re.search(r" {8,}", original) and len(tokens) > 2:
        report("FILENAME_WHITESPACE_GAP", 35,
               "Separación extensa de extensiones que dificulta ver el nombre",
               block=False)

    if ":" in original and active:
        report("FILENAME_ADS_LIKE", 75,
               "Nombre con dos puntos y extensión activa (posible flujo alternativo NTFS)",
               block=True)

    return FilenameInspection(effective_suffix=effective_suffix,
                              findings=tuple(findings))
