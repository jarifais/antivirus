from __future__ import annotations

from pathlib import Path

SCRIPT_EXTENSIONS = {
    ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf",
    ".py", ".php", ".pl", ".rb", ".sh", ".hta", ".bash", ".zsh",
}
EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx"}
DECOY_EXTENSIONS = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg",
    "png", "gif", "txt", "rtf", "zip", "rar", "7z", "mp3", "mp4", "mkv", "avi",
}
ACTIVE_EXTENSIONS = {
    "exe", "scr", "com", "bat", "cmd", "js", "jse", "vbs", "vbe", "ps1", "hta", "cpl", "msi",
}


def detect_type(data: bytes, path: Path | None = None) -> str:
    if not data:
        return "Empty file"
    if data.startswith(b"MZ"):
        return "PE/Windows executable"
    if data.startswith(b"\x7fELF"):
        return "ELF executable/object"
    if data.startswith(b"%PDF-"):
        return "PDF document"
    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06") or data.startswith(b"PK\x07\x08"):
        return "ZIP container"
    if data.startswith(b"Rar!\x1a\x07"):
        return "RAR container"
    if data.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7-Zip container"
    if data.startswith(b"\x1f\x8b"):
        return "GZIP stream"
    if data.startswith(b"BZh"):
        return "BZIP2 stream"
    if data.startswith(b"\xfd7zXZ\x00"):
        return "XZ stream"
    if len(data) >= 265 and data[257:262] == b"ustar":
        return "TAR container"
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "OLE/Compound document"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG image"
    if data.startswith(b"\xff\xd8\xff"):
        return "JPEG image"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "GIF image"
    if data.startswith(b"\x1aE\xdf\xa3"):
        return "EBML/Matroska/WebM"
    if len(data) >= 12 and data[4:8] == b"ftyp":
        return "ISO Base Media/MP4/MOV"
    if data.startswith(b"RIFF") and len(data) >= 12:
        if data[8:12] == b"AVI ":
            return "AVI video"
        if data[8:12] == b"WAVE":
            return "WAV audio"
        return "RIFF container"
    if data.startswith(b"fLaC"):
        return "FLAC audio"
    if data.startswith(b"ID3"):
        return "MP3 audio"
    # Mach-O/FAT magics, both endian variants.
    if data[:4] in {b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}:
        return "Mach-O executable/object"
    if len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001":
        return "ISO-9660 image"
    if data.startswith(b"#!"):
        return "Script with shebang"
    sample = data[:4096]
    printable = sum(1 for b in sample if b in b"\t\n\r" or 32 <= b < 127)
    if printable / max(1, len(sample)) > 0.92:
        return "Text/script-like file"
    return "Unknown/binary"


def looks_like_archive(detected_type: str, extension: str) -> bool:
    ext = extension.lower()
    return detected_type in {
        "ZIP container", "RAR container", "7-Zip container", "TAR container",
        "GZIP stream", "BZIP2 stream", "XZ stream",
    } or ext in {".zip", ".rar", ".7z", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".tbz", ".tbz2", ".txz", ".jar", ".apk", ".aab"}
