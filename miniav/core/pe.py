"""Read-only, bounded PE analysis. A signature's presence does not prove trust."""
from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path


class PEFormatError(ValueError):
    """Malformed or unsupported PE data."""


@dataclass(frozen=True)
class PEInfo:
    bits: int
    machine: int
    sections: tuple[dict, ...]
    imports: tuple[str, ...]
    signature_present: bool
    overlay_bytes: int


def inspect_pe(path: Path) -> PEInfo:
    """Inspect PE headers, sections and import table without executing code."""
    size = path.stat().st_size
    if size < 64:
        raise PEFormatError("Truncated DOS header")
    with path.open("rb") as stream:
        def read(offset: int, count: int) -> bytes:
            if offset < 0 or count < 0 or offset + count > size:
                raise PEFormatError("PE reference beyond file")
            stream.seek(offset)
            data = stream.read(count)
            if len(data) != count:
                raise PEFormatError("Truncated file read")
            return data

        def u16(data: bytes, offset: int) -> int:
            return struct.unpack_from("<H", data, offset)[0]

        def u32(data: bytes, offset: int) -> int:
            return struct.unpack_from("<I", data, offset)[0]

        def name_at(offset: int) -> str:
            data = read(offset, min(128, size - offset))
            if b"\0" not in data:
                raise PEFormatError("Unterminated import name")
            return data.split(b"\0", 1)[0].decode("ascii", "replace")

        dos = read(0, 64)
        if dos[:2] != b"MZ":
            raise PEFormatError("Missing MZ")
        pe_offset = u32(dos, 0x3c)
        if not 64 <= pe_offset <= 1024 * 1024:
            raise PEFormatError("PE header offset invalid")
        coff = read(pe_offset, 24)
        if coff[:4] != b"PE\0\0":
            raise PEFormatError("Missing PE signature")
        machine, section_count = struct.unpack_from("<HH", coff, 4)
        optional_size = u16(coff, 20)
        if not 1 <= section_count <= 96 or optional_size > 4096:
            raise PEFormatError("Unreasonable PE header limits")
        optional = read(pe_offset + 24, optional_size)
        if len(optional) < 2:
            raise PEFormatError("Missing optional header")
        magic = u16(optional, 0)
        if magic == 0x10b:
            bits, dir_offset, count_offset, min_opt = 32, 96, 92, 96
            thunk_size, ordinal_flag = 4, 0x80000000
        elif magic == 0x20b:
            bits, dir_offset, count_offset, min_opt = 64, 112, 108, 112
            thunk_size, ordinal_flag = 8, 0x8000000000000000
        else:
            raise PEFormatError("Unsupported PE type")
        if len(optional) < min_opt:
            raise PEFormatError("Truncated optional header")
        dir_count = u32(optional, count_offset)
        if dir_count > 64 or dir_offset + min(dir_count, 16) * 8 > len(optional):
            raise PEFormatError("Invalid data directories")
        section_offset = pe_offset + 24 + optional_size
        if section_offset + section_count * 40 > 1024 * 1024:
            raise PEFormatError("Oversized section table")
        raw_sections = read(section_offset, section_count * 40)
        sections = []
        for i in range(section_count):
            entry = raw_sections[i * 40:(i + 1) * 40]
            virtual_size, va, raw_size, raw_offset = struct.unpack_from("<IIII", entry, 8)
            flags = u32(entry, 36)
            if raw_size and (not raw_offset or raw_offset + raw_size > size):
                raise PEFormatError("Invalid section raw span")
            sections.append({
                "name": entry[:8].split(b"\0", 1)[0].decode("ascii", "replace"),
                "virtual_address": va, "virtual_size": virtual_size,
                "raw_size": raw_size, "raw_offset": raw_offset,
                "executable": bool(flags & 0x20000000),
                "writable": bool(flags & 0x80000000),
            })

        def directory(index: int) -> tuple[int, int]:
            if index >= dir_count:
                return 0, 0
            return struct.unpack_from("<II", optional, dir_offset + index * 8)

        def resolve(rva: int, count: int) -> int:
            for section in sections:
                offset = rva - section["virtual_address"]
                if 0 <= offset and offset + count <= section["raw_size"]:
                    result = section["raw_offset"] + offset
                    if result + count <= size:
                        return result
            header_size = u32(optional, 60)
            if 0 <= rva and rva + count <= min(header_size, size):
                return rva
            raise PEFormatError("Import RVA not backed by file")

        imports = []
        import_rva, import_size = directory(1)
        if import_rva or import_size:
            if not import_rva or import_size < 20:
                raise PEFormatError("Incomplete import directory")
            terminated = False
            for i in range(min(256, import_size // 20)):
                desc = read(resolve(import_rva + i * 20, 20), 20)
                if desc == bytes(20):
                    terminated = True
                    break
                oft, _, _, dll_rva, ft = struct.unpack("<IIIII", desc)
                dll = name_at(resolve(dll_rva, 1))
                thunk_rva = oft or ft
                if not thunk_rva:
                    raise PEFormatError("Missing thunk table")
                thunk_end = False
                for j in range(512):
                    chunk = read(resolve(thunk_rva + j * thunk_size, thunk_size), thunk_size)
                    value = struct.unpack("<Q" if bits == 64 else "<I", chunk)[0]
                    if not value:
                        thunk_end = True
                        break
                    if value & ordinal_flag:
                        name = f"ordinal-{value & 0xffff}"
                    else:
                        offset = resolve(value & ~ordinal_flag, 3)
                        name = name_at(offset + 2)
                    imports.append(f"{dll}!{name}")
                    if len(imports) > 1024:
                        raise PEFormatError("Too many imports")
                if not thunk_end:
                    raise PEFormatError("Unterminated thunk table")
            if not terminated:
                raise PEFormatError("Unterminated import directory")
        cert_offset, cert_size = directory(4)
        signature_present = bool(cert_offset and cert_size >= 8 and cert_offset + cert_size <= size)
        raw_end = max((s["raw_offset"] + s["raw_size"] for s in sections if s["raw_size"]),
                      default=section_offset + section_count * 40)
        return PEInfo(bits, machine, tuple(sections), tuple(imports),
                      signature_present, max(0, size - raw_end))
