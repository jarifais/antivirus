"""Synthetic PE files for unit tests only; not functioning executables."""
import struct


def make_pe(*, rwx=False, import_name=None):
    data = bytearray(0x400)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14c, 1, 0, 0, 0, 0xe0, 0x102)
    opt = 0x98
    struct.pack_into("<H", data, opt, 0x10b)
    struct.pack_into("<I", data, opt + 60, 0x200)
    struct.pack_into("<I", data, opt + 92, 16)
    sec = 0x178
    data[sec:sec + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", data, sec + 8, 0x200, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", data, sec + 36, 0xe0000020 if rwx else 0x60000020)
    if import_name:
        struct.pack_into("<II", data, opt + 104, 0x1100, 40)
        struct.pack_into("<IIIII", data, 0x300, 0x1150, 0, 0, 0x1140, 0x1150)
        data[0x340:0x340 + 13] = b"KERNEL32.dll\0"
        struct.pack_into("<II", data, 0x350, 0x1170, 0)
        data[0x370:0x372] = b"\x00\x00"
        data[0x372:0x372 + len(import_name) + 1] = import_name.encode() + b"\x00"
    return bytes(data)
