"""Patching (PatchService, api_minor 27, feature "patch"; docs/patching.md).

    with Client("127.0.0.1:50051", actor="user:alice") as rk:
        fw = rk.program("default/firmware.bin")
        print(fw.assemble(0x8010, "cmp r0,#0x9").candidates[0].bytes.hex())
        fw.patch_instruction(0x8010, "cmp r0,#0x9")            # one revision
        fw.patch_instruction(0x20040, "bl patch_cave")          # labels resolve
        fw.patch_bytes(0xa0000, bytes.fromhex("1eff2fe1"))      # bx lr
        for p in fw.patches():
            print(hex(p.address.offset), p.original_text, "->", p.text)
        hit = fw.detect_checksum(file_name="FW_202401011200_1234ABCD.bin").hits[0]
        out = fw.export(name_sum("sum32", template=hit.file_name_template))
        open(out.file_name, "wb").write(out.data)               # verified by the daemon

A patch is an assertion (FACT_KIND_PATCH): RetractAssertions undoes it,
RevertByProvenance reverts an author's patches with the rest of their work,
and the listing, decompiler, emulator and export all see the program as
patched.
"""

from __future__ import annotations

from typing import Iterable, Union

from revkit.v1 import patch_pb2

ALGORITHMS = {n.removeprefix("CHECKSUM_ALGORITHM_").lower().replace("_", "-"): v
              for n, v in patch_pb2.ChecksumAlgorithm.items() if v}


def algorithm(name: Union[str, int]) -> int:
    """ChecksumAlgorithm by name ("sum32", "crc32", "crc16-xmodem", ...) or value."""
    if isinstance(name, int):
        return name
    key = name.lower().replace("_", "-")
    if key not in ALGORITHMS:
        raise ValueError(f"unknown checksum algorithm {name!r}; one of {sorted(ALGORITHMS)}")
    return ALGORITHMS[key]


def checksum_field(alg: Union[str, int], offset: int, *, width: int = 4, big_endian: bool = False,
                   start: int = 0, end: int = 0, skip_padding: bool = False) -> patch_pb2.ExportFixup:
    """A checksum over [start, end) of the output (end 0: EOF; negative: back
    from it) written into the file at ``offset``."""
    return patch_pb2.ExportFixup(checksum=patch_pb2.ChecksumSpec(
        algorithm=algorithm(alg), start=start, end=end, skip_padding=skip_padding, field=True,
        field_offset=offset, field_width=width, field_big_endian=big_endian))


def name_sum(alg: Union[str, int] = "sum32", *, template: str = "{NAME}_{SUM:08X}{EXT}", start: int = 0,
             end: int = 0, fixups: Iterable[patch_pb2.ExportFixup] = ()) -> patch_pb2.ExportSettings:
    """Export settings whose file name carries a checksum of the output, e.g.
    the 32-bit sum of every byte in "NAME_1234ABCD.bin"."""
    f = patch_pb2.ExportFixup(checksum=patch_pb2.ChecksumSpec(algorithm=algorithm(alg), start=start, end=end, name=True))
    return patch_pb2.ExportSettings(fixups=[*fixups, f], file_name_template=template)


def pe_checksum() -> patch_pb2.ExportFixup:
    """The PE optional header's CheckSum, recomputed."""
    return patch_pb2.ExportFixup(pe_checksum=True)


def settings(*fixups: patch_pb2.ExportFixup, template: str = "", image_only: bool = False) -> patch_pb2.ExportSettings:
    fmt = patch_pb2.EXPORT_FORMAT_IMAGE if image_only else patch_pb2.EXPORT_FORMAT_FILE
    return patch_pb2.ExportSettings(format=fmt, fixups=list(fixups), file_name_template=template)


def describe(spec: patch_pb2.ChecksumSpec) -> str:
    """A spec in words, as the daemon's evidence says it."""
    alg = {v: k for k, v in ALGORITHMS.items()}.get(spec.algorithm, "?")
    end = "EOF" if spec.end == 0 else (f"EOF-{-spec.end:#x}" if spec.end < 0 else f"{spec.end:#x}")
    where = (f" into {spec.field_offset:#x} ({spec.field_width} bytes, {'big' if spec.field_big_endian else 'little'}-endian)"
             if spec.field else " into the file name" if spec.name else "")
    return f"{alg} over {spec.start:#x}..{end}{where}"


__all__ = ["ALGORITHMS", "algorithm", "checksum_field", "name_sum", "pe_checksum", "settings", "describe"]
