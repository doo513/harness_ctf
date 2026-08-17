from __future__ import annotations

import hashlib
import struct
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

_MACHINE = {3: "x86", 40: "arm", 62: "x86_64", 183: "aarch64", 243: "riscv"}
_ET = {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
PT_DYNAMIC = 2
PT_INTERP = 3
PT_GNU_STACK = 0x6474E551
PF_X = 1
DT_NULL = 0
DT_FLAGS_1 = 0x6FFFFFFB
DF_1_PIE = 0x08000000

@dataclass(frozen=True)
class PwnReconSnapshot:
    schema_version: int
    kind: str
    artifact_sha256: str
    file_type: str
    elf_type: str
    architecture: str
    bits: int
    endianness: str
    pie: bool | None
    nx: bool | None
    canary_present: bool | None
    interpreter: str | None
    entrypoint: int
    evidence_refs: tuple[str, ...] = ()

    def dump(self) -> dict[str, Any]:
        value = asdict(self); value["evidence_refs"] = list(self.evidence_refs); return value


def _u(data: bytes, fmt: str, offset: int) -> int:
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data): raise ValueError("truncated ELF field")
    return int(struct.unpack_from(fmt, data, offset)[0])


def inspect_elf_bytes(data: bytes, *, evidence_refs=()) -> PwnReconSnapshot:
    digest = hashlib.sha256(data).hexdigest()
    if len(data) < 52 or data[:4] != b"\x7fELF": raise ValueError("artifact is not ELF")
    cls, endian_id = data[4], data[5]
    if cls not in (1, 2) or endian_id not in (1, 2): raise ValueError("unsupported ELF identification")
    bits = 32 if cls == 1 else 64
    endianness = "little" if endian_id == 1 else "big"
    prefix = "<" if endian_id == 1 else ">"
    e_type = _u(data, prefix + "H", 16); machine = _u(data, prefix + "H", 18)
    if cls == 2:
        entry = _u(data, prefix + "Q", 24); phoff = _u(data, prefix + "Q", 32); phentsize = _u(data, prefix + "H", 54); phnum = _u(data, prefix + "H", 56)
    else:
        entry = _u(data, prefix + "I", 24); phoff = _u(data, prefix + "I", 28); phentsize = _u(data, prefix + "H", 42); phnum = _u(data, prefix + "H", 44)
    if phentsize <= 0: raise ValueError("invalid ELF program header table")
    if phoff + phentsize * phnum > len(data): raise ValueError("truncated ELF program header table")
    interpreter = None; nx = None; dynamic_ranges = []
    for i in range(phnum):
        off = phoff + i * phentsize
        if cls == 2:
            p_type = _u(data, prefix + "I", off); p_flags = _u(data, prefix + "I", off + 4); p_offset = _u(data, prefix + "Q", off + 8); p_filesz = _u(data, prefix + "Q", off + 32)
        else:
            p_type = _u(data, prefix + "I", off); p_offset = _u(data, prefix + "I", off + 4); p_filesz = _u(data, prefix + "I", off + 16); p_flags = _u(data, prefix + "I", off + 24)
        if p_offset + p_filesz > len(data): raise ValueError("ELF program segment extends past artifact")
        if p_type == PT_GNU_STACK: nx = not bool(p_flags & PF_X)
        elif p_type == PT_INTERP: interpreter = data[p_offset:p_offset+p_filesz].split(b"\0",1)[0].decode("utf-8", errors="replace")
        elif p_type == PT_DYNAMIC: dynamic_ranges.append((p_offset,p_filesz))
    pie: bool | None = False if e_type == 2 else None
    dyn_entry_size = 16 if cls == 2 else 8; dyn_fmt = prefix + ("QQ" if cls == 2 else "II")
    for start, length in dynamic_ranges:
        cursor, end = start, start + length
        while cursor + dyn_entry_size <= end:
            tag, value = struct.unpack_from(dyn_fmt, data, cursor); cursor += dyn_entry_size
            if tag == DT_NULL: break
            if tag == DT_FLAGS_1: pie = bool(int(value) & DF_1_PIE) if e_type == 3 else False
    canary_present: bool | None = True if b"__stack_chk_fail" in data else None
    return PwnReconSnapshot(1,"pwn_recon_snapshot",digest,"ELF",_ET.get(e_type,f"TYPE:{e_type}"),_MACHINE.get(machine,f"machine:{machine}"),bits,endianness,pie,nx,canary_present,interpreter,entry,tuple(evidence_refs))


def inspect_elf(path: str | Path, *, evidence_refs=()) -> PwnReconSnapshot:
    return inspect_elf_bytes(Path(path).read_bytes(), evidence_refs=evidence_refs)
