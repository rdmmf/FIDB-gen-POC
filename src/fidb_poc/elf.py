"""Small, dependency-free ELF inspector.

Only bytes are read. The target is never executed, mapped as code, or passed to
an emulation environment.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
from pathlib import Path
import struct


ELF_MAGIC = b"\x7fELF"
PT_DYNAMIC = 2
PT_INTERP = 3
SHT_SYMTAB = 2

MACHINES = {
    3: "x86",
    4: "M68K",
    8: "MIPS",
    20: "PowerPC",
    21: "PowerPC64",
    40: "ARM",
    42: "SH",
    62: "x86-64",
    183: "AArch64",
}


class ElfInspectionError(ValueError):
    """Raised when a target is not a supported, well-formed ELF file."""


def ghidra_language(machine: str, endianness: str, bits: int) -> str | None:
    """Map (machine, endianness, elf_class) to a Ghidra language ID.

    Shared between target detection (elf.py) and candidate object analysis
    (candidates.py) so both sides of a FID match always use the same
    disassembler -- previously only PowerPC had a mapping and everything
    else silently fell back to a hardcoded PowerPC language, so non-PowerPC
    targets and libraries were disassembled as garbage and never matched.
    """
    endian = "LE" if endianness == "little" else "BE"
    if machine == "PowerPC" and bits == 32:
        return f"PowerPC:{endian}:32:default"
    if machine == "x86":
        return f"x86:LE:{bits}:default"
    if machine == "x86-64":
        return "x86:LE:64:default"
    if machine == "MIPS" and bits == 32:
        return f"MIPS:{endian}:32:default"
    if machine == "ARM" and bits == 32:
        return f"ARM:{endian}:32:v7"
    if machine == "M68K" and bits == 32:
        return "68000:BE:32:default"
    if machine == "SH" and bits == 32:
        return f"SuperH4:{endian}:32:default"
    if machine == "AArch64" and bits == 64:
        return "AARCH64:LE:64:v8A"
    return None


@dataclass(frozen=True)
class ElfFacts:
    path: str
    sha256: str
    size: int
    elf_class: int
    endianness: str
    machine: str
    machine_id: int
    elf_type: int
    entry_point: str
    flags: str
    statically_linked: bool
    stripped: bool
    interpreter: bool
    dynamic_segment: bool
    section_names: tuple[str, ...]
    string_indicators: tuple[str, ...]
    ghidra_language_hint: str | None
    cpu_specific_evidence: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _slice(data: bytes, offset: int, size: int, label: str) -> bytes:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ElfInspectionError(f"truncated ELF while reading {label}")
    return data[offset : offset + size]


def _c_string(table: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(table):
        return ""
    end = table.find(b"\0", offset)
    raw = table[offset:] if end < 0 else table[offset:end]
    return raw.decode("ascii", errors="replace")


def inspect_elf(path: str | Path) -> ElfFacts:
    target = Path(path).expanduser()
    data = target.read_bytes()
    if len(data) < 16 or data[:4] != ELF_MAGIC:
        raise ElfInspectionError("target is not an ELF file")

    elf_class_raw, data_encoding = data[4], data[5]
    if elf_class_raw not in (1, 2):
        raise ElfInspectionError(f"unsupported ELF class: {elf_class_raw}")
    if data_encoding not in (1, 2):
        raise ElfInspectionError(f"unsupported ELF byte order: {data_encoding}")

    bits = 32 if elf_class_raw == 1 else 64
    byte_order = "little" if data_encoding == 1 else "big"
    prefix = "<" if data_encoding == 1 else ">"
    header_format = prefix + ("HHIIIIIHHHHHH" if bits == 32 else "HHIQQQIHHHHHH")
    header_size = struct.calcsize(header_format)
    header = struct.unpack(header_format, _slice(data, 16, header_size, "ELF header"))
    (
        elf_type,
        machine_id,
        _version,
        entry,
        program_offset,
        section_offset,
        flags,
        _elf_header_size,
        program_entry_size,
        program_count,
        section_entry_size,
        section_count,
        section_name_index,
    ) = header

    program_format = prefix + ("IIIIIIII" if bits == 32 else "IIQQQQQQ")
    expected_program_size = struct.calcsize(program_format)
    if program_count and program_entry_size < expected_program_size:
        raise ElfInspectionError("ELF program header entries are too small")

    program_types: list[int] = []
    for index in range(program_count):
        offset = program_offset + index * program_entry_size
        fields = struct.unpack(
            program_format,
            _slice(data, offset, expected_program_size, f"program header {index}"),
        )
        program_types.append(fields[0])

    section_format = prefix + ("IIIIIIIIII" if bits == 32 else "IIQQQQIIQQ")
    expected_section_size = struct.calcsize(section_format)
    if section_count and section_entry_size < expected_section_size:
        raise ElfInspectionError("ELF section header entries are too small")

    section_headers: list[tuple[int, ...]] = []
    for index in range(section_count):
        offset = section_offset + index * section_entry_size
        section_headers.append(
            struct.unpack(
                section_format,
                _slice(data, offset, expected_section_size, f"section header {index}"),
            )
        )

    section_names: list[str] = []
    if section_headers and section_name_index < len(section_headers):
        name_header = section_headers[section_name_index]
        name_offset, name_size = name_header[4], name_header[5]
        name_table = _slice(data, name_offset, name_size, "section name table")
        section_names = [_c_string(name_table, item[0]) for item in section_headers]

    lower_data = data.lower()
    indicators = tuple(
        indicator
        for indicator in ("glibc", "uclibc", "musl", "gcc", "clang", "zlib", "openwrt", "upx")
        if indicator.encode("ascii") in lower_data
    )

    machine = MACHINES.get(machine_id, f"unknown ({machine_id})")
    language_hint = ghidra_language(machine, byte_order, bits)

    cpu_evidence: list[str] = []
    # PowerPC e_flags value zero and a missing attributes section do not identify
    # an e500 core; keep this deliberately evidence-only.
    if ".gnu.attributes" in section_names:
        cpu_evidence.append(".gnu.attributes section present (not decoded in phase 1)")

    dynamic = PT_DYNAMIC in program_types
    interpreter = PT_INTERP in program_types
    has_symbols = any(item[1] == SHT_SYMTAB for item in section_headers)
    return ElfFacts(
        path=str(target.resolve()),
        sha256=hashlib.sha256(data).hexdigest(),
        size=len(data),
        elf_class=bits,
        endianness=byte_order,
        machine=machine,
        machine_id=machine_id,
        elf_type=elf_type,
        entry_point=f"0x{entry:x}",
        flags=f"0x{flags:x}",
        statically_linked=not dynamic and not interpreter,
        stripped=not has_symbols,
        interpreter=interpreter,
        dynamic_segment=dynamic,
        section_names=tuple(name for name in section_names if name),
        string_indicators=indicators,
        ghidra_language_hint=language_hint,
        cpu_specific_evidence=tuple(cpu_evidence),
    )
