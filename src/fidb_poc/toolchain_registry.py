"""Reviewed cross-toolchain lookup table, keyed by (family, arch, era).

Replaces the copy-pasted per-arch [[recipes]] blocks catalogs/default.toml
used to carry: this is a registry of pinned toolchains, not a recipe list.
A row can serve two consumers -- direct prebuilt-libc.a extraction
(url/sha256/library_member, same shape libc_catalog.py already handles) and
supplying a cross-compiler to a recipe_generator.py source-mode cell
(toolchain_url/toolchain_sha256/cross_bin_prefix/cross_arch) -- same pinned
toolchain, two uses, no duplication.
"""

from __future__ import annotations

from pathlib import Path
import tomllib

COMMON_FIELDS = {"family", "version", "variant", "machine", "endianness", "elf_class"}
SOURCE_FIELDS = {"toolchain_url", "toolchain_sha256", "cross_bin_prefix", "cross_arch"}


def _hex64(value: object, context: str) -> None:
    text = str(value)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise ValueError(f"invalid sha256 for {context}")


def load_toolchains(path: str | Path) -> list[dict[str, object]]:
    registry_path = Path(path)
    rows = tomllib.loads(registry_path.read_text(encoding="utf-8")).get("toolchain", [])
    seen: set[tuple[object, object, object]] = set()
    for row in rows:
        missing = COMMON_FIELDS - row.keys()
        if missing:
            raise ValueError(f"toolchain row is missing: {', '.join(sorted(missing))}")
        label = f'{row["family"]} {row["version"]} {row["variant"]}'
        key = (row["family"], row["version"], row["variant"])
        if key in seen:
            raise ValueError(f"duplicate toolchain row: {key}")
        seen.add(key)

        has_archive = "url" in row
        has_source = "toolchain_url" in row
        if not has_archive and not has_source:
            raise ValueError(f"{label} supplies neither url nor toolchain_url")
        if has_archive:
            _hex64(row["sha256"], label)
            if "library_member" not in row:
                raise ValueError(f"{label} has url but no library_member")
        if has_source:
            missing_source = SOURCE_FIELDS - row.keys()
            if missing_source:
                raise ValueError(f"{label} is missing: {', '.join(sorted(missing_source))}")
            _hex64(row["toolchain_sha256"], label)
    return rows
