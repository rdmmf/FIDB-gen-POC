"""Expand a hand-authored, reviewed "recipe" (source pin + build shape +
wanted toolchain family) into self-contained "cells" -- one per matching
toolchain_registry.py row, each shaped exactly like a catalogs/*.toml
mode="source" row so libc_catalog.py's prepare_recipe/select_recipes/_guess
(and hunt.py, which calls them) consume generated cells identically to
hand-written ones, with zero changes to that code.

This is the generator half of the recipe -> registry -> cell split
described in UNIFICATION_PLAN.md: a recipe is authored once regardless of
how many arches/toolchains it targets; the fan-out is computed instead of
copy-pasted, and gets one shared duplicate-cell check instead of one per
subsystem.
"""

from __future__ import annotations

from pathlib import Path
import tomllib

SCHEMA_VERSION = "fidb-recipe/v3"

REQUIRED_FIELDS = {
    "schema_version", "mode", "name", "version", "url", "sha256",
    "library_path", "build_adapter", "toolchain_family",
}

# Shared across every source-mode cell unless a recipe overrides it -- same
# Alpine guest image every VM-isolated build boots, pinned once here instead
# of repeated per recipe.
VM_ISO_URL = "https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/x86_64/alpine-virt-3.19.1-x86_64.iso"
VM_ISO_SHA256 = "366317d854d77fc5db3b2fd774f5e1e5db0a7ac210614fd39ddb555b09dbb344"


def _hex64(value: object, context: str) -> None:
    text = str(value)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise ValueError(f"invalid sha256 for {context}")


def load_recipes(directory: str | Path) -> list[dict[str, object]]:
    """Load mode="source" generator recipes from *.toml files in directory."""
    recipes = []
    for path in sorted(Path(directory).glob("*.toml")):
        recipe = tomllib.loads(path.read_text(encoding="utf-8"))
        if recipe.get("schema_version") != SCHEMA_VERSION:
            raise ValueError(f"unsupported or missing schema_version in {path}")
        if recipe.get("mode") != "source":
            raise ValueError(f'{path}: recipe_generator only handles mode="source" recipes')
        missing = REQUIRED_FIELDS - recipe.keys()
        if missing:
            raise ValueError(f"{path} is missing: {', '.join(sorted(missing))}")
        _hex64(recipe["sha256"], path.name)
        if "patches" in recipe:
            if not isinstance(recipe["patches"], dict):
                raise ValueError(f"{path}: patches must be a table keyed by toolchain variant")
            recipe["patches"] = {
                variant: [str((path.parent / patch).resolve()) for patch in patch_list]
                for variant, patch_list in recipe["patches"].items()
            }
        recipes.append(recipe)
    return recipes


def generate_cells(
    recipes: list[dict[str, object]], toolchains: list[dict[str, object]]
) -> list[dict[str, object]]:
    cells = []
    for recipe in recipes:
        family = recipe["toolchain_family"]
        wanted_variants = set(recipe.get("toolchain_variants", []))
        matches = [
            row for row in toolchains
            if row["family"] == family
            and "toolchain_url" in row
            and (not wanted_variants or row["variant"] in wanted_variants)
        ]
        if not matches:
            raise ValueError(
                f'recipe {recipe["name"]} {recipe["version"]}: no source-capable '
                f'toolchain rows found for toolchain_family={family!r}'
            )
        patches_by_variant = recipe.get("patches", {})
        for row in matches:
            cell = {
                "family": recipe["name"],
                "version": str(recipe["version"]),
                "variant": f'{row["variant"]}-source',
                "machine": row["machine"],
                "endianness": row["endianness"],
                "elf_class": row["elf_class"],
                "priority": int(recipe.get("priority", row.get("priority", 100))),
                "mode": "source",
                "source_url": recipe["url"],
                "source_sha256": recipe["sha256"],
                "toolchain_url": row["toolchain_url"],
                "toolchain_sha256": row["toolchain_sha256"],
                "vm_iso_url": recipe.get("vm_iso_url", VM_ISO_URL),
                "vm_iso_sha256": recipe.get("vm_iso_sha256", VM_ISO_SHA256),
                "arch": row["cross_arch"],
                "cross_bin_prefix": row["cross_bin_prefix"],
                "library_path": recipe["library_path"],
                "build_adapter": recipe["build_adapter"],
            }
            if "kernel_headers_relpath" in row:
                cell["kernel_headers_relpath"] = row["kernel_headers_relpath"]
            if row["variant"] in patches_by_variant:
                cell["patches"] = patches_by_variant[row["variant"]]
            cells.append(cell)
    check_no_collisions(cells)
    return cells


def check_no_collisions(cells: list[dict[str, object]]) -> None:
    seen: set[tuple[object, object, object]] = set()
    for cell in cells:
        key = (cell["family"], cell["version"], cell["variant"])
        if key in seen:
            raise ValueError(f"duplicate generated cell: {key}")
        seen.add(key)
