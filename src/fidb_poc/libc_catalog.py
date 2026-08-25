"""Select and prepare checksum-pinned libc/toolchain candidates ("cells").

A cell bakes in its own target architecture -- there is no separate Route to
apply, the cell *is* the route. That's a genuinely different shape from the
Library/Route/Treatment matrix (one cell covers one fixed (machine,
endianness, elf_class)), so this stays a parallel, self-contained subsystem
rather than being forced into config.Library. Ported from
compile-stdlib-poc's candidates.py.

Cells come from two places, both TOML, both loaded by their own module:
toolchain_registry.load_toolchains() for mode="archive" (direct prebuilt
libc.a extraction) and recipe_generator.generate_cells() for mode="source"
(VM-isolated cross-compile). This module only operates on already-loaded
cell dicts -- see hunt.py for where the two lists are combined.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
from urllib.request import Request, urlopen

from .elf import ghidra_language
from .investigate import Investigation

log = logging.getLogger(__name__)


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def select_recipes(
    investigation: Investigation,
    recipes: list[dict[str, object]],
    requested: tuple[str, ...] = (),
) -> list[dict[str, object]]:
    facts = investigation.target
    inferred = [
        package
        for hypothesis in investigation.hypotheses
        if hypothesis.disposition.startswith("build")
        for package in hypothesis.candidate_packages
    ]

    desired = requested or tuple(inferred)

    def wanted(recipe: dict[str, object]) -> bool:
        identity = f'{recipe["family"]}@{recipe["version"]}'
        return recipe["family"] in desired or identity in desired

    compatible = [
        recipe for recipe in recipes
        if recipe.get("machine") == facts.machine
        and recipe.get("endianness") == facts.endianness
        and int(recipe.get("elf_class", 0)) == facts.elf_class
        and wanted(recipe)
    ]
    order = {name: index for index, name in enumerate(requested or tuple(inferred))}
    compatible.sort(key=lambda recipe: (
        order.get(f'{recipe["family"]}@{recipe["version"]}', order.get(recipe["family"], 999)),
        int(recipe.get("priority", 100)),
    ))
    return compatible


def _download_url(url: str, expected: str, cache: Path) -> Path:
    archive = cache / expected
    cache.mkdir(parents=True, exist_ok=True)
    if archive.exists() and hashlib.sha256(archive.read_bytes()).hexdigest() == expected:
        log.info("cache hit: %s (sha256=%s) -> %s", url, expected[:12], archive)
        return archive

    log.info("downloading %s -> %s", url, archive)
    temporary = archive.with_suffix(".part")
    request = Request(url, headers={"User-Agent": "fidb-poc/0.1"})
    digest = hashlib.sha256()
    with urlopen(request) as response, temporary.open("wb") as output:
        while chunk := response.read(1024 * 1024):
            output.write(chunk)
            digest.update(chunk)
    if digest.hexdigest() != expected:
        temporary.unlink(missing_ok=True)
        log.info("FAILED checksum mismatch: %s", url)
        raise ValueError(f"checksum mismatch downloading {url}")
    temporary.replace(archive)
    log.info("download OK: %s -> %s", url, archive)
    return archive


def _extract_verified(archive: Path, destination: Path) -> str:
    """Extract a tar archive completely, verifying no members were silently dropped.

    tar extraction has been observed to silently skip files when the
    destination directory is being written to concurrently by other work.
    Re-extracting into an empty directory and checking the member count
    catches that instead of shipping a broken toolchain/source tree.
    """
    log.info("extracting %s -> %s", archive, destination)
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r:*") as source:
        names = source.getnames()
        source.extractall(destination, filter="tar")
    top_level = {name.split("/", 1)[0] for name in names if name}
    if len(top_level) != 1:
        raise ValueError(f"expected a single top-level directory in {archive}, got {top_level}")
    extracted_count = sum(1 for _ in destination.rglob("*"))
    if extracted_count < len(names):
        raise ValueError(
            f"incomplete extraction of {archive}: expected {len(names)} entries, got {extracted_count}"
        )
    return next(iter(top_level))


def prepare_recipe(
    recipe: dict[str, object], work: Path, download_cache: Path
) -> dict[str, object]:
    """Prepare one recipe's object files, from a prebuilt archive or a from-source build."""
    mode = recipe.get("mode")
    if mode == "source":
        return _prepare_source_recipe(recipe, work, download_cache)
    if mode != "archive":
        raise ValueError(f"unsupported candidate mode: {mode}")
    recipe_digest = _digest(recipe)
    root = work / "prepared" / recipe_digest[:16]
    objects = root / "objects"
    marker = root / "recipe.json"
    label = f'{recipe["family"]} {recipe["version"]} {recipe["variant"]}'
    if marker.exists() and objects.exists() and any(objects.glob("*.o")):
        log.info("already prepared: %s -> %s (skipping archive fetch)", label, objects)
        return _guess(recipe, objects, recipe_digest)

    log.info("preparing archive candidate: %s (url=%s)", label, recipe["url"])
    archive = _download_url(str(recipe["url"]), str(recipe["sha256"]), download_cache)
    root.mkdir(parents=True, exist_ok=True)
    library = root / "library.a"
    with tarfile.open(archive, "r:*") as source:
        member = source.getmember(str(recipe["library_member"]))
        if not member.isfile():
            raise ValueError(f"{member.name} is not a regular archive member")
        extracted = source.extractfile(member)
        if extracted is None:
            raise ValueError(f"cannot extract {member.name}")
        with library.open("wb") as output:
            shutil.copyfileobj(extracted, output)

    members = None
    if "members_file" in recipe:
        members = [
            line.strip() for line in Path(str(recipe["members_file"])).read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
    objects.mkdir(parents=True, exist_ok=True)
    subprocess.run(["ar", "x", str(library.resolve()), *(members or [])], cwd=objects, check=True)
    _normalize_object_extensions(objects)
    object_count = len(list(objects.glob("*.o")))
    if not object_count:
        log.info("FAILED: no object files extracted for %s", label)
        raise ValueError(f"no object files extracted for {recipe['family']} {recipe['version']}")
    marker.write_text(json.dumps(recipe, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    log.info("prepared OK: %s -> %d object files in %s", label, object_count, objects)
    return _guess(recipe, objects, recipe_digest)


def _normalize_object_extensions(objects: Path) -> None:
    """uClibc's PIC/shared objects come out of `ar x` as .os/.oS, and musl's
    static objects come out as .lo (libtool objects) -- neither is .o.

    Every downstream consumer (this module's own sanity checks,
    ghidra_fid.py's object handling) expects .o, so normalize once here
    rather than teach every glob about extra suffixes.
    """
    for member in objects.iterdir():
        if member.suffix.lower() in (".os", ".lo"):
            member.rename(member.with_suffix(".o"))


_SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "scripts"


def _prepare_source_recipe(
    recipe: dict[str, object], work: Path, download_cache: Path
) -> dict[str, object]:
    """Cross-compile a recipe from source inside an isolated, offline QEMU VM.

    Config generation (defconfig/oldconfig) needs only a native host
    compiler and runs directly on the host. Only the actual cross-compile,
    which must execute the downloaded third-party toolchain, runs inside
    the VM -- see scripts/drive_source_vm_build.py for the isolation
    details (network cut before the toolchain is ever invoked).
    """
    recipe_digest = _digest(recipe)
    root = work / "prepared" / recipe_digest[:16]
    objects = root / "objects"
    marker = root / "recipe.json"
    label = f'{recipe["family"]} {recipe["version"]} {recipe["variant"]}'
    if marker.exists() and objects.exists() and any(objects.glob("*.o")):
        log.info("already compiled: %s -> %s (skipping source build)", label, objects)
        return _guess(recipe, objects, recipe_digest)

    log.info(
        "compiling from source: %s (source=%s toolchain=%s)",
        label, recipe["source_url"], recipe["toolchain_url"],
    )
    source_archive = _download_url(str(recipe["source_url"]), str(recipe["source_sha256"]), download_cache)
    toolchain_archive = _download_url(
        str(recipe["toolchain_url"]), str(recipe["toolchain_sha256"]), download_cache
    )
    iso = _download_url(str(recipe["vm_iso_url"]), str(recipe["vm_iso_sha256"]), download_cache)

    vm_dir = root / "vm"
    if vm_dir.exists():
        shutil.rmtree(vm_dir)
    src_dir_name = _extract_verified(source_archive, vm_dir)
    toolchain_dir_name = _extract_verified(toolchain_archive, vm_dir)
    src_root = vm_dir / src_dir_name

    for patch in recipe.get("patches", []):
        log.info("applying patch %s to %s", patch, src_root)
        with Path(str(patch)).open("rb") as patch_file:
            subprocess.run(["patch", "-p1"], cwd=src_root, stdin=patch_file, check=True)

    build_adapter = recipe.get("build_adapter", "uclibc_defconfig")
    if build_adapter == "uclibc_defconfig":
        log.info("configuring: ARCH=%s CROSS=%s in %s", recipe["arch"], recipe["cross_bin_prefix"], src_root)
        subprocess.run(
            ["make", f"ARCH={recipe['arch']}", f"CROSS={recipe['cross_bin_prefix']}", "defconfig"],
            cwd=src_root, check=True,
        )
        if "kernel_headers_relpath" in recipe:
            headers = f"/root/toolchain/{recipe['kernel_headers_relpath']}"
            subprocess.run(
                ["sed", "-i", f's#^KERNEL_HEADERS=.*#KERNEL_HEADERS="{headers}"#', str(src_root / ".config")],
                check=True,
            )
        subprocess.run(
            ["make", f"ARCH={recipe['arch']}", f"CROSS={recipe['cross_bin_prefix']}", "oldconfig"],
            cwd=src_root, check=True, stdin=subprocess.DEVNULL,
        )

    out_dir = vm_dir / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["qemu-img", "create", "-f", "qcow2", str(vm_dir / "scratch.qcow2"), "3G"], check=True,
    )
    log.info(
        "cross-compiling %s inside isolated VM: src=%s toolchain=%s library=%s",
        label, src_dir_name, toolchain_dir_name, recipe["library_path"],
    )
    subprocess.run(
        [
            sys.executable, str(_SCRIPTS_DIR / "drive_source_vm_build.py"),
            "--work", str(vm_dir),
            "--iso", str(iso),
            "--src-dir", src_dir_name,
            "--toolchain-dir", toolchain_dir_name,
            "--build-adapter", str(recipe.get("build_adapter", "uclibc_defconfig")),
            "--arch", str(recipe["arch"]),
            "--cross-bin-prefix", str(recipe["cross_bin_prefix"]),
            "--output-relpath", str(recipe["library_path"]),
        ],
        check=True, timeout=3000,
    )

    built_library = out_dir / Path(str(recipe["library_path"])).name
    if not built_library.exists():
        log.info("FAILED: source build for %s did not produce %s", label, built_library.name)
        raise ValueError(
            f"source build for {recipe['family']} {recipe['version']} did not produce {built_library.name}"
        )
    log.info("compile OK: %s -> %s", label, built_library)
    objects.mkdir(parents=True, exist_ok=True)
    subprocess.run(["ar", "x", str(built_library.resolve())], cwd=objects, check=True)
    _normalize_object_extensions(objects)
    object_count = len(list(objects.glob("*.o")))
    if not object_count:
        log.info("FAILED: no object files extracted for %s", label)
        raise ValueError(f"no object files extracted for {recipe['family']} {recipe['version']}")
    marker.write_text(json.dumps(recipe, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    log.info("prepared OK: %s -> %d object files in %s", label, object_count, objects)
    return _guess(recipe, objects, recipe_digest)


def _guess(recipe: dict[str, object], objects: Path, recipe_digest: str) -> dict[str, object]:
    source_url = recipe["source_url"] if recipe.get("mode") == "source" else recipe["url"]
    source_sha256 = recipe["source_sha256"] if recipe.get("mode") == "source" else recipe["sha256"]
    language = ghidra_language(
        str(recipe["machine"]), str(recipe["endianness"]), int(recipe["elf_class"])
    )
    if language is None:
        raise ValueError(
            f"no Ghidra language mapping for {recipe['machine']} "
            f"({recipe['endianness']}, {recipe['elf_class']}-bit)"
        )
    return {
        "family": recipe["family"],
        "version": str(recipe["version"]),
        "variant": recipe["variant"],
        "language": language,
        "objects": str(objects),
        "pattern": str(recipe.get("pattern", ".*")),
        "limit": int(recipe["limit"]) if "limit" in recipe else None,
        "recipe_digest": recipe_digest,
        "source_url": source_url,
        "source_sha256": source_sha256,
    }
