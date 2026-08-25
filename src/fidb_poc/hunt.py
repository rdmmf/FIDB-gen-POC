"""Unattended investigate -> select -> prepare -> match workflow.

Ties together elf.py/investigate.py (target evidence), libc_catalog.py
(cell selection and object preparation) and ghidra_fid.py (in-process
analysis and FID matching) into one command. This is the "hunting" side of
the repo -- secondary to recipe generation, but it reuses the exact same
in-process Ghidra session machinery as ghidra_fid.build_library_fidb, so a
libc cell and a library recipe are matched/built through one Ghidra session
lifecycle either way.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
import re
import shutil

from . import ghidra_fid
from .investigate import investigate
from .libc_catalog import prepare_recipe, select_recipes
from .pipeline import find_ghidra, ghidra_environment
from .recipe_generator import generate_cells
from .recipe_generator import load_recipes as load_source_recipes
from .toolchain_registry import load_toolchains

log = logging.getLogger(__name__)


def load_cells(
    toolchains: str | Path, recipes: str | Path
) -> list[dict[str, object]]:
    """Every hunt candidate: archive-capable toolchain rows used directly,
    plus every recipe fanned out across its matching toolchain rows.

    Same registry backs both -- a row with url/sha256/library_member is
    already a self-contained mode="archive" cell (toolchain_registry.py
    tags it as such), no recipe required.
    """
    toolchain_rows = load_toolchains(toolchains)
    archive_cells = [row for row in toolchain_rows if row.get("mode") == "archive"]
    source_cells = generate_cells(load_source_recipes(recipes), toolchain_rows)
    return archive_cells + source_cells


def _select_objects(guess: dict[str, object]) -> list[Path]:
    objects_dir = Path(str(guess["objects"]))
    pattern = re.compile(str(guess["pattern"]))
    objects = [
        path for path in sorted(objects_dir.glob("*.o")) if pattern.search(path.name)
    ]
    limit = guess.get("limit")
    if limit is not None:
        objects = objects[: int(limit)]
    if not objects:
        raise ValueError(f"no object files selected from {objects_dir}")
    return objects


def hunt(
    target: str | Path,
    toolchains: str | Path = "toolchains/registry.toml",
    recipe_dir: str | Path = "recipes/libs",
    work: str | Path = "work/hunt",
    report: str | Path | None = None,
    maximum: int = 8,
    requested: tuple[str, ...] = (),
    fidb_dir: str | Path = "artifacts/fidbs",
) -> dict[str, object]:
    target_path = Path(target).expanduser().resolve()
    work_path = Path(work)
    if maximum < 1:
        raise ValueError("max_candidates must be at least 1")

    evidence = investigate(target_path)
    facts = evidence.target
    candidates = select_recipes(evidence, load_cells(toolchains, recipe_dir), requested)
    if not candidates:
        suffix = f" for {', '.join(requested)}" if requested else ""
        raise ValueError(f"no compatible catalog candidates{suffix}")
    if not facts.ghidra_language_hint:
        raise ValueError(
            f"no Ghidra language mapping for {facts.machine} "
            f"({facts.endianness}, {facts.elf_class}-bit); cannot analyze target"
        )

    headless, ghidra_home = find_ghidra()
    environment = ghidra_environment(work_path / "user")
    ghidra_fid.ensure_started(ghidra_home, environment)

    target_id = facts.sha256[:12]
    report_path = Path(report) if report else Path("artifacts") / f"hunt-{target_id}.json"
    target_project, target_program = ghidra_fid.analyze_target(
        target_path, work_path / "targets", f"target-{target_id}", facts.ghidra_language_hint,
    )

    log.info("investigated %s -> %d compatible candidate(s)", target_path, len(candidates))
    attempts = []
    for index, recipe in enumerate(candidates[:maximum], start=1):
        label = f'{recipe["family"]} {recipe["version"]} {recipe.get("variant")}'
        log.info("[%d/%d] trying candidate: %s", index, min(maximum, len(candidates)), label)
        guess = prepare_recipe(recipe, work_path, work_path / "downloads")
        objects = _select_objects(guess)
        digest = str(guess["recipe_digest"])[:12]
        candidate_dir = work_path / "candidates" / digest
        fidb = candidate_dir / "library.fidb"
        if fidb.exists():
            build = {"cached": 1}
        else:
            build = ghidra_fid.build_library_fidb(
                objects=objects,
                project_dir=candidate_dir / "project",
                project_name="objects",
                output=fidb,
                library=str(guess["family"]),
                version=str(guess["version"]),
                variant=str(guess["variant"]),
                language=str(guess["language"]),
                compiler_spec=ghidra_fid.compiler_spec_for_language(str(guess["language"])),
            )
        assessment = ghidra_fid.assess_fidb(
            target_project, f"target-{target_id}", target_program,
            fidb, candidate_dir / "matches.json",
        )
        attempts.append({"guess": guess, "fidb": str(fidb.resolve()), "build": build, "assessment": assessment})
        matched = bool(assessment["unambiguous_match_count"])
        log.info("%s: %s (matched=%s)", label, "MATCH" if matched else "no match", matched)
        if matched:
            pass # Do not break, find ALL statically linked functions

    exported = []
    export_dir = Path(fidb_dir)
    export_dir.mkdir(parents=True, exist_ok=True)
    for attempt in attempts:
        if not attempt["assessment"]["unambiguous_match_count"]:
            continue
        guess = attempt["guess"]
        name = "-".join(
            re.sub(r"[^A-Za-z0-9_.-]+", "-", str(guess[key])).strip("-")
            for key in ("family", "version", "variant")
        )
        recipe_id = str(guess.get("recipe_digest", "manual"))[:12]
        destination = export_dir / f"{name}-{recipe_id}.fidb"
        shutil.copy2(Path(str(attempt["fidb"])), destination)
        raw_destination = destination.with_suffix(".fidbf")
        ghidra_fid.export_raw_fidbf(destination, raw_destination)
        log.info("exported fidb: %s (raw: %s)", destination, raw_destination)
        exported.append(
            {
                "family": guess["family"],
                "version": guess["version"],
                "variant": guess["variant"],
                "fidb_path": str(destination.resolve()),
                "fidb_sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
                "fidbf_path": str(raw_destination.resolve()),
                "fidbf_sha256": hashlib.sha256(raw_destination.read_bytes()).hexdigest(),
                "matched_functions": attempt["assessment"]["matched_functions"],
                "unambiguous_matches": attempt["assessment"]["unambiguous_match_count"],
            }
        )

    result = {
        "investigation": evidence.to_dict(),
        "attempts": attempts,
        "matched": any(item["assessment"]["unambiguous_match_count"] for item in attempts),
        "toolchains": str(Path(toolchains)),
        "recipes": str(Path(recipe_dir)),
        "report": str(report_path),
        "fidbs": exported,
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    log.info("wrote hunt report: %s", report_path)
    return result
