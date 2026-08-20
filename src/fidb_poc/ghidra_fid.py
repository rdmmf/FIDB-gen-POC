"""In-process PyGhidra FID database construction.

Runs the JVM inside this Python process via the ``pyghidra`` package instead
of shelling out to Ghidra's ``analyzeHeadless``/``pyghidraRun`` launchers.
That launcher round-trip is what previously hung indefinitely: its version
check silently failed on a `pip`-less venv and fell into a blocking
``input()`` prompt with no terminal attached. The in-process API never spawns
that launcher, so the same failure mode cannot occur.
"""

from __future__ import annotations

import json
from pathlib import Path

import pyghidra


def ensure_started(install_dir: Path, environment: dict[str, str]) -> None:
    """Launch the JVM once for this process, with an isolated environment.

    The JVM can only be started once per process, so the deterministic
    HOME/XDG isolation that used to be applied per subprocess call is now
    applied once, before the first library is built.
    """
    if pyghidra.started():
        return
    import os

    os.environ.update(environment)
    pyghidra.start(install_dir=install_dir.resolve())


def _configure_fid_safe_analysis(program) -> None:
    """Match ``FunctionIDHeadlessPrescript.java``: FID/LID/demangler analyzers
    must be off while importing objects for FID creation, or they corrupt the
    very names FID is meant to identify; the scalar operand analyzer must be
    on so object-file references above 0x0 are resolved correctly.
    """
    from ghidra.program.model.listing import Program

    options = program.getOptions(Program.ANALYSIS_PROPERTIES)
    for name in (
        "Function ID",
        "Library Identification",
        "Demangler Microsoft",
        "Demangler GNU",
        "Demangler Rust",
        "Demangler Swift",
    ):
        if options.contains(name):
            options.setBoolean(name, False)
    if options.contains("Scalar Operand References"):
        options.setBoolean("Scalar Operand References", True)


def build_library_fidb(
    *,
    objects: list[Path],
    project_dir: Path,
    project_name: str,
    output: Path,
    library: str,
    version: str,
    variant: str,
    language: str,
    compiler_spec: str,
) -> dict[str, int]:
    """Import+analyze every object into one fresh Ghidra project, then build
    one FID database from all resulting programs.
    """
    from ghidra.feature.fid.db import FidFileManager
    from ghidra.feature.fid.service import FidService
    from ghidra.program.database import ProgramContentHandler
    from ghidra.program.model.lang import LanguageID
    from java.io import File
    from java.util import ArrayList

    if not objects:
        raise ValueError(f"no objects submitted for {library}")

    project_dir.mkdir(parents=True, exist_ok=True)
    monitor = pyghidra.task_monitor()

    def _prepare_and_analyze(program) -> None:
        _configure_fid_safe_analysis(program)
        pyghidra.analyze(program, monitor)

    with pyghidra.open_project(project_dir, project_name, create=True) as project:
        for obj in objects:
            loader = pyghidra.program_loader().project(project).source(str(obj))
            loader = loader.language(language).compiler(compiler_spec)
            with loader.load() as loaded:
                for item in loaded:
                    item.apply(_prepare_and_analyze)
                loaded.save(monitor)

        programs = ArrayList()
        pyghidra.walk_project(
            project,
            lambda file: programs.add(file),
            file_filter=lambda file: (
                file.getContentType() == ProgramContentHandler.PROGRAM_CONTENT_TYPE
            ),
        )
        if programs.isEmpty():
            raise RuntimeError(f"no programs were imported for {library}")

        output.parent.mkdir(parents=True, exist_ok=True)
        manager = FidFileManager.getInstance()
        manager.load()
        manager.createNewFidDatabase(File(str(output.resolve())))
        fid_file = manager.addUserFidFile(File(str(output.resolve())))
        database = fid_file.getFidDB(True)
        try:
            result = FidService().createNewLibraryFromPrograms(
                database,
                library,
                version,
                variant,
                programs,
                None,
                LanguageID(language),
                None,
                None,
                monitor,
            )
            database.saveDatabase(f"FIDB PoC deterministic population: {library}", monitor)
            # Explicit int(): these getters return boxed Java Integer/Long
            # objects via JPype, not plain Python int, and the pipeline's
            # provenance validation is strict about the exact type.
            return {
                "programs": int(programs.size()),
                "attempted": int(result.getTotalAttempted()),
                "added": int(result.getTotalAdded()),
                "excluded": int(result.getTotalExcluded()),
            }
        finally:
            database.close()
            manager.removeUserFile(fid_file)


def compiler_spec_for_language(language: str) -> str:
    """x86/x86-64 only define a "default" spec for 16-bit real mode; ELF
    binaries need the "gcc" spec. Every other processor defines "default" as
    the ELF/gcc-compatible spec, so only x86 is special-cased. Used for
    hunting (targets and catalog recipes), which have no Route to read an
    explicit compiler spec from -- build_library_fidb always takes one
    explicitly instead, since Route already carries the exact spec.
    """
    return "gcc" if language.startswith("x86:") else "default"


def analyze_target(
    target: Path, project_parent: Path, project_name: str, language: str
) -> tuple[Path, str]:
    """Import and analyze an unknown target once, then reuse its project."""
    project_parent.mkdir(parents=True, exist_ok=True)
    program_path = f"/{target.name}"
    monitor = pyghidra.task_monitor()
    with pyghidra.open_project(project_parent, project_name, create=True) as project:
        existing: set[str] = set()
        pyghidra.walk_project(project, lambda file: existing.add(str(file.getPathname())))
        if program_path not in existing:
            loader = pyghidra.program_loader().project(project).source(str(target.resolve()))
            loader = loader.language(language).compiler(compiler_spec_for_language(language))
            with loader.load() as loaded:
                for item in loaded:
                    item.apply(lambda program: pyghidra.analyze(program, monitor))
                loaded.save(monitor)
    return project_parent, program_path


def assess_fidb(
    target_project_dir: Path,
    target_project_name: str,
    target_program: str,
    fidb: Path,
    output: Path,
) -> dict[str, object]:
    """Query an analyzed target against exactly one FID database."""
    from ghidra.feature.fid.db import FidFileManager
    from ghidra.feature.fid.service import FidService
    from java.io import File

    with pyghidra.open_project(target_project_dir, target_project_name) as project:
        with pyghidra.program_context(project, target_program) as program:
            manager = FidFileManager.getInstance()
            manager.load()
            for item in manager.getFidFiles():
                item.setActive(False)
            candidate = manager.addUserFidFile(File(str(fidb.resolve())))
            candidate.setActive(True)
            service = FidService()
            query = manager.openFidQueryService(program.getLanguage(), False)
            matches = []
            matched_functions = 0
            try:
                results = service.processProgram(
                    program, query, service.getDefaultScoreThreshold(), pyghidra.task_monitor()
                )
                for result in results:
                    matched_functions += 1
                    for match in result.matches:
                        record = match.getFunctionRecord()
                        library = match.getLibraryRecord()
                        matches.append(
                            {
                                "address": str(result.function.getEntryPoint()),
                                "name": str(record.getName()),
                                "score": float(match.getOverallScore()),
                                "full_hash": format(
                                    int(result.hashQuad.getFullHash()) & ((1 << 64) - 1), "016x"
                                ),
                                "specific_hash": format(
                                    int(result.hashQuad.getSpecificHash()) & ((1 << 64) - 1), "016x"
                                ),
                                "library": str(library.getLibraryFamilyName()),
                                "version": str(library.getLibraryVersion()),
                                "variant": str(library.getLibraryVariant()),
                            }
                        )
            finally:
                query.close()
                manager.removeUserFile(candidate)

    names_by_address: dict[str, set[str]] = {}
    for match in matches:
        names_by_address.setdefault(str(match["address"]), set()).add(str(match["name"]))
    unambiguous = [
        match for match in matches if len(names_by_address[str(match["address"])]) == 1
    ]
    report = {
        "matched_functions": matched_functions,
        "match_count": len(matches),
        "unambiguous_match_count": len(unambiguous),
        "unambiguous_matches": unambiguous,
        "matches": matches,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def export_raw_fidbf(packed: Path, output: Path) -> Path:
    """Convert an attachable packed .fidb into Ghidra's installed raw .fidbf
    format -- the shape Ghidra's own bundled reference libraries ship in
    under Ghidra/Features/FunctionID/data/*.fidbf. build_library_fidb only
    ever produces the packed .fidb form.
    """
    from db import DBHandle
    from ghidra.feature.fid.db import FidFileManager
    from java.io import File

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".part")
    temporary.unlink(missing_ok=True)
    manager = FidFileManager.getInstance()
    manager.load()
    fid_file = manager.addUserFidFile(File(str(packed.resolve())))
    database = fid_file.getFidDB(False)
    try:
        database.saveRawDatabaseFile(File(str(temporary.resolve())), pyghidra.task_monitor())
    finally:
        database.close()
        manager.removeUserFile(fid_file)

    handle = DBHandle(File(str(temporary.resolve())))
    handle.close()
    temporary.replace(output)
    return output
