"""In-process PyGhidra FID database construction.

Runs the JVM inside this Python process via the ``pyghidra`` package instead
of shelling out to Ghidra's ``analyzeHeadless``/``pyghidraRun`` launchers.
That launcher round-trip is what previously hung indefinitely: its version
check silently failed on a `pip`-less venv and fell into a blocking
``input()`` prompt with no terminal attached. The in-process API never spawns
that launcher, so the same failure mode cannot occur.
"""

from __future__ import annotations

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
