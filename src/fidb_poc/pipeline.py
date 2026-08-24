from __future__ import annotations

import csv
import hashlib
import importlib.metadata
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Iterable
from urllib.error import HTTPError

from . import __version__, ghidra_fid
from .adapters import (
    AdapterError,
    Detection,
    build_commands,
    build_environment,
    copy_pristine_source,
    detect_project,
    find_static_archives,
    linked_output_command,
)
from .config import Configuration, Library, Route, Treatment

DETERMINISTIC_ENVIRONMENT = {
    "LC_ALL": "C",
    "LANG": "C",
    "TZ": "UTC",
    "SOURCE_DATE_EPOCH": "1704067200",
    "ZERO_AR_DATE": "1",
}

# Build subprocesses start from this deliberately small subset.  In particular,
# caller-provided CFLAGS, CPPFLAGS, LDFLAGS, MAKEFLAGS and CONFIG_SITE must not
# silently change a supposedly frozen build cell.
PASSTHROUGH_ENVIRONMENT = {
    "COMSPEC",
    "GHIDRA_HEADLESS",
    "JAVA_HOME",
    "JAVA_TOOL_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "WINDIR",
    "_JAVA_OPTIONS",
}


@dataclass
class BuildRecord:
    library: str = ""
    version: str = ""
    route: str = ""
    treatment: str = ""
    sensitivity_factor: str = ""
    treatment_description: str = ""
    target_os: str = ""
    architecture: str = ""
    binary_format: str = ""
    detected_languages: str = ""
    detected_build_system: str = ""
    detection_evidence: str = ""
    source_url: str = ""
    source_sha256: str = ""
    compiler_command: str = ""
    compiler_path: str = ""
    compiler_sha256: str = ""
    compiler_version: str = ""
    compiler_flags: str = ""
    archiver_command: str = ""
    archiver_path: str = ""
    archiver_sha256: str = ""
    archiver_version: str = ""
    ranlib_command: str = ""
    ranlib_path: str = ""
    ranlib_sha256: str = ""
    ranlib_version: str = ""
    static_archive_path: str = ""
    static_archive_sha256: str = ""
    analysis_artifact_kind: str = ""
    analysis_artifact_path: str = ""
    analysis_artifact_sha256: str = ""
    object_count: int = 0
    ghidra_language: str = ""
    ghidra_compiler_spec: str = ""
    ghidra_version: str = ""
    ghidra_release: str = ""
    ghidra_build: str = ""
    ghidra_application_properties_sha256: str = ""
    ghidra_headless_path: str = ""
    pyghidra_version: str = ""
    java_path: str = ""
    java_version: str = ""
    fidb_path: str = ""
    fidb_sha256: str = ""
    fidb_bytes: int = 0
    fid_programs: int = 0
    fid_attempted: int = 0
    fid_added: int = 0
    fid_excluded: int = 0
    status: str = "requested"
    error: str = ""


class PipelineError(RuntimeError):
    pass


@dataclass(frozen=True)
class GhidraIdentity:
    version: str
    release: str
    build: str
    properties_sha256: str
    headless_path: str


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def resolve_executable(
    command: tuple[str, ...], environment: dict[str, str] | None = None
) -> Path:
    search_path = environment.get("PATH") if environment is not None else None
    candidate = shutil.which(command[0], path=search_path)
    if candidate is None:
        raise PipelineError(f"required executable is unavailable: {command[0]}")
    return Path(candidate).resolve()


def command_text(command: Iterable[str]) -> str:
    return " ".join(command)


def run_command(
    command: list[str],
    *,
    cwd: Path | None,
    environment: dict[str, str],
    log_path: Path,
    timeout: int = 1800,
    verbose: bool = False,
) -> subprocess.CompletedProcess[str]:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    if verbose:
        print(f"    $ {command_text(command)}")
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        assert process.stdout is not None
        lines: list[str] = []
        # ponytail: no per-line timeout while streaming (a fully-silent hang
        # can't be interrupted here); process.wait() below still enforces one.
        for line in process.stdout:
            lines.append(line)
            print(f"    | {line.rstrip()}")
        process.stdout.close()
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise
        result = subprocess.CompletedProcess(command, returncode, "".join(lines), None)
    else:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
    log_path.write_text(
        f"$ {command_text(command)}\n\n{result.stdout}", encoding="utf-8"
    )
    if result.returncode != 0:
        raise PipelineError(
            f"command failed ({result.returncode}); see {log_path}: "
            f"{command_text(command)}"
        )
    return result


def pipeline_environment(extra: dict[str, str] | None = None) -> dict[str, str]:
    environment = {
        name: value
        for name, value in os.environ.items()
        if name in PASSTHROUGH_ENVIRONMENT
    }
    environment.update(DETERMINISTIC_ENVIRONMENT)
    if extra:
        environment.update(extra)
    return environment


def _remove_generated_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        shutil.rmtree(path)


def _recreate_directory(path: Path) -> None:
    _remove_generated_path(path)
    path.mkdir(parents=True)


def validate_generated_root(project_root: Path, path: Path, expected_name: str) -> Path:
    resolved_root = project_root.resolve()
    expected = resolved_root / expected_name
    if path.name != Path(expected_name).name or path.is_symlink():
        raise PipelineError(f"refusing unsafe generated root: {path}")
    if path.exists() and not path.is_dir():
        raise PipelineError(f"generated root is not a directory: {path}")
    resolved_path = path.resolve()
    if resolved_path != expected:
        raise PipelineError(
            f"generated root must resolve exactly to {expected}: {path}"
        )
    return resolved_path


def validate_generated_child(root: Path, path: Path, relative_name: str) -> Path:
    resolved_root = root.resolve()
    expected = resolved_root / relative_name
    if path.is_symlink() or path.resolve() != expected:
        raise PipelineError(
            f"refusing unsafe generated path; expected {expected}: {path}"
        )
    return expected


def download_library(library: Library, downloads: Path) -> Path:
    downloads.mkdir(parents=True, exist_ok=True)
    archive = downloads / f"{library.identifier}.tar.gz"
    if archive.is_file() and sha256(archive) == library.sha256:
        return archive
    if archive.exists():
        archive.unlink()

    partial = archive.with_suffix(archive.suffix + ".partial")
    request = urllib.request.Request(
        library.url, headers={"User-Agent": f"fidb-poc/{__version__}"}
    )
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                with partial.open("wb") as output:
                    shutil.copyfileobj(response, output)
            break
        except HTTPError as error:
            partial.unlink(missing_ok=True)
            retryable = error.code == 429 or 500 <= error.code < 600
            if not retryable or attempt == 2:
                raise
            time.sleep(2 ** (attempt + 1))
        except Exception:
            partial.unlink(missing_ok=True)
            raise
    observed = sha256(partial)
    if observed != library.sha256:
        partial.unlink(missing_ok=True)
        raise PipelineError(
            f"source hash mismatch for {library.identifier}: "
            f"expected {library.sha256}, observed {observed}"
        )
    partial.replace(archive)
    return archive


def _safe_member_path(destination: Path, member_name: str) -> Path:
    member = Path(member_name)
    if member.is_absolute() or ".." in member.parts:
        raise PipelineError(f"unsafe archive path: {member_name}")
    resolved = (destination / member).resolve()
    if destination.resolve() not in (resolved, *resolved.parents):
        raise PipelineError(f"archive member escapes destination: {member_name}")
    return resolved


def extract_source(library: Library, archive: Path, sources: Path) -> Path:
    observed = sha256(archive)
    if observed != library.sha256:
        raise PipelineError(
            f"source hash mismatch for {library.identifier}: "
            f"expected {library.sha256}, observed {observed}"
        )

    sources.mkdir(parents=True, exist_ok=True)
    destination = sources / library.identifier
    with tempfile.TemporaryDirectory(
        prefix=f".{library.identifier}-", dir=sources
    ) as temporary:
        staging = Path(temporary) / library.identifier
        staging.mkdir()
        with tarfile.open(archive, "r:*") as source_tar:
            for member in source_tar.getmembers():
                target = _safe_member_path(staging, member.name)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    raise PipelineError(
                        f"unsupported archive member type for {member.name!r}"
                    )
                target.parent.mkdir(parents=True, exist_ok=True)
                input_stream = source_tar.extractfile(member)
                if input_stream is None:
                    raise PipelineError(
                        f"could not read archive member {member.name!r}"
                    )
                with input_stream, target.open("wb") as output_stream:
                    shutil.copyfileobj(input_stream, output_stream)
                target.chmod(0o644)

        staged_root = staging / library.source_directory
        if not staged_root.is_dir():
            raise PipelineError(
                f"archive for {library.identifier} did not contain "
                f"{library.source_directory!r}"
            )
        _remove_generated_path(destination)
        staging.replace(destination)
    return destination / library.source_directory


def executable_identity(
    command: tuple[str, ...],
    environment: dict[str, str],
    *,
    label: str,
) -> tuple[Path, str]:
    executable = resolve_executable(command, environment)
    with tempfile.TemporaryDirectory(prefix=f"fidb-{label}-identity-") as temporary:
        result = subprocess.run(
            [*command, "--version"],
            cwd=temporary,
            env=environment,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
    version = "\n".join(
        part.strip() for part in (result.stdout, result.stderr) if part.strip()
    )
    if result.returncode != 0 or not version:
        raise PipelineError(f"could not identify {label}: {command_text(command)}")
    return executable, version


def compiler_identity(route: Route, environment: dict[str, str]) -> tuple[Path, str]:
    executable, version = executable_identity(
        route.compiler, environment, label="compiler"
    )
    missing_markers = [
        marker for marker in route.compiler_version_markers if marker not in version
    ]
    if missing_markers:
        raise PipelineError(
            f"compiler for {route.id} failed identity check; "
            f"missing version markers: {missing_markers}"
        )
    return executable, version


def _base_record(
    library: Library,
    route: Route,
    treatment: Treatment,
    detection: Detection,
) -> BuildRecord:
    return BuildRecord(
        library=library.name,
        version=library.version,
        route=route.id,
        treatment=treatment.id,
        sensitivity_factor=treatment.factor,
        treatment_description=treatment.description,
        target_os=route.target_os,
        architecture=route.architecture,
        binary_format=route.binary_format,
        detected_languages=";".join(detection.languages),
        detected_build_system=detection.build_system,
        detection_evidence=";".join(detection.evidence),
        source_url=library.url,
        source_sha256=library.sha256,
        compiler_command=command_text(route.compiler),
        compiler_flags=command_text(treatment.flags_for(route)),
        archiver_command=command_text(route.archiver),
        ranlib_command=command_text(route.ranlib),
        ghidra_language=route.ghidra_language,
        ghidra_compiler_spec=route.ghidra_compiler_spec,
    )


def _extract_archive_objects(
    archive: Path,
    destination: Path,
    route: Route,
    environment: dict[str, str],
    log_path: Path,
) -> list[Path]:
    listing = run_command(
        [*route.archiver, "t", str(archive)],
        cwd=archive.parent,
        environment=environment,
        log_path=log_path.with_name(f"{archive.name}-list.log"),
    ).stdout.splitlines()
    members = [name.strip() for name in listing if name.strip()]
    duplicates = sorted(name for name, count in Counter(members).items() if count > 1)
    if duplicates:
        raise PipelineError(
            f"archive {archive.name} has duplicate member names: {duplicates}"
        )
    invalid_members = sorted(
        name
        for name in members
        if Path(name).name != name or Path(name).suffix.lower() not in {".o", ".obj"}
    )
    if invalid_members:
        raise PipelineError(
            f"archive {archive.name} has non-object or nested members: "
            f"{invalid_members}"
        )
    _recreate_directory(destination)
    run_command(
        [*route.archiver, "x", str(archive)],
        cwd=destination,
        environment=environment,
        log_path=log_path.with_name(f"{archive.name}-extract.log"),
    )
    objects = sorted(
        path
        for path in destination.iterdir()
        if path.is_file() and path.suffix.lower() in {".o", ".obj"}
    )
    if not objects:
        raise PipelineError(f"archive {archive} contains no object members")
    observed_members = [path.name for path in objects]
    if Counter(observed_members) != Counter(members):
        raise PipelineError(
            f"archive extraction did not reconcile for {archive.name}; "
            f"listed={sorted(members)}, extracted={sorted(observed_members)}"
        )
    unexpected = sorted(
        path.name
        for path in destination.iterdir()
        if not path.is_file() or path.name not in members
    )
    if unexpected:
        raise PipelineError(
            f"archive extraction produced unexpected entries for {archive.name}: "
            f"{unexpected}"
        )
    return objects


def _validate_objects(
    objects: list[Path], route: Route, environment: dict[str, str]
) -> None:
    for object_path in objects:
        result = subprocess.run(
            ["file", "--brief", str(object_path)],
            env=environment,
            text=True,
            capture_output=True,
            check=True,
        )
        missing = [
            marker
            for marker in route.object_file_markers
            if marker not in result.stdout
        ]
        if missing:
            raise PipelineError(
                f"{object_path.name} does not match route {route.id}: "
                f"{result.stdout.strip()} (missing {missing})"
            )


def _validate_linked_output(
    output: Path, route: Route, environment: dict[str, str]
) -> None:
    result = subprocess.run(
        ["file", "--brief", str(output)],
        env=environment,
        text=True,
        capture_output=True,
        check=True,
    )
    missing = [
        marker for marker in route.linked_file_markers if marker not in result.stdout
    ]
    if missing:
        raise PipelineError(
            f"{output.name} does not match linked route {route.id}: "
            f"{result.stdout.strip()} (missing {missing})"
        )


def build_library(
    library: Library,
    route: Route,
    treatment: Treatment,
    detection: Detection,
    source_root: Path,
    work: Path,
    logs: Path,
    verbose: bool = False,
) -> tuple[BuildRecord, list[Path]]:
    record = _base_record(library, route, treatment, detection)
    if not treatment.applies_to(route):
        record.status = "unsupported"
        record.error = "treatment is not valid for this route"
        return record, []
    cell_id = f"{library.identifier}-{route.id}-{treatment.id}"
    build_root = work / "builds" / cell_id
    _remove_generated_path(build_root)
    cell_source = copy_pristine_source(source_root, build_root / "source")
    objects_root = build_root / "objects"
    environment = pipeline_environment(
        build_environment(
            detection.build_system,
            route=route,
            compiler_flags=treatment.flags_for(route),
        )
    )
    compiler_path, compiler_version = compiler_identity(route, environment)
    archiver_path, archiver_version = executable_identity(
        route.archiver, environment, label="archiver"
    )
    ranlib_path, ranlib_version = executable_identity(
        route.ranlib, environment, label="ranlib"
    )
    for index, command in enumerate(
        build_commands(
            detection.build_system,
            route=route,
            compiler_flags=treatment.flags_for(route),
            jobs=4,
        ),
        start=1,
    ):
        run_command(
            list(command),
            cwd=cell_source,
            environment=environment,
            log_path=logs / "build" / f"{cell_id}-{index:02d}.log",
            timeout=3600,
            verbose=verbose,
        )

    archives = find_static_archives(cell_source, library.static_archives)
    if treatment.phase == "compile":
        analysis_artifacts: list[Path] = []
        for index, archive in enumerate(archives, start=1):
            analysis_artifacts.extend(
                _extract_archive_objects(
                    archive,
                    objects_root / f"{index:02d}-{archive.stem}",
                    route,
                    environment,
                    logs / "archive" / cell_id / archive.name,
                )
            )
        _validate_objects(analysis_artifacts, route, environment)
        artifact_kind = "archive_members"
    else:
        linked_root = build_root / "linked"
        linked_root.mkdir(parents=True, exist_ok=True)
        linked_output = linked_root / f"{library.name}{route.linked_suffix}"
        command = linked_output_command(
            route=route,
            treatment=treatment,
            archives=archives,
            output=linked_output,
        )
        run_command(
            list(command),
            cwd=build_root,
            environment=environment,
            log_path=logs / "link" / f"{cell_id}.log",
            timeout=3600,
            verbose=verbose,
        )
        _validate_linked_output(linked_output, route, environment)
        analysis_artifacts = [linked_output]
        artifact_kind = "linked_library"

    record.compiler_path = str(compiler_path)
    record.compiler_sha256 = sha256(compiler_path)
    record.compiler_version = compiler_version.replace("\n", " | ")
    record.archiver_path = str(archiver_path)
    record.archiver_sha256 = sha256(archiver_path)
    record.archiver_version = archiver_version.replace("\n", " | ")
    record.ranlib_path = str(ranlib_path)
    record.ranlib_sha256 = sha256(ranlib_path)
    record.ranlib_version = ranlib_version.replace("\n", " | ")
    record.static_archive_path = ";".join(
        str(path.relative_to(work.parent)) for path in archives
    )
    record.static_archive_sha256 = ";".join(sha256(path) for path in archives)
    record.analysis_artifact_kind = artifact_kind
    record.analysis_artifact_path = ";".join(
        str(path.relative_to(work.parent)) for path in analysis_artifacts
    )
    record.analysis_artifact_sha256 = ";".join(
        sha256(path) for path in analysis_artifacts
    )
    record.object_count = len(analysis_artifacts)
    record.status = "built"
    return record, analysis_artifacts


def find_ghidra() -> tuple[Path, Path]:
    configured = os.environ.get("GHIDRA_HEADLESS")
    candidates = [Path(configured)] if configured else []
    candidates.extend(
        sorted(
            Path("/opt/homebrew/Cellar/ghidra").glob(
                "*/libexec/support/analyzeHeadless"
            ),
            reverse=True,
        )
    )
    for headless in candidates:
        if headless.is_file():
            return headless, headless.parent.parent
    raise PipelineError("Ghidra analyzeHeadless was not found; set GHIDRA_HEADLESS")


def find_pyghidra(headless: Path) -> Path:
    # Still used by language_probe.py's separate subprocess-based probe flow;
    # _populate_group no longer needs it (see ghidra_fid.py).
    launcher = headless.with_name("pyghidraRun")
    if launcher.is_file():
        return launcher
    raise PipelineError(
        f"Ghidra PyGhidra launcher was not found beside {headless}; "
        "install Ghidra 12 or later"
    )


def _require_executable_file(path: Path, label: str) -> Path:
    if not path.is_file() or not os.access(path, os.X_OK):
        raise PipelineError(f"{label} is not executable: {path}")
    return path


def ghidra_identity(headless: Path, ghidra_home: Path) -> GhidraIdentity:
    properties_path = ghidra_home / "Ghidra/application.properties"
    if not properties_path.is_file():
        raise PipelineError(
            f"Ghidra application properties were not found: {properties_path}"
        )
    properties = {}
    for raw_line in properties_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        properties[name.strip()] = value.strip()
    required = {
        "version": properties.get("application.version", ""),
        "release": properties.get("application.release.name", ""),
        "build": properties.get("application.build.date", ""),
    }
    missing = sorted(name for name, value in required.items() if not value)
    if missing:
        raise PipelineError(
            f"Ghidra application properties are missing: {', '.join(missing)}"
        )
    return GhidraIdentity(
        version=required["version"],
        release=required["release"],
        build=required["build"],
        properties_sha256=sha256(properties_path),
        headless_path=str(headless.resolve()),
    )


def java_identity(environment: dict[str, str]) -> tuple[Path, str, int]:
    java_home = environment.get("JAVA_HOME")
    if java_home:
        configured = Path(java_home) / "bin/java"
        if not configured.is_file() or not os.access(configured, os.X_OK):
            raise PipelineError(
                f"JAVA_HOME does not contain executable bin/java: {java_home}"
            )
        executable = configured.resolve()
    else:
        executable = resolve_executable(("java",), environment)
    result = subprocess.run(
        [str(executable), "-version"],
        env=environment,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    output = "\n".join(part for part in (result.stdout, result.stderr) if part).strip()
    match = re.search(r'version\s+"(?P<version>\d+(?:\.\d+)*)', output)
    if result.returncode != 0 or match is None:
        raise PipelineError(f"could not identify Java runtime: {output or executable}")
    version = match.group("version")
    components = version.split(".")
    major = int(components[1] if components[0] == "1" else components[0])
    if major < 21:
        raise PipelineError(
            f"Ghidra requires Java 21 or later; found Java {version} at {executable}"
        )
    return executable, version, major


def pyghidra_identity() -> str:
    # PyGhidra now runs in-process (see ghidra_fid.py), so its version is simply
    # this interpreter's installed package metadata, not a probed subprocess.
    try:
        return importlib.metadata.version("pyghidra")
    except importlib.metadata.PackageNotFoundError as error:
        raise PipelineError("could not identify installed pyghidra package") from error


def ghidra_environment(project_root: Path) -> dict[str, str]:
    project_root.mkdir(parents=True, exist_ok=True)
    xdg_directories = {
        "XDG_CONFIG_HOME": project_root / ".config",
        "XDG_CACHE_HOME": project_root / ".cache",
        "XDG_DATA_HOME": project_root / ".local/share",
        "XDG_STATE_HOME": project_root / ".local/state",
        "XDG_RUNTIME_DIR": project_root / ".runtime",
    }
    for directory in xdg_directories.values():
        directory.mkdir(parents=True, exist_ok=True)
    xdg_directories["XDG_RUNTIME_DIR"].chmod(0o700)
    inherited_java_options = os.environ.get("JAVA_TOOL_OPTIONS", "").strip()
    java_tool_options = " ".join(
        part
        for part in (
            inherited_java_options,
            f"-Duser.home={project_root.resolve()}",
        )
        if part
    )
    environment = pipeline_environment(
        {
            "GHIDRA_USER_HOME": str(project_root.resolve()),
            "HOME": str(project_root.resolve()),
            **{
                name: str(directory.resolve())
                for name, directory in xdg_directories.items()
            },
            "JAVA_TOOL_OPTIONS": java_tool_options,
        }
    )
    java_home = Path("/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home")
    if "JAVA_HOME" not in environment and java_home.is_dir():
        environment["JAVA_HOME"] = str(java_home)
        environment["PATH"] = f"{java_home / 'bin'}:{environment['PATH']}"
    return environment


def _validate_population_report(
    populations: list[dict],
    libraries: list[Library],
    group_id: str,
    output_directory: Path,
    expected_program_counts: dict[str, int],
) -> dict[str, dict]:
    expected_names = [library.name for library in libraries]
    observed_names = [row.get("library") for row in populations]
    if Counter(observed_names) != Counter(expected_names):
        raise PipelineError(
            "Ghidra population report does not match the requested libraries; "
            f"expected={sorted(expected_names)}, observed={sorted(observed_names)}"
        )

    by_library = {row["library"]: row for row in populations}
    for library in libraries:
        row = by_library[library.name]
        expected_fidb = (
            output_directory / f"{library.identifier}-{group_id}.fidb"
        ).resolve()
        observed_fidb = Path(row.get("fidb_path", "")).resolve()
        expected_identity = {
            "library": library.name,
            "version": library.version,
            "variant": group_id,
        }
        for field, expected in expected_identity.items():
            if row.get(field) != expected:
                raise PipelineError(
                    f"Ghidra population report has the wrong {field} for "
                    f"{library.identifier}: expected={expected!r}, "
                    f"observed={row.get(field)!r}"
                )
        if observed_fidb != expected_fidb:
            raise PipelineError(
                f"Ghidra population report points at an unexpected FIDB for "
                f"{library.identifier}: {observed_fidb}"
            )

        counts = {
            field: row.get(field)
            for field in ("program_count", "attempted", "added", "excluded")
        }
        if any(type(value) is not int or value < 0 for value in counts.values()):
            raise PipelineError(
                f"Ghidra population report has invalid counts for "
                f"{library.identifier}: {counts}"
            )
        if counts["program_count"] == 0 or counts["attempted"] == 0:
            raise PipelineError(
                f"Ghidra population report is empty for {library.identifier}"
            )
        expected_program_count = expected_program_counts.get(library.name)
        if expected_program_count is None:
            raise PipelineError(
                f"missing intended program count for {library.identifier}"
            )
        if counts["program_count"] != expected_program_count:
            raise PipelineError(
                f"Ghidra program count does not match the submitted artifacts for "
                f"{library.identifier}: expected={expected_program_count}, "
                f"observed={counts['program_count']}"
            )
        if counts["attempted"] != counts["added"] + counts["excluded"]:
            raise PipelineError(
                f"Ghidra population counts do not reconcile for "
                f"{library.identifier}: {counts}"
            )
        if counts["added"] == 0:
            raise PipelineError(f"Ghidra added no signatures for {library.identifier}")
        if not expected_fidb.is_file() or expected_fidb.stat().st_size == 0:
            raise PipelineError(f"Ghidra did not produce a non-empty {expected_fidb}")
    return by_library


def _populate_group(
    configuration: Configuration,
    project_root: Path,
    route: Route,
    treatment: Treatment,
    records: dict[tuple[str, str, str], BuildRecord],
    objects: dict[tuple[str, str, str], list[Path]],
    verbose: bool = False,
) -> None:
    headless, ghidra_home = find_ghidra()
    _require_executable_file(headless, "Ghidra analyzeHeadless")
    identity = ghidra_identity(headless, ghidra_home)
    group_id = f"{route.id}-{treatment.id}"
    projects = project_root / "work/ghidra/projects" / group_id
    references = project_root / "work/ghidra/references" / route.id / treatment.id
    candidates = project_root / "work/ghidra/candidates" / group_id
    output_fidb = project_root / "artifacts/libs/fidb"
    output_fidb.mkdir(parents=True, exist_ok=True)
    _recreate_directory(projects)
    _recreate_directory(references)
    _recreate_directory(candidates)
    # Shared across every route/treatment group in this run: the JVM can only
    # start once per process, so isolation is scoped to the whole `execute()`
    # run rather than per group (see ghidra_fid.ensure_started).
    user_root = project_root / "work/ghidra/user"
    user_root.mkdir(parents=True, exist_ok=True)

    available = []
    expected_program_counts: dict[str, int] = {}
    for library in configuration.libraries:
        key = (library.identifier, route.id, treatment.id)
        if records[key].status != "built":
            continue
        available.append(library)
        expected_program_counts[library.name] = len(objects[key])
        if not objects[key]:
            raise PipelineError(
                f"no analysis artifacts were submitted for {library.identifier}"
            )
        record = records[key]
        record.ghidra_version = identity.version
        record.ghidra_release = identity.release
        record.ghidra_build = identity.build
        record.ghidra_application_properties_sha256 = identity.properties_sha256
        record.ghidra_headless_path = identity.headless_path
    if not available:
        return

    environment = ghidra_environment(user_root)
    java, java_version, _ = java_identity(environment)
    pyghidra_version = pyghidra_identity()
    ghidra_fid.ensure_started(ghidra_home, environment)
    for library in available:
        key = (library.identifier, route.id, treatment.id)
        record = records[key]
        record.pyghidra_version = pyghidra_version
        record.java_path = str(java)
        record.java_version = java_version

    populations = []
    for library in available:
        key = (library.identifier, route.id, treatment.id)
        library_folder = references / library.identifier
        library_folder.mkdir(parents=True, exist_ok=True)
        staged_objects = []
        for index, object_path in enumerate(objects[key], start=1):
            destination = library_folder / f"{index:04d}-{object_path.name}"
            shutil.copy2(object_path, destination)
            staged_objects.append(destination)

        candidate_fidb = candidates / f"{library.identifier}-{group_id}.fidb"
        project_name = f"FIDB_{library.identifier}_{group_id}".replace("-", "_")
        result = ghidra_fid.build_library_fidb(
            objects=staged_objects,
            project_dir=projects / library.identifier,
            project_name=project_name,
            output=candidate_fidb,
            library=library.name,
            version=library.version,
            variant=group_id,
            language=route.ghidra_language,
            compiler_spec=route.ghidra_compiler_spec,
        )
        populations.append(
            {
                "library": library.name,
                "version": library.version,
                "variant": group_id,
                "fidb_path": str(candidate_fidb.resolve()),
                "program_count": result["programs"],
                "attempted": result["attempted"],
                "added": result["added"],
                "excluded": result["excluded"],
            }
        )

    by_library = _validate_population_report(
        populations,
        available,
        group_id,
        candidates,
        expected_program_counts,
    )
    for library in available:
        population = by_library[library.name]
        candidate_fidb = Path(population["fidb_path"])
        final_fidb = output_fidb / candidate_fidb.name
        candidate_fidb.replace(final_fidb)
        population["fidb_path"] = str(final_fidb.resolve())
    for library in available:
        key = (library.identifier, route.id, treatment.id)
        record = records[key]
        population = by_library[library.name]
        fidb = Path(population["fidb_path"])
        record.fidb_path = str(fidb.resolve().relative_to(project_root.resolve()))
        record.fidb_sha256 = sha256(fidb)
        record.fidb_bytes = fidb.stat().st_size
        record.fid_programs = population["program_count"]
        record.fid_attempted = population["attempted"]
        record.fid_added = population["added"]
        record.fid_excluded = population["excluded"]
        record.status = "complete"


def populate_fidbs(
    configuration: Configuration,
    project_root: Path,
    records: dict[tuple[str, str, str], BuildRecord],
    objects: dict[tuple[str, str, str], list[Path]],
    verbose: bool = False,
) -> None:
    for route in configuration.routes:
        for treatment in configuration.treatments:
            group_keys = [
                (library.identifier, route.id, treatment.id)
                for library in configuration.libraries
            ]
            if not any(records[key].status == "built" for key in group_keys):
                continue
            try:
                _populate_group(
                    configuration,
                    project_root,
                    route,
                    treatment,
                    records,
                    objects,
                    verbose=verbose,
                )
            except (
                KeyError,
                OSError,
                PipelineError,
                TypeError,
                ValueError,
                subprocess.SubprocessError,
            ) as error:
                group_id = f"{route.id}-{treatment.id}"
                _remove_generated_path(
                    project_root / "work/ghidra/candidates" / group_id
                )
                for library, key in zip(configuration.libraries, group_keys):
                    partial_fidb = (
                        project_root
                        / "artifacts/libs/fidb"
                        / f"{library.identifier}-{group_id}.fidb"
                    )
                    partial_fidb.unlink(missing_ok=True)
                    if records[key].status in {"built", "complete"}:
                        records[key].status = "fid_failed"
                        records[key].error = str(error)
                        records[key].fidb_path = ""
                        records[key].fidb_sha256 = ""
                        records[key].fidb_bytes = 0
                        records[key].fid_programs = 0
                        records[key].fid_attempted = 0
                        records[key].fid_added = 0
                        records[key].fid_excluded = 0


def write_manifest(records: Iterable[BuildRecord], destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    rows = [asdict(record) for record in records]
    if not rows:
        raise PipelineError("cannot write an empty manifest")
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=destination.parent,
            delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
            stream.flush()
            os.fsync(stream.fileno())
        temporary_path.chmod(0o644)
        temporary_path.replace(destination)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def plan(configuration: Configuration) -> list[str]:
    cells = [
        (library, route, treatment)
        for library in configuration.libraries
        for route in configuration.routes
        for treatment in configuration.treatments
    ]
    runnable = sum(treatment.applies_to(route) for _, route, treatment in cells)
    lines = [
        f"Plan: {len(configuration.libraries)} libraries; "
        f"{len(configuration.routes)} routes; "
        f"{len(configuration.treatments)} treatments; "
        f"{len(cells)} cells ({runnable} runnable)"
    ]
    for library, route, treatment in cells:
        status = "runnable" if treatment.applies_to(route) else "unsupported"
        lines.append(f"- {library.identifier} | {route.id} | {treatment.id} | {status}")
    return lines


def execute(
    configuration: Configuration,
    project_root: Path,
    progress: Callable[[str], None] | None = None,
    verbose: bool = False,
) -> Path:
    announce = progress or (lambda _: None)
    downloads = project_root / "work/downloads"
    sources = project_root / "work/sources"
    work = project_root / "work"
    logs = work / "logs"
    output = project_root / "artifacts" / "libs"
    manifest = output / "fidb_manifest.csv"
    validate_generated_root(project_root, work, "work")
    validate_generated_root(project_root, output, "artifacts/libs")
    generated_children = (
        (work, downloads, "downloads"),
        (work, sources, "sources"),
        (work, work / "builds", "builds"),
        (work, logs, "logs"),
        (work, work / "ghidra", "ghidra"),
        (output, output / "fidb", "fidb"),
        (output, manifest, "fidb_manifest.csv"),
    )
    for generated_root, path, relative_name in generated_children:
        validate_generated_child(generated_root, path, relative_name)
    if downloads.exists() and not downloads.is_dir():
        raise PipelineError(f"download cache is not a directory: {downloads}")
    if manifest.exists() and not manifest.is_file():
        raise PipelineError(f"manifest path is not a file: {manifest}")
    downloads.mkdir(parents=True, exist_ok=True)
    _recreate_directory(sources)
    _recreate_directory(work / "builds")
    _recreate_directory(logs)
    _recreate_directory(work / "ghidra")
    _recreate_directory(output / "fidb")
    manifest.unlink(missing_ok=True)
    records: dict[tuple[str, str, str], BuildRecord] = {}
    object_sets: dict[tuple[str, str, str], list[Path]] = {}
    source_roots: dict[str, Path] = {}
    detections: dict[str, Detection] = {}

    for index, library in enumerate(configuration.libraries, start=1):
        announce(
            f"[source {index}/{len(configuration.libraries)}] " f"{library.identifier}"
        )
        archive = download_library(library, downloads)
        source_root = extract_source(library, archive, sources)
        try:
            detection = detect_project(library, source_root)
        except AdapterError as error:
            raise PipelineError(str(error)) from error
        source_roots[library.identifier] = source_root
        detections[library.identifier] = detection
        announce(
            f"  verified: {detection.build_system}; "
            f"languages={','.join(detection.languages)}"
        )

    cell_count = (
        len(configuration.libraries)
        * len(configuration.routes)
        * len(configuration.treatments)
    )
    cell_index = 0
    for library in configuration.libraries:
        for route in configuration.routes:
            for treatment in configuration.treatments:
                cell_index += 1
                key = (library.identifier, route.id, treatment.id)
                announce(
                    f"[build {cell_index}/{cell_count}] {library.identifier} | "
                    f"{route.id} | {treatment.id}"
                )
                try:
                    record, built_objects = build_library(
                        library,
                        route,
                        treatment,
                        detections[library.identifier],
                        source_roots[library.identifier],
                        work,
                        logs,
                        verbose=verbose,
                    )
                except (
                    AdapterError,
                    OSError,
                    PipelineError,
                    subprocess.SubprocessError,
                ) as error:
                    record = _base_record(
                        library, route, treatment, detections[library.identifier]
                    )
                    record.status = "build_failed"
                    record.error = str(error)
                    built_objects = []
                records[key] = record
                object_sets[key] = built_objects
                visible_status = (
                    "compiled" if record.status == "built" else record.status
                )
                announce(f"  {visible_status}")

    announce("[ghidra] generating candidate FIDBs")
    populate_fidbs(configuration, project_root, records, object_sets, verbose=verbose)
    ordered = [
        records[(library.identifier, route.id, treatment.id)]
        for library in configuration.libraries
        for route in configuration.routes
        for treatment in configuration.treatments
    ]
    write_manifest(ordered, manifest)
    outcomes = Counter(record.status for record in ordered)
    summary = ", ".join(
        f"{status}={count}" for status, count in sorted(outcomes.items())
    )
    announce(f"Result: {summary}")
    announce(f"Manifest: {manifest}")
    incomplete = [record for record in ordered if record.status != "complete"]
    if incomplete:
        details = ", ".join(
            f"{record.library}/{record.route}/{record.treatment}={record.status}"
            for record in incomplete
        )
        raise PipelineError(
            f"pipeline did not complete every requested cell; {details}; "
            f"manifest retained at {manifest}"
        )
    return manifest


def doctor(configuration: Configuration, project_root: Path) -> list[str]:
    messages = []
    environment = pipeline_environment()
    required_tools = {
        name: resolve_executable((name,), environment)
        for name in ("file", "make", "sh")
    }
    messages.append(
        "build-tools: "
        + " ".join(f"{name}={path}" for name, path in required_tools.items())
    )
    for route in configuration.routes:
        compiler, compiler_version = compiler_identity(route, environment)
        archiver, archiver_version = executable_identity(
            route.archiver, environment, label="archiver"
        )
        ranlib, ranlib_version = executable_identity(
            route.ranlib, environment, label="ranlib"
        )
        messages.append(
            f"{route.id}: compiler={compiler} archiver={archiver} "
            f"ranlib={ranlib} language={route.ghidra_language} "
            f"compiler_spec={route.ghidra_compiler_spec} "
            f"compiler_version={compiler_version.splitlines()[0]} "
            f"archiver_version={archiver_version.splitlines()[0]} "
            f"ranlib_version={ranlib_version.splitlines()[0]}"
        )
    java, java_version, _ = java_identity(environment)
    messages.append(f"java: {java} version={java_version}")
    pyghidra_version = pyghidra_identity()
    messages.append(f"pyghidra-package: {pyghidra_version} python={sys.executable}")
    headless, ghidra_home = find_ghidra()
    _require_executable_file(headless, "Ghidra analyzeHeadless")
    identity = ghidra_identity(headless, ghidra_home)
    messages.append(
        f"ghidra: {identity.headless_path} version={identity.version} "
        f"release={identity.release} build={identity.build} "
        f"properties_sha256={identity.properties_sha256}"
    )
    messages.append(
        f"matrix: {len(configuration.treatments)} treatments; "
        f"{len(configuration.routes)} routes; {len(configuration.libraries)} libraries"
    )
    return messages
