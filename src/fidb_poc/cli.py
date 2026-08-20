from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from .config import RecipesNotFoundError, load_configuration, select_configuration
from .pipeline import PipelineError, doctor, execute, plan
from .request_queue import record_missing_requests


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description=(
            "Resolve library-name requests, fetch pinned sources, and build "
            "one Ghidra FIDB per library/route."
        )
    )
    result.add_argument(
        "--project-root",
        type=Path,
        default=Path.cwd(),
        help="project directory (default: current directory)",
    )
    result.add_argument(
        "--config",
        type=Path,
        help="worker configuration JSON (default: PROJECT/worker.json)",
    )
    result.add_argument(
        "--library",
        action="append",
        dest="libraries",
        help=(
            "library request to resolve and fetch; repeat for multiple libraries "
            "(default: requested_libraries in worker.json)"
        ),
    )
    result.add_argument(
        "--request-priority",
        type=int,
        choices=(0, 1, 2),
        default=0,
        help=(
            "priority recorded when a library has no recipe: "
            "0=campaign/analyst, 1=ranked catalogue, 2=discovery (default: 0)"
        ),
    )
    result.add_argument(
        "--doctor",
        action="store_true",
        help="validate configured tools without building",
    )
    result.add_argument(
        "--plan",
        action="store_true",
        help="print the selected build cells without downloading or compiling",
    )
    result.add_argument(
        "--profile",
        default="smoke",
        help="frozen treatment profile from worker.json (default: smoke)",
    )
    result.add_argument(
        "--route",
        action="append",
        dest="routes",
        help="route id to build; repeat as needed (required when building)",
    )
    result.add_argument(
        "--treatment",
        action="append",
        dest="treatments",
        help="exact treatment id; repeat as needed (overrides --profile)",
    )
    result.add_argument(
        "--fresh",
        action="store_true",
        help="remove only PROJECT/work and PROJECT/output before building",
    )
    result.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="stream compiler/Ghidra command output live instead of only on failure",
    )
    return result


def _validate_queue_token(label: str, value: str) -> None:
    if value != value.strip() or not value:
        raise ValueError(f"{label} must be a non-empty token without outer whitespace")
    if value[0] in "=+-@":
        raise ValueError(f"{label} must not begin with a spreadsheet formula marker")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"{label} must not contain control characters")


def _validate_project_checkout(project_root: Path, config_path: Path) -> None:
    if not project_root.is_dir():
        raise PipelineError(f"project root is not a directory: {project_root}")
    if not config_path.is_file() or project_root not in config_path.parents:
        raise PipelineError(
            f"configuration must be a file inside the project root: {config_path}"
        )
    sentinels = (
        project_root / "pyproject.toml",
        project_root / "src/fidb_poc/pipeline.py",
        project_root / "src/fidb_poc/ghidra_fid.py",
        project_root / "recipes",
    )
    missing = [
        str(path.relative_to(project_root))
        for path in sentinels
        if not path.exists()
        or path.resolve() == project_root
        or project_root not in path.resolve().parents
    ]
    if missing:
        raise PipelineError(
            "project root is not an FIDB-POC checkout; missing: " + ", ".join(missing)
        )


def _fresh_targets(project_root: Path) -> tuple[Path, Path]:
    targets = (project_root / "work", project_root / "output")
    for target, expected_name in zip(targets, ("work", "output")):
        if target.name != expected_name or target.parent != project_root:
            raise PipelineError(f"refusing unsafe --fresh target: {target}")
        if target.is_symlink():
            raise PipelineError(f"refusing symlinked --fresh target: {target}")
        if target.exists() and not target.is_dir():
            raise PipelineError(f"refusing non-directory --fresh target: {target}")
        resolved = target.resolve()
        expected = project_root / expected_name
        if resolved != expected:
            raise PipelineError(
                f"refusing --fresh target other than {expected}: {target}"
            )
    if targets[0] in targets[1].parents or targets[1] in targets[0].parents:
        raise PipelineError("refusing overlapping --fresh targets")
    return targets


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    if not arguments.doctor and not arguments.plan and not arguments.routes:
        print(
            "error: at least one --route is required when building; "
            "use --plan to inspect the available cells",
            file=sys.stderr,
        )
        return 2
    project_root = arguments.project_root.resolve()
    config_path = (arguments.config or project_root / "worker.json").resolve()
    try:
        for library in arguments.libraries or ():
            _validate_queue_token("--library", library)
        for route in arguments.routes or ():
            _validate_queue_token("--route", route)
        request_override = tuple(arguments.libraries) if arguments.libraries else None
        configuration = load_configuration(config_path, request_override)
        configuration = select_configuration(
            configuration,
            route_ids=tuple(arguments.routes) if arguments.routes else None,
            treatment_ids=(
                tuple(arguments.treatments) if arguments.treatments else None
            ),
            profile=arguments.profile,
        )
        if arguments.doctor:
            for message in doctor(configuration, project_root):
                print(message)
            return 0
        if arguments.plan:
            for message in plan(configuration):
                print(message)
            return 0
        _validate_project_checkout(project_root, config_path)
        if arguments.fresh:
            for target in _fresh_targets(project_root):
                if target.exists():
                    shutil.rmtree(target)
        execute(configuration, project_root, progress=print, verbose=arguments.verbose)
        return 0
    except RecipesNotFoundError as error:
        queue_path = record_missing_requests(
            project_root / "recipe_requests/pending.csv",
            error.requests,
            priority=arguments.request_priority,
            routes=tuple(arguments.routes or ()),
        )
        print(f"error: {error}", file=sys.stderr)
        print(f"Recipe request list: {queue_path}", file=sys.stderr)
        return 1
    except (OSError, ValueError, PipelineError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
