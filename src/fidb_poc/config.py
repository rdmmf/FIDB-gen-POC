from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, replace
from pathlib import Path


class RecipesNotFoundError(ValueError):
    def __init__(self, requests: tuple[str, ...], known: tuple[str, ...]):
        self.requests = requests
        self.known = known
        requested = ", ".join(repr(request) for request in requests)
        available = ", ".join(known)
        noun = "recipe" if len(requests) == 1 else "recipes"
        super().__init__(
            f"no approved {noun} for {requested}; known libraries: {available}"
        )


SAFE_PATH_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")


def _path_component(value: object, context: str) -> str:
    """Validate configuration text that later becomes one directory component."""
    if not isinstance(value, str) or SAFE_PATH_COMPONENT.fullmatch(value) is None:
        raise ValueError(
            f"{context} must be a safe path component containing only letters, "
            "numbers, dot, underscore, plus and hyphen"
        )
    return value


@dataclass(frozen=True)
class Library:
    name: str
    version: str
    url: str
    sha256: str
    source_directory: str
    project_markers: tuple[str, ...]
    allowed_build_systems: tuple[str, ...]
    preferred_build_system: str
    static_archives: tuple[str, ...]

    def __post_init__(self) -> None:
        _path_component(self.name, "library name")
        _path_component(self.version, "library version")
        _path_component(self.source_directory, "library source_directory")
        for archive in self.static_archives:
            _path_component(archive, "library static archive")

    @property
    def identifier(self) -> str:
        return f"{self.name}-{self.version}"


@dataclass(frozen=True)
class Route:
    id: str
    target_os: str
    architecture: str
    binary_format: str
    compiler: tuple[str, ...]
    archiver: tuple[str, ...]
    ranlib: tuple[str, ...]
    compiler_flags: tuple[str, ...]
    object_file_markers: tuple[str, ...]
    linked_suffix: str
    linked_file_markers: tuple[str, ...]
    ghidra_language: str
    ghidra_compiler_spec: str = "default"
    compiler_version_markers: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _path_component(self.id, "route id")


@dataclass(frozen=True)
class Treatment:
    id: str
    factor: str
    description: str
    remove_flags: tuple[str, ...]
    append_flags: tuple[str, ...]
    supported_routes: tuple[str, ...]
    phase: str = "compile"

    def __post_init__(self) -> None:
        _path_component(self.id, "treatment id")

    def applies_to(self, route: Route) -> bool:
        return not self.supported_routes or route.id in self.supported_routes

    def flags_for(self, route: Route) -> tuple[str, ...]:
        flags = [flag for flag in route.compiler_flags if flag not in self.remove_flags]
        flags.extend(self.append_flags)
        return tuple(flags)


@dataclass(frozen=True)
class Configuration:
    libraries: tuple[Library, ...]
    routes: tuple[Route, ...]
    treatments: tuple[Treatment, ...]
    profiles: dict[str, tuple[str, ...]]


def _required(record: dict, field: str, context: str):
    if field not in record:
        raise ValueError(f"{context} is missing {field!r}")
    return record[field]


def _load_recipe(path: Path) -> Library:
    row = tomllib.loads(path.read_text(encoding="utf-8"))
    if row.get("schema_version") != "fidb-recipe/v3":
        raise ValueError(f"unsupported or missing schema_version in {path}")
    if row.get("mode") != "native":
        raise ValueError(f'{path}: config.py only handles mode="native" recipes')
    library = Library(
        name=_path_component(
            _required(row, "name", f"recipe {path.name}"),
            f"recipe {path.name} name",
        ),
        version=_path_component(
            _required(row, "version", f"recipe {path.name}"),
            f"recipe {path.name} version",
        ),
        url=_required(row, "url", f"recipe {path.name}"),
        sha256=_required(row, "sha256", f"recipe {path.name}").lower(),
        source_directory=_path_component(
            _required(row, "source_directory", f"recipe {path.name}"),
            f"recipe {path.name} source_directory",
        ),
        project_markers=tuple(_required(row, "project_markers", f"recipe {path.name}")),
        allowed_build_systems=tuple(
            _required(row, "allowed_build_systems", f"recipe {path.name}")
        ),
        preferred_build_system=_required(
            row, "preferred_build_system", f"recipe {path.name}"
        ),
        static_archives=tuple(
            _path_component(value, f"recipe {path.name} static archive")
            for value in _required(row, "static_archives", f"recipe {path.name}")
        ),
    )
    if len(library.sha256) != 64:
        raise ValueError(f"{library.identifier} has an invalid SHA-256")
    if not library.project_markers or not library.static_archives:
        raise ValueError(f"{library.identifier} has incomplete detection metadata")
    if library.preferred_build_system not in library.allowed_build_systems:
        raise ValueError(f"{library.identifier} preferred build system is not allowed")
    return library


def _recipe_catalog(recipe_directory: Path) -> dict[str, Library]:
    if not recipe_directory.is_dir():
        raise ValueError(f"recipe directory does not exist: {recipe_directory}")
    recipes: dict[str, Library] = {}
    for path in sorted(recipe_directory.glob("*.toml")):
        recipe = _load_recipe(path)
        keys = (recipe.name, recipe.identifier, f"{recipe.name}@{recipe.version}")
        for key in keys:
            if key in recipes:
                raise ValueError(f"duplicate recipe request key: {key}")
            recipes[key] = recipe
    return recipes


def _resolve_requests(
    document: dict,
    config_path: Path,
    request_override: tuple[str, ...] | None,
) -> tuple[Library, ...]:
    requests = request_override or tuple(
        _required(document, "requested_libraries", "worker configuration")
    )
    if not requests:
        raise ValueError("at least one library request is required")
    recipe_directory = config_path.parent / document.get("recipe_directory", "recipes")
    catalog = _recipe_catalog(recipe_directory)
    libraries = []
    missing = []
    for request in requests:
        recipe = catalog.get(request)
        if recipe is None:
            missing.append(request)
            continue
        libraries.append(recipe)
    if missing:
        known = tuple(sorted({recipe.name for recipe in catalog.values()}))
        raise RecipesNotFoundError(tuple(missing), known)
    if len({library.identifier for library in libraries}) != len(libraries):
        raise ValueError("library requests resolve to duplicate recipes")
    return tuple(libraries)


def load_configuration(
    path: Path,
    request_override: tuple[str, ...] | None = None,
) -> Configuration:
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("schema_version") != "fidb-worker/v2":
        raise ValueError("unsupported or missing schema_version")

    libraries = _resolve_requests(document, path, request_override)
    routes = tuple(
        Route(
            id=_path_component(_required(row, "id", "route"), "route id"),
            target_os=_required(row, "target_os", "route"),
            architecture=_required(row, "architecture", "route"),
            binary_format=_required(row, "binary_format", "route"),
            compiler=tuple(_required(row, "compiler", "route")),
            archiver=tuple(_required(row, "archiver", "route")),
            ranlib=tuple(row.get("ranlib", row["archiver"])),
            compiler_flags=tuple(row.get("compiler_flags", [])),
            object_file_markers=tuple(_required(row, "object_file_markers", "route")),
            linked_suffix=_required(row, "linked_suffix", "route"),
            linked_file_markers=tuple(_required(row, "linked_file_markers", "route")),
            ghidra_language=_required(row, "ghidra_language", "route"),
            ghidra_compiler_spec=row.get("ghidra_compiler_spec", "default"),
            compiler_version_markers=tuple(row.get("compiler_version_markers", [])),
        )
        for row in _required(document, "routes", "worker configuration")
    )
    treatments = tuple(
        Treatment(
            id=_path_component(_required(row, "id", "treatment"), "treatment id"),
            factor=_required(row, "factor", "treatment"),
            description=_required(row, "description", "treatment"),
            remove_flags=tuple(row.get("remove_flags", [])),
            append_flags=tuple(row.get("append_flags", [])),
            supported_routes=tuple(row.get("supported_routes", [])),
            phase=row.get("phase", "compile"),
        )
        for row in _required(document, "treatments", "worker configuration")
    )
    profiles = {
        name: tuple(treatment_ids)
        for name, treatment_ids in _required(
            document, "profiles", "worker configuration"
        ).items()
    }

    if not routes or not treatments:
        raise ValueError("at least one route and treatment are required")
    if len({route.id for route in routes}) != len(routes):
        raise ValueError("route ids must be unique")
    if len({row.id for row in treatments}) != len(treatments):
        raise ValueError("treatment ids must be unique")
    treatment_ids = {row.id for row in treatments}
    for name, profile_ids in profiles.items():
        unknown = set(profile_ids) - treatment_ids
        if unknown:
            raise ValueError(f"profile {name!r} contains unknown treatments: {unknown}")
    for route in routes:
        if not route.compiler or not route.archiver:
            raise ValueError(f"{route.id} has an empty tool command")
        if not route.linked_suffix.startswith(".") or not route.linked_file_markers:
            raise ValueError(f"{route.id} has incomplete linked-output metadata")
    invalid_phases = {row.phase for row in treatments} - {"compile", "link"}
    if invalid_phases:
        raise ValueError(f"unsupported treatment phases: {sorted(invalid_phases)}")

    return Configuration(
        libraries=libraries,
        routes=routes,
        treatments=treatments,
        profiles=profiles,
    )


def select_configuration(
    configuration: Configuration,
    *,
    route_ids: tuple[str, ...] | None,
    treatment_ids: tuple[str, ...] | None,
    profile: str,
) -> Configuration:
    known_routes = {row.id: row for row in configuration.routes}
    known_treatments = {row.id: row for row in configuration.treatments}
    requested_routes = route_ids or tuple(known_routes)
    if treatment_ids:
        requested_treatments = treatment_ids
    else:
        if profile not in configuration.profiles:
            raise ValueError(f"unknown treatment profile: {profile}")
        requested_treatments = configuration.profiles[profile]

    missing_routes = set(requested_routes) - set(known_routes)
    missing_treatments = set(requested_treatments) - set(known_treatments)
    if missing_routes:
        raise ValueError(f"unknown routes: {sorted(missing_routes)}")
    if missing_treatments:
        raise ValueError(f"unknown treatments: {sorted(missing_treatments)}")
    return replace(
        configuration,
        routes=tuple(known_routes[row] for row in requested_routes),
        treatments=tuple(known_treatments[row] for row in requested_treatments),
    )
