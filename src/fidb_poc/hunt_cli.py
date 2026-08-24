"""`fidb-hunt`: investigate an unknown target and match it against libc
toolchain candidates, and separately build a known-source malware corpus
from the same recipe/toolchain machinery. A separate entry point from
`fidb-poc` (which only ever builds the reviewed recipes/ + worker.json
library matrix), mirroring the existing fidb-language-probe script --
hunting an arbitrary target and shaping a ground-truth corpus are both a
distinct concern from generating recipes for known-good libraries.
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import sys
from pathlib import Path

from .elf import ElfInspectionError, inspect_elf
from .hunt import hunt
from .investigate import investigate
from .malware_build import build_malware_binary
from .recipe_generator import generate_cells, load_recipes
from .toolchain_registry import load_toolchains

log = logging.getLogger(__name__)


def _json(value: object) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def _doctor_report() -> dict[str, object]:
    tools = {
        name: shutil.which(name)
        for name in ("file", "ar", "make", "patch", "qemu-img", "qemu-system-x86_64")
    }
    try:
        import pexpect  # noqa: F401

        pexpect_available = True
    except ImportError:
        pexpect_available = False
    return {
        "tools": tools,
        "capabilities": {
            "archive_candidates": tools["ar"] is not None,
            "source_candidates": (
                pexpect_available
                and tools["qemu-img"] is not None
                and tools["qemu-system-x86_64"] is not None
                and tools["patch"] is not None
            ),
        },
        "notes": [
            "archive_candidates covers Bootlin-sysroot-style catalog entries (ar x only, nothing executed).",
            "source_candidates additionally requires QEMU/KVM and pexpect for the isolated cross-compile VM.",
        ],
    }


def build_parser() -> argparse.ArgumentParser:
    # -v works before AND after the subcommand (`fidb-hunt -v hunt ...` and
    # `fidb-hunt hunt ... -v` both parse) since it's declared on both the
    # top-level parser and every subparser via this shared parent.
    verbose = argparse.ArgumentParser(add_help=False)
    verbose.add_argument(
        "-v", "--verbose", action="store_true",
        help="log each file compiled/downloaded, URLs used, pass/fail, and storage paths",
    )
    parser = argparse.ArgumentParser(prog="fidb-hunt", parents=[verbose])
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("doctor", help="report host capabilities for hunting", parents=[verbose])
    inspect_parser = subcommands.add_parser(
        "inspect", help="safely inspect an ELF target", parents=[verbose]
    )
    inspect_parser.add_argument("target")
    investigate_parser = subcommands.add_parser(
        "investigate", help="infer candidate library families", parents=[verbose]
    )
    investigate_parser.add_argument("target")
    hunt_parser = subcommands.add_parser(
        "hunt", help="investigate, prepare, and test libc candidates", parents=[verbose]
    )
    hunt_parser.add_argument("target")
    hunt_parser.add_argument("--toolchains", default="toolchains/registry.toml")
    hunt_parser.add_argument("--recipes", default="recipes/libs")
    hunt_parser.add_argument("--work", default="work/hunt")
    hunt_parser.add_argument("--report")
    hunt_parser.add_argument("--max-candidates", type=int, default=8)
    hunt_parser.add_argument("--guess", action="append", default=[])
    hunt_parser.add_argument("--fidb-dir", default="artifacts/fidbs")
    malware_parser = subcommands.add_parser(
        "build-malware",
        help="cross-compile recipes/malware/*.toml into a static ground-truth corpus",
        parents=[verbose],
    )
    malware_parser.add_argument("--recipes", default="recipes/malware")
    malware_parser.add_argument("--toolchains", default="toolchains/registry.toml")
    malware_parser.add_argument("--work", default="work/malware")
    malware_parser.add_argument("--out", default="artifacts/malware")
    malware_parser.add_argument("--download-cache", default="work/downloads")
    return parser


def _build_malware(args: argparse.Namespace) -> int:
    recipes = load_recipes(args.recipes)
    if not recipes:
        print(f"fidb-hunt: no recipes found under {args.recipes}", file=sys.stderr)
        return 2
    cells = generate_cells(recipes, load_toolchains(args.toolchains))
    log.info("%d recipe(s) -> %d cell(s)", len(recipes), len(cells))

    out_root = Path(args.out)
    out_root.mkdir(parents=True, exist_ok=True)
    for cell in cells:
        result = build_malware_binary(cell, Path(args.work), Path(args.download_cache))
        tag = f'origin:{result["family"]}/fork:{result["variant"]}/arch:{result["arch"]}'
        destination_dir = out_root / result["family"] / result["variant"]
        destination_dir.mkdir(parents=True, exist_ok=True)
        binary_destination = destination_dir / Path(result["binary_path"]).name
        binary_destination.write_bytes(Path(result["binary_path"]).read_bytes())
        # Belt and suspenders on top of malware_build.py's chmod: never rely
        # on umask alone to keep a static analysis corpus entry non-executable.
        binary_destination.chmod(0o644)
        manifest = {**result, "tag": tag}
        (destination_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f'{tag}: {binary_destination} (sha256={result["binary_sha256"][:12]})')
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING, format="%(message)s"
    )
    try:
        if args.command == "doctor":
            _json(_doctor_report())
        elif args.command == "inspect":
            _json(inspect_elf(args.target).to_dict())
        elif args.command == "investigate":
            _json(investigate(args.target).to_dict())
        elif args.command == "hunt":
            report = hunt(
                args.target, args.toolchains, args.recipes, args.work, args.report,
                args.max_candidates, tuple(args.guess), args.fidb_dir,
            )
            last = report["attempts"][-1]["assessment"] if report["attempts"] else None
            _json(
                {
                    "matched": report["matched"],
                    "attempts": len(report["attempts"]),
                    "matched_functions": last["matched_functions"] if last else 0,
                    "unambiguous_matches": last["unambiguous_match_count"] if last else 0,
                    "report": report["report"],
                    "fidbs": report["fidbs"],
                }
            )
        elif args.command == "build-malware":
            return _build_malware(args)
        return 0
    except (ElfInspectionError, OSError, ValueError) as error:
        print(f"fidb-hunt: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
