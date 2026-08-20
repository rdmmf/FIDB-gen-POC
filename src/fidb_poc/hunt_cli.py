"""`fidb-hunt`: investigate an unknown target and match it against catalog
libc/toolchain candidates. A separate entry point from `fidb-poc` (which
only ever builds the reviewed recipes/ + worker.json library matrix),
mirroring the existing fidb-language-probe script -- hunting an arbitrary
target is a distinct concern from generating recipes.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys

from .elf import ElfInspectionError, inspect_elf
from .hunt import hunt
from .investigate import investigate


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
        "hunt", help="investigate, prepare, and test catalog candidates", parents=[verbose]
    )
    hunt_parser.add_argument("target")
    hunt_parser.add_argument("--catalog", default="catalogs/default.toml")
    hunt_parser.add_argument("--work", default="work/hunt")
    hunt_parser.add_argument("--report")
    hunt_parser.add_argument("--max-candidates", type=int, default=8)
    hunt_parser.add_argument("--guess", action="append", default=[])
    hunt_parser.add_argument("--fidb-dir", default="artifacts/fidbs")
    return parser


def main(argv: list[str] | None = None) -> int:
    import logging

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
                args.target, args.catalog, args.work, args.report,
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
        return 0
    except (ElfInspectionError, OSError, ValueError) as error:
        print(f"fidb-hunt: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
