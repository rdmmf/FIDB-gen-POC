# FIDB worker proof of concept

This repository is a small, inspectable proof of concept that builds Ghidra
Function ID databases for two pinned C libraries on one native Linux toolchain.
It demonstrates a constrained path from a library name to a non-empty FIDB and a
CSV evidence manifest:

```text
library name
  -> reviewed, hash-pinned recipe
  -> source download and SHA-256 verification
  -> fixed Python build adapter
  -> native GNU GCC compilation and ELF validation
  -> Ghidra analysis and FID generation
  -> one FIDB and one manifest row per build cell
```

The caller supplies a library name, the configured route and a treatment. It
cannot supply a URL, compiler command or shell fragment.

## Demonstrated scope

The supported demonstration is deliberately narrow:

- host and target: native Linux x86-64;
- toolchain: `/usr/bin/gcc`, `/usr/bin/ar` and `/usr/bin/ranlib` (the validated
  Fedora host used GNU GCC and GNU binutils);
- Ghidra language and compiler specification: `x86:LE:64:default` and `gcc`;
- libraries: zlib 1.3.1 and bzip2 1.0.7;
- treatment: `baseline_o2` (`-O2`, compiled without `-g` or LTO, frame pointer
  retained); and
- profile: `smoke`.

The latest local end-to-end validation completed both libraries on Fedora Linux
x86-64 with native GNU GCC. Its Ghidra installation metadata reported version
12.1.2 and release name `DEV`; it must not be represented as an official Ghidra
12.1.2 release. Evidence intended for sharing should identify the actual Ghidra
build recorded by the generated manifest.

macOS, Windows, cross-compilers, non-x86 processors, alternate optimization
treatments and arbitrary upstream projects are outside this PoC's supported and
validated scope. The GNU identity check uses the `Free Software Foundation`
copyright marker instead of a distribution-specific first-line banner. This is
compatible with conventional Fedora, Arch, Debian and Ubuntu GCC output, but the
successful validation above is the claim being made—not a multi-distribution test
matrix.

The two reviewed recipes exercise different upstream build shapes:

| Library | Version | Build shape | Worker adapter |
| ------- | ------: | ----------- | -------------- |
| zlib | 1.3.1 | Autoconf | fixed Autoconf adapter |
| bzip2 | 1.0.7 | Make | fixed Make adapter |

## Requirements

Run the PoC from the repository's source checkout. The Python wheel is not a
standalone distribution: runtime configuration, recipes and Ghidra scripts remain
checkout-local.

The host needs:

- Linux x86-64;
- Python 3.10 or newer and [`uv`][1];
- native GNU GCC at `/usr/bin/gcc`, `ar` and `ranlib` at `/usr/bin/ar` and
  `/usr/bin/ranlib`, plus `make`, a POSIX `sh`, and `file`;
- Ghidra with `support/analyzeHeadless` plus the compatible PyGhidra components;
  and
- Java 21.

`GHIDRA_HEADLESS` is required for the supported Linux run; the worker does not
auto-discover Linux Ghidra installations. Set it to a path valid in the shell
that runs the worker. A host installation might use:

```sh
export GHIDRA_HEADLESS=/opt/ghidra/support/analyzeHeadless
```

If the same host installation is mounted into a Toolbx or other container, its
path may instead be:

```sh
export GHIDRA_HEADLESS=/run/host/opt/ghidra/support/analyzeHeadless
```

The `/run/host` path is container-specific and should not be used from the host
shell. If Java 21 is not on `PATH`, set `JAVA_HOME` to its JDK directory. Some
containers may also require `JDK_JAVA_OPTIONS=-XX:-UseContainerSupport` for Java
home discovery; it is not normally needed on the host.

## Run the demonstration

From the repository root, install the locked Python environment, inspect the plan
and check the configured tools:

```sh
uv sync --locked

uv run fidb-poc \
  --plan \
  --route linux-x86_64-gnu-gcc \
  --profile smoke

uv run fidb-poc \
  --doctor \
  --route linux-x86_64-gnu-gcc
```

Then run a clean end-to-end build:

```sh
GHIDRA_HEADLESS=/opt/ghidra/support/analyzeHeadless \
  uv run fidb-poc --fresh \
    --route linux-x86_64-gnu-gcc \
    --profile smoke
```

With no `--library`, the worker uses the name-only request queue in `worker.json`
and builds both libraries. To build only zlib, add `--library zlib`. A successful
two-library run ends with:

```text
Result: complete=2
Manifest: .../artifacts/libs/fidb_manifest.csv
```

A real build exits nonzero if any requested cell does not reach `complete`, so
shell automation and CI cannot mistake a printed `build_failed` or `fid_failed`
result for success. `--plan` performs no download, compilation or Ghidra work.

## Run the notebook

The walkthrough in `notebooks/demo.ipynb` uses the optional notebook dependency
group. From the repository root, install that group and start Jupyter with the
project environment and the host Ghidra path:

```sh
uv sync --locked --group notebook

GHIDRA_HEADLESS=/opt/ghidra/support/analyzeHeadless \
  uv run --group notebook jupyter lab notebooks/demo.ipynb
```

Inside Toolbx, use
`GHIDRA_HEADLESS=/run/host/opt/ghidra/support/analyzeHeadless` instead. If that
container cannot discover Java correctly, also set
`JDK_JAVA_OPTIONS=-XX:-UseContainerSupport` as described above. Start Jupyter
from the repository root so the notebook uses this checkout and its locked
environment.

The notebook executes a real zlib build and a LanguageID diagnostic probe. It
therefore recreates `work/` and `artifacts/libs/`, including a candidate FIDB, CSV
reports and a PNG chart. Remove those generated directories after the demo when
preparing a source-only handoff.

## Inputs, evidence and temporary outputs

`recipes/*.toml` (`mode="native"`) is the reviewed source catalogue for this
worker. Each recipe declares the canonical name and version, archive URL and
SHA-256, expected source markers, build system and expected static archive.
A recipe cannot contain a command. Every recipe in this repository -- native
library, libc, or malware fork alike -- uses this same `fidb-recipe/v3` TOML
schema; only the directory and `mode` differ. See **Hunting an unknown
target** below for the other two.

`worker.json` is trusted operator configuration for the single Linux route, one
treatment and one profile. It is not untrusted request data.

A real run creates temporary working state and evidence:

```text
work/                         downloaded/extracted source, builds, logs, Ghidra projects
artifacts/libs/fidb/                  generated per-cell FIDBs
artifacts/libs/fidb_manifest.csv      result and provenance rows
```

`--fresh` removes `work/` and `artifacts/libs/` at the start and then recreates
them during the run (`artifacts/malware/` and `artifacts/fidbs/` are a separate
subsystem's evidence and are never touched by this build's `--fresh`). It is a
clean-build option, not a post-run cleanup option.

Without `--fresh`, only a hash-verified downloaded source archive may be reused.
Every real run still replaces the worker-managed extracted sources, builds, logs,
Ghidra state, current FIDBs and manifest. Paths outside those managed locations
are not part of the cleanup.

These directories are intentionally ignored and are not source deliverables. A
source-only handoff must omit `work/`, `artifacts/libs/`, `.venv/`, `.idea/`,
Python caches and notebook execution outputs. Prefer producing a handoff from a
real clean Git checkout or an explicit source allowlist rather than archiving
an active working directory. At minimum, remove the generated roots after
preserving any evidence that is meant to be reviewed:

```sh
rm -rf -- work artifacts/libs
```

The manifest and FIDBs are evidence for a particular execution, not permanent
proof embedded in the source distribution. Share them separately when execution
evidence is required.

## Safety and authority boundary

The worker resolves a library name through a deterministic catalogue, verifies the
downloaded bytes, selects a fixed adapter, validates the compiler and output
formats, and asks Ghidra to populate the FIDB. Unknown names, hash mismatches,
missing markers, wrong compiler identities, wrong binary formats, population-count
mismatches and empty FIDBs fail closed.

An approved source archive still contains executable upstream build logic such as
`configure` and Makefiles. A SHA-256 check establishes which bytes were run; it
does not make those bytes safe. This PoC assumes reviewed pinned upstreams, a
controlled environment without unreviewed compiler/linker overrides, and a
least-privileged non-sensitive host.

Production hardening is explicitly deferred. This PoC does not claim:

- sandboxed hostile-source execution;
- support for additional operating systems, architectures, compilers or projects;
- byte-for-byte reproducibility across independent hosts;
- signed releases, SBOM/SPDX output or an external authority database;
- a standalone installable worker package;
- continuous Ghidra integration in hosted CI; or
- production publication, retention or merged route-pack workflows.

This source snapshot does not contain a project `LICENSE` file or license
metadata. Do not treat access to the files as permission to redistribute them;
an external handoff needs owner-approved terms or a confirmed governing private
agreement.

## Requests without recipes

If a requested library has no approved recipe, the worker fails closed and records
the request in `recipe_requests/pending.csv`. This file is a human-review queue,
not an executable recipe. For example:

```sh
uv run fidb-poc \
  --plan \
  --library libpng \
  --route linux-x86_64-gnu-gcc \
  --request-priority 1
```

Priorities are `0` for a campaign or analyst request, `1` for a ranked catalogue
and `2` for discovery. Adding a recipe or adapter is an ordinary reviewed source
change.

## Hunting an unknown target

Building the two reviewed recipes above is only one thing `fidb-poc` does.
The same binary also takes an arbitrary target and works out which libc it was
probably built against, cross-compiling candidates inside an isolated,
network-severed QEMU VM when no prebuilt archive matches -- via the
`inspect`/`investigate`/`hunt`/`build-malware`/`hunt-doctor` subcommands
(`fidb-hunt` still works too, as a thin alias over the same code):

```text
target binary
  -> investigate: infer machine/endianness/elf_class and libc family hypotheses
  -> select: matching toolchain rows + recipe-generated cells, closest priority first
  -> prepare: extract a prebuilt libc.a, or cross-compile one in an isolated VM
  -> match: Ghidra FID comparison against the target
  -> report + copy: exported .fidb/.fidbf per unambiguous match, ready to reuse
```

```sh
uv run fidb-poc hunt path/to/target --fidb-dir artifacts/fidbs
```

Candidates come from `toolchains/registry.toml` (pinned cross-toolchains,
some directly archive-extractable) and `recipes/libs/*.toml`
(`mode="source"`, fanned out per matching toolchain by
`recipe_generator.generate_cells`) -- see `UNIFICATION_PLAN.md` for why this
is one schema instead of the two ad hoc ones this repository started with.

The same VM isolation also builds a static, known-source malware corpus from
`recipes/malware/*.toml`, for use as ground truth rather than as an unknown
target to match:

```sh
uv run fidb-poc build-malware --recipes recipes/malware
```

See `recipes/malware/README.md` before adding a fork recipe -- source
archives are pinned by SHA-256, never a moving branch ref, and are only ever
unpacked/compiled inside the disposable, offline VM.

## Verification

The deterministic unit and formatting checks do not download library source or run
Ghidra:

```sh
uv run python -m unittest discover -s tests -v
uv run black --check src tests ghidra_scripts
```

GitHub Actions runs those checks on Python 3.14 only; it does not run Ghidra. The
actual supported demonstration is the explicit host command in **Run the
demonstration**. An opt-in live zlib check is also available when the host has
network access, the native toolchain and Ghidra:

```sh
GHIDRA_HEADLESS=/opt/ghidra/support/analyzeHeadless \
FIDB_RUN_LIVE_SMOKE=1 \
  uv run python -m unittest tests.test_live_smoke -v
```

## Code map

| Path | Responsibility |
| ---- | -------------- |
| `src/fidb_poc/cli.py` | `fidb-poc` command-line boundary and exit status |
| `src/fidb_poc/config.py` | recipe, route and treatment validation |
| `src/fidb_poc/adapters.py` | fixed Autoconf/Make command construction |
| `src/fidb_poc/pipeline.py` | retrieval, build isolation, validation, Ghidra and manifest output |
| `ghidra_scripts/populate_library_fid_databases.py` | FID database population adapter |
| `recipes/*.toml` | reviewed name-to-source catalogue, one `fidb-recipe/v3` schema throughout |
| `src/fidb_poc/hunt_cli.py` | hunt/malware subcommand boundary (`hunt`, `build-malware`, `doctor`, `investigate`, `inspect`), reached via `fidb-poc <subcommand>` or the `fidb-hunt` alias |
| `src/fidb_poc/hunt.py` | investigate -> select -> prepare -> match -> export workflow |
| `src/fidb_poc/toolchain_registry.py` | pinned cross-toolchain rows (`toolchains/registry.toml`) |
| `src/fidb_poc/recipe_generator.py` | recipe x toolchain registry -> resolved build cells |
| `src/fidb_poc/libc_catalog.py` | cell selection, download, extraction and VM-isolated source build |
| `src/fidb_poc/malware_build.py` | cell -> linked malware binary + provenance manifest |

The repository also contains an experimental `fidb-language-probe` analysis
utility. It is not part of the supported worker demonstration or the validation
claim above.

[1]: https://docs.astral.sh/uv/
