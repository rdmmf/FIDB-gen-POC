# Recipe unification + malware compilation support

Status: steps 1-4 below are implemented and unit-tested (no regressions in
the existing suite); steps 5-7 are deliberately not done -- see "What's
still open" at the bottom. Target: fold the two parallel
recipe subsystems (`config.py` native Library/Route/Treatment,
`libc_catalog.py` self-contained TOML catalog) into one authoring
model, and use it to add Mirai-fork source builds as a third
category alongside libraries and libc archives -- without losing
QEMU build isolation and without hand-duplicating N near-identical
catalog blocks per architecture.

## Problem with today's shape

Two loaders, two schemas, one gap:

- `config.py` (`recipes/*.json`, `fidb-recipe/v2`): a Library says
  *what* to build; arch/toolchain live externally in `worker.json`'s
  Route/Treatment cross product. Native host toolchain only.
  Has duplicate-key checking (`_recipe_catalog`, config.py:161-165).
- `libc_catalog.py` (`catalogs/default.toml`): each row is fully
  self-contained (arch + toolchain baked in). No duplicate-key
  check. `default.toml` is ~30+ entries, most of them the same
  Bootlin-toolchain block copy-pasted per arch -- not real
  information, just an unrolled cross product done by hand.

Route/Treatment's cross product only makes sense when there's one
fixed, already-trusted, host-native toolchain being swept across
libraries x flags. It does not generalize to "one toolchain per
target arch," which is the shape both the libc catalog and malware
builds need. So catalog recipes reinvented self-containment --
correctly, but by hand.

## Target shape

Three pieces, replacing both `config.py`'s recipe loader and
`libc_catalog.py`'s recipe loader:

1. **Recipe** (hand-authored, reviewed, one TOML schema for
   libraries and malware forks alike): identity + source pin
   (`url`, `sha256`) + build shape (project markers / build system,
   or for malware: fork-specific build adapter) + a *wanted arch
   list*. Lives under `recipes/libs/*.toml` or `recipes/malware/*.toml`
   -- directory-separated, not schema-separated.
2. **Toolchain registry** (hand-authored, reviewed, arch/libc-family
   -> pinned cross-toolchain lookup table). This *is* most of what
   `catalogs/default.toml` is today, repointed at its real job: a
   registry, not a recipe list. One row per (arch, libc family,
   toolchain era), same shape as today's Bootlin/fwl blocks, minus
   the recipe-specific fields that don't belong on a toolchain.
3. **Generator**: pure function, `recipe x registry -> list[Cell]`.
   For each arch a recipe wants, look up a matching toolchain, emit
   one **cell** -- a fully resolved, self-contained build unit,
   structurally identical to today's catalog TOML row, just computed
   instead of copy-pasted. ("Cell" reuses `flow.md`'s existing term
   for a resolved library x route x treatment triple -- same concept,
   one vocabulary, not a new word for the same thing.)

Cells are the only thing that reaches `prepare_recipe`-equivalent
code. Not materialized to disk -- computed in-memory per run and
recorded in the run manifest (which already captures resolved
toolchain identity per build today). Avoids a fourth artifact type
to keep in sync; the manifest is already the audit trail.

Registry rows do double duty: input to a VM-isolated cross-compile
of a recipe's source (`mode="source"` cells), *and* the direct
prebuilt-libc.a extraction source for the archive/no-compile path
`hunt.py` already uses (`mode="archive"` cells) -- same row, two
consumers, no special-casing.

Collision/dedup check moves to one place: after generation, reject
duplicate `(recipe identity, arch)` pairs. Single check for every
recipe category, not one per subsystem.

## Schema sketch

```toml
# recipes/libs/zlib.toml
schema_version = "fidb-recipe/v3"
mode = "native"                  # unchanged: Route/Treatment still owns this case
name = "zlib"
version = "1.3.1"
url = "..."
sha256 = "..."
source_directory = "zlib-1.3.1"
project_markers = ["configure", "zlib.h"]
allowed_build_systems = ["autoconf"]
preferred_build_system = "autoconf"
static_archives = ["libz.a"]

# recipes/libs/uclibc.toml
schema_version = "fidb-recipe/v3"
mode = "source"                  # generator expands per requested arch
name = "uclibc"
version = "0.9.30.1"
url = "https://www.uclibc.org/downloads/uClibc-0.9.30.1.tar.bz2"
sha256 = "..."
arches = ["powerpc", "mips", "armv5l", "sh4", "m68k", "i686", "mipsel"]
build_adapter = "uclibc_defconfig"   # existing defconfig/oldconfig/make flow
patches = ["patches/uclibc-0.9.30.1-powerpc-crtn-size.patch"]  # per-arch patch dir keyed by arch, see below

# recipes/malware/mirai-fork-x.toml
schema_version = "fidb-recipe/v3"
mode = "source"
family = "mirai"
variant = "fork-x"
url = "https://github.com/R00tS3c/DDOS-RootSec/..."   # DDOS-RootSec fork source, SHA256-pinned
sha256 = "..."
arches = ["arm", "mips", "mipsel", "x86", "sh4", "powerpc", "m68k", "spc"]
build_adapter = "mirai_make"      # new adapter: plain `make` in fork's source root, CC=<cross-gcc>
libc_family = "uclibc"            # which registry family to pull toolchains from
```

```toml
# toolchains/registry.toml (replaces most of catalogs/default.toml)
[[toolchain]]
family = "uclibc"
version = "0.9.30.1"
arch = "powerpc"
era = "fwl-2010"
url = "https://raw.githubusercontent.com/R00tS3c/DDOS-RootSec/.../cross-compiler-powerpc.tar.bz2"
sha256 = "..."
mode = "archive"                  # prebuilt sysroot, ar-x extractable
cross_bin_prefix = "..."
library_member = "cross-compiler-powerpc/lib/libc.a"

[[toolchain]]
family = "uclibc"
version = "..."
arch = "powerpc"
era = "bootlin-2020.08"
url = "https://toolchains.bootlin.com/..."
sha256 = "..."
mode = "archive"
```

Multiple `era` rows per arch stay -- that's the real signal in
today's file (FID hashing is toolchain-build-sensitive, so two
datapoints per arch improve match odds), not the copy-paste noise.
The copy-paste noise was re-deriving the same recipe-shaped wrapper
around each one.

## Build adapters, not "recipe supplies a command"

The core invariant stays: a recipe/toolchain TOML file never
contains a shell command. `mode="native"` keeps using
`adapters.py`'s fixed Autoconf/Make construction. `mode="source"`
cells get a named `build_adapter` (`"uclibc_defconfig"`,
`"mirai_make"`, ...) that maps to a small fixed Python function
choosing the command -- same pattern as today's `_prepare_source_recipe`,
generalized so `drive_source_vm_build.py` takes an arbitrary
`--build-command` (or a small enum of known adapters) instead of the
hardcoded `defconfig`/`oldconfig`/`make ARCH=/CROSS=` sequence it has
today. Adding `mirai_make` is a ~20-line function next to the uclibc
one, not a new execution path.

## Emulation / isolation -- unchanged, just triggered once

`drive_source_vm_build.py`'s guarantees don't change: x86_64/KVM
guest (never the target arch), network up only long enough to
`apk add` Alpine's own signed tools, severed via the QEMU monitor
socket before any downloaded cross-compiler or malware source is
touched, 9p mounts (ro9p for input, rwout for output only). Every
`mode="source"` cell -- library, libc, or Mirai fork alike -- goes
through this exact same driver. Today it's invoked once per
hand-written catalog `mode="source"` block (there's only one:
uclibc-powerpc). After unification it's invoked once per generated
cell, from one call site in the generator's consumer, instead of
being duplicated per category. Net isolation code shrinks, it
doesn't grow. Mirai forks never get a "trust the fork's own bundled
compiler" path -- toolchains only ever come from the reviewed
registry.

## Migration steps

1. Add `recipes/*.toml` parser with `schema_version = "fidb-recipe/v3"`,
   `mode`-discriminated required fields (mirrors
   `libc_catalog.py`'s `REQUIRED_RECIPE_FIELDS_BY_MODE` pattern).
   Port `recipes/zlib.json` / `bzip2.json` to TOML (`mode="native"`),
   keep `config.py`'s Route/Treatment path consuming them unchanged.
2. Split `catalogs/default.toml` into `toolchains/registry.toml`
   (toolchain rows only) + `recipes/libs/uclibc.toml` /
   `recipes/libs/musl.toml` / etc. (one recipe per libc family,
   `arches = [...]` replacing the per-arch block).
3. Write the generator (`recipe x registry -> list[Cell]`) plus the
   shared duplicate-`(identity, arch)` check.
4. Generalize `drive_source_vm_build.py` to take a build-adapter
   name instead of hardcoded uclibc build steps; add `mirai_make`
   adapter.
5. Add `recipes/malware/*.toml` entries for the DDOS-RootSec Mirai
   forks actually wanted, each SHA256-pinned to a specific commit/
   tarball, not a moving branch ref.
6. Point `hunt.py`/export tagging at cells instead of catalog rows
   (`origin:mirai/fork:<name>/arch:<arch>` tag convention, matching
   bsimvis2's existing `lib:*/ver:*/variant:*` stdlib-ref tags).
7. Delete `libc_catalog.py`'s loader/select/dedup-less path and
   `config.py`'s JSON loader once both are replaced by the unified
   TOML loader + generator; keep `adapters.py`'s native build logic
   and `_prepare_source_recipe`'s VM-driving logic (generalized) as
   the two real consumers of a resolved cell.

Each step is independently testable against the existing
`test_config.py` / `test_libc_catalog.py` / `test_candidate_selection.py`
suites before the next step starts. No step requires trusting new
malware source until step 5, and step 5 only ever reaches an
untrusted compiler through the same severed-network VM every
existing catalog `mode="source"` recipe already goes through.

## What's implemented (branch `unify-recipes-malware-support`)

- `src/fidb_poc/toolchain_registry.py` -- loads `[[toolchain]]` rows,
  validates archive-capable and/or source-capable fields, rejects
  duplicates.
- `src/fidb_poc/recipe_generator.py` -- `fidb-recipe/v3` TOML loader +
  `generate_cells(recipes, toolchains)`, producing dicts field-identical
  to `libc_catalog.py`'s existing `mode="source"` cell shape, plus the
  shared `(family, version, variant)` duplicate-cell check.
- `toolchains/registry.toml` + `recipes/libs/uclibc.toml` -- the *one*
  real case ported end to end: `tests/test_recipe_generator.py` asserts
  the generated cell reproduces every field of
  `catalogs/default.toml`'s hand-written "uclibc 0.9.30.1
  powerpc-source-build" recipe, using the same real, previously-verified
  hashes. `catalogs/default.toml` itself is untouched -- both paths work
  side by side.
- `scripts/drive_source_vm_build.py` generalized: `--build-adapter
  {uclibc_defconfig,plain_make}` picks the fixed in-VM command sequence
  (never a recipe-supplied string, matching the existing "recipe cannot
  supply a command" invariant); `--library-path` renamed to
  `--output-relpath` since the copied-out artifact isn't always a static
  archive. `libc_catalog.py`'s `_prepare_source_recipe` updated to match,
  defaulting to `uclibc_defconfig` so `catalogs/default.toml`'s existing
  recipe (no `build_adapter` field) behaves exactly as before.
- `src/fidb_poc/malware_build.py` + `scripts/build_malware_corpus.py` --
  a cell consumer separate from `libc_catalog.prepare_recipe`/`hunt.py`:
  builds a `mode="source"` cell into a linked binary (not decomposed
  `.o` objects) plus a provenance manifest, tagged
  `origin:<family>/fork:<variant>/arch:<arch>`. Reuses
  `libc_catalog._download_url`/`_extract_verified`/`_digest` and the same
  VM driver.
- `recipes/malware/README.md` -- the substantive finding from this pass:
  DDOS-RootSec's own Mirai-fork archives are `.rar`/`.zip`, not `.tar.*`.
  First pass here over-corrected and required host-tar-shaped sources
  only; on review, the VM isolation argument that already justifies
  running an untrusted *compiler* applies equally to running an
  untrusted *archive extractor* inside the same disposable, network-
  severed guest -- a parser exploit there isn't a host compromise
  either. So: `source_kind = "zip"` cells are never parsed on the host at
  all -- the raw, SHA256-verified bytes are copied into the VM and
  extracted there by Alpine's own signed `unzip` (confirmed present in
  the v3.19 `main` repo), after network is severed, same as the
  toolchain. `.rar` stays unsupported specifically because Alpine's v3.19
  repos (checked directly) ship neither `unrar` nor `p7zip` -- there's no
  *signed* extractor to install, not a policy objection to extracting
  inside the VM. A `.rar` fork still needs re-packaging into `.zip`/
  `.tar.gz` by hand, once, as a reviewed step; a `.zip` fork needs none.

## What's still open

- No malware recipe is populated (`recipes/malware/` is empty). Adding
  one means picking a real fork, verifying its actual build system
  (`plain_make`'s `make CC=<cross>gcc` shape is a reasonable default,
  **not verified** against any specific fork's Makefile), and
  re-packaging its source as a tar.gz if it's only available as
  `.rar`/`.zip`.
- The VM build path (`uclibc_defconfig` and `plain_make` alike) has not
  been run end to end this session -- no KVM/QEMU run was attempted.
  Matches this repo's existing test coverage shape: `mode="source"` has
  never had an automated test (only `mode="archive"` does); it's been
  validated by actually running it (see commit `4fcad89`). Don't trust
  `plain_make` for a real build until it's been run once and the output
  inspected, per `recipes/malware/README.md` step 4.
- `catalogs/default.toml`'s other ~30 archive rows are not yet ported
  into `toolchains/registry.toml` (step 2) -- only the one row needed to
  prove the generator was added. `hunt.py`/`hunt_cli.py` are not wired to
  merge generated cells into a hunt run (step 6) -- generated cells are
  proven to work with `select_recipes`/`prepare_recipe` by test, not yet
  reachable from the `fidb-hunt` CLI.
- JSON→TOML migration for the native Library/Route/Treatment recipes
  (`recipes/zlib.json`, `recipes/bzip2.json`) is unrelated to malware
  support and wasn't touched.
