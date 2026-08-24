# FIDB worker flow

This document traces a normal build from the `fidb-poc` CLI command to the
generated Function ID databases and provenance manifest.

The current `worker.json` expands to two build cells:

```text
zlib x linux-x86_64-gnu-gcc x baseline_o2
> one zlib FIDB

bzip2 x linux-x86_64-gnu-gcc x baseline_o2
> one bzip2 FIDB
```

## End-to-end flow

```text
CLI command
> Python entry point
> Parse and validate arguments
> Load worker configuration
> Resolve reviewed library recipes
> Select routes and treatments
> Prepare work and output directories
> Download and hash-check source archives
> Safely extract source trees
> Detect source identity and build system
> Expand library x route x treatment build cells
> Compile a static library for each cell
> Extract and validate compiled object files
> Import objects into Ghidra
> Generate one candidate FIDB per library
> Validate Ghidra's population report
> Admit valid FIDBs into artifacts/libs/fidb/
> Write artifacts/libs/fidb_manifest.csv
> Return success only if every requested cell completed
```

## 1. CLI entry

Example invocation:

```bash
GHIDRA_HEADLESS=/opt/ghidra/support/analyzeHeadless \
uv run fidb-poc \
  --library zlib \
  --route linux-x86_64-gnu-gcc \
  --profile smoke
```

Inside Toolbx, use
`GHIDRA_HEADLESS=/run/host/opt/ghidra/support/analyzeHeadless` instead. If Java
discovery requires it there, also set
`JDK_JAVA_OPTIONS=-XX:-UseContainerSupport`.

```text
uv run fidb-poc
> pyproject.toml resolves the command to fidb_poc.cli:main
> cli.parser() parses the arguments
> cli.main() controls the requested operation
```

Code:

- [`pyproject.toml`: CLI registration](pyproject.toml)
- [`parser()`](src/fidb_poc/cli.py)
- [`main()`](src/fidb_poc/cli.py)

The main CLI branches are:

```text
--doctor
> inspect the selected toolchain without building

--plan
> print the expanded build cells without downloading or compiling

normal build
> require at least one explicit --route
> validate the checkout
> optionally perform safe --fresh cleanup
> call pipeline.execute()
```

Code: [`cli.main()` dispatch](src/fidb_poc/cli.py)

## 2. Configuration and recipe resolution

```text
cli.main()
> load_configuration(worker.json)
> _resolve_requests()
> _recipe_catalog()
> _load_recipe(recipes/*.json)
> select_configuration()
```

Code:

- [`load_configuration()`](src/fidb_poc/config.py)
- [`_resolve_requests()`](src/fidb_poc/config.py)
- [`_load_recipe()`](src/fidb_poc/config.py)
- [`select_configuration()`](src/fidb_poc/config.py)

The trusted worker configuration currently selects:

```text
worker.json
> requested libraries: zlib and bzip2
> route: linux-x86_64-gnu-gcc
> compiler: /usr/bin/gcc
> output format: x86-64 ELF
> Ghidra language: x86:LE:64:default
> Ghidra compiler specification: gcc
> treatment: baseline_o2
```

Configuration: [`worker.json`](worker.json)

Library resolution is name-based:

```text
zlib
> recipes/zlib.toml
> version 1.3.1
> pinned source URL and SHA-256
> expected source markers
> Autoconf adapter
> expected libz.a

bzip2
> recipes/bzip2.toml
> version 1.0.7
> pinned source URL and SHA-256
> expected source markers
> Make adapter
> expected libbz2.a
```

Recipes:

- [`recipes/zlib.toml`](recipes/zlib.toml)
- [`recipes/bzip2.toml`](recipes/bzip2.toml)

An unknown name takes a fail-closed side path:

```text
unknown --library value
> RecipesNotFoundError
> record_missing_requests()
> recipe_requests/pending.csv
> exit without downloading or executing unreviewed build instructions
```

Code:

- [`RecipesNotFoundError` handling](src/fidb_poc/cli.py)
- [`record_missing_requests()`](src/fidb_poc/request_queue.py)

## 3. Pipeline setup

```text
cli.main()
> _validate_project_checkout()
> optional safe --fresh cleanup
> execute(configuration, project_root)
```

Code:

- [`_validate_project_checkout()`](src/fidb_poc/cli.py)
- [`execute()` invocation](src/fidb_poc/cli.py)
- [`pipeline.execute()`](src/fidb_poc/pipeline.py)

`execute()` validates and prepares these generated paths:

```text
PROJECT/
> work/
  > downloads/
  > sources/
  > builds/
  > logs/
  > ghidra/
> artifacts/libs/
  > fidb/
  > fidb_manifest.csv
```

Code: [`execute()` directory setup](src/fidb_poc/pipeline.py)

`work/downloads/` is a verified download cache. The other generated working
directories and the output FIDB directory are recreated for the invocation.

## 4. Download and verify source

For each resolved library:

```text
execute()
> download_library()
> download the recipe's pinned URL to a partial file
> calculate SHA-256
> compare it with the recipe SHA-256
> atomically rename the verified download into the cache
```

Code: [`download_library()`](src/fidb_poc/pipeline.py)

Generated cache entries:

```text
work/downloads/
> zlib-1.3.1.tar.gz
> bzip2-1.0.7.tar.gz
```

Failure path:

```text
downloaded archive has an unexpected SHA-256
> delete the partial archive
> raise PipelineError
> do not compile it
```

## 5. Safely extract source

```text
verified archive
> extract_source()
> verify the archive hash again
> inspect every archive member
> reject links, devices, traversal and unsupported member types
> extract into a temporary staging directory
> require the recipe's expected source directory
> move the staged tree into work/sources/
```

Code: [`extract_source()`](src/fidb_poc/pipeline.py)

Generated source roots:

```text
work/sources/zlib-1.3.1/zlib-1.3.1/
work/sources/bzip2-1.0.7/bzip2-1.0.7/
```

## 6. Detect source identity and build system

```text
extracted source
> detect_project()
> require the recipe's project markers
> detect known build-system markers
> reject unexpected build systems
> detect supported source languages
```

Code: [`detect_project()`](src/fidb_poc/adapters.py)

Current detection:

```text
zlib source
> zlib.h + configure
> Autoconf adapter

bzip2 source
> bzlib.h + Makefile
> Make adapter
```

## 7. Expand build cells

```text
every selected library
> every selected route
> every selected treatment
> one build_library() call per combination
```

Code: [`execute()` build loops](src/fidb_poc/pipeline.py)

The key for each record is:

```text
(library identifier, route ID, treatment ID)
```

## 8. Compile each cell

```text
build_library()
> copy pristine source into the cell build directory
> create a restricted deterministic environment
> identify and validate the configured compiler
> locate archiver and ranlib
> build_commands()
> execute fixed adapter commands
> find the exact expected static archive
```

Code:

- [`build_library()`](src/fidb_poc/pipeline.py)
- [`compiler_identity()`](src/fidb_poc/pipeline.py)
- [`build_commands()`](src/fidb_poc/adapters.py)
- [`find_static_archives()`](src/fidb_poc/adapters.py)
- [`run_command()` and log capture](src/fidb_poc/pipeline.py)

The fixed adapters produce commands shaped like:

```text
zlib
> sh configure --static
> make -j4 libz.a AR=/usr/bin/ar ARFLAGS=rc RANLIB=/usr/bin/ranlib

bzip2
> make -j4 libbz2.a CC=/usr/bin/gcc CFLAGS=<trusted flags> AR=/usr/bin/ar RANLIB=/usr/bin/ranlib
```

The recipe cannot supply a command. Command construction lives in
`src/fidb_poc/adapters.py` and is ordinary reviewed code.

Generated build material and logs:

```text
work/builds/<library>-<route>-<treatment>/
work/logs/build/
```

## 9. Extract and validate object files

The baseline compile-phase treatment analyzes the members of each static
archive individually:

```text
libz.a or libbz2.a
> archiver t
> reject duplicate, nested or non-object members
> archiver x
> reconcile listed members with extracted files
> file --brief each object
> require the route's ELF + x86-64 + relocatable markers
```

Code:

- [`_extract_archive_objects()`](src/fidb_poc/pipeline.py)
- [`_validate_objects()`](src/fidb_poc/pipeline.py)

Generated objects:

```text
work/builds/<cell>/objects/
> adler32.o
> crc32.o
> compress.o
> ...
```

After this stage the cell's `BuildRecord.status` becomes `built`. A failed cell
is retained in the manifest as `build_failed` with its error message.

## 10. Import compiled objects into Ghidra

```text
execute()
> populate_fidbs()
> _populate_group() for each route/treatment group
> locate analyzeHeadless and pyghidraRun
> identify Ghidra, Java and PyGhidra versions
> copy cell objects into Ghidra reference folders
> invoke analyzeHeadless
```

Code:

- [`populate_fidbs()`](src/fidb_poc/pipeline.py)
- [`_populate_group()`](src/fidb_poc/pipeline.py)
- [`find_ghidra()`](src/fidb_poc/pipeline.py)
- [`ghidra_environment()`](src/fidb_poc/pipeline.py)

The first Ghidra invocation is constructed as:

```text
analyzeHeadless
> import work/ghidra/references/ recursively
> use processor x86:LE:64:default
> use compiler specification gcc
> run FunctionIDHeadlessPrescript.java
> store analyzed programs in a temporary Ghidra project
```

Code: [`analyzeHeadless` argument construction](src/fidb_poc/pipeline.py)

Generated Ghidra working data:

```text
work/ghidra/projects/
work/ghidra/references/
work/ghidra/user/
work/logs/ghidra/<route>-<treatment>-import.log
```

## 11. Populate candidate FID databases

```text
_populate_group()
> write <route>-<treatment>-libraries.tsv
> invoke pyghidraRun --headless
> run populate_library_fid_databases.py as a post-script
> find imported Ghidra programs
> create one candidate FIDB per library
> generate Function ID signatures
> write a JSONL population report
```

Code:

- [`pyghidraRun` argument construction](src/fidb_poc/pipeline.py)
- [`populate_library_fid_databases.py`](ghidra_scripts/populate_library_fid_databases.py)

Inside the Ghidra script:

```text
libraries.tsv row
> find the corresponding Ghidra project folder
> collect analyzed programs
> FidFileManager.createNewFidDatabase()
> FidService.createNewLibraryFromPrograms()
> save the candidate FIDB
> report program, attempted, added and excluded counts
```

Candidate location:

```text
work/ghidra/candidates/linux-x86_64-gnu-gcc-baseline_o2/
> zlib-1.3.1-linux-x86_64-gnu-gcc-baseline_o2.fidb
> bzip2-1.0.7-linux-x86_64-gnu-gcc-baseline_o2.fidb
```

## 12. Validate and admit FIDBs

```text
population JSONL
> _read_population_report()
> _validate_population_report()
> verify library, version and variant
> verify the expected FIDB path
> verify the submitted program count
> require attempted = added + excluded
> require at least one added signature
> require a non-empty FIDB
> move the candidate into artifacts/libs/fidb/
> hash the final FIDB
> mark the BuildRecord complete
```

Code:

- [`_read_population_report()`](src/fidb_poc/pipeline.py)
- [`_validate_population_report()`](src/fidb_poc/pipeline.py)
- [Candidate admission and record update](src/fidb_poc/pipeline.py)

Final database paths:

```text
artifacts/libs/fidb/
> zlib-1.3.1-linux-x86_64-gnu-gcc-baseline_o2.fidb
> bzip2-1.0.7-linux-x86_64-gnu-gcc-baseline_o2.fidb
```

A Ghidra-stage error removes partial admitted output for the affected group and
records `fid_failed` rather than silently dropping the cell.

## 13. Write the provenance manifest

```text
all BuildRecord objects
> write_manifest()
> convert records into CSV rows
> write a temporary CSV in artifacts/libs/
> flush and fsync it
> atomically replace artifacts/libs/fidb_manifest.csv
```

Code:

- [`BuildRecord`](src/fidb_poc/pipeline.py)
- [`write_manifest()`](src/fidb_poc/pipeline.py)
- [`execute()` finalization](src/fidb_poc/pipeline.py)

The manifest records:

```text
library and version
> route and treatment
> source URL and SHA-256
> compiler, archiver and ranlib paths, versions and SHA-256 values
> compiler flags
> static archive path and SHA-256
> analyzed artifact paths and SHA-256 values
> Ghidra identity
> Java and PyGhidra identity
> FIDB path, size and SHA-256
> attempted, added and excluded signature counts
> final status and error
```

The manifest is written even when one or more cells fail. After writing it:

```text
every record is complete
> return artifacts/libs/fidb_manifest.csv
> CLI exits 0

one or more records are incomplete
> retain artifacts/libs/fidb_manifest.csv as evidence
> raise PipelineError with per-cell statuses
> CLI exits 1
```

## Condensed call chain

```text
uv run fidb-poc
> pyproject.toml: fidb_poc.cli:main
> cli.main()
> config.load_configuration()
> config._resolve_requests()
> config._load_recipe()
> config.select_configuration()
> pipeline.execute()
> pipeline.download_library()
> pipeline.extract_source()
> adapters.detect_project()
> pipeline.build_library()
> adapters.build_commands()
> pipeline._extract_archive_objects()
> pipeline._validate_objects()
> pipeline.populate_fidbs()
> pipeline._populate_group()
> Ghidra analyzeHeadless
> Ghidra FunctionIDHeadlessPrescript.java
> PyGhidra pyghidraRun
> ghidra_scripts/populate_library_fid_databases.py
> FidService.createNewLibraryFromPrograms()
> pipeline._validate_population_report()
> artifacts/libs/fidb/*.fidb
> pipeline.write_manifest()
> artifacts/libs/fidb_manifest.csv
```
