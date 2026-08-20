import csv
import io
import tarfile
import tempfile
import unittest
from dataclasses import fields
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fidb_poc.pipeline import (
    BuildRecord,
    PipelineError,
    _populate_group,
    _validate_population_report,
    compiler_identity,
    find_pyghidra,
    ghidra_environment,
    _safe_member_path,
    execute,
    extract_source,
    java_identity,
    pipeline_environment,
    plan,
    populate_fidbs,
    run_command,
    sha256,
    write_manifest,
)
from fidb_poc.adapters import Detection
from fidb_poc.config import Library, load_configuration, select_configuration


class PipelineTests(unittest.TestCase):
    def test_run_command_verbose_streams_and_still_matches_buffered_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "logs" / "cmd.log"
            command = ["python3", "-c", "print('line1'); print('line2')"]
            printed = []
            with patch("builtins.print", side_effect=lambda *a: printed.append(" ".join(a))):
                result = run_command(
                    command,
                    cwd=None,
                    environment={"PATH": "/usr/bin:/bin"},
                    log_path=log_path,
                    verbose=True,
                )
            self.assertEqual(result.returncode, 0)
            self.assertIn("line1\nline2\n", result.stdout)
            self.assertTrue(any("line1" in line for line in printed))
            self.assertIn("line1", log_path.read_text(encoding="utf-8"))

    def test_ghidra_environment_isolates_linux_xdg_directories(self):
        inherited = {
            "XDG_CONFIG_HOME": "/read-only/config",
            "XDG_CACHE_HOME": "/read-only/cache",
            "XDG_DATA_HOME": "/read-only/data",
            "XDG_STATE_HOME": "/read-only/state",
            "XDG_RUNTIME_DIR": "/read-only/runtime",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "ghidra-user"
            with patch.dict("os.environ", inherited):
                environment = ghidra_environment(root)

            self.assertEqual(environment["HOME"], str(root.resolve()))
            for name, inherited_path in inherited.items():
                self.assertNotEqual(environment[name], inherited_path)
                self.assertTrue(Path(environment[name]).is_dir())
            self.assertEqual(
                Path(environment["XDG_RUNTIME_DIR"]).stat().st_mode & 0o777,
                0o700,
            )

    def test_compiler_identity_runs_in_an_isolated_directory(self):
        root = Path(__file__).resolve().parents[1]
        configuration = load_configuration(
            root / "worker.json", request_override=("zlib",)
        )
        route = next(
            row for row in configuration.routes if row.id == "linux-x86_64-gnu-gcc"
        )
        completed = SimpleNamespace(
            stdout="gcc (GCC) 15.3.1 - Free Software Foundation",
            stderr="",
            returncode=0,
        )

        with (
            patch(
                "fidb_poc.pipeline.resolve_executable",
                return_value=Path("/usr/bin/gcc"),
            ),
            patch("fidb_poc.pipeline.subprocess.run", return_value=completed) as run,
        ):
            executable, version = compiler_identity(route, {})

        probe_directory = Path(run.call_args.kwargs["cwd"])
        self.assertEqual(executable, Path("/usr/bin/gcc"))
        self.assertEqual(version, completed.stdout)
        self.assertTrue(probe_directory.name.startswith("fidb-compiler-identity-"))
        self.assertFalse(probe_directory.exists())

    def test_pyghidra_launcher_is_resolved_beside_headless(self):
        with tempfile.TemporaryDirectory() as temporary:
            support = Path(temporary)
            headless = support / "analyzeHeadless"
            launcher = support / "pyghidraRun"
            launcher.touch()

            self.assertEqual(find_pyghidra(headless), launcher)

    def test_missing_pyghidra_launcher_is_explicit(self):
        with tempfile.TemporaryDirectory() as temporary:
            headless = Path(temporary) / "analyzeHeadless"

            with self.assertRaisesRegex(PipelineError, "PyGhidra launcher"):
                find_pyghidra(headless)

    def test_plan_lists_selected_cells_without_running_tools(self):
        root = Path(__file__).resolve().parents[1]
        configuration = load_configuration(
            root / "worker.json", request_override=("zlib",)
        )
        configuration = select_configuration(
            configuration,
            route_ids=("linux-x86_64-gnu-gcc",),
            treatment_ids=None,
            profile="smoke",
        )

        lines = plan(configuration)

        self.assertEqual(
            lines[0], "Plan: 1 libraries; 1 routes; 1 treatments; 1 cells (1 runnable)"
        )
        self.assertEqual(
            lines[1],
            "- zlib-1.3.1 | linux-x86_64-gnu-gcc | baseline_o2 | runnable",
        )

    def test_archive_path_rejects_traversal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(PipelineError):
                _safe_member_path(root, "../escape")
            with self.assertRaises(PipelineError):
                _safe_member_path(root, "/absolute")

    def test_manifest_is_readable_csv(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "manifest.csv"
            record = BuildRecord(
                library="zlib",
                version="1.3.1",
                route="linux-x86_64-gnu-gcc",
                target_os="linux",
                architecture="x86_64",
                binary_format="ELF",
                source_url="https://example.invalid/zlib.tar.gz",
                source_sha256="a" * 64,
                compiler_command="gcc",
                compiler_path="/usr/bin/gcc",
                compiler_sha256="b" * 64,
                compiler_version=(
                    "gcc (GCC) 15.3.1 | Copyright Free Software Foundation"
                ),
                compiler_flags="-O2",
                static_archive_path="work/libz.a",
                static_archive_sha256="c" * 64,
                object_count=15,
            )
            write_manifest([record], destination)
            with destination.open(newline="", encoding="utf-8") as stream:
                reader = csv.DictReader(stream)
                rows = list(reader)

            self.assertEqual(
                reader.fieldnames, [field.name for field in fields(record)]
            )
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["library"], "zlib")
            self.assertEqual(rows[0]["version"], "1.3.1")
            self.assertEqual(rows[0]["route"], "linux-x86_64-gnu-gcc")
            self.assertEqual(rows[0]["object_count"], "15")
            self.assertEqual(list(destination.parent.glob(".*.tmp")), [])
            self.assertEqual(destination.stat().st_mode & 0o777, 0o644)

    def test_population_report_must_reconcile_before_completion(self):
        root = Path(__file__).resolve().parents[1]
        configuration = load_configuration(
            root / "worker.json", request_override=("zlib",)
        )
        library = configuration.libraries[0]
        group_id = "linux-x86_64-gnu-gcc-baseline_o2"
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            fidb = output / f"{library.identifier}-{group_id}.fidb"
            fidb.write_bytes(b"fidb")
            population = {
                "library": "zlib",
                "version": "1.3.1",
                "variant": group_id,
                "fidb_path": str(fidb),
                "program_count": 15,
                "attempted": 124,
                "added": 113,
                "excluded": 11,
            }

            rows = _validate_population_report(
                [population], [library], group_id, output, {"zlib": 15}
            )
            self.assertEqual(rows["zlib"], population)

            population["excluded"] = 10
            with self.assertRaisesRegex(PipelineError, "do not reconcile"):
                _validate_population_report(
                    [population], [library], group_id, output, {"zlib": 15}
                )

            population["excluded"] = 11
            with self.assertRaisesRegex(PipelineError, "program count"):
                _validate_population_report(
                    [population], [library], group_id, output, {"zlib": 14}
                )

    def test_pipeline_environment_drops_inherited_build_flags(self):
        inherited = {
            "PATH": "/usr/bin",
            "JDK_JAVA_OPTIONS": "-XX:-UseContainerSupport",
            "CFLAGS": "-DINJECTED",
            "CPPFLAGS": "-I/untrusted",
            "LDFLAGS": "-L/untrusted",
            "MAKEFLAGS": "-f/untrusted",
            "CONFIG_SITE": "/untrusted/config.site",
        }
        with patch.dict("os.environ", inherited, clear=True):
            environment = pipeline_environment()

        self.assertEqual(environment["PATH"], "/usr/bin")
        self.assertEqual(environment["JDK_JAVA_OPTIONS"], "-XX:-UseContainerSupport")
        for name in ("CFLAGS", "CPPFLAGS", "LDFLAGS", "MAKEFLAGS", "CONFIG_SITE"):
            self.assertNotIn(name, environment)
        self.assertEqual(environment["LC_ALL"], "C")

    def test_cached_source_tampering_is_discarded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "demo.tar.gz"
            original = b"int demo(void) { return 1; }\n"
            with tarfile.open(archive, "w:gz") as source_tar:
                directory = tarfile.TarInfo("demo-1.0")
                directory.type = tarfile.DIRTYPE
                source_tar.addfile(directory)
                member = tarfile.TarInfo("demo-1.0/demo.c")
                member.size = len(original)
                source_tar.addfile(member, io.BytesIO(original))
            library = Library(
                name="demo",
                version="1.0",
                url="https://example.invalid/demo.tar.gz",
                sha256=sha256(archive),
                source_directory="demo-1.0",
                project_markers=("demo.c",),
                allowed_build_systems=("make",),
                preferred_build_system="make",
                static_archives=("libdemo.a",),
            )
            sources = root / "sources"
            first = extract_source(library, archive, sources)
            (first / "demo.c").write_text("tampered", encoding="utf-8")

            second = extract_source(library, archive, sources)

            self.assertEqual((second / "demo.c").read_bytes(), original)

    def test_java_identity_prefers_java_home(self):
        with tempfile.TemporaryDirectory() as temporary:
            java = Path(temporary) / "jdk/bin/java"
            java.parent.mkdir(parents=True)
            java.write_text(
                "#!/bin/sh\necho 'openjdk version \"21.0.11\"' >&2\n",
                encoding="utf-8",
            )
            java.chmod(0o755)

            executable, version, major = java_identity(
                {"JAVA_HOME": str(java.parents[1]), "PATH": "/unavailable"}
            )

            self.assertEqual(executable, java.resolve())
            self.assertEqual(version, "21.0.11")
            self.assertEqual(major, 21)

    def test_population_schema_failure_cleans_partial_fidbs(self):
        source_root = Path(__file__).resolve().parents[1]
        configuration = load_configuration(
            source_root / "worker.json", request_override=("zlib",)
        )
        configuration = select_configuration(
            configuration,
            route_ids=("linux-x86_64-gnu-gcc",),
            treatment_ids=None,
            profile="smoke",
        )
        library = configuration.libraries[0]
        route = configuration.routes[0]
        treatment = configuration.treatments[0]
        key = (library.identifier, route.id, treatment.id)
        record = BuildRecord(status="built")
        group_id = f"{route.id}-{treatment.id}"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = (
                root
                / "work/ghidra/candidates"
                / group_id
                / f"{library.identifier}-{group_id}.fidb"
            )
            published = root / "output/fidb" / candidate.name
            candidate.parent.mkdir(parents=True)
            published.parent.mkdir(parents=True)
            candidate.write_bytes(b"partial")
            published.write_bytes(b"partial")

            with patch(
                "fidb_poc.pipeline._populate_group",
                side_effect=ValueError("malformed report schema"),
            ):
                populate_fidbs(configuration, root, {key: record}, {key: []})

            self.assertEqual(record.status, "fid_failed")
            self.assertIn("malformed report schema", record.error)
            self.assertFalse(candidate.exists())
            self.assertFalse(published.exists())

    def test_populate_group_builds_fidb_via_inprocess_pyghidra(self):
        """`_populate_group` must drive `ghidra_fid.build_library_fidb` (the
        in-process pyghidra API) rather than shelling out to
        analyzeHeadless/pyghidraRun -- that subprocess round-trip is what
        hung indefinitely on a pip-less venv.
        """
        source_root = Path(__file__).resolve().parents[1]
        configuration = load_configuration(
            source_root / "worker.json", request_override=("zlib",)
        )
        configuration = select_configuration(
            configuration,
            route_ids=("linux-x86_64-gnu-gcc",),
            treatment_ids=None,
            profile="smoke",
        )
        library = configuration.libraries[0]
        route = configuration.routes[0]
        treatment = configuration.treatments[0]
        key = (library.identifier, route.id, treatment.id)
        records = {key: BuildRecord(status="built")}

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            headless = root / "ghidra/support/analyzeHeadless"
            headless.parent.mkdir(parents=True)
            headless.write_text("#!/bin/sh\n", encoding="utf-8")
            headless.chmod(0o755)
            properties = root / "ghidra/Ghidra/application.properties"
            properties.parent.mkdir(parents=True)
            properties.write_text(
                "application.version=12.0.4\n"
                "application.release.name=PUBLIC\n"
                "application.build.date=2026-01-01\n",
                encoding="utf-8",
            )
            obj = root / "adler32.o"
            obj.write_bytes(b"fake object")
            objects = {key: [obj]}

            def fake_build(*, output, **_kwargs):
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_bytes(b"fake fidb")
                return {"programs": 1, "attempted": 1, "added": 1, "excluded": 0}

            with (
                patch(
                    "fidb_poc.pipeline.find_ghidra",
                    return_value=(headless, root / "ghidra"),
                ),
                patch(
                    "fidb_poc.pipeline.java_identity",
                    return_value=(Path("/usr/bin/java"), "21.0.1", 21),
                ),
                patch(
                    "fidb_poc.pipeline.pyghidra_identity", return_value="3.1.0"
                ),
                patch("fidb_poc.pipeline.ghidra_fid.ensure_started"),
                patch(
                    "fidb_poc.pipeline.ghidra_fid.build_library_fidb",
                    side_effect=fake_build,
                ) as build,
            ):
                _populate_group(configuration, root, route, treatment, records, objects)

            self.assertEqual(build.call_args.kwargs["language"], route.ghidra_language)
            self.assertEqual(
                build.call_args.kwargs["compiler_spec"], route.ghidra_compiler_spec
            )
            record = records[key]
            self.assertEqual(record.status, "complete")
            self.assertEqual(record.fid_added, 1)
            self.assertEqual(record.pyghidra_version, "3.1.0")
            self.assertTrue((root / record.fidb_path).is_file())

    def test_execute_rejects_symlinked_generated_root(self):
        source_root = Path(__file__).resolve().parents[1]
        configuration = load_configuration(
            source_root / "worker.json", request_override=("zlib",)
        )
        configuration = select_configuration(
            configuration,
            route_ids=("linux-x86_64-gnu-gcc",),
            treatment_ids=None,
            profile="smoke",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_directory = root / "src"
            source_directory.mkdir()
            marker = source_directory / "keep.txt"
            marker.write_text("keep", encoding="utf-8")
            (root / "work").symlink_to(source_directory, target_is_directory=True)

            with self.assertRaisesRegex(PipelineError, "generated root"):
                execute(configuration, root)

            self.assertEqual(marker.read_text(encoding="utf-8"), "keep")
            self.assertEqual(list(source_directory.iterdir()), [marker])

    def test_execute_writes_manifest_then_raises_for_failed_cell(self):
        source_root = Path(__file__).resolve().parents[1]
        configuration = load_configuration(
            source_root / "worker.json", request_override=("zlib",)
        )
        configuration = select_configuration(
            configuration,
            route_ids=("linux-x86_64-gnu-gcc",),
            treatment_ids=None,
            profile="smoke",
        )
        detection = Detection(
            build_system="autoconf",
            evidence=("configure",),
            languages=("C",),
            project_markers=("configure",),
        )
        failed = BuildRecord(
            library="zlib",
            version="1.3.1",
            route="linux-x86_64-gnu-gcc",
            treatment="baseline_o2",
            status="build_failed",
            error="compiler failed",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stale = root / "output/fidb/stale.fidb"
            stale.parent.mkdir(parents=True)
            stale.write_bytes(b"stale")
            progress = []
            with (
                patch("fidb_poc.pipeline.download_library", return_value=root / "a"),
                patch("fidb_poc.pipeline.extract_source", return_value=root / "source"),
                patch("fidb_poc.pipeline.detect_project", return_value=detection),
                patch("fidb_poc.pipeline.build_library", return_value=(failed, [])),
                patch("fidb_poc.pipeline.populate_fidbs"),
                self.assertRaisesRegex(PipelineError, "did not complete"),
            ):
                execute(configuration, root, progress=progress.append)

            manifest = root / "output/fidb_manifest.csv"
            self.assertTrue(manifest.is_file())
            self.assertFalse(stale.exists())
            self.assertIn("Result: build_failed=1", progress)
            self.assertIn(f"Manifest: {manifest}", progress)


if __name__ == "__main__":
    unittest.main()
