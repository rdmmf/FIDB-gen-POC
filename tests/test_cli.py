import contextlib
import csv
import io
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fidb_poc.cli import main
from fidb_poc.pipeline import PipelineError


class CommandLineTests(unittest.TestCase):
    def test_build_requires_an_explicit_route(self):
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            status = main([])

        self.assertEqual(status, 2)
        self.assertIn("at least one --route is required", errors.getvalue())

    def test_plan_does_not_require_installed_toolchains(self):
        root = Path(__file__).resolve().parents[1]
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = main(
                [
                    "--project-root",
                    str(root),
                    "--plan",
                    "--library",
                    "zlib",
                    "--route",
                    "linux-x86_64-gnu-gcc",
                ]
            )

        self.assertEqual(status, 0)
        self.assertIn("1 cells (1 runnable)", output.getvalue())
        self.assertIn("zlib-1.3.1", output.getvalue())

    def test_missing_recipe_is_written_to_the_request_list(self):
        source_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copy(source_root / "worker.json", root / "worker.json")
            shutil.copytree(source_root / "recipes", root / "recipes")
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors):
                status = main(
                    [
                        "--project-root",
                        str(root),
                        "--plan",
                        "--library",
                        "libpng",
                        "--route",
                        "linux-x86_64-gnu-gcc",
                        "--request-priority",
                        "1",
                    ]
                )

            self.assertEqual(status, 1)
            path = root / "recipe_requests/pending.csv"
            with path.open(newline="", encoding="utf-8") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(rows[0]["library_request"], "libpng")
            self.assertEqual(rows[0]["priority"], "1")
            self.assertIn(str(path), errors.getvalue())

    def test_pipeline_error_returns_nonzero(self):
        root = Path(__file__).resolve().parents[1]
        errors = io.StringIO()
        with (
            patch(
                "fidb_poc.cli.execute",
                side_effect=PipelineError("pipeline did not complete"),
            ),
            contextlib.redirect_stderr(errors),
        ):
            status = main(
                [
                    "--project-root",
                    str(root),
                    "--library",
                    "zlib",
                    "--route",
                    "linux-x86_64-gnu-gcc",
                ]
            )

        self.assertEqual(status, 1)
        self.assertIn("pipeline did not complete", errors.getvalue())

    def test_formula_like_library_is_rejected_without_queue_write(self):
        source_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copy(source_root / "worker.json", root / "worker.json")
            shutil.copytree(source_root / "recipes", root / "recipes")
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors):
                status = main(
                    [
                        "--project-root",
                        str(root),
                        "--plan",
                        '--library==HYPERLINK("https://example.invalid")',
                        "--route",
                        "linux-x86_64-gnu-gcc",
                    ]
                )

            self.assertEqual(status, 1)
            self.assertFalse((root / "recipe_requests/pending.csv").exists())
            self.assertIn("formula marker", errors.getvalue())

    def test_fresh_rejects_non_checkout_without_deleting_outputs(self):
        source_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copy(source_root / "worker.json", root / "worker.json")
            shutil.copytree(source_root / "recipes", root / "recipes")
            work_marker = root / "work/keep.txt"
            output_marker = root / "artifacts/libs/keep.txt"
            work_marker.parent.mkdir()
            output_marker.parent.mkdir(parents=True)
            work_marker.write_text("keep", encoding="utf-8")
            output_marker.write_text("keep", encoding="utf-8")
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors):
                status = main(
                    [
                        "--project-root",
                        str(root),
                        "--fresh",
                        "--library",
                        "zlib",
                        "--route",
                        "linux-x86_64-gnu-gcc",
                    ]
                )

            self.assertEqual(status, 1)
            self.assertTrue(work_marker.is_file())
            self.assertTrue(output_marker.is_file())
            self.assertIn("not an FIDB-POC checkout", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
