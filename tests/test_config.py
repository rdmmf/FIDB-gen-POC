import json
import shutil
import tempfile
import tomllib
import unittest
from dataclasses import replace
from pathlib import Path

from fidb_poc.config import (
    RecipesNotFoundError,
    load_configuration,
)


class ConfigurationTests(unittest.TestCase):
    def test_repository_configuration_is_valid(self):
        root = Path(__file__).resolve().parents[1]
        configuration = load_configuration(root / "worker.json")
        self.assertEqual(
            [row.identifier for row in configuration.libraries],
            ["zlib-1.3.1", "bzip2-1.0.7"],
        )
        self.assertEqual(len(configuration.routes), 1)
        self.assertEqual(
            [route.id for route in configuration.routes],
            ["linux-x86_64-gnu-gcc"],
        )
        gcc_route = configuration.routes[0]
        self.assertEqual(gcc_route.target_os, "linux")
        self.assertEqual(gcc_route.architecture, "x86_64")
        self.assertEqual(gcc_route.binary_format, "ELF")
        self.assertEqual(gcc_route.compiler, ("/usr/bin/gcc",))
        self.assertEqual(gcc_route.archiver, ("/usr/bin/ar",))
        self.assertEqual(gcc_route.ranlib, ("/usr/bin/ranlib",))
        self.assertEqual(
            gcc_route.compiler_version_markers,
            ("Free Software Foundation",),
        )
        self.assertIn("-fPIC", gcc_route.compiler_flags)
        self.assertNotIn("-g", gcc_route.compiler_flags)
        self.assertEqual([row.id for row in configuration.treatments], ["baseline_o2"])
        self.assertEqual(
            configuration.treatments[0].description,
            "O2, compiled without -g or LTO, frame pointer retained",
        )
        self.assertEqual(configuration.profiles, {"smoke": ("baseline_o2",)})

    def test_work_request_contains_library_names_not_source_details(self):
        root = Path(__file__).resolve().parents[1]
        document = json.loads((root / "worker.json").read_text())
        self.assertEqual(document["requested_libraries"], ["zlib", "bzip2"])
        self.assertNotIn("url", document)
        self.assertNotIn("sources", document)

    def test_recipes_describe_detection_not_translation_units(self):
        root = Path(__file__).resolve().parents[1]
        recipe = tomllib.loads((root / "recipes/zlib.toml").read_text())
        self.assertEqual(recipe["preferred_build_system"], "autoconf")
        self.assertEqual(recipe["static_archives"], ["libz.a"])
        self.assertNotIn("sources", recipe)
        self.assertNotIn("command", recipe)

    def test_command_line_request_override_resolves_one_recipe(self):
        root = Path(__file__).resolve().parents[1]
        configuration = load_configuration(
            root / "worker.json", request_override=("zlib",)
        )
        self.assertEqual(
            [row.identifier for row in configuration.libraries],
            ["zlib-1.3.1"],
        )

    def test_unknown_library_request_fails_closed(self):
        root = Path(__file__).resolve().parents[1]
        with self.assertRaisesRegex(ValueError, "no approved recipe"):
            load_configuration(
                root / "worker.json", request_override=("imaginary-lib",)
            )

    def test_all_unknown_library_requests_are_reported(self):
        root = Path(__file__).resolve().parents[1]
        with self.assertRaises(RecipesNotFoundError) as raised:
            load_configuration(
                root / "worker.json",
                request_override=("imaginary-one", "imaginary-two"),
            )
        self.assertEqual(raised.exception.requests, ("imaginary-one", "imaginary-two"))

    def test_duplicate_routes_are_rejected(self):
        root = Path(__file__).resolve().parents[1]
        document = json.loads((root / "worker.json").read_text())
        document["recipe_directory"] = str(root / "recipes")
        document["routes"].append(document["routes"][0])
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.json"
            path.write_text(json.dumps(document))
            with self.assertRaisesRegex(ValueError, "route ids must be unique"):
                load_configuration(path)

    def test_generated_path_components_cannot_escape_the_project(self):
        root = Path(__file__).resolve().parents[1]
        document = json.loads((root / "worker.json").read_text())
        document["recipe_directory"] = str(root / "recipes")
        document["routes"][0]["id"] = "../../src"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "route id must be a safe"):
                load_configuration(path)

    def test_recipe_path_components_cannot_escape_the_source_root(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            checkout = Path(temporary)
            shutil.copy(root / "worker.json", checkout / "worker.json")
            shutil.copytree(root / "recipes", checkout / "recipes")
            recipe_path = checkout / "recipes/zlib.toml"
            text = recipe_path.read_text(encoding="utf-8")
            text = text.replace(
                'source_directory = "zlib-1.3.1"',
                'source_directory = "../../src"',
            )
            recipe_path.write_text(text, encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "source_directory must be a safe"):
                load_configuration(checkout / "worker.json")

    def test_programmatic_configuration_rejects_unsafe_generated_components(self):
        root = Path(__file__).resolve().parents[1]
        configuration = load_configuration(root / "worker.json")

        with self.assertRaisesRegex(ValueError, "route id must be a safe"):
            replace(configuration.routes[0], id="../../src")
        with self.assertRaisesRegex(ValueError, "treatment id must be a safe"):
            replace(configuration.treatments[0], id="../output")
        with self.assertRaisesRegex(ValueError, "library name must be a safe"):
            replace(configuration.libraries[0], name="/tmp/escape")


if __name__ == "__main__":
    unittest.main()
