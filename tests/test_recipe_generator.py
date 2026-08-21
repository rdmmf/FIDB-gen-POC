import tempfile
import unittest
from pathlib import Path

from fidb_poc.recipe_generator import generate_cells, load_recipes
from fidb_poc.toolchain_registry import load_toolchains


class RecipeGeneratorTests(unittest.TestCase):
    def test_repository_uclibc_recipe_reproduces_the_hand_written_catalog_entry(self):
        """Cross-check against catalogs/default.toml's hand-written
        "uclibc 0.9.30.1 powerpc-source-build" recipe -- same real,
        previously-verified hashes, now produced by recipe x registry
        instead of copy-pasted.
        """
        root = Path(__file__).resolve().parents[1]
        recipes = load_recipes(root / "recipes" / "libs")
        toolchains = load_toolchains(root / "toolchains" / "registry.toml")
        cells = generate_cells(recipes, toolchains)
        matching = [cell for cell in cells if cell["family"] == "uclibc"]
        self.assertEqual(len(matching), 1)
        cell = matching[0]

        self.assertEqual(cell["version"], "0.9.30.1")
        self.assertEqual(cell["mode"], "source")
        self.assertEqual(cell["machine"], "PowerPC")
        self.assertEqual(cell["endianness"], "big")
        self.assertEqual(cell["elf_class"], 32)
        self.assertEqual(
            cell["source_url"], "https://uclibc.org/downloads/uClibc-0.9.30.1.tar.bz2"
        )
        self.assertEqual(
            cell["source_sha256"],
            "2d9769a02c46cff73f56a076268192da1ce91c913e2e4e31c120be098f704c8c",
        )
        self.assertEqual(
            cell["toolchain_url"],
            "https://toolchains.bootlin.com/downloads/releases/toolchains/"
            "powerpc-e500mc/tarballs/powerpc-e500mc--uclibc--stable-2017.05-toolchains-1-1.tar.bz2",
        )
        self.assertEqual(
            cell["toolchain_sha256"],
            "2eca639c6194147da52d3e3cbd9d3f0fafe23fe152200d4e720cb28ed963d980",
        )
        self.assertEqual(cell["arch"], "powerpc")
        self.assertEqual(cell["cross_bin_prefix"], "bin/powerpc-buildroot-linux-uclibc-")
        self.assertEqual(
            cell["kernel_headers_relpath"],
            "powerpc-buildroot-linux-uclibc/sysroot/usr/include",
        )
        self.assertEqual(cell["library_path"], "lib/libc.a")
        self.assertEqual(cell["build_adapter"], "uclibc_defconfig")
        self.assertEqual(len(cell["patches"]), 1)
        self.assertTrue(Path(cell["patches"][0]).is_file())
        self.assertTrue(cell["patches"][0].endswith("uclibc-0.9.30.1-powerpc-crtn-size.patch"))

    def test_duplicate_generated_cells_are_rejected(self):
        recipe = {
            "schema_version": "fidb-recipe/v3", "mode": "source",
            "name": "dup", "version": "1", "url": "https://example.invalid/a.tar.gz",
            "sha256": "a" * 64, "library_path": "lib/libc.a",
            "build_adapter": "uclibc_defconfig", "toolchain_family": "dupfamily",
        }
        toolchain = {
            "family": "dupfamily", "version": "1", "variant": "only",
            "machine": "ARM", "endianness": "little", "elf_class": 32,
            "toolchain_url": "https://example.invalid/tc.tar.bz2", "toolchain_sha256": "b" * 64,
            "cross_bin_prefix": "bin/arm-", "cross_arch": "arm",
        }
        cells = generate_cells([recipe], [toolchain])
        self.assertEqual(len(cells), 1)
        with self.assertRaisesRegex(ValueError, "duplicate generated cell"):
            generate_cells([recipe, dict(recipe)], [toolchain])

    def test_recipe_with_no_matching_toolchain_family_fails_closed(self):
        recipe = {
            "schema_version": "fidb-recipe/v3", "mode": "source",
            "name": "orphan", "version": "1", "url": "https://example.invalid/a.tar.gz",
            "sha256": "a" * 64, "library_path": "lib/libc.a",
            "build_adapter": "uclibc_defconfig", "toolchain_family": "nonexistent",
        }
        with self.assertRaisesRegex(ValueError, "no source-capable"):
            generate_cells([recipe], [])

    def test_recipe_missing_required_field_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.toml"
            path.write_text(
                'schema_version = "fidb-recipe/v3"\nmode = "source"\nname = "x"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "is missing"):
                load_recipes(directory)


if __name__ == "__main__":
    unittest.main()
