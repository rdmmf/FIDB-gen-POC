import tempfile
import unittest
from pathlib import Path

from fidb_poc.toolchain_registry import load_toolchains


class ToolchainRegistryTests(unittest.TestCase):
    def test_repository_registry_is_valid(self):
        root = Path(__file__).resolve().parents[1]
        rows = load_toolchains(root / "toolchains" / "registry.toml")
        self.assertEqual(len(rows), 41)
        source_rows = [row for row in rows if "toolchain_url" in row]
        self.assertEqual(len(source_rows), 1)
        row = source_rows[0]
        self.assertEqual(row["family"], "uclibc")
        self.assertEqual(row["cross_arch"], "powerpc")
        self.assertEqual(len(row["toolchain_sha256"]), 64)

    def test_archive_row_members_file_is_resolved_and_hashed(self):
        root = Path(__file__).resolve().parents[1]
        rows = load_toolchains(root / "toolchains" / "registry.toml")
        row = next(row for row in rows if row.get("members_file"))
        self.assertTrue(Path(row["members_file"]).is_file())
        self.assertEqual(len(row["members_sha256"]), 64)
        self.assertEqual(row["mode"], "archive")

    def test_source_row_missing_cross_arch_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "registry.toml"
            path.write_text(
                """
                [[toolchain]]
                family = "x"
                version = "1"
                variant = "y"
                machine = "ARM"
                endianness = "little"
                elf_class = 32
                toolchain_url = "https://example.invalid/toolchain.tar.bz2"
                toolchain_sha256 = "%s"
                cross_bin_prefix = "bin/arm-"
                """ % ("a" * 64),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "cross_arch"):
                load_toolchains(path)

    def test_duplicate_rows_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "registry.toml"
            row = """
            [[toolchain]]
            family = "x"
            version = "1"
            variant = "y"
            machine = "ARM"
            endianness = "little"
            elf_class = 32
            url = "https://example.invalid/a.tar.bz2"
            sha256 = "%s"
            library_member = "lib/libc.a"
            """ % ("a" * 64)
            path.write_text(row + row, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate toolchain row"):
                load_toolchains(path)


if __name__ == "__main__":
    unittest.main()
