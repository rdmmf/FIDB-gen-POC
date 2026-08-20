from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

from fidb_poc.libc_catalog import prepare_recipe


class CandidatePreparationTests(unittest.TestCase):
    def test_downloads_verifies_and_extracts_selected_archive_members(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = root / "inputs"
            inputs.mkdir()
            (inputs / "keep.o").write_bytes(b"keep")
            (inputs / "skip.o").write_bytes(b"skip")
            library = root / "libtest.a"
            subprocess.run(
                ["ar", "rcs", str(library), "keep.o", "skip.o"], cwd=inputs, check=True
            )
            archive = root / "candidate.tar.gz"
            with tarfile.open(archive, "w:gz") as output:
                output.add(library, arcname="toolchain/lib/libtest.a")
            members = root / "members.txt"
            members.write_text("keep.o\n", encoding="utf-8")
            recipe = {
                "family": "testlib",
                "version": "1",
                "variant": "fixture",
                "machine": "ARM",
                "endianness": "little",
                "elf_class": 32,
                "mode": "archive",
                "url": archive.as_uri(),
                "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                "library_member": "toolchain/lib/libtest.a",
                "members_file": str(members),
                "members_sha256": hashlib.sha256(members.read_bytes()).hexdigest(),
            }

            guess = prepare_recipe(recipe, root / "work", root / "downloads")
            objects = Path(str(guess["objects"]))

            self.assertEqual((objects / "keep.o").read_bytes(), b"keep")
            self.assertFalse((objects / "skip.o").exists())
            self.assertEqual(guess["source_sha256"], recipe["sha256"])
