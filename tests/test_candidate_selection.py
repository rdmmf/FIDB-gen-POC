from pathlib import Path
from types import SimpleNamespace
import unittest

from fidb_poc.libc_catalog import load_recipes, select_recipes


class CandidateSelectionTests(unittest.TestCase):
    def test_uses_investigation_family_and_target_architecture(self) -> None:
        investigation = SimpleNamespace(
            target=SimpleNamespace(machine="PowerPC", endianness="big", elf_class=32),
            hypotheses=(SimpleNamespace(
                disposition="build", candidate_packages=("uclibc", "glibc")
            ),),
        )
        recipes = [
            {"family": "musl", "version": "1", "machine": "PowerPC", "endianness": "big", "elf_class": 32},
            {"family": "uclibc", "version": "1", "machine": "PowerPC", "endianness": "big", "elf_class": 32},
            {"family": "uclibc", "version": "1", "machine": "MIPS", "endianness": "big", "elf_class": 32},
        ]

        selected = select_recipes(investigation, recipes)

        self.assertEqual([recipe["family"] for recipe in selected], ["uclibc"])

    def test_default_catalog_prefers_source_build_over_prebuilt_archive(self) -> None:
        # This is the "recipe generation from investigate" path: given the same
        # PowerPC/uClibc evidence, hunt should try the from-source recipe first
        # (a real compile, not a third-party prebuilt archive) since it has a
        # lower priority number, before falling back to the archive.
        catalog = Path(__file__).resolve().parents[1] / "catalogs" / "default.toml"
        recipes = load_recipes(catalog)
        investigation = SimpleNamespace(
            target=SimpleNamespace(machine="PowerPC", endianness="big", elf_class=32),
            hypotheses=(SimpleNamespace(
                disposition="build", candidate_packages=("uclibc",)
            ),),
        )

        selected = select_recipes(investigation, recipes)

        self.assertEqual([recipe["mode"] for recipe in selected], ["source", "archive"])
        source_recipe = selected[0]
        self.assertTrue(Path(source_recipe["patches"][0]).exists())

    def test_default_catalog_covers_common_mirai_architectures(self) -> None:
        # Locks in corpus coverage: these (machine, endianness, elf_class)
        # combos make up the bulk of a real mirai-family sample set. Each
        # should resolve to at least one Bootlin-sysroot archive recipe.
        catalog = Path(__file__).resolve().parents[1] / "catalogs" / "default.toml"
        recipes = load_recipes(catalog)
        combos = [
            ("ARM", "little", 32),
            ("MIPS", "big", 32),
            ("MIPS", "little", 32),
            ("x86", "little", 32),
            ("x86-64", "little", 64),
            ("M68K", "big", 32),
            ("AArch64", "little", 64),
            ("SH", "little", 32),
        ]
        for machine, endianness, elf_class in combos:
            investigation = SimpleNamespace(
                target=SimpleNamespace(machine=machine, endianness=endianness, elf_class=elf_class),
                hypotheses=(SimpleNamespace(disposition="build", candidate_packages=("uclibc",)),),
            )
            with self.subTest(machine=machine, endianness=endianness, elf_class=elf_class):
                self.assertTrue(select_recipes(investigation, recipes))
