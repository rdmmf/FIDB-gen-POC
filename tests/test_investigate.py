import unittest

from fidb_poc.investigate import find_decodings


class InvestigationTests(unittest.TestCase):
    def test_finds_single_byte_xor_strings(self) -> None:
        encoded = bytes(value ^ 3 for value in b"/bin/busybox\0/dev/watchdog\0password is wrong\0")
        best = find_decodings(encoded, limit=1)[0]
        self.assertEqual(best.key, 3)
        self.assertIn("/bin/busybox", best.strings)
