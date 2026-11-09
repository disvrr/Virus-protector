"""Tests for the core modules. Run with: python -m unittest discover -s tests -v"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import heuristics
import integrity
import quarantine
import scanner

# The EICAR test string is assembled from parts so the test file itself is not flagged by antivirus software.
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


class TestScanner(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.db = scanner.load_signatures()

    def tearDown(self):
        self.tmp.cleanup()

    def test_eicar_detected_by_hash(self):
        f = self.dir / "eicar.com"
        f.write_bytes(EICAR)
        self.assertIsNotNone(scanner.scan_file(f, self.db))

    def test_eicar_detected_by_pattern(self):
        f = self.dir / "doc.txt"
        f.write_bytes(b"hello\n" + EICAR + b"\nworld")
        det = scanner.scan_file(f, self.db)
        self.assertIsNotNone(det)
        self.assertIn("Signature", det.reason)

    def test_clean_file(self):
        f = self.dir / "clean.txt"
        f.write_text("ordinary text")
        self.assertIsNone(scanner.scan_file(f, self.db))


class TestQuarantine(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self._old = quarantine.QUARANTINE_DIR
        quarantine.QUARANTINE_DIR = self.dir / "q"

    def tearDown(self):
        quarantine.QUARANTINE_DIR = self._old
        self.tmp.cleanup()

    def test_quarantine_and_restore(self):
        f = self.dir / "bad.bin"
        f.write_bytes(b"payload" * 100)
        qid = quarantine.quarantine_file(f, "test")
        self.assertFalse(f.exists())
        self.assertIn(qid, quarantine.list_items())
        stored = (quarantine.QUARANTINE_DIR / f"{qid}.quar").read_bytes()
        self.assertNotEqual(stored, b"payload" * 100) # The content is obfuscated.
        quarantine.restore(qid)
        self.assertEqual(f.read_bytes(), b"payload" * 100)
        self.assertNotIn(qid, quarantine.list_items())

    def test_delete(self):
        f = self.dir / "bad2.bin"
        f.write_bytes(b"x")
        qid = quarantine.quarantine_file(f)
        quarantine.delete(qid)
        self.assertEqual(quarantine.list_items(), {})


class TestIntegrity(unittest.TestCase):
    def test_detects_changes(self):
        with tempfile.TemporaryDirectory() as t:
            d = Path(t) / "data"
            d.mkdir()
            (d / "a.txt").write_text("a")
            (d / "b.txt").write_text("b")
            base = Path(t) / "baseline.json"
            self.assertEqual(integrity.build_baseline(d, base), 2)
            (d / "a.txt").write_text("changed")
            (d / "b.txt").unlink()
            (d / "c.txt").write_text("new")
            diff = integrity.check_baseline(d, base)
            self.assertEqual(diff["modified"], ["a.txt"])
            self.assertEqual(diff["deleted"], ["b.txt"])
            self.assertEqual(diff["new"], ["c.txt"])


class TestHeuristics(unittest.TestCase):
    def test_double_extension(self):
        with tempfile.TemporaryDirectory() as t:
            f = Path(t) / "report.pdf.exe"
            f.write_bytes(b"MZ" + b"\x00" * 100)
            res = heuristics.analyze_file(f)
            self.assertGreaterEqual(res.score, 30)

    def test_disguised_executable(self):
        with tempfile.TemporaryDirectory() as t:
            f = Path(t) / "photo.jpg"
            f.write_bytes(b"MZ" + b"\x90" * 200)
            self.assertGreaterEqual(heuristics.analyze_file(f).score, 40)

    def test_ransomware_strings(self):
        with tempfile.TemporaryDirectory() as t:
            f = Path(t) / "run.bat"
            f.write_bytes(b"vssadmin delete shadows /all /quiet\npowershell -enc AAAA")
            self.assertEqual(heuristics.analyze_file(f).verdict, "likely malicious")

    def test_clean_text(self):
        with tempfile.TemporaryDirectory() as t:
            f = Path(t) / "notes.txt"
            f.write_text("just notes")
            self.assertEqual(heuristics.analyze_file(f).verdict, "clean")

    def test_entropy(self):
        self.assertEqual(heuristics.shannon_entropy(b"aaaa"), 0.0)
        self.assertAlmostEqual(heuristics.shannon_entropy(bytes(range(256))), 8.0)


if __name__ == "__main__":
    unittest.main()
