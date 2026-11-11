import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from i17e_runner.markers import extract_markers, looks_like_widget_marker, matches_success
from i17e_runner.proof import collect_backup_matches


class MarkerTests(unittest.TestCase):
    def test_stage_a_fields(self):
        text = "noise\nRESULT SS2 R=0 M=0 HIT=545/585 LEN=327744 PH=12 NT=0\n"
        markers = extract_markers(text)
        self.assertTrue(markers.found)
        self.assertEqual(markers.fields["hit"], "545/585")
        self.assertEqual(markers.fields["len"], "327744")
        self.assertEqual(markers.fields["ph"], "12")
        self.assertIn("result", markers.tokens)
        self.assertIsNone(markers.guard)

    def test_guard_detected(self):
        markers = extract_markers("U_NF\nNO_RT\n")
        self.assertEqual(markers.guard, "u_nf")

    def test_success_matching(self):
        self.assertTrue(matches_success("HIT=545/585", [r"HIT="]))
        self.assertTrue(matches_success("RESULT SS2", [r"RESULT\b"]))
        self.assertFalse(matches_success("blank bubble", [r"HIT="]))

    def test_widget_marker_scan_excludes_plain_ok(self):
        self.assertEqual(looks_like_widget_marker("just OK\n"), [])
        found = looks_like_widget_marker("HIT=545/585\n")
        self.assertEqual(found, ["HIT=545/585"])


class ProofTests(unittest.TestCase):
    def test_collect_from_manifest_db(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            device_folder = root / "FAKE-DEVICE-0001"
            device_folder.mkdir()
            file_id = "ab" * 20
            (device_folder / file_id).write_bytes(b"RCE_OK\n")
            database = sqlite3.connect(device_folder / "Manifest.db")
            database.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT)")
            database.execute("INSERT INTO Files VALUES (?, ?, ?)",
                             (file_id, "AppDomainGroup-group.ph.telegra.Telegraph",
                              "rce.txt"))
            database.commit()
            database.close()
            out = root / "matches"
            matches = collect_backup_matches(root, r".*rce\.txt$", out_dir=out)
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0].kind, "rce")
            self.assertTrue(matches[0].rce_ok)
            self.assertTrue(matches[0].copied_path)
            self.assertEqual(matches[0].text, "RCE_OK\n")

    def test_collect_from_plain_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            folder = root / "00000000-0000-0000-0000-000000000000"
            folder.mkdir()
            (folder / "rce.txt").write_bytes(b"RCE_OK\n")
            (folder / "spdb").write_bytes(b"SQLite format 3\x00")
            matches = collect_backup_matches(
                root, r"00000000.*rce\.txt|.*spdb"
            )
            kinds = sorted(match.kind for match in matches)
            self.assertEqual(kinds, ["rce", "spdb"])
            self.assertTrue(any(match.rce_ok for match in matches))
            self.assertTrue(any(match.spdb_ok for match in matches))


if __name__ == "__main__":
    unittest.main()
