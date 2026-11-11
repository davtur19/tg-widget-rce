import os
import tempfile
import unittest

from i17e_runner.clean import ChatCleaner, parse_id_list, read_id_file
from i17e_runner.errors import ChatCleanupError, ConfigError
from i17e_runner.ledger import ChatLedger

from tests.fakes import FAKE_CHAT, FakeBot, FakeOcr


class CleanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ledger = ChatLedger.load(os.path.join(self.tmp.name, "ledger.json"))
        self.bot = FakeBot()
        self.cleaner = ChatCleaner(self.bot, self.ledger, FakeOcr())

    def tearDown(self):
        self.tmp.cleanup()

    def test_deletes_ledger_and_extra_ids(self):
        self.ledger.add_payload(FAKE_CHAT, 10)
        self.ledger.add_anchor(FAKE_CHAT, 11)
        result = self.cleaner.clean(FAKE_CHAT, extra_ids=[12])
        self.assertTrue(result.clean)
        self.assertEqual(result.removed_ids, [10, 11, 12])
        self.assertEqual(sorted(self.bot.deleted), [10, 11, 12])
        self.assertEqual(self.ledger.pending_ids(FAKE_CHAT), [])

    def test_absent_counts_as_removed(self):
        self.ledger.add_payload(FAKE_CHAT, 20)
        self.bot.absent.add(20)
        result = self.cleaner.clean(FAKE_CHAT)
        self.assertTrue(result.clean)
        self.assertEqual(result.absent_ids, [20])
        self.assertEqual(self.ledger.pending_ids(FAKE_CHAT), [])

    def test_hard_failure_keeps_ledger_and_reports(self):
        self.ledger.add_payload(FAKE_CHAT, 30)
        self.ledger.add_payload(FAKE_CHAT, 31)
        self.bot.fail.add(30)
        result = self.cleaner.clean(FAKE_CHAT)
        self.assertFalse(result.clean)
        self.assertEqual([item["message_id"] for item in result.failed], [30])
        self.assertEqual(self.ledger.pending_ids(FAKE_CHAT), [30])
        with self.assertRaises(ChatCleanupError):
            self.cleaner.require_clean(result)

    def test_screenshot_marker_marks_dirty(self):
        self.ledger.add_payload(FAKE_CHAT, 40)
        ocr = FakeOcr({"chat.png": "old bubble\nRESULT SS2 HIT=545/585\n"})
        cleaner = ChatCleaner(self.bot, self.ledger, ocr)
        result = cleaner.clean(FAKE_CHAT, screenshot="chat.png",
                               verify_screenshot=True)
        self.assertFalse(result.clean)
        self.assertTrue(result.screenshot_markers)

    def test_dry_run_does_not_call_bot(self):
        self.ledger.add_payload(FAKE_CHAT, 50)
        result = self.cleaner.clean(FAKE_CHAT, extra_ids=[51], dry_run=True)
        self.assertTrue(result.planned)
        self.assertEqual(result.requested_ids, [50, 51])
        self.assertEqual(self.bot.deleted, [])

    def test_parse_id_list(self):
        self.assertEqual(parse_id_list(["1,2", "3;4", " 5 "]), [1, 2, 3, 4, 5])
        with self.assertRaises(ConfigError):
            parse_id_list(["x"])

    def test_read_id_file(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as handle:
            handle.write("10, 11\n12\n")
            path = handle.name
        try:
            self.assertEqual(read_id_file(path), [10, 11, 12])
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
