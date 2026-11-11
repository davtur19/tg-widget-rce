import json
import os
import tempfile
import unittest

from i17e_runner.ledger import ChatLedger

from tests.fakes import FAKE_CHAT


class LedgerTests(unittest.TestCase):
    def test_roundtrip_and_pending(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "state", "ledger.json")
            ledger = ChatLedger.load(path)
            ledger.add_payload(FAKE_CHAT, 10, "sha")
            ledger.add_anchor(FAKE_CHAT, 11)
            ledger.save()

            loaded = ChatLedger.load(path)
            self.assertEqual(loaded.pending_ids(FAKE_CHAT), [10, 11])
            self.assertEqual(loaded.known_max_message_id(FAKE_CHAT), 11)

            loaded.mark_deleted(FAKE_CHAT, 10)
            loaded.mark_deleted(FAKE_CHAT, 11)
            loaded.save()
            again = ChatLedger.load(path)
            self.assertEqual(again.pending_ids(FAKE_CHAT), [])
            self.assertEqual(again.entry(FAKE_CHAT).deleted_ids, [10, 11])

    def test_atomic_file_is_valid_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "ledger.json")
            ledger = ChatLedger.load(path)
            ledger.add_payload("1", 5)
            ledger.save()
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
            self.assertEqual(data["schema"], "i17e-runner/ledger/1")
            self.assertEqual(data["chats"]["1"]["payload_ids"], [5])

    def test_chat_isolation(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = ChatLedger.load(os.path.join(tmp, "ledger.json"))
            ledger.add_payload("a", 1)
            ledger.add_payload("b", 2)
            self.assertEqual(ledger.pending_ids("a"), [1])
            self.assertEqual(ledger.pending_ids("b"), [2])


if __name__ == "__main__":
    unittest.main()
