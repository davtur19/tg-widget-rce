import json
import os
import tempfile
import unittest

from i17e_runner.clean import ChatCleaner
from i17e_runner.config import RunPaths, RuntimeConfig, Target
from i17e_runner.ledger import ChatLedger
from i17e_runner.model import AttemptSpec
from i17e_runner.redact import null_redactor
from i17e_runner.report import Reporter
from i17e_runner.runner import AttemptRunner

from tests.fakes import (
    FAKE_APPGROUP,
    FAKE_CHAT,
    FAKE_TOKEN,
    FAKE_UDID,
    FailingOcr,
    FakeBot,
    FakeDevice,
    FakeOcr,
    FakeProc,
)


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.payload = os.path.join(self.tmp.name, "payload.html")
        with open(self.payload, "w", encoding="utf-8") as handle:
            handle.write("<html><body>stage A</body></html>")

    def tearDown(self):
        self.tmp.cleanup()

    def make_cfg(self, **overrides):
        paths = RunPaths.create(os.path.join(self.tmp.name, "out"),
                                os.path.join(self.tmp.name, "state"))
        values = dict(
            target=Target(),
            udid=FAKE_UDID,
            appgroup=FAKE_APPGROUP,
            chat_id=FAKE_CHAT,
            token=FAKE_TOKEN,
            p3="p3",
            usb_recover="/fake/usb_recover.py",
            paths=paths,
            usb_attempts=1,
            device_timeout=5.0,
            command_timeout=5.0,
            launch_wait=0.0,
            shot_start=0.0,
            shot_count=1,
            shot_interval=0.0,
            shot_extra=(),
            screenshots=True,
            ocr_mode="off",
            ocr_max=1,
            backup=False,
            verbose=False,
        )
        values.update(overrides)
        return RuntimeConfig(**values)

    def make_runner(self, cfg, *, device=None, bot=None, ocr=None):
        ledger = ChatLedger.load(cfg.paths.state_dir / "ledger.json")
        bot = bot or FakeBot()
        device = device or FakeDevice(cfg.target)
        ocr = ocr or FailingOcr()
        cleaner = ChatCleaner(bot, ledger, ocr)
        reporter = Reporter(cfg.paths, null_redactor())
        runner = AttemptRunner(
            cfg, device=device, bot=bot, cleaner=cleaner, ocr=ocr,
            reporter=reporter, sleep=lambda _: None, log=lambda *_: None,
        )
        return runner, bot, ledger, device

    def test_full_attempt_pass_with_marker_and_cleanup(self):
        cfg = self.make_cfg()
        runner, bot, ledger, device = self.make_runner(cfg)
        ledger.add_payload(FAKE_CHAT, 4000, "old")
        ledger.save()
        bot.log_path = cfg.paths.log_dir / "K3_01_console.log"

        result = runner.run(AttemptSpec(label="K3", payload=self.payload,
                                        expect="marker",
                                        success_markers=["HIT="]))

        self.assertEqual(result.verdict["status"], "pass")
        self.assertEqual(result.verdict["reason"], "marker")
        self.assertEqual(len(bot.sent), 1)
        self.assertEqual(result.payload["message_id"], 5001)
        self.assertEqual(result.marker["fields"]["hit"], "545/585")
        self.assertIn("HIT=", result.logs["tail"])
        self.assertEqual(len(result.screenshots), 1)
        self.assertTrue(result.chat["clean_before_send"])
        self.assertTrue(result.chat["clean_after"])
        self.assertIn(4000, result.chat["deleted_ids"])
        self.assertIn(5001, result.chat["deleted_after"])
        self.assertTrue(result.chat["last_message_ok"])
        self.assertTrue(device.launch_handles[0].proc.terminated)
        self.assertTrue(result.processes["console_stop"]["terminated"])
        self.assertIn("frida_before", result.processes)
        self.assertEqual(ledger.pending_ids(FAKE_CHAT), [])
        with open(result.extras["artifacts"]["json"], encoding="utf-8") as handle:
            data = json.load(handle)
        self.assertEqual(data["verdict"]["status"], "pass")

    def test_post_launch_taps_open_the_chat(self):
        cfg = self.make_cfg(launch_taps=((90.0, 1919.0),), tap_delay=0.0)
        runner, bot, ledger, device = self.make_runner(cfg)
        bot.log_path = cfg.paths.log_dir / "K3_01_console.log"
        result = runner.run(AttemptSpec(label="K3", payload=self.payload,
                                        expect="marker",
                                        success_markers=["HIT="]))
        self.assertEqual(device.taps, [(90.0, 1919.0)])
        self.assertTrue(result.extras["input"]["taps"][0]["ok"])

    def test_ocr_marker_is_a_second_channel(self):
        cfg = self.make_cfg(ocr_mode="on")
        ocr = FakeOcr({"K3_01_s01.png": "RESULT SS2\nHIT=12/36\n"})
        runner, bot, ledger, device = self.make_runner(cfg, ocr=ocr)
        bot.marker = ""

        result = runner.run(AttemptSpec(label="K3", payload=self.payload,
                                        expect="marker",
                                        success_markers=["HIT="]))
        self.assertEqual(result.verdict["status"], "pass")
        self.assertEqual(result.marker["fields"]["hit"], "12/36")
        self.assertTrue(ocr.read_paths)

    def test_old_widget_marker_in_pre_send_screenshot_aborts(self):
        cfg = self.make_cfg(ocr_mode="on")
        ocr = FakeOcr({"pre_send.png": "old bubble\nRESULT SS2 HIT=545/585\n"})
        runner, bot, ledger, device = self.make_runner(cfg, ocr=ocr)

        result = runner.run(AttemptSpec(label="K3", payload=self.payload,
                                        expect="marker"))

        self.assertEqual(result.verdict["status"], "invalid")
        self.assertEqual(result.verdict["reason"], "chat_dirty")
        self.assertEqual(bot.sent, [])
        self.assertFalse(result.chat["clean_before_send"])

    def test_proof_file_passes_when_required(self):
        cfg = self.make_cfg(backup=True)
        runner, bot, ledger, device = self.make_runner(cfg)
        bot.log_path = cfg.paths.log_dir / "S_01_console.log"
        spec = AttemptSpec(
            label="S", payload=self.payload, expect="proof", require_proof=True,
            backup_regex=FAKE_APPGROUP + r".*rce\.txt|.*spdb",
        )
        result = runner.run(spec)
        self.assertEqual(result.verdict["status"], "pass")
        self.assertEqual(result.verdict["reason"], "proof")
        self.assertTrue(result.proof["rce_ok"])
        self.assertTrue(result.proof["spdb_ok"])
        self.assertEqual(len(result.proof["matches"]), 2)

    def test_proof_missing_fails_when_required(self):
        cfg = self.make_cfg(backup=True)
        device = FakeDevice(cfg.target)
        device.proof_file = False
        runner, bot, ledger, device = self.make_runner(cfg, device=device)
        bot.log_path = cfg.paths.log_dir / "S_01_console.log"
        spec = AttemptSpec(label="S", payload=self.payload, expect="proof",
                           require_proof=True, backup_regex=FAKE_APPGROUP + ".*rce.txt")
        result = runner.run(spec)
        self.assertEqual(result.verdict["status"], "fail")
        self.assertEqual(result.verdict["reason"], "proof_missing")

    def test_launch_failure_is_invalid(self):
        cfg = self.make_cfg()
        device = FakeDevice(cfg.target)

        def failing_launch(log_path, **kwargs):
            path = cfg.paths.log_dir / "K3_01_console.log"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("boom\n", encoding="utf-8")
            proc = FakeProc()
            proc.returncode = 1
            from i17e_runner.device import LaunchHandle
            return LaunchHandle(proc=proc, log_path=path, offset=0)

        device.launch_console = failing_launch
        runner, bot, ledger, device = self.make_runner(cfg, device=device)
        result = runner.run(AttemptSpec(label="K3", payload=self.payload))
        self.assertEqual(result.verdict["status"], "invalid")
        self.assertEqual(result.verdict["reason"], "launch_failed")
        self.assertEqual(bot.sent, [])

    def test_send_failure_is_invalid(self):
        cfg = self.make_cfg()
        bot = FakeBot()
        bot.send_widget = lambda *args, **kwargs: (_ for _ in ()).throw(
            __import__("i17e_runner.errors", fromlist=["BotApiError"]).BotApiError(
                "sendWidget", "chat not found"))
        runner, bot, ledger, device = self.make_runner(cfg, bot=bot)
        result = runner.run(AttemptSpec(label="K3", payload=self.payload))
        self.assertEqual(result.verdict["status"], "invalid")
        self.assertEqual(result.verdict["reason"], "send_failed")

    def test_dry_run_has_no_side_effects(self):
        cfg = self.make_cfg(dry_run=True)
        runner, bot, ledger, device = self.make_runner(cfg)
        ledger.add_payload(FAKE_CHAT, 777)
        ledger.save()
        result = runner.run(AttemptSpec(label="K3", payload=self.payload,
                                        expect="marker"))
        self.assertEqual(result.verdict["status"], "plan")
        self.assertEqual(bot.sent, [])
        self.assertEqual(device.launch_handles, [])
        self.assertEqual(result.chat["planned_delete_ids"], [777])
        self.assertEqual(ledger.pending_ids(FAKE_CHAT), [777])

    def test_guard_stops_verdict(self):
        cfg = self.make_cfg()
        runner, bot, ledger, device = self.make_runner(cfg)
        bot.log_path = cfg.paths.log_dir / "K3_01_console.log"
        bot.marker = "U_NF\n"
        result = runner.run(AttemptSpec(label="K3", payload=self.payload,
                                        expect="marker"))
        self.assertEqual(result.verdict["status"], "fail")
        self.assertEqual(result.verdict["reason"], "endgame_guard")

    def test_account_id_and_appgroup_in_log_are_redacted(self):
        cfg = self.make_cfg()
        ledger = ChatLedger.load(cfg.paths.state_dir / "ledger.json")
        bot = FakeBot()
        bot.log_path = cfg.paths.log_dir / "K3_01_console.log"
        bot.marker = ("account-219999999999999999 "
                      "11111111-2222-3333-4444-555555555555\nHIT=545/585\n")
        device = FakeDevice(cfg.target)
        from i17e_runner.redact import Redactor
        redactor = (Redactor()
                    .add(FAKE_UDID, "<UDID>")
                    .add(FAKE_CHAT, "<CHAT_ID>"))
        reporter = Reporter(cfg.paths, redactor)
        runner = AttemptRunner(
            cfg, device=device, bot=bot, cleaner=ChatCleaner(bot, ledger, FailingOcr()),
            ocr=FailingOcr(), reporter=reporter, sleep=lambda _: None,
            log=lambda *_: None,
        )
        result = runner.run(AttemptSpec(label="K3", payload=self.payload,
                                        expect="marker",
                                        success_markers=["HIT="]))
        with open(result.extras["artifacts"]["json"], encoding="utf-8") as handle:
            text = handle.read()
        self.assertIn("<ACCOUNT_ID>", text)
        self.assertIn("<APPGROUP>", text)
        self.assertNotIn("219999999999999999", text)
        self.assertNotIn("11111111-2222-3333-4444-555555555555", text)

    def test_dead_console_records_dead(self):
        cfg = self.make_cfg()
        runner, bot, ledger, device = self.make_runner(cfg)
        bot.log_path = cfg.paths.log_dir / "K3_01_console.log"
        bot.marker = ""
        # Make the fake console exit between send and state check.
        original_send = bot.send_widget

        def send_and_exit(*args, **kwargs):
            outcome = original_send(*args, **kwargs)
            device.launch_handles[0].proc.returncode = -6
            return outcome

        bot.send_widget = send_and_exit
        result = runner.run(AttemptSpec(label="K3", payload=self.payload,
                                        expect="marker"))
        self.assertEqual(result.app["state"], "dead")
        self.assertEqual(result.verdict["reason"], "app_dead_no_marker")


if __name__ == "__main__":
    unittest.main()
