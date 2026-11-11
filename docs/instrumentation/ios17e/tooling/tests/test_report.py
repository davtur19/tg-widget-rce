import json
import os
import tempfile
import unittest

from i17e_runner.config import RunPaths
from i17e_runner.model import AttemptResult, MatrixSummary
from i17e_runner.redact import Redactor, null_redactor
from i17e_runner.report import Reporter
from i17e_runner.stats import clopper_pearson_lower


class RedactTests(unittest.TestCase):
    def test_nested_replacement(self):
        redactor = (Redactor()
                    .add("SECRET_TOKEN", "<BOT_TOKEN>")
                    .add("FAKE-UDID-0001", "<UDID>")
                    .add("12345", "<CHAT_ID>")
                    .add("00000000-0000-0000-0000-000000000000", "<APPGROUP>"))
        data = {
            "token": "SECRET_TOKEN",
            "udid": "FAKE-UDID-0001",
            "chat": 12345,
            "path": "/x/SECRET_TOKEN/FAKE-UDID-0001",
            "nested": ["00000000-0000-0000-0000-000000000000", 42],
        }
        out = redactor.obj(data)
        self.assertEqual(out["token"], "<BOT_TOKEN>")
        self.assertEqual(out["udid"], "<UDID>")
        self.assertEqual(out["chat"], "<CHAT_ID>")
        self.assertEqual(out["path"], "/x/<BOT_TOKEN>/<UDID>")
        self.assertEqual(out["nested"], ["<APPGROUP>", 42])

    def test_null_redactor(self):
        redactor = null_redactor()
        self.assertEqual(redactor.obj({"a": "SECRET"}), {"a": "SECRET"})
        self.assertEqual(redactor.text("SECRET"), "SECRET")


class ReportTests(unittest.TestCase):
    def test_write_attempt_json_md_and_jsonl(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = RunPaths.create(os.path.join(tmp, "out"),
                                    os.path.join(tmp, "state"))
            redactor = Redactor().add("FAKE-UDID-0001", "<UDID>")
            reporter = Reporter(paths, redactor)
            result = AttemptResult(label="K3", index=2)
            result.payload = {"message_id": 5001, "sha256": "abc"}
            result.device = {"udid": "FAKE-UDID-0001"}
            result.app = {"state": "alive"}
            result.finish(status="pass", reason="marker", success=True)
            info = reporter.write_attempt(result)
            with open(info["json"], encoding="utf-8") as handle:
                data = json.load(handle)
            self.assertEqual(data["attempt"]["label"], "K3")
            self.assertEqual(data["device"]["udid"], "<UDID>")
            self.assertEqual(data["verdict"]["status"], "pass")
            with open(info["markdown"], encoding="utf-8") as handle:
                markdown = handle.read()
            self.assertIn("# Attempt K3 #2", markdown)
            self.assertIn("**pass**", markdown)
            with open(info["results_jsonl"], encoding="utf-8") as handle:
                lines = [line for line in handle if line.strip()]
            self.assertEqual(len(lines), 1)

    def test_write_matrix(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = RunPaths.create(os.path.join(tmp, "out"),
                                    os.path.join(tmp, "state"))
            reporter = Reporter(paths, null_redactor())
            summary = MatrixSummary(name="m")
            summary.labels = [{"label": "K3", "n": 2, "passed": 2, "failed": 0,
                               "invalid": 0, "app_deaths": 0, "markers": 2,
                               "proofs": 0, "cp_lower_95_one_sided": 0.25}]
            summary.counts = {"attempts": 2, "passed": 2, "failed": 0,
                              "invalid": 0}
            info = reporter.write_matrix(summary)
            with open(info["markdown"], encoding="utf-8") as handle:
                text = handle.read()
            self.assertIn("# Matrix m", text)
            self.assertIn("| K3 | 2 | 2 | 0 | 0 |", text)


class StatsTests(unittest.TestCase):
    def test_zero_success(self):
        self.assertEqual(clopper_pearson_lower(0, 10), 0.0)

    def test_all_success_matches_rule_of_three_style(self):
        self.assertAlmostEqual(clopper_pearson_lower(10, 10), 0.7411, places=3)
        self.assertAlmostEqual(clopper_pearson_lower(30, 30), 0.9048, places=3)

    def test_partial(self):
        value = clopper_pearson_lower(9, 10)
        self.assertGreater(value, 0.55)
        self.assertLess(value, 0.75)


if __name__ == "__main__":
    unittest.main()
