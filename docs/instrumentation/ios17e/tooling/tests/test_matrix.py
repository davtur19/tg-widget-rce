import json
import os
import tempfile
import unittest

from i17e_runner.config import RunPaths
from i17e_runner.matrix import MatrixRunner, load_matrix
from i17e_runner.model import AttemptResult
from i17e_runner.redact import null_redactor
from i17e_runner.report import Reporter


class StubRunner:
    def __init__(self, results):
        self.results = list(results)
        self.calls = []

    def run(self, spec, *, occurrence=1, extra_delete_ids=()):
        self.calls.append((spec.label, occurrence))
        state = self.results.pop(0) if self.results else {}
        result = AttemptResult(label=spec.label, index=occurrence)
        result.finish(status=state.get("status", "pass"),
                      reason=state.get("reason", "marker"),
                      success=state.get("status") == "pass")
        result.app = {"state": state.get("app", "alive")}
        result.marker = {"found": state.get("marker", True)}
        result.proof = {"proof_ok": state.get("proof", False)}
        result.payload = {"message_id": state.get("mid")}
        return result


class MatrixTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.paths = RunPaths.create(os.path.join(self.tmp.name, "out"),
                                     os.path.join(self.tmp.name, "state"))
        self.reporter = Reporter(self.paths, null_redactor())

    def tearDown(self):
        self.tmp.cleanup()

    def write_spec(self, data):
        path = os.path.join(self.tmp.name, "matrix.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        return path

    def test_expand_count_and_placeholder(self):
        path = self.write_spec({
            "name": "m",
            "attempts": [{"label": "K3", "payload": "<APPGROUP>.html", "count": 3}],
        })
        spec = load_matrix(path, appgroup="APP", payload_root="/payloads")
        self.assertEqual(len(spec.expand()), 3)
        self.assertTrue(spec.attempts[0].payload.startswith("/payloads/"))
        self.assertEqual(spec.attempts[0].payload,
                         "/payloads/APP.html")

    def test_placeholder_can_stay_unresolved_for_plan(self):
        path = self.write_spec({
            "name": "m",
            "attempts": [{"label": "S", "payload": "a.html", "count": 1,
                          "backup_regex": "<APPGROUP>.*rce.txt|.*spdb"}],
        })
        spec = load_matrix(path, allow_unresolved=True)
        self.assertEqual(spec.attempts[0].backup_regex,
                         "<APPGROUP>.*rce.txt|.*spdb")
        with self.assertRaises(Exception):
            load_matrix(path)

    def test_gate_skips_label(self):
        path = self.write_spec({
            "name": "m",
            "attempts": [
                {"label": "K3", "payload": "a.html", "count": 2},
                {"label": "K4", "payload": "a.html", "count": 2,
                 "gate": {"label": "K3", "min_passed": 2}},
            ],
        })
        spec = load_matrix(path)
        runner = StubRunner([{"status": "pass"}, {"status": "fail"}])
        matrix = MatrixRunner(spec, runner, self.reporter, log=lambda *_: None,
                              sleep=lambda _: None)
        summary = matrix.run()
        self.assertEqual([call[0] for call in runner.calls], ["K3", "K3"])
        self.assertEqual(len(summary.skipped), 2)
        self.assertIn("gate K3", summary.skipped[0]["reason"])

    def test_consecutive_deaths_stop_label(self):
        path = self.write_spec({
            "name": "m",
            "attempts": [{"label": "K3", "payload": "a.html", "count": 4,
                          "stop_after_consecutive_deaths": 2}],
        })
        spec = load_matrix(path)
        runner = StubRunner([
            {"status": "fail", "reason": "app_dead_no_marker", "app": "dead",
             "marker": False},
            {"status": "fail", "reason": "app_dead_no_marker", "app": "dead",
             "marker": False},
            {"status": "pass"},
        ])
        matrix = MatrixRunner(spec, runner, self.reporter, log=lambda *_: None,
                              sleep=lambda _: None)
        summary = matrix.run()
        self.assertEqual(len(runner.calls), 2)
        self.assertEqual(len(summary.skipped), 2)
        self.assertTrue(any("consecutive" in item["reason"]
                            for item in summary.stopped))
        label = summary.labels[0]
        self.assertEqual(label["n"], 2)
        self.assertEqual(label["app_deaths"], 2)

    def test_invalid_stops_matrix(self):
        path = self.write_spec({
            "name": "m",
            "attempts": [{"label": "K3", "payload": "a.html", "count": 2}],
        })
        spec = load_matrix(path)
        runner = StubRunner([{"status": "invalid", "reason": "wrong_device"}])
        matrix = MatrixRunner(spec, runner, self.reporter, log=lambda *_: None,
                              sleep=lambda _: None)
        summary = matrix.run()
        self.assertEqual(len(runner.calls), 1)
        self.assertEqual(summary.counts["invalid"], 1)
        self.assertEqual(len(summary.skipped), 1)

    def test_counts_and_rate(self):
        path = self.write_spec({
            "name": "m",
            "attempts": [{"label": "K3", "payload": "a.html", "count": 4}],
        })
        spec = load_matrix(path)
        runner = StubRunner([{"status": "pass"}, {"status": "pass"},
                             {"status": "pass"}, {"status": "fail"}])
        matrix = MatrixRunner(spec, runner, self.reporter, log=lambda *_: None,
                              sleep=lambda _: None)
        summary = matrix.run()
        self.assertEqual(summary.counts["passed"], 3)
        self.assertEqual(summary.counts["failed"], 1)
        self.assertAlmostEqual(summary.labels[0]["cp_lower_95_one_sided"],
                               0.25, places=2)

    def test_dry_run_plans_every_attempt(self):
        path = self.write_spec({
            "name": "m",
            "attempts": [{"label": "K3", "payload": "a.html", "count": 3}],
        })
        spec = load_matrix(path)

        class PlanRunner:
            def __init__(self):
                self.calls = []

            def run(self, spec, *, occurrence=1, extra_delete_ids=()):
                self.calls.append((spec.label, occurrence))
                result = AttemptResult(label=spec.label, index=occurrence)
                result.verdict = {"status": "plan", "reason": "dry_run",
                                  "success": None}
                return result

        runner = PlanRunner()
        matrix = MatrixRunner(spec, runner, self.reporter, log=lambda *_: None,
                              sleep=lambda _: None, dry_run=True)
        summary = matrix.run()
        self.assertEqual(len(runner.calls), 3)
        self.assertEqual(summary.counts["planned"], 3)
        self.assertEqual(summary.counts["failed"], 0)


if __name__ == "__main__":
    unittest.main()
