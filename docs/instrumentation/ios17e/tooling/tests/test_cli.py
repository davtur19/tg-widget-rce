import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
PAYLOAD = os.path.join(REPO, "lab", "ios17e", "reliability_20261109",
                       "fix_v10", "out", "v14_stage_a.html")


def run_cli(*args, env=None):
    environment = dict(os.environ)
    environment.pop("BOT_TOKEN", None)
    environment.pop("I17E_UDID", None)
    environment.pop("I17E_CHAT_ID", None)
    if env:
        environment.update(env)
    return subprocess.run(
        [sys.executable, "-m", "i17e_runner", *args],
        cwd=HERE, capture_output=True, text=True, timeout=120, env=environment,
    )


class CliTests(unittest.TestCase):
    def make_fake_p3(self, tmp, *, model="iPhone18,5", version="27.0",
                     build="24A437", app_version="13.2", app_build="36535"):
        path = os.path.join(tmp, "fake_p3.py")
        device = {
            "Identifier": "FAKE-UDID-0001", "UniqueDeviceID": "FAKE-UDID-0001",
            "DeviceName": "Fake iPhone", "ProductType": model,
            "ProductVersion": version, "BuildVersion": build,
            "ConnectionType": "USB",
        }
        app = {"ph.telegra.Telegraph": {
            "CFBundleIdentifier": "ph.telegra.Telegraph",
            "CFBundleShortVersionString": app_version,
            "CFBundleVersion": app_build,
        }}
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(
                "#!/usr/bin/env python3\n"
                "import json, sys\n"
                "DEVICE = json.loads(%r)\n"
                "APP = json.loads(%r)\n"
                "args = sys.argv[1:]\n"
                "if 'usbmux' in args:\n"
                "    print(json.dumps([DEVICE]))\n"
                "elif 'apps' in args:\n"
                "    print(json.dumps(APP))\n"
                "else:\n"
                "    print('{}')\n"
                % (json.dumps(device), json.dumps(app))
            )
        os.chmod(path, 0o755)
        return path

    def test_doctor_with_host_mock(self):
        with tempfile.TemporaryDirectory() as tmp:
            p3 = self.make_fake_p3(tmp)
            result = run_cli("doctor", "--p3", p3, "--udid", "FAKE-UDID-0001")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("iPhone18,5", result.stdout)
            self.assertIn("13.2", result.stdout)
            self.assertIn("36535", result.stdout)

    def test_doctor_wrong_model_exits_3(self):
        with tempfile.TemporaryDirectory() as tmp:
            p3 = self.make_fake_p3(tmp, model="iPhone15,2")
            result = run_cli("doctor", "--p3", p3, "--udid", "FAKE-UDID-0001")
            self.assertEqual(result.returncode, 3, result.stderr)
            self.assertIn("WRONG DEVICE", result.stderr)

    def test_doctor_wrong_app_exits_3(self):
        with tempfile.TemporaryDirectory() as tmp:
            p3 = self.make_fake_p3(tmp, app_version="13.1", app_build="36000")
            result = run_cli("doctor", "--p3", p3, "--udid", "FAKE-UDID-0001")
            self.assertEqual(result.returncode, 3, result.stderr)
            self.assertIn("WRONG APP", result.stderr)

    def test_help_and_version(self):
        result = run_cli("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("doctor", result.stdout)
        result = run_cli("--version")
        self.assertEqual(result.returncode, 0)
        self.assertIn("i17e_runner", result.stdout)

    def test_doctor_dry_run(self):
        result = run_cli("doctor", "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data["expected"]["model"], "iPhone18,5")
        self.assertEqual(data["expected"]["build"], "24A437")
        self.assertEqual(data["expected"]["app_build"], "36535")

    @unittest.skipUnless(os.path.isfile(PAYLOAD), "lab payload not present")
    def test_send_dry_run_validates_payload(self):
        result = run_cli("send", "--html", PAYLOAD, "--chat-id", "12345",
                         "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("8647 raw", result.stdout)
        self.assertIn("3660 zlib9", result.stdout)
        self.assertIn("bot<BOT_TOKEN>", result.stdout)
        self.assertNotIn("api.telegram.org/beta/bot1", result.stdout)

    @unittest.skipUnless(os.path.isfile(PAYLOAD), "lab payload not present")
    def test_run_dry_run_writes_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_cli(
                "run", "--html", PAYLOAD, "--chat-id", "12345", "--label", "K3",
                "--dry-run", "--out", os.path.join(tmp, "out"),
                "--state-dir", os.path.join(tmp, "state"),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(result.stdout)
            self.assertEqual(data["verdict"]["status"], "plan")
            self.assertTrue(os.path.isfile(data["extras"]["artifacts"]["json"]))
            with open(data["extras"]["artifacts"]["json"], encoding="utf-8") as handle:
                artifact = json.load(handle)
            self.assertEqual(artifact["chat"]["id"], "<CHAT_ID>")
            self.assertEqual(artifact["payload"]["sha256"],
                             "4906d6f990c443103f0ab398ce0aa1fe5b06700ae4deb4ca0dfda9a58fb1101a")

    def test_clean_dry_run_reads_ledger(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_cli(
                "clean", "--chat-id", "12345", "--payload-id", "5001",
                "--dry-run", "--out", os.path.join(tmp, "out"),
                "--state-dir", os.path.join(tmp, "state"),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(result.stdout)
            self.assertTrue(data["planned"])
            self.assertEqual(data["requested_ids"], [5001])

    def test_wrong_payload_size_exits_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "huge.html")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("A" * 40000)
            result = run_cli("send", "--html", path, "--chat-id", "12345",
                             "--dry-run")
            self.assertEqual(result.returncode, 2)
            self.assertIn("exceeds", result.stderr)


if __name__ == "__main__":
    unittest.main()
