import json
import os
import tempfile
import unittest

from i17e_runner.config import Target
from i17e_runner.device import (
    DeviceManager,
    normalize_version,
    parse_app_query,
    parse_usbmux_list,
    version_matches,
)
from i17e_runner.errors import ConfigError, DeviceMismatch, UsbRecoveryError
from i17e_runner.proc import CmdResult

from tests.fakes import FAKE_UDID, FakeProc


DEVICE = {
    "Identifier": FAKE_UDID,
    "UniqueDeviceID": FAKE_UDID,
    "DeviceName": "Fake iPhone",
    "ProductType": "iPhone18,5",
    "ProductVersion": "27.0",
    "BuildVersion": "24A437",
    "ConnectionType": "USB",
}

APP = {
    "ph.telegra.Telegraph": {
        "CFBundleIdentifier": "ph.telegra.Telegraph",
        "CFBundleShortVersionString": "13.2",
        "CFBundleVersion": "36535",
    }
}


class CannedCmd:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def run(self, cmd, timeout=30.0, check=False, env=None, cwd=None, stdin=None):
        self.calls.append(list(cmd))
        joined = " ".join(str(part) for part in cmd)
        for needle, response in self.responses:
            if needle in joined:
                if callable(response):
                    response = response(cmd)
                if isinstance(response, CmdResult):
                    return response
                return CmdResult(cmd=list(cmd), returncode=0, stdout=response)
        return CmdResult(cmd=list(cmd), returncode=0, stdout="")

    def popen(self, cmd, stdout, env=None, cwd=None):
        return FakeProc()

    def pgrep(self, pattern, timeout=5.0):
        return []


class DeviceParseTests(unittest.TestCase):
    def test_parse_usbmux_json(self):
        devices = parse_usbmux_list(json.dumps([DEVICE]))
        self.assertEqual(devices[0]["ProductType"], "iPhone18,5")

    def test_parse_usbmux_with_log_noise(self):
        devices = parse_usbmux_list("INFO noise\n" + json.dumps([DEVICE]) + "\n")
        self.assertEqual(len(devices), 1)

    def test_parse_usbmux_empty(self):
        self.assertEqual(parse_usbmux_list("[]"), [])

    def test_parse_usbmux_invalid(self):
        with self.assertRaises(ConfigError):
            parse_usbmux_list("not json")

    def test_parse_app_query_keyed_and_flat(self):
        self.assertEqual(parse_app_query(json.dumps(APP), "ph.telegra.Telegraph")[
            "CFBundleVersion"], "36535")
        self.assertEqual(parse_app_query(json.dumps(APP["ph.telegra.Telegraph"]),
                                         "ph.telegra.Telegraph")["CFBundleVersion"],
                         "36535")

    def test_version_normalization(self):
        self.assertTrue(version_matches("13.2", "13.2"))
        self.assertTrue(version_matches("13.2.0", "13.2"))
        self.assertFalse(version_matches("13.1", "13.2"))
        self.assertEqual(normalize_version("13.2.0"), (13, 2))


class DeviceCheckTests(unittest.TestCase):
    def manager(self, devices=None, app=None):
        responses = [
            ("usbmux list", json.dumps(devices if devices is not None else [DEVICE])),
            ("apps query", json.dumps(app or APP)),
        ]
        return DeviceManager(CannedCmd(responses), p3="p3", target=Target(),
                             udid=FAKE_UDID)

    def test_check_ok(self):
        check = self.manager().check()
        self.assertEqual(check.model, "iPhone18,5")
        self.assertEqual(check.app_build, "36535")
        self.assertTrue(check.app_checked)

    def test_wrong_model_stops(self):
        wrong = dict(DEVICE, ProductType="iPhone15,2")
        with self.assertRaises(DeviceMismatch) as ctx:
            self.manager(devices=[wrong]).check()
        self.assertIn("WRONG DEVICE", str(ctx.exception))

    def test_wrong_udid_stops(self):
        wrong = dict(DEVICE, Identifier="OTHER", UniqueDeviceID="OTHER")
        with self.assertRaises(DeviceMismatch) as ctx:
            self.manager(devices=[wrong]).check()
        self.assertIn("wrong device", str(ctx.exception).lower())

    def test_wrong_os_build_stops(self):
        wrong = dict(DEVICE, ProductVersion="27.1")
        with self.assertRaises(DeviceMismatch):
            self.manager(devices=[wrong]).check()

    def test_wrong_app_stops(self):
        app = {"ph.telegra.Telegraph": {
            "CFBundleIdentifier": "ph.telegra.Telegraph",
            "CFBundleShortVersionString": "13.1",
            "CFBundleVersion": "36000",
        }}
        with self.assertRaises(DeviceMismatch) as ctx:
            self.manager(app=app).check()
        self.assertIn("WRONG APP", str(ctx.exception))

    def test_multiple_devices_without_udid(self):
        manager = self.manager(devices=[DEVICE, dict(DEVICE, Identifier="OTHER",
                                                     UniqueDeviceID="OTHER")])
        manager.udid = None
        with self.assertRaises(DeviceMismatch):
            manager.check()

    def test_ensure_connected_recovers(self):
        calls = {"count": 0}

        def usbmux(cmd):
            calls["count"] += 1
            if calls["count"] == 1:
                return "[]"
            return json.dumps([DEVICE])

        responses = [
            ("usbmux list", usbmux),
            ("apps query", json.dumps(APP)),
            ("usb_recover", "RECOVERED\n"),
        ]
        manager = DeviceManager(CannedCmd(responses), p3="p3", target=Target(),
                                udid=FAKE_UDID)
        check = manager.ensure_connected("/fake/usb_recover.py", recovery_attempts=1,
                                         sleep=lambda _: None)
        self.assertEqual(check.model, "iPhone18,5")

    def test_ensure_connected_gives_up(self):
        manager = DeviceManager(CannedCmd([("usbmux list", "[]"),
                                           ("usb_recover", "FAILED\n")]),
                                p3="p3", target=Target(), udid=FAKE_UDID)
        with self.assertRaises(UsbRecoveryError):
            manager.ensure_connected("/fake/usb_recover.py", recovery_attempts=1,
                                     sleep=lambda _: None)

    def test_launch_command_has_console_userspace(self):
        cmd = self.manager().launch_command()
        self.assertIn("--console", cmd)
        self.assertIn("--userspace", cmd)
        self.assertIn("ph.telegra.Telegraph", cmd)

    def test_backup_command_modern_and_legacy(self):
        manager = self.manager()
        modern = manager.backup_command("/tmp/backup", "APP.*rce.txt|.*spdb")
        self.assertEqual(modern[:4], ["p3", "backup2", "backup", "/tmp/backup"])
        self.assertEqual(modern[-2:], ["--only-regex", "APP.*rce.txt|.*spdb"])
        legacy = manager.backup_command("/tmp/backup", "APP.*rce.txt", legacy=True)
        self.assertEqual(legacy, ["p3", "backup2", "--only-regex", "APP.*rce.txt"])

    def test_recover_invokes_documented_script_with_udid(self):
        canned = CannedCmd([("usb_recover", "RECOVERED\n")])
        manager = DeviceManager(canned, p3="p3", target=Target(), udid=FAKE_UDID)
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as handle:
            script = handle.name
        try:
            result = manager.recover(script, attempts=2)
        finally:
            os.unlink(script)
        self.assertTrue(result.ok)
        cmd = canned.calls[0]
        self.assertIn(script, cmd)
        self.assertIn("--udid", cmd)
        self.assertEqual(cmd[cmd.index("--udid") + 1], FAKE_UDID)
        self.assertEqual(cmd[cmd.index("--pymobiledevice3") + 1], "p3")
        self.assertEqual(cmd[cmd.index("--attempts") + 1], "2")


if __name__ == "__main__":
    unittest.main()
