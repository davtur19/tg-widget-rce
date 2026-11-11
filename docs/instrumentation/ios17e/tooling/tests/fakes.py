"""Host-only fakes: no device, no network."""
from __future__ import annotations

import os
from pathlib import Path

from i17e_runner.botapi import BotApiError, DeleteOutcome, SendOutcome
from i17e_runner.device import DeviceCheck, LaunchHandle
from i17e_runner.ocr import OcrLine, OcrResult
from i17e_runner.proc import CmdResult

FAKE_UDID = "FAKE-UDID-0001"
FAKE_CHAT = "12345"
FAKE_APPGROUP = "00000000-0000-0000-0000-000000000000"
FAKE_TOKEN = "FAKE_TOKEN_FOR_TESTS"


class FakeProc:
    def __init__(self):
        self.pid = 4242
        self.returncode = None
        self.terminated = False
        self.killed = False

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = 0

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self, timeout=None):
        return self.returncode


class FakeDevice:
    def __init__(self, target, *, check=None):
        self.target = target
        self.check_result = check or DeviceCheck(
            model=target.model, os_version=target.os_version, build=target.build,
            udid=FAKE_UDID, name="Fake iPhone", connection="USB",
            bundle_id=target.bundle_id, app_version=target.app_version,
            app_build=target.app_build, app_checked=True,
        )
        self.launch_handles: list[LaunchHandle] = []
        self.screenshot_paths: list[str] = []
        self.backup_calls: list[dict] = []
        self.recover_calls: list[list] = []
        self.taps: list[tuple] = []
        self.drags: list[tuple] = []
        self.proof_file = True
        self.frida = []

    def ensure_connected(self, script=None, **kwargs):
        return self.check_result

    def check(self, **kwargs):
        return self.check_result

    def launch_command(self, *, kill_existing=True):
        return ["pymobiledevice3", "developer", "core-device",
                "launch-application", self.target.bundle_id, "--console", "--userspace"]

    def launch_console(self, log_path, *, kill_existing=True, wait=0.0, sleep=None):
        path = Path(log_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as handle:
            handle.write("fake console start\n")
        proc = FakeProc()
        handle = LaunchHandle(proc=proc, log_path=path, offset=0,
                              cmd=self.launch_command(kill_existing=kill_existing))
        self.launch_handles.append(handle)
        return handle

    def screenshot(self, path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 64)
        self.screenshot_paths.append(str(path))
        return CmdResult(cmd=["screenshot", str(path)], returncode=0, stdout="saved")

    def recover(self, script, *, attempts=None, timeout=180.0):
        self.recover_calls.append([script, attempts])
        return CmdResult(cmd=["usb_recover"], returncode=0, stdout="RECOVERED\n")

    def tap(self, x, y):
        self.taps.append((x, y))
        return CmdResult(cmd=["tap", str(x), str(y)], returncode=0)

    def drag(self, x1, y1, x2, y2):
        self.drags.append((x1, y1, x2, y2))
        return CmdResult(cmd=["drag"], returncode=0)

    def run_backup(self, backup_dir, regex, *, legacy=False, timeout=120.0):
        backup = Path(backup_dir)
        self.backup_calls.append({"dir": str(backup), "regex": regex,
                                  "legacy": legacy, "timeout": timeout})
        backup.mkdir(parents=True, exist_ok=True)
        if self.proof_file:
            folder = backup / FAKE_APPGROUP
            folder.mkdir(parents=True, exist_ok=True)
            (folder / "rce.txt").write_bytes(b"RCE_OK\n")
            (folder / "spdb").write_bytes(b"SQLite format 3\x00" + b"\x00" * 32)
        command = ["pymobiledevice3", "backup2", "backup", str(backup),
                   "--only-regex", regex]
        return CmdResult(cmd=command, returncode=0, stdout="backup done")

    def frida_pids(self):
        return list(self.frida)

    def console_pids(self):
        return []

    def kill_pids(self, pids, sig=None):
        return {"killed": list(pids), "failed": []}


class FakeBot:
    def __init__(self, *, start_id=5000):
        self.next_id = start_id
        self.sent: list[dict] = []
        self.deleted: list[int] = []
        self.absent: set[int] = set()
        self.fail: set[int] = set()
        self.log_path = None
        self.marker = "RESULT SS2 HIT=545/585 LEN=327744\n"
        self.safe = "https://api.telegram.org/beta/bot<BOT_TOKEN>/sendWidget"

    def safe_endpoint(self, method):
        return "https://api.telegram.org/beta/bot<BOT_TOKEN>/%s" % method

    def send_widget(self, chat_id, html, **kwargs):
        self.next_id += 1
        self.sent.append({"chat_id": str(chat_id), "html": html, **kwargs,
                          "message_id": self.next_id})
        if self.log_path and self.marker:
            with open(self.log_path, "a", encoding="utf-8") as handle:
                handle.write(self.marker)
        return SendOutcome(message_id=self.next_id, widget_id="widget-1")

    def delete_message(self, chat_id, message_id):
        if message_id in self.fail:
            raise BotApiError("deleteMessage", "Bad Request: message can't be deleted")
        if message_id in self.absent:
            return DeleteOutcome(message_id, "absent", "message to delete not found")
        self.deleted.append(message_id)
        return DeleteOutcome(message_id, "deleted")


class FakeOcr:
    def __init__(self, texts=None):
        self.available = True
        self.error = None
        self.texts = texts or {}
        self.read_paths: list[str] = []

    def read(self, path):
        self.read_paths.append(str(path))
        text = self.texts.get(os.path.basename(str(path)), "")
        lines = [OcrLine(text=line, y=float(index))
                 for index, line in enumerate(text.splitlines()) if line.strip()]
        return OcrResult(available=True, path=str(path), lines=lines)


class FailingOcr:
    available = False
    error = "rapidocr_onnxruntime is not installed"

    def read(self, path):
        return OcrResult(available=False, path=str(path), error=self.error)
