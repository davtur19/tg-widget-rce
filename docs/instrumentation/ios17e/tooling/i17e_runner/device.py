"""pymobiledevice3 / CoreDevice operations.

Only host-side commands are issued.  The device is targeted through
``PYMOBILEDEVICE3_UDID`` so that a second attached phone can never be picked by
accident.  Model, OS build and installed app version are verified before any
run; a mismatch is a hard stop.
"""
from __future__ import annotations

import json
import os
import plistlib
import re
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from .errors import (
    CommandFailed,
    CommandTimeout,
    ConfigError,
    DeviceMismatch,
    LaunchError,
    UsbDropped,
    UsbRecoveryError,
)
from .proc import CommandRunner, CmdResult, file_size, looks_like_usb_drop, read_from
from .config import Target


@dataclass
class DeviceCheck:
    model: str
    os_version: str
    build: str
    udid: str | None
    name: str | None = None
    connection: str | None = None
    bundle_id: str | None = None
    app_version: str | None = None
    app_build: str | None = None
    app_checked: bool = False
    source: str = "usbmux"

    def to_dict(self) -> dict:
        return {
            "model": self.model,
            "os_version": self.os_version,
            "build": self.build,
            "udid": self.udid,
            "name": self.name,
            "connection": self.connection,
            "bundle_id": self.bundle_id,
            "app_version": self.app_version,
            "app_build": self.app_build,
            "app_checked": self.app_checked,
            "source": self.source,
        }


@dataclass
class LaunchHandle:
    proc: subprocess.Popen
    log_path: Path
    offset: int
    cmd: list[str] = field(default_factory=list)
    started_at: float = 0.0

    @property
    def alive(self) -> bool:
        return self.proc.poll() is None

    @property
    def returncode(self):
        return self.proc.poll()

    def stop(self, *, term_timeout: float = 5.0) -> dict:
        """Terminate the console attachment; never leave it running."""

        info = {"pid": getattr(self.proc, "pid", None), "terminated": False,
                "killed": False, "returncode": self.proc.poll()}
        if self.proc.poll() is not None:
            info["terminated"] = True
            return info
        try:
            self.proc.terminate()
            info["terminated"] = True
        except ProcessLookupError:
            info["terminated"] = True
        try:
            self.proc.wait(timeout=term_timeout)
        except subprocess.TimeoutExpired:
            try:
                self.proc.kill()
                info["killed"] = True
            except ProcessLookupError:
                pass
            try:
                self.proc.wait(timeout=term_timeout)
            except subprocess.TimeoutExpired:
                pass
        info["returncode"] = self.proc.poll()
        return info


def parse_usbmux_list(stdout: str) -> list[dict]:
    """Parse ``pymobiledevice3 usbmux list`` JSON, tolerating log noise."""

    text = (stdout or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("[")
        end = text.rfind("]")
        if start < 0 or end <= start:
            raise ConfigError("cannot parse usbmux list output: %r" % text[:400])
        try:
            data = json.loads(text[start:end + 1])
        except json.JSONDecodeError as exc:
            raise ConfigError("cannot parse usbmux list output: %s" % exc) from exc
    if isinstance(data, str):
        data = [data]
    if not isinstance(data, list):
        raise ConfigError("unexpected usbmux list JSON type: %s" % type(data).__name__)
    return [entry for entry in data if isinstance(entry, dict)]


def parse_app_query(stdout: str, bundle_id: str) -> dict:
    """Parse ``pymobiledevice3 apps query <bundle>`` output.

    pymobiledevice3 prints a JSON object keyed by bundle identifier.  Older
    builds printed a plist or a Python dict; accept those too.
    """

    text = (stdout or "").strip()
    if not text:
        raise ConfigError("empty apps query output for %s" % bundle_id)

    data = None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            try:
                data = json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                data = None
    if data is None:
        try:
            data = plistlib.loads(text.encode("utf-8", "replace"))
        except Exception:  # noqa: BLE001
            data = None
    if data is None:
        # last resort: regex key/value pairs (plist text or repr)
        data = {}
        for key in ("CFBundleShortVersionString", "CFBundleVersion",
                    "CFBundleIdentifier"):
            match = re.search(r"['\"]?%s['\"]?\s*[:=]\s*['\"]([^'\"]+)" % key, text)
            if match:
                data[key] = match.group(1)
        if not data:
            raise ConfigError("cannot parse apps query output: %r" % text[:400])

    if isinstance(data, list) and data:
        data = data[0]
    if not isinstance(data, dict):
        raise ConfigError("unexpected apps query JSON type: %s" % type(data).__name__)
    if bundle_id in data and isinstance(data[bundle_id], dict):
        return data[bundle_id]
    return data


def normalize_version(value: str | None) -> tuple[int, ...]:
    if value is None:
        return ()
    parts: list[int] = []
    for piece in str(value).strip().split("."):
        match = re.match(r"(\d+)", piece)
        if not match:
            break
        parts.append(int(match.group(1)))
    while parts and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def version_matches(actual: str | None, expected: str) -> bool:
    if actual is None:
        return False
    return normalize_version(actual) == normalize_version(expected)


class DeviceManager:
    def __init__(
        self,
        cmd: CommandRunner | None = None,
        *,
        p3: str = "pymobiledevice3",
        target: Target | None = None,
        udid: str | None = None,
        timeout: float = 30.0,
        recover_python: str | None = None,
        log=None,
    ):
        self.cmd = cmd or CommandRunner()
        self.p3 = p3
        self.target = target or Target()
        self.udid = udid
        self.timeout = timeout
        self.recover_python = recover_python
        self._log = log or (lambda *_: None)

    # -- environment -----------------------------------------------------
    def env(self) -> dict[str, str]:
        environment = dict(os.environ)
        if self.udid:
            environment["PYMOBILEDEVICE3_UDID"] = self.udid
        return environment

    # -- discovery -------------------------------------------------------
    def _python_for_recovery(self) -> str:
        """Prefer the interpreter next to pymobiledevice3 (it has pyusb)."""

        if self.recover_python:
            return self.recover_python
        resolved = shutil.which(self.p3) or self.p3
        candidate = Path(resolved).resolve().parent / "python"
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
        return sys.executable

    def list_devices(self) -> list[dict]:
        result = self.cmd.run(
            [self.p3, "usbmux", "list"], timeout=self.timeout, env=self.env()
        )
        if not result.ok:
            raise UsbDropped(result) if looks_like_usb_drop(result) else CommandFailed(result)
        return parse_usbmux_list(result.stdout)

    def find_device(self, devices: list[dict]) -> dict:
        if not devices:
            raise DeviceMismatch(
                "no device is listed by usbmux: the USB link is down or the phone "
                "is locked/untrusted. Run `i17e_runner recover --udid <UDID>` "
                "and wake/unlock/Trust the phone.",
                expected=self.target.to_dict(),
                found=[],
            )
        if self.udid:
            for device in devices:
                identifiers = {
                    str(device.get("UniqueDeviceID") or ""),
                    str(device.get("Identifier") or ""),
                    str(device.get("SerialNumber") or ""),
                }
                if self.udid in identifiers:
                    return device
            found = [summarize_device(d) for d in devices]
            raise DeviceMismatch(
                "wrong device: UDID %s is not attached. Attached: %s. "
                "Refusing to run." % (self.udid, ", ".join(found) or "none"),
                expected={"udid": self.udid, **self.target.to_dict()},
                found=found,
            )
        if len(devices) > 1:
            raise DeviceMismatch(
                "multiple devices are attached (%s); pass --udid to choose the "
                "iPhone 17e explicitly." % ", ".join(summarize_device(d) for d in devices),
                expected=self.target.to_dict(),
                found=[summarize_device(d) for d in devices],
            )
        return devices[0]

    def app_info(self, bundle_id: str | None = None) -> dict:
        bundle = bundle_id or self.target.bundle_id
        result = self.cmd.run(
            [self.p3, "apps", "query", bundle],
            timeout=self.timeout,
            env=self.env(),
        )
        if not result.ok:
            raise UsbDropped(result) if looks_like_usb_drop(result) else CommandFailed(result)
        return parse_app_query(result.stdout, bundle)

    def check(self, *, skip_app: bool = False, app_info: dict | None = None) -> DeviceCheck:
        device = self.find_device(self.list_devices())
        model = str(device.get("ProductType") or "")
        os_version = str(device.get("ProductVersion") or "")
        build = str(device.get("BuildVersion") or "")
        actual_udid = str(device.get("UniqueDeviceID") or device.get("Identifier") or "") or None

        problems: list[str] = []
        if model != self.target.model:
            problems.append("model %s (expected %s)" % (model or "?", self.target.model))
        if os_version != self.target.os_version:
            problems.append("iOS %s (expected %s)" % (os_version or "?", self.target.os_version))
        if build != self.target.build:
            problems.append("build %s (expected %s)" % (build or "?", self.target.build))
        if problems:
            raise DeviceMismatch(
                "WRONG DEVICE: found %s. Refusing to run on a non-target phone."
                % ", ".join(problems),
                expected=self.target.to_dict(),
                found=summarize_device(device),
            )

        check = DeviceCheck(
            model=model,
            os_version=os_version,
            build=build,
            udid=actual_udid,
            name=device.get("DeviceName"),
            connection=device.get("ConnectionType"),
            bundle_id=self.target.bundle_id,
        )

        if not skip_app:
            info = app_info if app_info is not None else self.app_info()
            app_version = str(info.get("CFBundleShortVersionString") or "")
            app_build = str(info.get("CFBundleVersion") or "")
            app_bundle = str(info.get("CFBundleIdentifier") or self.target.bundle_id)
            check.bundle_id = app_bundle
            check.app_version = app_version
            check.app_build = app_build
            check.app_checked = True
            app_problems: list[str] = []
            if app_bundle != self.target.bundle_id:
                app_problems.append("bundle %s (expected %s)" % (app_bundle, self.target.bundle_id))
            if not version_matches(app_version, self.target.app_version):
                app_problems.append(
                    "version %s (expected %s)" % (app_version or "?", self.target.app_version)
                )
            if app_build != self.target.app_build:
                app_problems.append(
                    "build %s (expected %s)" % (app_build or "?", self.target.app_build)
                )
            if app_problems:
                raise DeviceMismatch(
                    "WRONG APP: %s: %s. Install the target build before running."
                    % (self.target.bundle_id, ", ".join(app_problems)),
                    expected=self.target.to_dict(),
                    found={"bundle_id": app_bundle, "app_version": app_version,
                           "app_build": app_build},
                )
        return check

    # -- USB recovery ----------------------------------------------------
    def recover(self, script: str, *, attempts: int | None = None,
                timeout: float = 180.0) -> CmdResult:
        if not self.udid:
            raise ConfigError("USB recovery needs --udid (or $I17E_UDID)")
        if not Path(script).is_file():
            raise ConfigError(
                "USB recovery script not found: %s (pass --usb-recover)" % script
            )
        python = self._python_for_recovery()
        argv = [
            python,
            script,
            "--udid",
            self.udid,
            "--pymobiledevice3",
            self.p3,
        ]
        if attempts is not None:
            argv += ["--attempts", str(int(attempts))]
        result = self.cmd.run(argv, timeout=timeout)
        if not result.ok:
            raise UsbRecoveryError(
                "USB recovery failed (rc=%s):\n%s"
                % (result.returncode, result.brief(1200))
            )
        return result

    def ensure_connected(
        self,
        script: str | None = None,
        *,
        recovery_attempts: int = 2,
        retry_pause: float = 2.0,
        sleep=time.sleep,
        skip_app: bool = False,
    ) -> DeviceCheck:
        """Return a verified device, recovering the link when needed."""

        last_error: Exception | None = None
        for cycle in range(max(1, recovery_attempts + 1)):
            try:
                devices = self.list_devices()
                if devices:
                    return self.check(skip_app=skip_app)
            except (UsbDropped, CommandFailed, CommandTimeout) as exc:
                last_error = exc
            if cycle < recovery_attempts and script:
                self._log("USB link missing; running documented recovery")
                try:
                    self.recover(script, attempts=2)
                except (UsbRecoveryError, ConfigError) as exc:
                    last_error = exc
                sleep(retry_pause)
            elif cycle < recovery_attempts:
                sleep(retry_pause)
        if isinstance(last_error, DeviceMismatch):
            raise last_error
        raise UsbRecoveryError(
            "device %s is not usable after %d recovery cycle(s): %s"
            % (self.udid or "<auto>", recovery_attempts + 1, last_error)
        )

    # -- launch ----------------------------------------------------------
    def launch_command(self, *, kill_existing: bool = True) -> list[str]:
        argv = [
            self.p3,
            "developer",
            "core-device",
            "launch-application",
            self.target.bundle_id,
            "--console",
            "--userspace",
        ]
        if not kill_existing:
            argv.append("--no-kill-existing")
        return argv

    def launch_console(
        self,
        log_path: str | os.PathLike,
        *,
        kill_existing: bool = True,
        launcher: CommandRunner | None = None,
        wait: float = 0.0,
        sleep=time.sleep,
    ) -> LaunchHandle:
        path = Path(log_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        offset = file_size(path)
        argv = self.launch_command(kill_existing=kill_existing)
        runner = launcher or self.cmd
        try:
            with open(path, "ab") as sink:
                proc = runner.popen(argv, stdout=sink, env=self.env())
        except OSError as exc:
            raise LaunchError(
                "cannot start launch-application (%s): %s" % (self.p3, exc)
            ) from exc
        handle = LaunchHandle(
            proc=proc,
            log_path=path,
            offset=offset,
            cmd=argv,
            started_at=time.time(),
        )
        if wait > 0:
            sleep(wait)
        return handle

    def screenshot(self, path: str | os.PathLike) -> CmdResult:
        return self.cmd.run(
            [self.p3, "developer", "core-device", "screen-capture", "screenshot",
             str(path), "--userspace"],
            timeout=self.timeout,
            env=self.env(),
        )

    # -- input (pixel coordinates in the 1170x2532 screenshot space) ------
    def _normalize(self, x: float, y: float) -> tuple[int, int]:
        nx = max(0, min(65535, int(x / self.target.screen_width * 65535)))
        ny = max(0, min(65535, int(y / self.target.screen_height * 65535)))
        return nx, ny

    def tap(self, x: float, y: float) -> CmdResult:
        nx, ny = self._normalize(x, y)
        return self.cmd.run(
            [self.p3, "developer", "core-device", "universal-hid-service",
             "tap", str(nx), str(ny), "--userspace"],
            timeout=self.timeout,
            env=self.env(),
        )

    def drag(self, x1: float, y1: float, x2: float, y2: float) -> CmdResult:
        nx1, ny1 = self._normalize(x1, y1)
        nx2, ny2 = self._normalize(x2, y2)
        return self.cmd.run(
            [self.p3, "developer", "core-device", "universal-hid-service",
             "drag", str(nx1), str(ny1), str(nx2), str(ny2), "--userspace"],
            timeout=self.timeout,
            env=self.env(),
        )

    # -- proof -----------------------------------------------------------
    def backup_command(self, backup_dir: str | os.PathLike, regex: str,
                       *, legacy: bool = False) -> list[str]:
        if legacy:
            # Older documented CLI: `backup2 --only-regex ...` with a default
            # backup directory.
            return [self.p3, "backup2", "--only-regex", regex]
        return [self.p3, "backup2", "backup", str(backup_dir), "--only-regex", regex]

    def run_backup(self, backup_dir: str | os.PathLike, regex: str,
                   *, legacy: bool = False, timeout: float = 120.0) -> CmdResult:
        directory = Path(backup_dir)
        directory.mkdir(parents=True, exist_ok=True)
        return self.cmd.run(
            self.backup_command(directory, regex, legacy=legacy),
            timeout=timeout,
            env=self.env(),
            # The legacy shorthand has no explicit destination; run it inside
            # the attempt directory so the result can still be collected.
            cwd=str(directory) if legacy else None,
        )

    # -- processes -------------------------------------------------------
    def console_pids(self) -> list[int]:
        pattern = "launch-application %s" % self.target.bundle_id
        return self.cmd.pgrep(pattern)

    def frida_pids(self) -> list[int]:
        return self.cmd.pgrep("frida")

    def kill_pids(self, pids: list[int], *, sig=signal.SIGTERM) -> dict:
        killed: list[int] = []
        failed: list[int] = []
        for pid in pids:
            try:
                os.kill(pid, sig)
                killed.append(pid)
            except ProcessLookupError:
                continue
            except PermissionError:
                failed.append(pid)
        return {"killed": killed, "failed": failed}


def summarize_device(device: dict | str) -> str:
    if not isinstance(device, dict):
        return str(device)
    return "%s (%s %s %s, %s)" % (
        device.get("UniqueDeviceID") or device.get("Identifier") or "?",
        device.get("ProductType") or "?",
        device.get("ProductVersion") or "?",
        device.get("BuildVersion") or "?",
        device.get("ConnectionType") or "?",
    )
