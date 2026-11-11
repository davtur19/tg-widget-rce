"""Host command execution with timeouts and USB-drop classification.

The runner never uses a shell.  Every command is a list of argv items so that
tokens, UDIDs and AppGroup values cannot leak through shell interpolation.
"""
from __future__ import annotations

import os
import re
import subprocess
import time
from dataclasses import dataclass

from .errors import CommandFailed, CommandTimeout, UsbDropped

DEFAULT_TIMEOUT = 30.0

# Error fragments that mean "the USB/usbmux link is gone", not "the command was
# wrong".  Kept deliberately narrow; unknown failures stay CommandFailed.
_USB_MARKERS = (
    "Device is not connected",
    "device is not connected",
    "usbmux",
    "Usbmux",
    "USBMux",
    "Could not connect",
    "ConnectionError",
    "BrokenPipe",
    "Broken pipe",
    "Pipe error",
    "Bad file descriptor",
    "No such device",
    "no device found",
    "InvalidService",
    "InvalidHostID",
    "Connection reset",
    "connection reset",
    "not paired",
    "Please unlock",
    "please unlock",
    "Failed to connect",
)


@dataclass
class CmdResult:
    """Result of one host command."""

    cmd: list[str]
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    duration_s: float = 0.0
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    @property
    def combined(self) -> str:
        if self.stderr and self.stdout:
            return self.stdout + "\n" + self.stderr
        return self.stdout or self.stderr

    def brief(self, limit: int = 600) -> str:
        text = (self.stderr or self.stdout or "").strip()
        if len(text) > limit:
            text = text[-limit:]
        return text

    def to_dict(self) -> dict:
        return {
            "cmd": list(self.cmd),
            "returncode": self.returncode,
            "timed_out": self.timed_out,
            "duration_s": round(self.duration_s, 3),
            "stdout_tail": self.stdout[-2000:],
            "stderr_tail": self.stderr[-2000:],
        }


def looks_like_usb_drop(result: CmdResult) -> bool:
    """True when the failure text matches the documented USB-drop symptoms."""

    if result.ok:
        return False
    text = result.combined
    return any(marker in text for marker in _USB_MARKERS)


class CommandRunner:
    """Thin, testable wrapper around :mod:`subprocess`."""

    def run(
        self,
        cmd: list[str],
        *,
        timeout: float = DEFAULT_TIMEOUT,
        check: bool = False,
        env: dict[str, str] | None = None,
        cwd: str | os.PathLike | None = None,
        stdin: str | None = None,
    ) -> CmdResult:
        argv = [str(part) for part in cmd]
        started = time.monotonic()
        try:
            completed = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=timeout,
                env=env,
                cwd=cwd,
                input=stdin,
                check=False,
            )
            result = CmdResult(
                cmd=argv,
                returncode=completed.returncode,
                stdout=completed.stdout or "",
                stderr=completed.stderr or "",
                duration_s=time.monotonic() - started,
            )
        except subprocess.TimeoutExpired as exc:
            result = CmdResult(
                cmd=argv,
                returncode=None,
                stdout=_decode(exc.stdout),
                stderr=_decode(exc.stderr),
                duration_s=time.monotonic() - started,
                timed_out=True,
            )
        except FileNotFoundError as exc:
            result = CmdResult(
                cmd=argv,
                returncode=127,
                stdout="",
                stderr=str(exc),
                duration_s=time.monotonic() - started,
            )

        if check and not result.ok:
            if result.timed_out:
                raise CommandTimeout(argv, timeout)
            if looks_like_usb_drop(result):
                raise UsbDropped(result)
            raise CommandFailed(result)
        return result

    def popen(
        self,
        cmd: list[str],
        *,
        stdout,
        env: dict[str, str] | None = None,
        cwd: str | os.PathLike | None = None,
    ) -> subprocess.Popen:
        argv = [str(part) for part in cmd]
        return subprocess.Popen(
            argv,
            stdout=stdout,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            env=env,
            cwd=cwd,
            start_new_session=True,
        )

    def pgrep(self, pattern: str, *, timeout: float = 5.0) -> list[int]:
        """Return PIDs matching ``pattern`` using ``pgrep -f`` (best effort)."""

        result = self.run(["pgrep", "-f", pattern], timeout=timeout)
        pids: list[int] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.isdigit():
                pids.append(int(line))
        return pids


def _decode(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def read_from(path: str | os.PathLike, offset: int, limit: int = 1 << 20) -> str:
    """Read a text log starting at a byte offset (UTF-8, replacement chars)."""

    try:
        with open(path, "rb") as handle:
            handle.seek(max(0, offset))
            data = handle.read(limit)
    except OSError:
        return ""
    return data.decode("utf-8", "replace")


def file_size(path: str | os.PathLike) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def wait_for_size(path: str | os.PathLike, minimum: int, timeout: float) -> bool:
    """Wait until ``path`` reaches ``minimum`` bytes (used for launch checks)."""

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if file_size(path) >= minimum:
            return True
        time.sleep(0.2)
    return file_size(path) >= minimum


def strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text)
