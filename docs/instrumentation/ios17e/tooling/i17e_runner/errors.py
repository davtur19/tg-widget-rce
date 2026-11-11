"""Exception hierarchy for the iPhone 17e test runner.

All failures that the CLI reports as a structured attempt result derive from
``RunnerError``.  Exit codes are defined in :mod:`i17e_runner.cli`.
"""
from __future__ import annotations


class RunnerError(Exception):
    """Base class for every expected runner failure."""


class ConfigError(RunnerError):
    """Bad or missing configuration (paths, environment, CLI values)."""


class PayloadError(RunnerError):
    """The payload does not satisfy the sendWidget envelope."""


class CommandTimeout(RunnerError):
    """A host command exceeded its timeout."""

    def __init__(self, cmd: list[str], timeout: float):
        self.cmd = list(cmd)
        self.timeout = timeout
        super().__init__(
            "command timed out after %.1fs: %s" % (timeout, " ".join(map(str, cmd)))
        )


class CommandFailed(RunnerError):
    """A host command returned a non-zero status."""

    def __init__(self, result, message: str | None = None):
        self.result = result
        if message is None:
            message = "command failed (rc=%s): %s\n%s" % (
                result.returncode,
                " ".join(map(str, result.cmd)),
                (result.stderr or result.stdout or "")[-1200:],
            )
        super().__init__(message)


class UsbDropped(CommandFailed):
    """A host command failed because the USB/usbmux link went away."""


class UsbRecoveryError(RunnerError):
    """The documented USB recovery procedure did not bring the device back."""


class DeviceMismatch(RunnerError):
    """The attached device or installed app is not the documented target."""

    def __init__(self, message: str, *, expected=None, found=None):
        self.expected = expected
        self.found = found
        super().__init__(message)


class LaunchError(RunnerError):
    """Telegram could not be launched with a console attached."""


class BotApiError(RunnerError):
    """The Bot API rejected a call."""

    def __init__(self, method: str, description: str, *, code=None):
        self.method = method
        self.description = description
        self.code = code
        super().__init__("%s: %s" % (method, description))


class ChatCleanupError(RunnerError):
    """At least one known payload/anchor message could not be removed."""

    def __init__(self, message: str, *, failures=None, deleted=None):
        self.failures = list(failures or [])
        self.deleted = list(deleted or [])
        super().__init__(message)


class ProofError(RunnerError):
    """The proof backup/pull could not be executed."""


class MatrixSpecError(ConfigError):
    """A matrix specification file is invalid."""
