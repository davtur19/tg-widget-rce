"""Configuration defaults and placeholder handling.

No operator-specific value is stored in this file.  The UDID, chat id,
AppGroup UUID and bot token always come from the command line or environment
at runtime.
"""
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from .errors import ConfigError

VERSION = "1.0.0"
SCHEMA = "i17e-runner/attempt/1"

PLACEHOLDER_APPGROUP = "<APPGROUP>"
PLACEHOLDER_UDID = "<UDID>"
PLACEHOLDER_CHAT = "<CHAT_ID>"
PLACEHOLDER_HOME = "<HOME>"

DEFAULT_P3_CANDIDATES = (
    "pymobiledevice3",
)
DEFAULT_USB_RECOVER_REL = "tg-rce/docs/instrumentation/ios17e/usb_recover.py"


@dataclass(frozen=True)
class Target:
    """The documented stock iOS 17e target."""

    model: str = "iPhone18,5"
    os_version: str = "27.0"
    build: str = "24A437"
    bundle_id: str = "ph.telegra.Telegraph"
    app_version: str = "13.2"
    app_build: str = "36535"
    screen_width: int = 1170
    screen_height: int = 2532

    def to_dict(self) -> dict:
        return {
            "model": self.model,
            "os_version": self.os_version,
            "build": self.build,
            "bundle_id": self.bundle_id,
            "app_version": self.app_version,
            "app_build": self.app_build,
            "screen": [self.screen_width, self.screen_height],
        }


def package_dir() -> Path:
    return Path(__file__).resolve().parent


def find_repo_root(start: Path | None = None) -> Path | None:
    """Locate the campaign repository root without hard-coding a home path."""

    current = (start or package_dir()).resolve()
    for candidate in (current, *current.parents):
        if (candidate / "tg-rce").is_dir() and (candidate / "lab").is_dir():
            return candidate
    return None


def default_p3() -> str:
    """Resolve pymobiledevice3: env, PATH, then the campaign venv."""

    env = os.environ.get("I17E_PYMOBILEDEVICE3") or os.environ.get("PYMOBILEDEVICE3")
    if env:
        return env
    found = shutil.which("pymobiledevice3")
    if found:
        return found
    repo = find_repo_root()
    if repo is not None:
        candidate = repo / "ios_sideload" / "venv" / "bin" / "pymobiledevice3"
        if candidate.is_file():
            return str(candidate)
    # Let the command fail with a clear message if it really is absent.
    return "pymobiledevice3"


def default_usb_recover() -> str:
    """Resolve the documented USB recovery script.

    Preference order: env, campaign repository copy, then the sanitized
    vendored copy shipped with this tool.
    """

    env = os.environ.get("I17E_USB_RECOVER")
    if env:
        return env
    repo = find_repo_root()
    if repo is not None:
        candidate = repo / DEFAULT_USB_RECOVER_REL
        if candidate.is_file():
            return str(candidate)
    return str(package_dir() / "vendor" / "usb_recover.py")


def default_state_dir() -> str:
    env = os.environ.get("I17E_STATE_DIR")
    if env:
        return env
    base = os.environ.get("XDG_STATE_HOME")
    if base:
        return str(Path(base) / "i17e_runner")
    return str(Path.home() / ".local" / "state" / "i17e_runner")


def expand_placeholders(
    value: str,
    *,
    appgroup: str | None = None,
    udid: str | None = None,
    chat_id: str | None = None,
) -> str:
    """Expand documentation placeholders used in specs and examples."""

    text = str(value)
    mapping = {
        PLACEHOLDER_APPGROUP: appgroup,
        PLACEHOLDER_UDID: udid,
        PLACEHOLDER_CHAT: chat_id,
        PLACEHOLDER_HOME: os.path.expanduser("~"),
    }
    for placeholder, replacement in mapping.items():
        if placeholder in text:
            if replacement is None:
                raise ConfigError(
                    "%s is used but no value was supplied (pass --appgroup/--udid/"
                    "--chat-id or set the corresponding environment variable)"
                    % placeholder
                )
            text = text.replace(placeholder, str(replacement))
    return text


def require_appgroup(appgroup: str | None, regex: str | None) -> str:
    """Return the backup regex, expanding ``<APPGROUP>`` or raising clearly."""

    if regex:
        return expand_placeholders(regex, appgroup=appgroup)
    if not appgroup:
        raise ConfigError(
            "proof backup needs --appgroup (or $I17E_APPGROUP) or an explicit "
            "--backup-regex"
        )
    return "%s.*rce.txt|.*spdb" % appgroup


def mask_udid(udid: str | None) -> str | None:
    if not udid:
        return udid
    text = str(udid)
    if len(text) <= 12:
        return "<UDID>"
    return "%s…%s" % (text[:8], text[-4:])


@dataclass
class RunPaths:
    out: Path
    state_dir: Path
    payload_root: Path | None = None
    log_dir: Path | None = None
    shot_dir: Path | None = None
    backup_dir: Path | None = None

    @classmethod
    def create(cls, out: str | os.PathLike, state_dir: str | os.PathLike,
               payload_root: str | os.PathLike | None = None) -> "RunPaths":
        out_path = Path(out).expanduser().resolve()
        paths = cls(
            out=out_path,
            state_dir=Path(state_dir).expanduser().resolve(),
            payload_root=Path(payload_root).expanduser().resolve() if payload_root else None,
            log_dir=out_path / "logs",
            shot_dir=out_path / "shots",
            backup_dir=out_path / "backups",
        )
        for directory in (paths.out, paths.state_dir, paths.log_dir, paths.shot_dir,
                          paths.backup_dir):
            directory.mkdir(parents=True, exist_ok=True)
        return paths

    def to_dict(self) -> dict:
        return {
            "out": str(self.out),
            "state_dir": str(self.state_dir),
            "payload_root": str(self.payload_root) if self.payload_root else None,
        }


@dataclass
class RuntimeConfig:
    """Everything a run needs, independent of argparse."""

    target: Target = field(default_factory=Target)
    udid: str | None = None
    appgroup: str | None = None
    chat_id: str | None = None
    account_id: str | None = None
    p3: str = field(default_factory=default_p3)
    usb_recover: str = field(default_factory=default_usb_recover)
    recover_python: str | None = None
    paths: RunPaths | None = None
    # device behaviour
    usb_attempts: int = 3
    skip_app_check: bool = False
    device_timeout: float = 30.0
    launch_wait: float = 3.5
    launch_taps: tuple[tuple[float, float], ...] = ()
    launch_drags: tuple[tuple[float, float, float, float], ...] = ()
    tap_delay: float = 0.7
    shot_start: float = 0.6
    shot_count: int = 12
    shot_interval: float = 0.25
    shot_extra: tuple[float, ...] = (5.0, 10.0)
    screenshots: bool = True
    ocr_mode: str = "auto"  # auto | on | off
    ocr_max: int = 6
    no_launch: bool = False
    console_log: str | None = None
    kill_existing: bool = True
    backup: bool = False
    backup_regex: str | None = None
    backup_cli: str = "modern"  # modern | legacy
    require_proof: bool = False
    # bot behaviour
    token: str | None = None
    api: str = "beta"
    allow_queries: bool = True
    background_query: bool = True
    widget_height: int | None = None
    widget_width: int | None = None
    # verdict
    success_markers: tuple[str, ...] = (r"HIT=|RESULT\b|N17E|js_free_rt",)
    expect: str = "marker_or_proof"
    # output
    redact: bool = True
    dry_run: bool = False
    verbose: bool = False
    command_timeout: float = 30.0
    backup_timeout: float = 120.0
    payload_raw_limit: int = 32768
    payload_zlib_limit: int = 4096
    fail_on_frida: bool = False
