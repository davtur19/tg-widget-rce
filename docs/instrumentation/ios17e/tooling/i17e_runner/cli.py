"""Command-line interface for the iPhone 17e test runner."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import VERSION
from .botapi import BotClient
from .clean import ChatCleaner, parse_id_list, read_id_file
from .config import (
    RuntimeConfig,
    RunPaths,
    Target,
    default_p3,
    default_state_dir,
    default_usb_recover,
    mask_udid,
)
from .device import DeviceManager
from .errors import (
    ChatCleanupError,
    CommandFailed,
    CommandTimeout,
    ConfigError,
    DeviceMismatch,
    PayloadError,
    RunnerError,
    UsbDropped,
    UsbRecoveryError,
)
from .ledger import ChatLedger
from .matrix import MatrixRunner, load_matrix
from .model import AttemptSpec
from .ocr import OcrEngine
from .payload import hash_matches, inspect_payload
from .proc import CommandRunner
from .redact import Redactor, null_redactor
from .report import Reporter
from .runner import AttemptRunner

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_CONFIG = 2
EXIT_DEVICE = 3
EXIT_USB = 4
EXIT_CHAT = 5
EXIT_ERROR = 6

PLACEHOLDER_TOKEN = "DRY_RUN_TOKEN"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="i17e_runner",
        description="Generic iPhone 17e test runner for the P1/v14/session matrices.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version="i17e_runner " + VERSION)

    base = argparse.ArgumentParser(add_help=False)
    base.add_argument("--p3", default=default_p3(),
                      help="pymobiledevice3 executable (default: env/PATH/venv)")
    base.add_argument("--usb-recover", default=default_usb_recover(),
                      help="documented usb_recover.py (default: repo copy or vendored)")
    base.add_argument("--recover-python",
                      default=os.environ.get("I17E_RECOVER_PYTHON"),
                      help="Python with pyusb for recovery (default: next to p3)")
    base.add_argument("--udid", default=os.environ.get("I17E_UDID"),
                      help="target UDID (default: $I17E_UDID; never stored)")
    base.add_argument("--account-id", default=os.environ.get("I17E_ACCOUNT_ID"),
                      help="account directory id to redact (default: $I17E_ACCOUNT_ID)")
    base.add_argument("--state-dir", default=default_state_dir(),
                      help="local ledger state directory (default: $XDG_STATE_HOME)")
    base.add_argument("--out", default="runs", help="artifact directory (default: runs)")
    base.add_argument("--payload-root", default=None,
                      help="base directory for relative payload paths")
    base.add_argument("--redact", dest="redact", action="store_true", default=True,
                      help="redact token/UDID/chat/AppGroup in artifacts (default)")
    base.add_argument("--no-redact", dest="redact", action="store_false",
                      help="keep real values in local artifacts")
    base.add_argument("--timeout", type=float, default=30.0,
                      help="per-command timeout in seconds (default: 30)")
    base.add_argument("--verbose", "-v", action="store_true")
    base.add_argument("--dry-run", action="store_true",
                      help="plan only: no network, no device")
    base.add_argument("--expect-model", default="iPhone18,5")
    base.add_argument("--expect-os", default="27.0")
    base.add_argument("--expect-build", default="24A437")
    base.add_argument("--bundle", default="ph.telegra.Telegraph")
    base.add_argument("--expect-app-version", default="13.2")
    base.add_argument("--expect-app-build", default="36535")
    base.add_argument("--skip-app-check", action="store_true",
                      help="skip the installed app version check (not recommended)")

    bot = argparse.ArgumentParser(add_help=False)
    bot.add_argument("--token", default=os.environ.get("BOT_TOKEN"),
                     help="Bot API token (default: $BOT_TOKEN; never commit it)")
    bot.add_argument("--chat-id", default=os.environ.get("I17E_CHAT_ID"),
                     help="target chat id (default: $I17E_CHAT_ID)")
    bot.add_argument("--api", choices=("beta", "standard"), default="beta")
    bot.add_argument("--allow-queries", dest="allow_queries", action="store_true",
                     default=True)
    bot.add_argument("--no-allow-queries", dest="allow_queries", action="store_false")
    bot.add_argument("--background-query", dest="background_query", action="store_true",
                     default=True)
    bot.add_argument("--no-background-query", dest="background_query",
                     action="store_false")
    bot.add_argument("--height", type=int, default=None, help="widget bubble height")
    bot.add_argument("--width", type=int, default=None, help="widget bubble width")

    run = argparse.ArgumentParser(add_help=False)
    run.add_argument("--usb-attempts", type=int, default=3)
    run.add_argument("--launch-wait", type=float, default=3.5)
    run.add_argument("--tap", action="append", default=[],
                     help="post-launch tap at X,Y pixels (repeatable)")
    run.add_argument("--drag", action="append", default=[],
                     help="post-launch drag X1,Y1,X2,Y2 pixels")
    run.add_argument("--tap-delay", type=float, default=0.7,
                     help="delay between post-launch input events")
    run.add_argument("--shot-start", type=float, default=0.6)
    run.add_argument("--shot-count", type=int, default=12)
    run.add_argument("--shot-interval", type=float, default=0.25)
    run.add_argument("--shot-extra", default="5,10",
                     help="comma-separated extra screenshot delays (default: 5,10)")
    run.add_argument("--screenshots", dest="screenshots", action="store_true",
                     default=True)
    run.add_argument("--no-screenshots", dest="screenshots", action="store_false")
    run.add_argument("--ocr", choices=("auto", "on", "off"), default="auto")
    run.add_argument("--ocr-max", type=int, default=6)
    run.add_argument("--no-launch", action="store_true",
                     help="warm mode: use an already attached --console-log")
    run.add_argument("--console-log", default=None,
                     help="existing console log for --no-launch")
    run.add_argument("--no-kill-existing", dest="kill_existing", action="store_false",
                     default=True)
    run.add_argument("--backup", dest="backup", action="store_true", default=False,
                     help="pull the proof file after the render")
    run.add_argument("--no-backup", dest="backup", action="store_false")
    run.add_argument("--appgroup", default=os.environ.get("I17E_APPGROUP"),
                     help="AppGroup UUID for the proof regex (default: $I17E_APPGROUP)")
    run.add_argument("--backup-regex", default=None,
                     help="proof regex; <APPGROUP> is expanded at runtime")
    run.add_argument("--backup-cli", choices=("modern", "legacy"), default="modern",
                     help="modern: `backup2 backup DIR`; legacy: documented shorthand")
    run.add_argument("--require-proof", action="store_true")
    run.add_argument("--success-marker", action="append", default=None,
                     help="regex marking success (repeatable)")
    run.add_argument("--expect", choices=("marker", "proof", "alive", "any",
                                          "marker_or_proof", "manual"),
                     default="marker_or_proof")
    run.add_argument("--fail-on-frida", action="store_true")

    sub = parser.add_subparsers(dest="command", required=True)

    doctor = sub.add_parser("doctor", parents=[base],
                            help="check UDID, model, iOS build and app version")
    doctor.set_defaults(func=cmd_doctor)

    recover = sub.add_parser("recover", parents=[base],
                             help="run the documented USB recovery")
    recover.add_argument("--attempts", type=int, default=3)
    recover.set_defaults(func=cmd_recover)

    clean = sub.add_parser("clean", parents=[base, bot],
                           help="delete known payload/anchor message ids")
    clean.add_argument("--delete-id", action="append", default=[],
                       help="message id or comma list (repeatable)")
    clean.add_argument("--payload-id", action="append", default=[],
                       help="known payload id to register and delete")
    clean.add_argument("--anchor-id", action="append", default=[],
                       help="known anchor id to register and delete")
    clean.add_argument("--ids-file", default=None,
                       help="file with message ids (one per line or comma list)")
    clean.add_argument("--screenshot", default=None,
                       help="existing chat screenshot for marker verification")
    clean.add_argument("--verify-screenshot", action="store_true")
    clean.set_defaults(func=cmd_clean)

    send = sub.add_parser("send", parents=[base, bot],
                          help="inspect and send one payload as the last message")
    send.add_argument("--html", required=True)
    send.add_argument("--expect-sha256", default=None)
    send.set_defaults(func=cmd_send)

    run_cmd = sub.add_parser("run", parents=[base, bot, run],
                             help="run one full attempt")
    run_cmd.add_argument("--html", required=True)
    run_cmd.add_argument("--label", default="attempt")
    run_cmd.add_argument("--expect-sha256", default=None)
    run_cmd.add_argument("--delete-id", action="append", default=[],
                         help="extra old message ids to delete before the send")
    run_cmd.set_defaults(func=cmd_run)

    matrix = sub.add_parser("matrix", parents=[base, bot, run],
                            help="execute a JSON matrix specification")
    matrix.add_argument("--spec", required=True)
    matrix.add_argument("--stop-on-invalid", dest="stop_on_invalid",
                        action="store_true", default=True)
    matrix.add_argument("--continue-on-invalid", dest="stop_on_invalid",
                        action="store_false")
    matrix.add_argument("--strict", action="store_true",
                        help="exit non-zero when any attempt fails")
    matrix.set_defaults(func=cmd_matrix)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except ConfigError as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return EXIT_CONFIG
    except DeviceMismatch as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return EXIT_DEVICE
    except UsbRecoveryError as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return EXIT_USB
    except ChatCleanupError as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return EXIT_CHAT
    except PayloadError as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return EXIT_CONFIG
    except UsbDropped as exc:
        print("ERROR: USB link dropped: %s" % exc, file=sys.stderr)
        return EXIT_USB
    except (CommandTimeout, CommandFailed, RunnerError) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001
        print("ERROR: unexpected %s: %s" % (type(exc).__name__, exc),
              file=sys.stderr)
        return EXIT_ERROR


# ---------------------------------------------------------------------------
# shared construction
# ---------------------------------------------------------------------------
def _parse_point(value: str) -> tuple[float, float]:
    pieces = [piece.strip() for piece in str(value).replace(";", ",").split(",")]
    if len(pieces) != 2:
        raise ConfigError("--tap expects X,Y pixels: %r" % value)
    try:
        x, y = float(pieces[0]), float(pieces[1])
    except ValueError as exc:
        raise ConfigError("invalid --tap coordinates: %r" % value) from exc
    return x, y


def _parse_drag(value: str) -> tuple[float, float, float, float]:
    pieces = [piece.strip() for piece in str(value).replace(";", ",").split(",")]
    if len(pieces) != 4:
        raise ConfigError("--drag expects X1,Y1,X2,Y2 pixels: %r" % value)
    try:
        return tuple(float(piece) for piece in pieces)  # type: ignore[return-value]
    except ValueError as exc:
        raise ConfigError("invalid --drag coordinates: %r" % value) from exc


def build_config(args) -> RuntimeConfig:
    target = Target(
        model=args.expect_model,
        os_version=args.expect_os,
        build=args.expect_build,
        bundle_id=args.bundle,
        app_version=args.expect_app_version,
        app_build=args.expect_app_build,
    )
    paths = RunPaths.create(args.out, args.state_dir, args.payload_root)
    shot_extra = tuple(
        float(piece) for piece in str(getattr(args, "shot_extra", "") or "").split(",")
        if piece.strip()
    )
    cfg = RuntimeConfig(
        target=target,
        udid=args.udid,
        appgroup=getattr(args, "appgroup", None),
        chat_id=getattr(args, "chat_id", None),
        account_id=getattr(args, "account_id", None),
        p3=args.p3,
        usb_recover=args.usb_recover,
        recover_python=getattr(args, "recover_python", None),
        paths=paths,
        usb_attempts=max(1, int(getattr(args, "usb_attempts", 3))),
        skip_app_check=bool(getattr(args, "skip_app_check", False)),
        device_timeout=args.timeout,
        command_timeout=args.timeout,
        launch_wait=getattr(args, "launch_wait", 3.5),
        launch_taps=tuple(_parse_point(value) for value in getattr(args, "tap", []) or []),
        launch_drags=tuple(_parse_drag(value) for value in getattr(args, "drag", []) or []),
        tap_delay=getattr(args, "tap_delay", 0.7),
        shot_start=getattr(args, "shot_start", 0.6),
        shot_count=getattr(args, "shot_count", 12),
        shot_interval=getattr(args, "shot_interval", 0.25),
        shot_extra=shot_extra,
        screenshots=getattr(args, "screenshots", True),
        ocr_mode=getattr(args, "ocr", "auto"),
        ocr_max=getattr(args, "ocr_max", 6),
        no_launch=getattr(args, "no_launch", False),
        console_log=getattr(args, "console_log", None),
        kill_existing=getattr(args, "kill_existing", True),
        backup=getattr(args, "backup", False),
        backup_regex=getattr(args, "backup_regex", None),
        backup_cli=getattr(args, "backup_cli", "modern"),
        require_proof=getattr(args, "require_proof", False),
        token=getattr(args, "token", None),
        api=getattr(args, "api", "beta"),
        allow_queries=getattr(args, "allow_queries", True),
        background_query=getattr(args, "background_query", True),
        widget_height=getattr(args, "height", None),
        widget_width=getattr(args, "width", None),
        success_markers=tuple(getattr(args, "success_marker", None) or
                              (r"HIT=|RESULT\b|N17E|js_free_rt",)),
        expect=getattr(args, "expect", "marker_or_proof"),
        redact=bool(args.redact),
        dry_run=bool(args.dry_run),
        verbose=bool(args.verbose),
        fail_on_frida=bool(getattr(args, "fail_on_frida", False)),
    )
    return cfg


def build_redactor(args) -> Redactor:
    if not args.redact:
        return null_redactor()
    redactor = Redactor().add_home()
    redactor.add(getattr(args, "token", None), "<BOT_TOKEN>")
    redactor.add(getattr(args, "udid", None), "<UDID>")
    redactor.add(getattr(args, "appgroup", None), "<APPGROUP>")
    redactor.add(getattr(args, "chat_id", None), "<CHAT_ID>")
    redactor.add(getattr(args, "account_id", None), "<ACCOUNT_ID>")
    return redactor


def build_ocr(cfg: RuntimeConfig) -> OcrEngine:
    return OcrEngine(cfg.ocr_mode)


def build_device(cfg: RuntimeConfig) -> DeviceManager:
    return DeviceManager(
        CommandRunner(),
        p3=cfg.p3,
        target=cfg.target,
        udid=cfg.udid,
        timeout=cfg.command_timeout,
        recover_python=cfg.recover_python,
    )


def build_bot(cfg: RuntimeConfig, *, allow_placeholder: bool = False) -> BotClient:
    token = cfg.token
    if not token and allow_placeholder:
        token = PLACEHOLDER_TOKEN
    if not token:
        raise ConfigError("no bot token: pass --token or set BOT_TOKEN (never commit it)")
    return BotClient(token, api=cfg.api, timeout=cfg.command_timeout)


def _ledger(cfg: RuntimeConfig) -> ChatLedger:
    return ChatLedger.load(cfg.paths.state_dir / "ledger.json")


def _require_chat(cfg: RuntimeConfig) -> str:
    if not cfg.chat_id:
        raise ConfigError("--chat-id is required (or set $I17E_CHAT_ID)")
    return str(cfg.chat_id)


def _require_udid(cfg: RuntimeConfig) -> str:
    if not cfg.udid:
        raise ConfigError("--udid is required (or set $I17E_UDID)")
    return str(cfg.udid)


def _resolve_payload_arg(cfg: RuntimeConfig, value: str) -> str:
    path = Path(value).expanduser()
    if path.is_absolute():
        return str(path)
    if cfg.paths and cfg.paths.payload_root:
        candidate = cfg.paths.payload_root / path
        if candidate.exists():
            return str(candidate)
    return str(path.resolve())


def _print_json(data) -> None:
    print(json.dumps(data, indent=2, sort_keys=True))


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------
def cmd_doctor(args) -> int:
    cfg = build_config(args)
    if cfg.dry_run:
        _print_json({"status": "plan", "expected": cfg.target.to_dict(),
                     "check": "usbmux list + apps query"})
        return EXIT_OK
    device = build_device(cfg)
    check = device.check(skip_app=bool(args.skip_app_check))
    print("OK: %s %s %s (build %s), %s %s (%s)" % (
        check.model, check.os_version, check.connection or "USB",
        check.build, check.bundle_id, check.app_version, check.app_build))
    print("UDID: %s" % mask_udid(check.udid))
    return EXIT_OK


def cmd_recover(args) -> int:
    cfg = build_config(args)
    udid = _require_udid(cfg)
    device = build_device(cfg)
    if cfg.dry_run:
        _print_json(build_redactor(args).obj({
            "status": "plan",
            "cmd": ["python3", cfg.usb_recover, "--udid", "<UDID>",
                    "--pymobiledevice3", cfg.p3, "--attempts", str(args.attempts)],
        }))
        return EXIT_OK
    device.recover(cfg.usb_recover, attempts=args.attempts)
    check = device.check(skip_app=bool(args.skip_app_check))
    print("RECOVERED: %s %s %s" % (check.model, check.os_version, check.build))
    return EXIT_OK


def cmd_clean(args) -> int:
    cfg = build_config(args)
    chat = cfg.chat_id or "<CHAT_ID>"
    if not cfg.dry_run:
        chat = _require_chat(cfg)
    ledger = _ledger(cfg)
    ocr = build_ocr(cfg)
    bot = build_bot(cfg, allow_placeholder=cfg.dry_run)
    cleaner = ChatCleaner(bot, ledger, ocr)

    ids = parse_id_list(args.delete_id)
    if args.ids_file:
        ids += read_id_file(args.ids_file)
    payload_ids = parse_id_list(args.payload_id)
    anchor_ids = parse_id_list(args.anchor_id)
    if payload_ids and not cfg.dry_run:
        cleaner.register_ids(chat, payload_ids, "payload")
    if anchor_ids and not cfg.dry_run:
        cleaner.register_ids(chat, anchor_ids, "anchor")

    screenshot = args.screenshot
    if args.verify_screenshot and not screenshot and not cfg.dry_run:
        device = build_device(cfg)
        device.ensure_connected(
            cfg.usb_recover,
            recovery_attempts=max(0, cfg.usb_attempts - 1),
            skip_app=True,
        )
        screenshot = str(cfg.paths.shot_dir / "clean_pre_send.png")
        command = device.screenshot(screenshot)
        if not command.ok or not os.path.isfile(screenshot) or os.path.getsize(screenshot) == 0:
            raise CommandFailed(command, "clean-up screenshot failed: %s"
                                % command.brief(600))
    result = cleaner.clean(
        chat,
        extra_ids=sorted(set(ids) | set(payload_ids) | set(anchor_ids)),
        dry_run=cfg.dry_run,
        screenshot=screenshot,
        verify_screenshot=bool(args.verify_screenshot and screenshot),
    )
    _print_json(build_redactor(args).obj(result.to_dict()))
    if result.clean:
        return EXIT_OK
    return EXIT_CHAT


def cmd_send(args) -> int:
    cfg = build_config(args)
    chat = cfg.chat_id or "<CHAT_ID>"
    if not cfg.dry_run:
        chat = _require_chat(cfg)
    info, data = inspect_payload(
        _resolve_payload_arg(cfg, args.html),
        raw_limit=cfg.payload_raw_limit,
        zlib_limit=cfg.payload_zlib_limit,
    )
    if args.expect_sha256 and not hash_matches(info.sha256, args.expect_sha256):
        raise PayloadError("payload sha256 %s does not match expected %s"
                           % (info.sha256, args.expect_sha256))
    if cfg.dry_run:
        print("[*] payload %d raw / %d zlib9 / sha256 %s"
              % (info.raw, info.zlib9, info.sha256))
        print("[*] POST %s chat_id=%s"
              % (build_bot(cfg, allow_placeholder=True).safe_endpoint("sendWidget"), chat))
        return EXIT_OK

    bot = build_bot(cfg)
    ledger = _ledger(cfg)
    before_max = ledger.known_max_message_id(chat)
    outcome = bot.send_widget(
        chat,
        data.decode("utf-8", "replace"),
        allow_queries=cfg.allow_queries,
        background_query=cfg.background_query,
        height=cfg.widget_height,
        width=cfg.widget_width,
    )
    ledger.add_payload(chat, outcome.message_id, info.sha256, None)
    ledger.save()
    print("sent: message_id=%s widget_id=%s raw=%d zlib9=%d sha256=%s"
          % (outcome.message_id, outcome.widget_id, info.raw, info.zlib9, info.sha256))
    print("last_message_ok=%s previous_max=%s"
          % (before_max is None or outcome.message_id > before_max, before_max))
    return EXIT_OK


def cmd_run(args) -> int:
    cfg = build_config(args)
    if cfg.dry_run:
        cfg.chat_id = cfg.chat_id or "<CHAT_ID>"
    else:
        _require_chat(cfg)
    if not cfg.dry_run:
        _require_udid(cfg)
        if (cfg.backup or cfg.require_proof) and not cfg.appgroup and not cfg.backup_regex:
            raise ConfigError(
                "proof backup needs --appgroup/$I17E_APPGROUP or --backup-regex"
            )
        if cfg.backup_regex and "<APPGROUP>" in cfg.backup_regex and not cfg.appgroup:
            raise ConfigError(
                "--backup-regex uses <APPGROUP> but --appgroup/$I17E_APPGROUP "
                "is not set"
            )
    ledger = _ledger(cfg)
    ocr = build_ocr(cfg)
    bot = build_bot(cfg, allow_placeholder=cfg.dry_run)
    cleaner = ChatCleaner(bot, ledger, ocr)
    reporter = Reporter(cfg.paths, build_redactor(args))
    device = build_device(cfg)
    runner = AttemptRunner(
        cfg, device=device, bot=bot, cleaner=cleaner, ocr=ocr,
        reporter=reporter, log=lambda message: print(message, file=sys.stderr),
    )
    spec = AttemptSpec(
        label=args.label,
        payload=args.html,
        expect=args.expect,
        success_markers=args.success_marker,
        backup_regex=args.backup_regex,
        require_proof=args.require_proof,
        expect_sha256=args.expect_sha256,
    )
    extra_ids = parse_id_list(args.delete_id)
    result = runner.run(spec, extra_delete_ids=extra_ids)
    _print_json(result.to_dict(reporter.redactor))
    return _exit_for_verdict(result.verdict)


def cmd_matrix(args) -> int:
    cfg = build_config(args)
    if cfg.dry_run:
        cfg.chat_id = cfg.chat_id or "<CHAT_ID>"
    else:
        _require_chat(cfg)
    if not cfg.dry_run:
        _require_udid(cfg)
    # Matrix specs may carry placeholders; expand with the current values.
    spec = load_matrix(
        args.spec,
        payload_root=(str(cfg.paths.payload_root) if cfg.paths.payload_root else None),
        appgroup=cfg.appgroup,
        udid=cfg.udid,
        chat_id=cfg.chat_id,
        allow_unresolved=cfg.dry_run,
    )
    if not cfg.dry_run:
        for attempt in spec.attempts:
            if attempt.require_proof and not attempt.backup_regex and not cfg.appgroup:
                raise ConfigError(
                    "attempt %s requires proof but no --appgroup/$I17E_APPGROUP "
                    "or --backup-regex was supplied" % attempt.label
                )
    ledger = _ledger(cfg)
    ocr = build_ocr(cfg)
    bot = build_bot(cfg, allow_placeholder=cfg.dry_run)
    cleaner = ChatCleaner(bot, ledger, ocr)
    reporter = Reporter(cfg.paths, build_redactor(args))
    device = build_device(cfg)
    runner = AttemptRunner(
        cfg, device=device, bot=bot, cleaner=cleaner, ocr=ocr,
        reporter=reporter, log=lambda message: print(message, file=sys.stderr),
    )
    matrix = MatrixRunner(
        spec, runner, reporter,
        log=lambda message: print(message, file=sys.stderr),
        stop_on_invalid=args.stop_on_invalid, dry_run=cfg.dry_run,
    )
    summary = matrix.run()
    _print_json(reporter.redactor.obj(summary.to_dict()))
    invalid_reasons = {
        (attempt or {}).get("reason")
        for attempt in summary.attempts
        if (attempt or {}).get("status") in ("invalid", "error")
    }
    if "wrong_device" in invalid_reasons:
        return EXIT_DEVICE
    if "usb_unavailable" in invalid_reasons:
        return EXIT_USB
    if "chat_dirty" in invalid_reasons:
        return EXIT_CHAT
    if summary.counts.get("invalid"):
        return EXIT_ERROR
    if args.strict and summary.counts.get("failed"):
        return EXIT_FAIL
    return EXIT_OK


def _exit_for_verdict(verdict: dict) -> int:
    status = (verdict or {}).get("status")
    reason = (verdict or {}).get("reason")
    if status in ("pass", "plan", "manual"):
        return EXIT_OK
    if status == "fail":
        return EXIT_FAIL
    if reason == "wrong_device":
        return EXIT_DEVICE
    if reason == "usb_unavailable":
        return EXIT_USB
    if reason == "chat_dirty":
        return EXIT_CHAT
    if status in ("invalid", "error"):
        return EXIT_ERROR
    return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
