"""One-attempt pipeline for the iPhone 17e matrices.

Order of operations (the same as the campaign runbook):

  verify device -> clean chat -> launch with console -> verify chat screen
  -> capture log offset -> send widget as the last message -> screenshots
  -> console tail + OCR -> app state -> proof backup -> delete the payload
  -> JSON/Markdown result.

Every step is bounded by a timeout; USB drops trigger the documented recovery
and a bounded retry.  The console attachment is terminated in ``finally`` so no
CoreDevice process is left behind.
"""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path

from .clean import ChatCleaner, CleanupResult
from .config import RuntimeConfig, expand_placeholders, require_appgroup
from .errors import (
    BotApiError,
    ChatCleanupError,
    CommandFailed,
    CommandTimeout,
    DeviceMismatch,
    LaunchError,
    PayloadError,
    ProofError,
    RunnerError,
    UsbDropped,
    UsbRecoveryError,
)
from .markers import (
    DEFAULT_SUCCESS_MARKERS,
    extract_markers,
    first_success_line,
    looks_like_widget_marker,
    matches_success,
)
from .model import AttemptResult, AttemptSpec
from .payload import hash_matches, inspect_payload
from .proc import file_size, looks_like_usb_drop, read_from
from .proof import ProofReport, collect_backup_matches, summarize

PRE_SEND_SHOT = "pre_send.png"


def wall_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class AttemptRunner:
    def __init__(
        self,
        cfg: RuntimeConfig,
        *,
        device,
        bot,
        cleaner: ChatCleaner,
        ocr,
        reporter,
        sleep=time.sleep,
        monotonic=time.monotonic,
        log=print,
    ):
        if cfg.paths is None:
            raise ValueError("RuntimeConfig.paths is required")
        self.cfg = cfg
        self.device = device
        self.bot = bot
        self.cleaner = cleaner
        self.ocr = ocr
        self.reporter = reporter
        self.sleep = sleep
        self.monotonic = monotonic
        self.log = log

    # -- public ----------------------------------------------------------
    def run(self, spec: AttemptSpec, *, occurrence: int = 1,
            extra_delete_ids=()) -> AttemptResult:
        result = AttemptResult(label=spec.label, index=occurrence)
        result.chat["id"] = self.cfg.chat_id
        started = self.monotonic()
        timeline: dict = {"t_start": wall_now()}

        payload_info = None
        html = None
        handle = None
        sent_mid = None
        sent_sha = None
        fatal: tuple[str, str, bool] | None = None
        clean_after_needed = False
        dry_run = False

        try:
            payload_info, html = inspect_payload(
                self._resolve_payload(spec.payload),
                raw_limit=self.cfg.payload_raw_limit,
                zlib_limit=self.cfg.payload_zlib_limit,
            )
            result.payload.update(payload_info.to_dict())
            self._check_expected_hash(payload_info.sha256, spec)

            if self.cfg.dry_run:
                dry_run = True
                return self._finish_dry_run(result, spec, payload_info, extra_delete_ids,
                                            started)

            self._log("device check")
            check = self.device.ensure_connected(
                self.cfg.usb_recover,
                recovery_attempts=max(0, self.cfg.usb_attempts - 1),
                sleep=self.sleep,
                skip_app=self.cfg.skip_app_check,
            )
            result.device = check.to_dict()
            timeline["t_device_ok"] = wall_now()

            self._check_frida(result)

            self._log("chat cleanup")
            clean_before = self.cleaner.clean(
                self.cfg.chat_id, extra_ids=extra_delete_ids, dry_run=False
            )
            result.chat["clean_before_send"] = clean_before.clean
            result.chat["deleted_ids"] = clean_before.removed_ids
            result.chat["cleanup_before"] = clean_before.to_dict()
            timeline["t_clean_ok"] = wall_now()
            self._require_clean(clean_before)

            self._log("launch")
            handle = self._launch(result)
            timeline["t_launch"] = wall_now()
            self._post_launch_input(result)
            timeline["t_input"] = wall_now()

            pre_shot = self._pre_send_verify(result, handle, clean_before)
            if pre_shot is not None and pre_shot:
                clean_before.screenshot_markers = pre_shot
                clean_before.screenshot = str(
                    self.cfg.paths.shot_dir / PRE_SEND_SHOT
                )
                self._require_clean(clean_before)
            timeline["t_pre_send_ok"] = wall_now()

            log_path = self._log_path(handle)
            offset_send = file_size(log_path)
            result.logs.update({
                "path": str(log_path),
                "offset_before": getattr(handle, "offset", 0) if handle else 0,
                "offset_send": offset_send,
            })
            timeline["t_send"] = wall_now()
            self._log("send")
            send = self.bot.send_widget(
                self.cfg.chat_id,
                html.decode("utf-8", "replace"),
                allow_queries=self.cfg.allow_queries,
                background_query=self.cfg.background_query,
                height=self.cfg.widget_height,
                width=self.cfg.widget_width,
            )
            sent_mid = send.message_id
            clean_after_needed = True
            sent_sha = payload_info.sha256
            before_max = self.cleaner.ledger.known_max_message_id(self.cfg.chat_id)
            self.cleaner.ledger.add_payload(
                self.cfg.chat_id, sent_mid, sent_sha, wall_now()
            )
            self.cleaner.ledger.save()
            result.payload["message_id"] = sent_mid
            result.chat["last_message_ok"] = before_max is None or sent_mid > before_max
            result.chat["previous_max_message_id"] = before_max

            shots = self._capture_shots(result)
            self._read_console_and_ocr(result, spec, log_path, offset_send, shots)
            self._app_state(result, handle)
            self._read_proof(result, spec)
            timeline["t_proof_done"] = wall_now()

            if spec.require_proof and not (result.proof or {}).get("proof_ok"):
                fatal = ("fail", "proof_missing", False)

        except DeviceMismatch as exc:
            result.error("wrong_device", str(exc))
            fatal = ("invalid", "wrong_device", False)
        except ChatCleanupError as exc:
            result.error("chat_dirty", str(exc))
            cleanup_result = getattr(exc, "result", None)
            if cleanup_result is not None:
                result.chat["cleanup_before"] = cleanup_result.to_dict()
                result.chat["clean_before_send"] = cleanup_result.clean
            fatal = ("invalid", "chat_dirty", False)
        except UsbRecoveryError as exc:
            result.error("usb", str(exc))
            fatal = ("invalid", "usb_unavailable", False)
        except LaunchError as exc:
            result.error("launch", str(exc))
            fatal = ("invalid", "launch_failed", False)
        except PayloadError as exc:
            result.error("payload", str(exc))
            fatal = ("invalid", "payload_invalid", False)
        except BotApiError as exc:
            result.error("bot_api", str(exc))
            fatal = ("invalid", "send_failed" if sent_mid is None else "bot_api", False)
        except UsbDropped as exc:
            result.error("usb", str(exc))
            fatal = ("invalid", "usb_unavailable", False)
        except (CommandFailed, CommandTimeout, ProofError) as exc:
            result.error("command", str(exc))
            fatal = ("error", "command_failed", False)
        except RunnerError as exc:
            result.error("runner", str(exc))
            fatal = ("error", "runner_error", False)
        except Exception as exc:  # noqa: BLE001
            result.error("unexpected", "%s: %s" % (type(exc).__name__, exc))
            fatal = ("error", "unexpected", False)
        finally:
            if not dry_run:
                # Delete the payload even if a later step failed: the next
                # attempt must start from a clean chat.
                if sent_mid is not None and clean_after_needed:
                    try:
                        cleanup_after = self.cleaner.clean(
                            self.cfg.chat_id, extra_ids=[sent_mid], dry_run=False
                        )
                        result.chat["clean_after"] = cleanup_after.clean
                        result.chat["cleanup_after"] = cleanup_after.to_dict()
                        result.chat["deleted_after"] = cleanup_after.removed_ids
                        if not cleanup_after.clean:
                            result.error(
                                "cleanup_after",
                                "payload message %s could not be deleted after "
                                "the run; the next attempt will retry" % sent_mid,
                            )
                    except Exception as exc:  # noqa: BLE001
                        result.chat["clean_after"] = False
                        result.error("cleanup_after", str(exc))

                result.processes.update(self._stop_and_check(result, handle))
                timeline["t_end"] = wall_now()
                result.timeline.update(timeline)
                result.timeline["durations"] = self._durations(result, started, timeline)
                result.duration_s = self.monotonic() - started

                if fatal is None:
                    self._verdict(result, spec)
                else:
                    status, reason, success = fatal
                    result.finish(status=status, reason=reason, success=success)

                result.extras.setdefault("spec", spec.to_dict())
                result.extras.setdefault("cfg", {
                    "api": self.cfg.api,
                    "screenshots": self.cfg.screenshots,
                    "ocr": self.cfg.ocr_mode,
                    "backup": self.cfg.backup,
                    "redacted": self.cfg.redact,
                    "dry_run": self.cfg.dry_run,
                })
                try:
                    self._learn_secrets(json.dumps(result.to_dict(), default=str))
                except Exception:
                    pass
                try:
                    paths = self.reporter.write_attempt(result)
                    result.extras["artifacts"] = paths
                except Exception as exc:  # noqa: BLE001
                    self.log("WARNING: could not write result: %s" % exc)
        return result

    # -- steps -----------------------------------------------------------
    def _resolve_payload(self, payload: str) -> str:
        path = Path(payload).expanduser()
        if path.is_absolute():
            return str(path)
        if self.cfg.paths and self.cfg.paths.payload_root:
            candidate = self.cfg.paths.payload_root / path
            if candidate.exists():
                return str(candidate)
        return str(path.resolve())

    def _check_expected_hash(self, actual: str, spec: AttemptSpec) -> None:
        expected = getattr(spec, "expect_sha256", None)
        if expected and not hash_matches(actual, expected):
            raise PayloadError(
                "payload sha256 %s does not match expected %s" % (actual, expected)
            )

    def _check_frida(self, result: AttemptResult) -> None:
        try:
            pids = self.device.frida_pids()
        except Exception:  # noqa: BLE001
            pids = []
        result.processes["frida_before"] = pids
        if pids:
            message = (
                "frida process(es) already attached: %s; this tool never starts "
                "frida — stop them before a device run" % pids
            )
            if self.cfg.fail_on_frida:
                raise RunnerError(message)
            result.error("frida_present", message)

    def _launch(self, result: AttemptResult):
        if self.cfg.no_launch:
            log_path = self.cfg.console_log
            if not log_path:
                raise LaunchError("--no-launch requires --console-log")
            result.logs.update({"path": str(log_path), "offset_before": file_size(log_path),
                                "mode": "warm"})
            return None

        attempts = max(1, self.cfg.usb_attempts)
        last_error: LaunchError | None = None
        for attempt in range(attempts):
            try:
                return self._launch_once(result)
            except LaunchError as exc:
                last_error = exc
                if attempt + 1 >= attempts:
                    break
                result.error("launch_retry", str(exc))
                self._log("launch failed; recovering USB and retrying")
                try:
                    self.device.recover(self.cfg.usb_recover, attempts=2)
                except Exception as recover_exc:  # noqa: BLE001
                    result.error("usb_recover", str(recover_exc))
                self.sleep(2.0)
        raise last_error or LaunchError("launch failed")

    def _launch_once(self, result: AttemptResult):
        if self.cfg.kill_existing:
            stale = self.device.console_pids()
            result.processes["stale_console_before"] = stale
            if stale:
                result.processes["stale_console_killed"] = self.device.kill_pids(stale)

        log_path = self.cfg.paths.log_dir / ("%s_%02d_console.log"
                                             % (_safe(result.label), result.index))
        handle = None
        try:
            handle = self.device.launch_console(
                log_path,
                kill_existing=self.cfg.kill_existing,
                wait=self.cfg.launch_wait,
                sleep=self.sleep,
            )
            result.logs.update({
                "path": str(log_path),
                "offset_before": handle.offset,
                "launch_cmd": list(handle.cmd),
            })
            if not handle.alive:
                tail = read_from(log_path, handle.offset, 4000)
                raise LaunchError(
                    "launch-application exited early (rc=%s): %s"
                    % (handle.returncode, tail[-1200:])
                )
            return handle
        except Exception:
            if handle is not None and handle.alive:
                handle.stop()
            raise

    def _post_launch_input(self, result: AttemptResult) -> None:
        """Optional HID taps/drags to open the chat after a relaunch."""

        events: list[dict] = []
        result.extras.setdefault("input", {"taps": [], "drags": []})
        for x, y in self.cfg.launch_taps:
            events.append({
                "kind": "tap",
                "x": x,
                "y": y,
                "ok": self._hid_with_retry(result, lambda: self.device.tap(x, y)),
            })
        for x1, y1, x2, y2 in self.cfg.launch_drags:
            events.append({
                "kind": "drag",
                "x1": x1,
                "y1": y1,
                "x2": x2,
                "y2": y2,
                "ok": self._hid_with_retry(
                    result, lambda: self.device.drag(x1, y1, x2, y2)
                ),
            })
        result.extras["input"] = {
            "taps": [event for event in events if event["kind"] == "tap"],
            "drags": [event for event in events if event["kind"] == "drag"],
        }
        if events and not all(event["ok"] for event in events):
            raise LaunchError("post-launch HID input failed; see extras.input")

    def _hid_with_retry(self, result: AttemptResult, action) -> bool:
        attempts = max(1, min(3, self.cfg.usb_attempts))
        for attempt in range(attempts):
            command = action()
            if command.ok:
                self.sleep(self.cfg.tap_delay)
                return True
            if attempt + 1 < attempts:
                result.error("hid", "input failed (rc=%s): %s"
                             % (command.returncode, command.brief(400)))
                try:
                    self.device.recover(self.cfg.usb_recover, attempts=2)
                except Exception as exc:  # noqa: BLE001
                    result.error("usb_recover", str(exc))
                self.sleep(2.0)
        return False

    def _pre_send_verify(self, result: AttemptResult, handle, clean_before):
        if not self.cfg.screenshots:
            return None
        path = self.cfg.paths.shot_dir / PRE_SEND_SHOT
        ok = self._screenshot_with_retry(result, path)
        result.chat["pre_send_screenshot"] = str(path) if ok else None
        if not ok:
            return None
        if not getattr(self.ocr, "available", False):
            result.ocr = {"available": False, "error": getattr(self.ocr, "error", None)}
            return None
        ocr_result = self.ocr.read(str(path))
        result.ocr = {"available": True, "error": ocr_result.error,
                      "pre_send_text": ocr_result.text[:4000]}
        return looks_like_widget_marker(ocr_result.text)

    def _require_clean(self, cleanup: CleanupResult) -> None:
        if not cleanup.clean:
            error = ChatCleanupError(
                "chat is not clean before the run: %s"
                % (cleanup.failed or cleanup.screenshot_markers),
                failures=cleanup.failed,
                deleted=cleanup.deleted_ids,
            )
            error.result = cleanup  # type: ignore[attr-defined]
            raise error

    def _screenshot_with_retry(self, result: AttemptResult, path: Path) -> bool:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            try:
                path.unlink()
            except OSError:
                pass
        attempts = max(1, self.cfg.usb_attempts)
        for attempt in range(attempts):
            command = self.device.screenshot(path)
            if command.ok and path.exists() and path.stat().st_size > 0:
                return True
            if attempt + 1 < attempts and (looks_like_usb_drop(command) or not command.ok):
                self.log("screenshot failed; recovering USB")
                try:
                    self.device.recover(self.cfg.usb_recover, attempts=2)
                except Exception as exc:  # noqa: BLE001
                    result.error("usb_recover", str(exc))
                self.sleep(2.0)
            else:
                result.error(
                    "screenshot",
                    "screen-capture failed (rc=%s): %s"
                    % (command.returncode, command.brief(500)),
                )
        return False

    def _capture_shots(self, result: AttemptResult) -> list[dict]:
        if not self.cfg.screenshots:
            return []
        schedule = self._shot_schedule()
        shots: list[dict] = []
        base = self.monotonic()
        for index, delay in enumerate(schedule, start=1):
            target = base + delay
            now = self.monotonic()
            if target > now:
                self.sleep(target - now)
            path = self.cfg.paths.shot_dir / (
                "%s_%02d_s%02d.png" % (_safe(result.label), result.index, index)
            )
            started = self.monotonic()
            ok = self._screenshot_with_retry(result, path)
            shot = {
                "index": index,
                "t_rel_s": round(started - base, 3),
                "path": str(path),
                "ok": ok,
                "size": file_size(path),
                "ocr": None,
                "markers": [],
            }
            shots.append(shot)
            result.screenshots.append(shot)
            if index == 1:
                result.timeline["t_first_shot"] = wall_now()
            result.timeline["t_last_shot"] = wall_now()
        return shots

    def _shot_schedule(self) -> list[float]:
        schedule: list[float] = []
        count = max(0, self.cfg.shot_count)
        for index in range(count):
            delay = self.cfg.shot_start + index * self.cfg.shot_interval
            if delay >= 0:
                schedule.append(delay)
        schedule.extend(delay for delay in self.cfg.shot_extra if delay >= 0)
        return sorted(set(round(value, 3) for value in schedule))

    def _read_console_and_ocr(self, result: AttemptResult, spec: AttemptSpec,
                              log_path: Path, offset: int, shots: list[dict]) -> None:
        text = read_from(log_path, offset, limit=2 << 20)
        launch_offset = int(result.logs.get("offset_before") or 0)
        launch_text = read_from(log_path, launch_offset,
                                max(0, offset - launch_offset) + 4000)
        result.logs.update({
            "new_bytes": max(0, file_size(log_path) - offset),
            "tail": text[-20000:],
            "launch_tail": launch_text[-8000:],
            "marker_lines": [
                line.strip() for line in text.splitlines()
                if looks_like_widget_marker(line)
            ][:50],
        })
        ocr_text = self._ocr_shots(result, shots)
        combined = text + ("\n" + ocr_text if ocr_text else "")
        self._learn_secrets(combined)
        markers = extract_markers(combined)
        result.marker = markers.to_dict()
        if markers.found:
            result.timeline["t_marker_observed"] = wall_now()
        success_line = first_success_line(
            combined, self._success_markers_for_spec(spec)
        )
        if success_line:
            result.marker["success_line"] = success_line

    def _ocr_shots(self, result: AttemptResult, shots: list[dict]) -> str:
        if not shots:
            return ""
        if not getattr(self.ocr, "available", False):
            result.ocr = {"available": False, "error": getattr(self.ocr, "error", None)}
            return ""
        limit = max(0, min(self.cfg.ocr_max, len(shots)))
        if limit == 0:
            return ""
        if len(shots) <= limit:
            selected = shots
        else:
            indexes = sorted({round(i * (len(shots) - 1) / (limit - 1))
                              for i in range(limit)})
            selected = [shots[i] for i in indexes]
        texts: list[str] = []
        records: list[dict] = []
        for shot in selected:
            ocr_result = self.ocr.read(shot["path"])
            shot["ocr"] = {"available": ocr_result.available,
                           "error": ocr_result.error,
                           "text": ocr_result.text[:4000]}
            shot["markers"] = looks_like_widget_marker(ocr_result.text)
            records.append({"path": shot["path"], "error": ocr_result.error,
                            "text": ocr_result.text[:4000]})
            if ocr_result.text:
                texts.append(ocr_result.text)
        result.ocr = {"available": True, "selected": records,
                      "error": records[0]["error"] if records else None}
        return "\n".join(texts)

    def _app_state(self, result: AttemptResult, handle) -> None:
        if handle is None:
            result.app = {"state": "unknown", "evidence": "warm mode (--no-launch)"}
            return
        returncode = handle.proc.poll()
        if returncode is None:
            result.app = {"state": "alive", "evidence": "console process is still attached",
                          "exit_code": None}
        else:
            result.app = {"state": "dead",
                          "evidence": "console process exited (rc=%s)" % returncode,
                          "exit_code": returncode}
        joined = "\n".join(
            str(item.get("text") or "") for item in (result.ocr or {}).get("selected", [])
        ) if isinstance(result.ocr, dict) else ""
        if "Widget stopped" in joined:
            result.app["bubble"] = "stopped"
        elif (result.marker or {}).get("found"):
            result.app["bubble"] = "marker"
        elif joined:
            result.app["bubble"] = "blank"
        else:
            result.app["bubble"] = "unknown"

    def _read_proof(self, result: AttemptResult, spec: AttemptSpec) -> None:
        if not (self.cfg.backup or spec.require_proof or spec.backup_regex):
            return
        regex = spec.backup_regex or self.cfg.backup_regex
        try:
            regex = require_appgroup(self.cfg.appgroup, regex)
            regex = expand_placeholders(
                regex,
                appgroup=self.cfg.appgroup,
                udid=self.cfg.udid,
                chat_id=self.cfg.chat_id,
            )
        except Exception as exc:  # noqa: BLE001
            result.proof = ProofReport(error=str(exc), regex=regex).to_dict()
            result.error("proof_config", str(exc))
            return

        backup_dir = self.cfg.paths.backup_dir / (
            "%s_%02d" % (_safe(result.label), result.index)
        )
        report = ProofReport(attempted=True, regex=regex, backup_dir=str(backup_dir))
        last_exc = None
        for attempt in range(max(1, min(3, self.cfg.usb_attempts))):
            report.retries = attempt
            try:
                command = self.device.run_backup(
                    backup_dir, regex, legacy=(self.cfg.backup_cli == "legacy"),
                    timeout=self.cfg.backup_timeout,
                )
            except (UsbDropped, CommandFailed, CommandTimeout) as exc:
                last_exc = exc
                report.error = str(exc)
                if attempt + 1 < self.cfg.usb_attempts:
                    self.log("proof backup failed; recovering USB")
                    try:
                        self.device.recover(self.cfg.usb_recover, attempts=2)
                    except Exception as recover_exc:  # noqa: BLE001
                        report.error = "%s; recovery: %s" % (exc, recover_exc)
                    self.sleep(2.0)
                continue
            report.command = list(command.cmd)
            report.returncode = command.returncode
            report.duration_s = command.duration_s
            report.stdout_tail = command.stdout[-2000:]
            report.stderr_tail = command.stderr[-2000:]
            if not command.ok:
                report.error = "backup2 rc=%s: %s" % (
                    command.returncode, command.brief(1200))
                if looks_like_usb_drop(command) and attempt + 1 < self.cfg.usb_attempts:
                    try:
                        self.device.recover(self.cfg.usb_recover, attempts=2)
                    except Exception as recover_exc:  # noqa: BLE001
                        report.error = "%s; recovery: %s" % (report.error, recover_exc)
                    self.sleep(2.0)
                continue
            try:
                report.matches = collect_backup_matches(
                    backup_dir, regex, out_dir=backup_dir / "matches"
                )
                summarize(report)
                report.error = None
            except ProofError as exc:
                report.error = str(exc)
            break
        if last_exc is not None and not report.matches:
            report.error = report.error or str(last_exc)
        result.proof = report.to_dict()
        if report.error:
            result.error("proof", report.error)

    def _stop_and_check(self, result: AttemptResult, handle) -> dict:
        info: dict = {}
        if handle is not None:
            info["console_stop"] = handle.stop()
        try:
            remaining = self.device.console_pids()
        except Exception:  # noqa: BLE001
            remaining = []
        info["console_pids_after"] = remaining
        if remaining and handle is not None:
            info["leftover_killed"] = self.device.kill_pids(remaining)
        elif remaining:
            info["leftover_note"] = "warm mode: not killing a console started by the operator"
        try:
            frida_after = self.device.frida_pids()
        except Exception:  # noqa: BLE001
            frida_after = []
        info["frida_after"] = frida_after
        return info

    # -- verdict ---------------------------------------------------------
    def _verdict(self, result: AttemptResult, spec: AttemptSpec) -> None:
        marker = result.marker or {}
        text = marker.get("text") or ""
        patterns = self._success_markers_for_spec(spec)
        marker_ok = bool(marker.get("found")) and matches_success(text, patterns)
        proof_ok = bool((result.proof or {}).get("proof_ok"))
        app_state = (result.app or {}).get("state")
        guard = marker.get("guard")

        if guard:
            result.finish(status="fail", reason="endgame_guard", success=False)
            return

        expect = (spec.expect or self.cfg.expect or "marker_or_proof").lower()
        if expect == "marker":
            success = marker_ok
            reason = "marker" if success else "no_marker"
        elif expect == "proof":
            success = proof_ok
            reason = "proof" if success else "proof_missing"
        elif expect == "alive":
            success = app_state == "alive"
            reason = "app_alive" if success else "app_dead"
        elif expect == "any":
            success = marker_ok or proof_ok or app_state == "alive"
            reason = "marker_or_proof_or_alive" if success else "no_evidence"
        elif expect == "manual":
            result.finish(status="manual", reason="manual_review", success=None)
            return
        else:  # marker_or_proof (default)
            success = marker_ok or proof_ok
            reason = "marker" if marker_ok else ("proof" if proof_ok else "no_marker")
        if spec.require_proof and not proof_ok:
            success = False
            reason = "proof_missing"
        if success:
            result.finish(status="pass", reason=reason, success=True)
            return

        if app_state == "dead":
            reason = "app_dead_no_marker" if not marker.get("found") else "app_dead"
        elif not marker.get("found"):
            reason = "no_marker" if reason == "no_marker" else reason
        result.finish(status="fail", reason=reason, success=False)

    def _learn_secrets(self, text: str) -> None:
        """Add account/AppGroup values seen in the log to the artifact redactor."""

        redactor = getattr(self.reporter, "redactor", None)
        if redactor is None or not text:
            return
        for match in re.finditer(r"account-(\d{4,})", text):
            redactor.add(match.group(1), "<ACCOUNT_ID>")
        for match in re.finditer(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
            text,
        ):
            redactor.add(match.group(0), "<APPGROUP>")
        for match in re.finditer(
            r"currentAccountId[^0-9]{0,24}(\d{4,})", text
        ):
            redactor.add(match.group(1), "<ACCOUNT_ID>")

    def _success_markers_for_spec(self, spec_or_result) -> tuple[str, ...]:
        markers = getattr(spec_or_result, "success_markers", None)
        if markers:
            return tuple(markers)
        return tuple(self.cfg.success_markers or DEFAULT_SUCCESS_MARKERS)

    # -- dry run ---------------------------------------------------------
    def _finish_dry_run(self, result: AttemptResult, spec: AttemptSpec, payload_info,
                        extra_delete_ids, started) -> AttemptResult:
        planned_ids = self.cleaner.ledger.pending_ids(self.cfg.chat_id)
        planned_ids = sorted(set(planned_ids) | {int(v) for v in extra_delete_ids})
        result.chat = {
            "id": self.cfg.chat_id,
            "planned_delete_ids": planned_ids,
            "dry_run": True,
        }
        result.logs = {
            "planned": {
                "launch": self.device.launch_command(kill_existing=self.cfg.kill_existing),
                "screenshot": [self.cfg.p3, "developer", "core-device",
                               "screen-capture", "screenshot", "<path>", "--userspace"],
                "send": "POST %s (chat_id=%s, raw=%d, zlib9=%d)"
                        % (self.bot.safe_endpoint("sendWidget"), self.cfg.chat_id,
                           payload_info.raw, payload_info.zlib9),
                "input": {
                    "taps": [list(point) for point in self.cfg.launch_taps],
                    "drags": [list(point) for point in self.cfg.launch_drags],
                },
            }
        }
        result.device = {"checked": False, "dry_run": True,
                         "expected": self.cfg.target.to_dict()}
        result.verdict = {"status": "plan", "reason": "dry_run", "success": None}
        result.ended_at = wall_now()
        result.timeline = {"t_start": result.started_at, "t_end": result.ended_at}
        result.duration_s = self.monotonic() - started
        result.extras["spec"] = spec.to_dict()
        try:
            result.extras["artifacts"] = self.reporter.write_attempt(result)
        except Exception as exc:  # noqa: BLE001
            self.log("WARNING: could not write plan: %s" % exc)
        return result

    def _log_path(self, handle) -> Path:
        if handle is not None:
            return Path(handle.log_path)
        if self.cfg.console_log:
            return Path(self.cfg.console_log)
        raise LaunchError("no console log path")

    def _durations(self, result: AttemptResult, started: float, timeline: dict) -> dict:
        return {
            "total_s": round(self.monotonic() - started, 3),
            "launch_wait_s": self.cfg.launch_wait,
            "shot_count": len(result.screenshots),
        }

    def _log(self, message: str) -> None:
        if self.cfg.verbose:
            self.log("[i17e] %s" % message)


def _safe(value: str) -> str:
    import re

    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "attempt"
