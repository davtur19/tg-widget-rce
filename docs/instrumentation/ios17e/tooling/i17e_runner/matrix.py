"""Matrix specification loading and sequential execution."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from .config import expand_placeholders
from .errors import MatrixSpecError
from .model import AttemptSpec, MatrixSummary
from .stats import clopper_pearson_lower


@dataclass
class MatrixSpec:
    name: str
    attempts: list[AttemptSpec] = field(default_factory=list)
    notes: str | None = None
    payload_root: str | None = None
    path: str | None = None

    def expand(self) -> list[AttemptSpec]:
        expanded: list[AttemptSpec] = []
        for spec in self.attempts:
            for _ in range(spec.count):
                expanded.append(spec)
        return expanded

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "notes": self.notes,
            "payload_root": self.payload_root,
            "attempts": [spec.to_dict() for spec in self.attempts],
        }


def _expand(value: str, *, appgroup: str | None, udid: str | None,
            chat_id: str | None, allow_unresolved: bool) -> str:
    try:
        return expand_placeholders(value, appgroup=appgroup, udid=udid,
                                   chat_id=chat_id)
    except Exception:
        if allow_unresolved:
            return value
        raise


def load_matrix(path: str, *, payload_root: str | None = None,
                appgroup: str | None = None, udid: str | None = None,
                chat_id: str | None = None,
                allow_unresolved: bool = False) -> MatrixSpec:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except OSError as exc:
        raise MatrixSpecError("cannot read matrix %s: %s" % (path, exc)) from exc
    except json.JSONDecodeError as exc:
        raise MatrixSpecError("invalid JSON in %s: %s" % (path, exc)) from exc
    if not isinstance(data, dict):
        raise MatrixSpecError("matrix %s must be a JSON object" % path)

    name = str(data.get("name") or Path(path).stem)
    base_root = payload_root or data.get("payload_root")
    entries = data.get("attempts")
    if not isinstance(entries, list) or not entries:
        raise MatrixSpecError("matrix %s has no attempts[]" % path)

    attempts: list[AttemptSpec] = []
    for entry in entries:
        try:
            spec = AttemptSpec.from_dict(entry, base_dir=base_root)
        except (ValueError, TypeError) as exc:
            raise MatrixSpecError("matrix %s: %s" % (path, exc)) from exc
        # Expand documentation placeholders inside payload paths and regexes.
        spec.payload = _expand(spec.payload, appgroup=appgroup, udid=udid,
                               chat_id=chat_id,
                               allow_unresolved=allow_unresolved)
        if spec.backup_regex:
            spec.backup_regex = _expand(spec.backup_regex, appgroup=appgroup,
                                        udid=udid, chat_id=chat_id,
                                        allow_unresolved=allow_unresolved)
        if spec.success_markers:
            spec.success_markers = [
                _expand(marker, appgroup=appgroup, udid=udid, chat_id=chat_id,
                        allow_unresolved=allow_unresolved)
                for marker in spec.success_markers
            ]
        attempts.append(spec)
    return MatrixSpec(
        name=name,
        attempts=attempts,
        notes=data.get("notes"),
        payload_root=base_root,
        path=str(Path(path).resolve()),
    )


class MatrixRunner:
    def __init__(self, spec: MatrixSpec, runner, reporter, *, log=print,
                 sleep=time.sleep, stop_on_invalid: bool = True,
                 dry_run: bool = False):
        self.spec = spec
        self.runner = runner
        self.reporter = reporter
        self.log = log
        self.sleep = sleep
        self.stop_on_invalid = stop_on_invalid
        self.dry_run = dry_run
        self.attempt_counter: dict[str, int] = {}

    def run(self) -> MatrixSummary:
        summary = MatrixSummary(name=self.spec.name)
        results: list = []
        stats: dict[str, dict] = {}
        consecutive_deaths = 0
        stopped_labels: set[str] = set()
        invalid_stop = False

        for spec in self.spec.expand():
            if invalid_stop:
                summary.skipped.append({
                    "label": spec.label,
                    "reason": "stopped after an invalid attempt",
                })
                continue

            gate = spec.gate
            if gate and not self.dry_run:
                gate_label = str(gate.get("label") or "")
                minimum = int(gate.get("min_passed") or 0)
                actual = (stats.get(gate_label) or {}).get("passed", 0)
                if actual < minimum:
                    summary.skipped.append({
                        "label": spec.label,
                        "reason": "gate %s needs %d pass(es), got %d"
                                  % (gate_label, minimum, actual),
                    })
                    continue

            if spec.label in stopped_labels:
                summary.skipped.append({
                    "label": spec.label,
                    "reason": "stop condition already reached",
                })
                continue

            self.attempt_counter[spec.label] = self.attempt_counter.get(spec.label, 0) + 1
            occurrence = self.attempt_counter[spec.label]
            self.log("=== %s #%d ===" % (spec.label, occurrence))
            result = self.runner.run(spec, occurrence=occurrence)
            results.append(result)
            summary.attempts.append({
                "label": result.label,
                "index": result.index,
                "status": (result.verdict or {}).get("status"),
                "reason": (result.verdict or {}).get("reason"),
                "app_state": (result.app or {}).get("state"),
                "marker": (result.marker or {}).get("found"),
                "proof": bool((result.proof or {}).get("proof_ok")),
                "message_id": (result.payload or {}).get("message_id"),
            })

            label_stats = stats.setdefault(spec.label, {
                "label": spec.label,
                "n": 0,
                "passed": 0,
                "failed": 0,
                "invalid": 0,
                "manual": 0,
                "planned": 0,
                "app_deaths": 0,
                "markers": 0,
                "proofs": 0,
            })
            label_stats["n"] += 1
            verdict = result.verdict or {}
            status = verdict.get("status")
            if status == "pass":
                label_stats["passed"] += 1
            elif status == "manual":
                label_stats["manual"] += 1
            elif status == "plan":
                label_stats["planned"] += 1
            elif status in ("invalid", "error"):
                label_stats["invalid"] += 1
            else:
                label_stats["failed"] += 1
            if (result.app or {}).get("state") == "dead":
                label_stats["app_deaths"] += 1
                consecutive_deaths += 1
            else:
                consecutive_deaths = 0
            if (result.marker or {}).get("found"):
                label_stats["markers"] += 1
            if (result.proof or {}).get("proof_ok"):
                label_stats["proofs"] += 1

            reason = verdict.get("reason")
            if self.stop_on_invalid and status in ("invalid", "error"):
                invalid_stop = True
                summary.stopped.append({
                    "label": spec.label,
                    "reason": "invalid attempt (%s); matrix stopped" % reason,
                })

            limit = spec.stop_after_consecutive_deaths
            if limit and consecutive_deaths >= limit:
                stopped_labels.add(spec.label)
                summary.stopped.append({
                    "label": spec.label,
                    "reason": "%d consecutive app deaths" % consecutive_deaths,
                })
                consecutive_deaths = 0

        summary.ended_at = _now()
        summary.labels = []
        for label, label_stats in stats.items():
            valid = label_stats["passed"] + label_stats["failed"]
            label_stats["valid"] = valid
            label_stats["cp_lower_95_one_sided"] = clopper_pearson_lower(
                label_stats["passed"], valid
            )
            summary.labels.append(label_stats)
        summary.counts = {
            "attempts": len(results),
            "passed": sum(1 for r in results if (r.verdict or {}).get("status") == "pass"),
            "failed": sum(1 for r in results if (r.verdict or {}).get("status") == "fail"),
            "invalid": sum(1 for r in results if (r.verdict or {}).get("status")
                           in ("invalid", "error")),
            "manual": sum(1 for r in results if (r.verdict or {}).get("status") == "manual"),
            "planned": sum(1 for r in results if (r.verdict or {}).get("status") == "plan"),
            "skipped": len(summary.skipped),
        }
        summary.counts["valid"] = summary.counts["passed"] + summary.counts["failed"]
        summary.counts["cp_lower_95_one_sided"] = clopper_pearson_lower(
            summary.counts["passed"], summary.counts["valid"]
        )
        self.reporter.write_matrix(summary)
        return summary


def _now() -> str:
    from .model import utc_now

    return utc_now()
