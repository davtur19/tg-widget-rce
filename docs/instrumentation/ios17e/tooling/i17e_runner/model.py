"""Result and attempt-specification models."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .config import SCHEMA, VERSION


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class AttemptSpec:
    label: str
    payload: str
    count: int = 1
    expect: str = "marker_or_proof"
    success_markers: list[str] | None = None
    backup_regex: str | None = None
    require_proof: bool = False
    gate: dict | None = None
    stop_after_consecutive_deaths: int | None = None
    expect_sha256: str | None = None
    notes: str | None = None

    @classmethod
    def from_dict(cls, data: dict, *, base_dir: str | None = None) -> "AttemptSpec":
        if not isinstance(data, dict):
            raise ValueError("attempt entry must be an object")
        label = str(data.get("label") or "").strip()
        payload = str(data.get("payload") or "").strip()
        if not label:
            raise ValueError("attempt entry has no label")
        if not payload:
            raise ValueError("attempt %s has no payload" % label)
        if base_dir and not os.path.isabs(payload):
            payload = os.path.normpath(os.path.join(base_dir, payload))
        markers = data.get("success_markers")
        if markers is None and data.get("success_marker"):
            markers = [data["success_marker"]]
        if isinstance(markers, str):
            markers = [markers]
        return cls(
            label=label,
            payload=payload,
            count=max(1, int(data.get("count") or 1)),
            expect=str(data.get("expect") or "marker_or_proof"),
            success_markers=[str(item) for item in markers] if markers else None,
            backup_regex=data.get("backup_regex"),
            require_proof=bool(data.get("require_proof") or False),
            gate=data.get("gate"),
            stop_after_consecutive_deaths=(
                int(data["stop_after_consecutive_deaths"])
                if data.get("stop_after_consecutive_deaths") is not None else None
            ),
            expect_sha256=data.get("expect_sha256"),
            notes=data.get("notes"),
        )

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "payload": self.payload,
            "count": self.count,
            "expect": self.expect,
            "success_markers": self.success_markers,
            "backup_regex": self.backup_regex,
            "require_proof": self.require_proof,
            "gate": self.gate,
            "stop_after_consecutive_deaths": self.stop_after_consecutive_deaths,
            "expect_sha256": self.expect_sha256,
            "notes": self.notes,
        }


@dataclass
class AttemptResult:
    label: str
    index: int
    schema: str = SCHEMA
    tool: dict = field(default_factory=lambda: {"name": "i17e_runner", "version": VERSION})
    started_at: str = field(default_factory=utc_now)
    ended_at: str | None = None
    duration_s: float | None = None
    verdict: dict = field(default_factory=dict)
    device: dict = field(default_factory=dict)
    payload: dict = field(default_factory=dict)
    chat: dict = field(default_factory=dict)
    timeline: dict = field(default_factory=dict)
    logs: dict = field(default_factory=dict)
    screenshots: list[dict] = field(default_factory=list)
    ocr: dict = field(default_factory=dict)
    marker: dict = field(default_factory=dict)
    app: dict = field(default_factory=dict)
    proof: dict = field(default_factory=dict)
    cleanup: dict = field(default_factory=dict)
    processes: dict = field(default_factory=dict)
    errors: list[dict] = field(default_factory=list)
    extras: dict = field(default_factory=dict)

    def error(self, kind: str, message: str, **extra) -> None:
        item = {"kind": kind, "message": str(message)}
        item.update(extra)
        self.errors.append(item)

    def finish(self, *, status: str, reason: str, success: bool | None) -> None:
        self.ended_at = utc_now()
        self.verdict = {"status": status, "reason": reason, "success": success}

    def to_dict(self, redactor=None) -> dict:
        data = {
            "schema": self.schema,
            "tool": self.tool,
            "attempt": {
                "label": self.label,
                "index": self.index,
                "started_at": self.started_at,
                "ended_at": self.ended_at,
                "duration_s": round(self.duration_s, 3) if self.duration_s is not None else None,
            },
            "verdict": dict(self.verdict),
            "device": dict(self.device),
            "payload": dict(self.payload),
            "chat": dict(self.chat),
            "timeline": dict(self.timeline),
            "logs": dict(self.logs),
            "screenshots": list(self.screenshots),
            "ocr": dict(self.ocr),
            "marker": dict(self.marker),
            "app": dict(self.app),
            "proof": dict(self.proof),
            "cleanup": dict(self.cleanup),
            "processes": dict(self.processes),
            "errors": list(self.errors),
            "extras": dict(self.extras),
        }
        if redactor is not None:
            data = redactor.obj(data)
        return data


@dataclass
class MatrixSummary:
    name: str
    started_at: str = field(default_factory=utc_now)
    ended_at: str | None = None
    counts: dict = field(default_factory=dict)
    labels: list[dict] = field(default_factory=list)
    attempts: list[dict] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)
    stopped: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "counts": self.counts,
            "labels": self.labels,
            "attempts": self.attempts,
            "skipped": self.skipped,
            "stopped": self.stopped,
        }


def redacted_attempt_dict(result: AttemptResult, redactor) -> dict:
    return result.to_dict(redactor)
