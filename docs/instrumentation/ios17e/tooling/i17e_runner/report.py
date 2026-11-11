"""Write per-attempt JSON/Markdown artifacts and matrix summaries."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from .config import RunPaths
from .model import AttemptResult, MatrixSummary


def _safe_label(label: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", label).strip("_")
    return cleaned or "attempt"


class Reporter:
    def __init__(self, paths: RunPaths, redactor):
        self.paths = paths
        self.redactor = redactor
        self.attempt_dir = paths.out / "attempts"
        self.attempt_dir.mkdir(parents=True, exist_ok=True)
        self.results_path = paths.out / "results.jsonl"
        self.summary_path = paths.out / "SUMMARY.md"

    def write_attempt(self, result: AttemptResult) -> dict:
        data = result.to_dict(self.redactor)
        stamp = re.sub(r"[^0-9A-Za-z]+", "", result.started_at or "")[:15] or "run"
        base = "%s_%02d_%s" % (_safe_label(result.label), result.index, stamp)
        json_path = self.attempt_dir / (base + ".json")
        md_path = self.attempt_dir / (base + ".md")
        _atomic_write(json_path, json.dumps(data, indent=2, sort_keys=True) + "\n")
        _atomic_write(md_path, render_attempt_markdown(data))
        with open(self.results_path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(data, sort_keys=True) + "\n")
        return {"json": str(json_path), "markdown": str(md_path),
                "results_jsonl": str(self.results_path)}

    def write_matrix(self, summary: MatrixSummary) -> dict:
        data = self.redactor.obj(summary.to_dict())
        json_path = self.paths.out / "matrix_summary.json"
        md_path = self.summary_path
        _atomic_write(json_path, json.dumps(data, indent=2, sort_keys=True) + "\n")
        _atomic_write(md_path, render_matrix_markdown(data))
        return {"json": str(json_path), "markdown": str(md_path)}


def render_attempt_markdown(data: dict) -> str:
    attempt = data.get("attempt") or {}
    verdict = data.get("verdict") or {}
    payload = data.get("payload") or {}
    device = data.get("device") or {}
    chat = data.get("chat") or {}
    marker = data.get("marker") or {}
    app = data.get("app") or {}
    proof = data.get("proof") or {}
    timeline = data.get("timeline") or {}

    lines = [
        "# Attempt %s #%s" % (attempt.get("label"), attempt.get("index")),
        "",
        "| field | value |",
        "|---|---|",
        "| status | **%s** |" % verdict.get("status"),
        "| reason | `%s` |" % verdict.get("reason"),
        "| success | %s |" % verdict.get("success"),
        "| started | %s |" % attempt.get("started_at"),
        "| duration | %s s |" % attempt.get("duration_s"),
        "",
        "## Payload",
        "",
        "| field | value |",
        "|---|---|",
        "| path | `%s` |" % payload.get("path"),
        "| raw / zlib9 | %s / %s |" % (payload.get("raw"), payload.get("zlib9")),
        "| sha256 | `%s` |" % payload.get("sha256"),
        "| message id | %s |" % payload.get("message_id"),
        "",
        "## Device and app",
        "",
        "| field | value |",
        "|---|---|",
        "| model | %s |" % device.get("model"),
        "| iOS / build | %s / %s |" % (device.get("os_version"), device.get("build")),
        "| UDID | `%s` |" % device.get("udid"),
        "| app | %s %s (%s) |" % (device.get("bundle_id"), device.get("app_version"),
                                   device.get("app_build")),
        "| app state | %s |" % app.get("state"),
        "| app evidence | %s |" % app.get("evidence"),
        "",
        "## Chat",
        "",
        "| field | value |",
        "|---|---|",
        "| chat | `%s` |" % chat.get("id"),
        "| clean before send | %s |" % chat.get("clean_before_send"),
        "| deleted ids | %s |" % _fmt_list(chat.get("deleted_ids")),
        "| last message | %s |" % chat.get("last_message_ok"),
        "| clean after run | %s |" % chat.get("clean_after"),
        "",
        "## Marker",
        "",
        "```",
        (marker.get("text") or marker.get("first") or "(none)")[:4000],
        "```",
        "",
        "fields: `%s`" % json.dumps(marker.get("fields") or {}, sort_keys=True),
        "guard: `%s`" % marker.get("guard"),
        "",
        "## Proof",
        "",
        "| field | value |",
        "|---|---|",
        "| attempted | %s |" % proof.get("attempted"),
        "| found | %s |" % proof.get("found"),
        "| rce_ok | %s |" % proof.get("rce_ok"),
        "| spdb_ok | %s |" % proof.get("spdb_ok"),
        "| regex | `%s` |" % proof.get("regex"),
        "| error | %s |" % proof.get("error"),
        "",
        "## Timeline",
        "",
        "```json",
        json.dumps(timeline, indent=2, sort_keys=True),
        "```",
        "",
    ]
    errors = data.get("errors") or []
    if errors:
        lines += ["## Errors", ""]
        for error in errors:
            lines.append("- **%s**: %s" % (error.get("kind"), error.get("message")))
        lines.append("")

    shots = data.get("screenshots") or []
    if shots:
        lines += ["## Screenshots", "", "| t_rel_s | file | ok | markers |", "|---|---|---|---|"]
        for shot in shots:
            markers = ", ".join(shot.get("markers") or [])
            lines.append("| %s | `%s` | %s | %s |" % (
                shot.get("t_rel_s"), shot.get("path"), shot.get("ok"), markers))
        lines.append("")

    matches = proof.get("matches") or []
    if matches:
        lines += ["## Proof matches", "",
                  "| kind | path | size | sha256 |", "|---|---|---|---|"]
        for match in matches:
            lines.append("| %s | `%s` | %s | `%s` |" % (
                match.get("kind"), match.get("relative_path"), match.get("size"),
                (match.get("sha256") or "")[:16]))
        lines.append("")
    return "\n".join(lines)


def render_matrix_markdown(data: dict) -> str:
    lines = [
        "# Matrix %s" % data.get("name"),
        "",
        "| field | value |",
        "|---|---|",
        "| started | %s |" % data.get("started_at"),
        "| ended | %s |" % data.get("ended_at"),
        "| attempts | %s |" % (data.get("counts") or {}).get("attempts"),
        "| passed | %s |" % (data.get("counts") or {}).get("passed"),
        "| failed | %s |" % (data.get("counts") or {}).get("failed"),
        "| invalid | %s |" % (data.get("counts") or {}).get("invalid"),
        "",
        "## Per label",
        "",
        "| label | n | pass | fail | invalid | deaths | markers | proof | CP lower 95% |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for label in data.get("labels") or []:
        lines.append("| %(label)s | %(n)s | %(passed)s | %(failed)s | %(invalid)s | "
                     "%(deaths)s | %(markers)s | %(proofs)s | %(cp)s |" % {
                         "label": label.get("label"),
                         "n": label.get("n"),
                         "passed": label.get("passed"),
                         "failed": label.get("failed"),
                         "invalid": label.get("invalid"),
                         "deaths": label.get("app_deaths"),
                         "markers": label.get("markers"),
                         "proofs": label.get("proofs"),
                         "cp": _fmt_rate(label.get("cp_lower_95_one_sided")),
                     })
    lines.append("")
    skipped = data.get("skipped") or []
    if skipped:
        lines += ["## Skipped", ""]
        for item in skipped:
            lines.append("- %s: %s" % (item.get("label"), item.get("reason")))
        lines.append("")
    stopped = data.get("stopped") or []
    if stopped:
        lines += ["## Stopped", ""]
        for item in stopped:
            lines.append("- %s: %s" % (item.get("label"), item.get("reason")))
        lines.append("")
    return "\n".join(lines)


def _fmt_list(values) -> str:
    if values is None:
        return "[]"
    if isinstance(values, (list, tuple, set)):
        return ", ".join(str(value) for value in values) or "[]"
    return str(values)


def _fmt_rate(value) -> str:
    if value is None:
        return "-"
    try:
        return "%.3f" % float(value)
    except (TypeError, ValueError):
        return "-"


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    with open(temp, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.replace(temp, path)
