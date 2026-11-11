"""Proof retrieval from a MobileBackup2 backup.

The documented proof command is::

    pymobiledevice3 backup2 --only-regex '<APPGROUP>.*rce.txt|.*spdb'

Current pymobiledevice3 requires the ``backup`` sub-command and a destination
directory; both forms are supported (``--backup-cli modern|legacy``).  After
the backup, this module resolves the filtered files through ``Manifest.db``
and copies the matches next to the attempt result.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from .errors import ProofError

RCE_TEXT = b"RCE_OK\n"


@dataclass
class ProofMatch:
    kind: str
    relative_path: str
    source_path: str
    size: int
    sha256: str
    copied_path: str | None = None
    text: str | None = None
    rce_ok: bool = False
    spdb_ok: bool = False

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "relative_path": self.relative_path,
            "source_path": self.source_path,
            "size": self.size,
            "sha256": self.sha256,
            "copied_path": self.copied_path,
            "text": self.text,
            "rce_ok": self.rce_ok,
            "spdb_ok": self.spdb_ok,
        }


@dataclass
class ProofReport:
    attempted: bool = False
    regex: str | None = None
    backup_dir: str | None = None
    found: bool = False
    matches: list[ProofMatch] = field(default_factory=list)
    rce_ok: bool = False
    spdb_ok: bool = False
    command: list[str] = field(default_factory=list)
    returncode: int | None = None
    duration_s: float = 0.0
    error: str | None = None
    stdout_tail: str = ""
    stderr_tail: str = ""
    retries: int = 0

    @property
    def proof_ok(self) -> bool:
        return self.rce_ok or self.spdb_ok or bool(self.matches)

    def to_dict(self) -> dict:
        return {
            "attempted": self.attempted,
            "regex": self.regex,
            "backup_dir": self.backup_dir,
            "found": self.found,
            "proof_ok": self.proof_ok,
            "rce_ok": self.rce_ok,
            "spdb_ok": self.spdb_ok,
            "matches": [match.to_dict() for match in self.matches],
            "command": list(self.command),
            "returncode": self.returncode,
            "duration_s": round(self.duration_s, 3),
            "error": self.error,
            "stdout_tail": self.stdout_tail[-2000:],
            "stderr_tail": self.stderr_tail[-2000:],
            "retries": self.retries,
        }


def _kind(relative_path: str) -> str:
    lowered = relative_path.lower()
    if lowered.endswith("rce.txt") or "/rce.txt" in lowered:
        return "rce"
    if lowered.endswith("spdb") or "/spdb" in lowered:
        return "spdb"
    return "other"


def _sha256(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(1 << 20)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def collect_backup_matches(
    backup_root: str | os.PathLike,
    regex: str,
    *,
    out_dir: str | os.PathLike | None = None,
) -> list[ProofMatch]:
    """Find files in a backup whose device path matches ``regex``."""

    root = Path(backup_root)
    if not root.exists():
        raise ProofError("backup directory does not exist: %s" % root)
    try:
        pattern = re.compile(regex)
    except re.error as exc:
        raise ProofError("invalid backup regex %r: %s" % (regex, exc)) from exc

    manifests = list(root.rglob("Manifest.db"))
    candidates: list[tuple[str, Path]] = []  # (device relative path, local path)

    if manifests:
        index: dict[str, list[Path]] = {}
        for path in root.rglob("*"):
            if path.is_file() and path.name != "Manifest.db":
                index.setdefault(path.name, []).append(path)
        seen: set[tuple[str, str]] = set()
        for manifest in manifests:
            try:
                uri = "%s?mode=ro" % manifest.resolve().as_uri()
                connection = sqlite3.connect(uri, uri=True)
                rows = connection.execute(
                    "SELECT fileID, domain, relativePath FROM Files"
                ).fetchall()
                connection.close()
            except sqlite3.Error as exc:
                raise ProofError("cannot read %s: %s" % (manifest, exc)) from exc
            for file_id, domain, relative_path in rows:
                relative_path = relative_path or ""
                domain = domain or ""
                device_path = "%s/%s" % (domain, relative_path)
                if not pattern.search(device_path):
                    continue
                if (device_path, str(file_id)) in seen:
                    continue
                seen.add((device_path, str(file_id)))
                for local in index.get(str(file_id), []):
                    candidates.append((device_path, local))
    else:
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            relative = str(path.relative_to(root))
            if pattern.search(relative):
                candidates.append((relative, path))

    matches: list[ProofMatch] = []
    copied_dir = Path(out_dir) if out_dir else None
    if copied_dir:
        copied_dir.mkdir(parents=True, exist_ok=True)

    for index, (device_path, local_path) in enumerate(sorted(candidates, key=lambda item: item[0])):
        size, sha = _sha256(local_path)
        kind = _kind(device_path)
        copied_path = None
        if copied_dir:
            target = copied_dir / ("%02d_%s" % (index, local_path.name))
            shutil.copy2(local_path, target)
            copied_path = str(target)
        text = None
        rce_ok = False
        if kind == "rce" and size <= 4096:
            data = local_path.read_bytes()
            text = data.decode("utf-8", "replace")
            rce_ok = data == RCE_TEXT
        matches.append(ProofMatch(
            kind=kind,
            relative_path=device_path,
            source_path=str(local_path),
            size=size,
            sha256=sha,
            copied_path=copied_path,
            text=text,
            rce_ok=rce_ok,
            spdb_ok=(kind == "spdb" and size > 0),
        ))
    return matches


def summarize(report: ProofReport) -> None:
    report.found = bool(report.matches)
    report.rce_ok = any(match.rce_ok for match in report.matches)
    report.spdb_ok = any(match.spdb_ok for match in report.matches)
