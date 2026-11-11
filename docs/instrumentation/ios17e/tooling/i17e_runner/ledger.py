"""Persistent per-chat ledger of payload and anchor message ids.

The Bot API cannot list a chat's history.  The only reliable way to prove that
no old widget payload remains is to remember every payload message id this
tool (or the operator) ever sent to a chat, delete those ids, and only then
allow a run.  The ledger is local state and is never committed.
"""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .errors import ConfigError

SCHEMA = "i17e-runner/ledger/1"


@dataclass
class ChatEntry:
    payload_ids: list[int] = field(default_factory=list)
    anchor_ids: list[int] = field(default_factory=list)
    deleted_ids: list[int] = field(default_factory=list)
    last_message_id: int | None = None
    last_payload_sha256: str | None = None
    last_send_at: str | None = None

    def to_dict(self) -> dict:
        return {
            "payload_ids": sorted(self.payload_ids),
            "anchor_ids": sorted(self.anchor_ids),
            "deleted_ids": sorted(self.deleted_ids),
            "last_message_id": self.last_message_id,
            "last_payload_sha256": self.last_payload_sha256,
            "last_send_at": self.last_send_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ChatEntry":
        return cls(
            payload_ids=[int(v) for v in data.get("payload_ids") or []],
            anchor_ids=[int(v) for v in data.get("anchor_ids") or []],
            deleted_ids=[int(v) for v in data.get("deleted_ids") or []],
            last_message_id=_int_or_none(data.get("last_message_id")),
            last_payload_sha256=data.get("last_payload_sha256"),
            last_send_at=data.get("last_send_at"),
        )


class ChatLedger:
    def __init__(self, path: str | os.PathLike, chats: dict[str, ChatEntry] | None = None):
        self.path = Path(path)
        self.chats: dict[str, ChatEntry] = chats or {}

    # -- persistence -----------------------------------------------------
    @classmethod
    def load(cls, path: str | os.PathLike) -> "ChatLedger":
        ledger = cls(path)
        if not ledger.path.exists():
            return ledger
        try:
            with open(ledger.path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigError("cannot read chat ledger %s: %s" % (ledger.path, exc)) from exc
        if not isinstance(data, dict):
            raise ConfigError("chat ledger %s is not a JSON object" % ledger.path)
        for chat_id, entry in (data.get("chats") or {}).items():
            ledger.chats[str(chat_id)] = ChatEntry.from_dict(entry or {})
        return ledger

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "schema": SCHEMA,
            "chats": {chat_id: entry.to_dict() for chat_id, entry in sorted(self.chats.items())},
        }
        fd, temp_path = tempfile.mkstemp(
            prefix=".ledger.", suffix=".tmp", dir=str(self.path.parent)
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2, sort_keys=True)
                handle.write("\n")
            os.replace(temp_path, self.path)
        finally:
            if os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass

    # -- entries ---------------------------------------------------------
    def entry(self, chat_id) -> ChatEntry:
        key = str(chat_id)
        if key not in self.chats:
            self.chats[key] = ChatEntry()
        return self.chats[key]

    def add_payload(self, chat_id, message_id: int, sha256: str | None = None,
                    when: str | None = None) -> None:
        entry = self.entry(chat_id)
        if int(message_id) not in entry.payload_ids:
            entry.payload_ids.append(int(message_id))
        entry.last_message_id = int(message_id)
        entry.last_payload_sha256 = sha256
        entry.last_send_at = when

    def add_anchor(self, chat_id, message_id: int) -> None:
        entry = self.entry(chat_id)
        if int(message_id) not in entry.anchor_ids:
            entry.anchor_ids.append(int(message_id))
        entry.last_message_id = int(message_id)

    def add_known(self, chat_id, message_id: int, kind: str = "payload") -> None:
        if kind == "anchor":
            self.add_anchor(chat_id, message_id)
        else:
            self.add_payload(chat_id, message_id)

    def pending_ids(self, chat_id) -> list[int]:
        entry = self.entry(chat_id)
        return sorted(set(entry.payload_ids) | set(entry.anchor_ids))

    def mark_deleted(self, chat_id, message_id: int) -> None:
        entry = self.entry(chat_id)
        mid = int(message_id)
        entry.payload_ids = [v for v in entry.payload_ids if v != mid]
        entry.anchor_ids = [v for v in entry.anchor_ids if v != mid]
        if mid not in entry.deleted_ids:
            entry.deleted_ids.append(mid)

    def known_max_message_id(self, chat_id) -> int | None:
        entry = self.entry(chat_id)
        ids = entry.payload_ids + entry.anchor_ids + entry.deleted_ids
        if entry.last_message_id is not None:
            ids.append(entry.last_message_id)
        return max(ids) if ids else None

    def has_pending(self, chat_id) -> bool:
        return bool(self.pending_ids(chat_id))

    def to_dict(self) -> dict:
        return {
            "schema": SCHEMA,
            "path": str(self.path),
            "chats": {chat_id: entry.to_dict() for chat_id, entry in sorted(self.chats.items())},
        }


def _int_or_none(value):
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
