"""Chat clean-up gate.

The chat must be clean before every send: old widget payloads re-render on
open and can fault the process before the new page runs.  Clean-up deletes
every payload/anchor id recorded in the local ledger plus ids supplied by the
operator, and records the outcome.  ``clean`` is false if any id cannot be
deleted or if OCR of the pre-send screenshot still shows a payload marker.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .errors import BotApiError, ChatCleanupError, ConfigError
from .ledger import ChatLedger
from .markers import looks_like_widget_marker

DELETED = "deleted"
ABSENT = "absent"


@dataclass
class CleanupResult:
    chat_id: str
    requested_ids: list[int] = field(default_factory=list)
    deleted_ids: list[int] = field(default_factory=list)
    absent_ids: list[int] = field(default_factory=list)
    failed: list[dict] = field(default_factory=list)
    planned: bool = False
    screenshot_markers: list[str] = field(default_factory=list)
    screenshot: str | None = None
    ocr_error: str | None = None

    @property
    def clean(self) -> bool:
        return not self.failed and not self.screenshot_markers

    @property
    def removed_ids(self) -> list[int]:
        return sorted(set(self.deleted_ids) | set(self.absent_ids))

    def to_dict(self) -> dict:
        return {
            "chat_id": self.chat_id,
            "requested_ids": sorted(self.requested_ids),
            "deleted_ids": sorted(self.deleted_ids),
            "absent_ids": sorted(self.absent_ids),
            "removed_ids": self.removed_ids,
            "failed": list(self.failed),
            "planned": self.planned,
            "screenshot": self.screenshot,
            "screenshot_markers": list(self.screenshot_markers),
            "ocr_error": self.ocr_error,
            "clean": self.clean,
        }


class ChatCleaner:
    def __init__(self, bot, ledger: ChatLedger, ocr=None):
        self.bot = bot
        self.ledger = ledger
        self.ocr = ocr

    def register_ids(self, chat_id, ids, kind: str = "payload") -> None:
        for message_id in ids:
            self.ledger.add_known(chat_id, int(message_id), kind)
        self.ledger.save()

    def clean(
        self,
        chat_id,
        *,
        extra_ids=(),
        dry_run: bool = False,
        screenshot: str | None = None,
        verify_screenshot: bool = False,
    ) -> CleanupResult:
        chat_key = str(chat_id)
        requested = set(self.ledger.pending_ids(chat_key))
        requested.update(int(value) for value in extra_ids)
        result = CleanupResult(
            chat_id=chat_key,
            requested_ids=sorted(requested),
            planned=dry_run,
            screenshot=str(screenshot) if screenshot else None,
        )

        if dry_run:
            return result

        # Newest first: deleting the visible tail before older rows keeps the
        # chat usable if a later delete fails.
        for message_id in sorted(requested, reverse=True):
            try:
                outcome = self.bot.delete_message(chat_key, message_id)
            except BotApiError as exc:
                result.failed.append({
                    "message_id": message_id,
                    "error": str(exc),
                    "description": getattr(exc, "description", str(exc)),
                })
                continue
            if outcome.status == DELETED:
                result.deleted_ids.append(message_id)
            elif outcome.status == ABSENT:
                result.absent_ids.append(message_id)
            else:
                result.failed.append({
                    "message_id": message_id,
                    "error": "unexpected delete status %r" % outcome.status,
                })
                continue
            self.ledger.mark_deleted(chat_key, message_id)

        self.ledger.save()

        if verify_screenshot and screenshot:
            self._verify_screenshot(result, screenshot)

        return result

    @staticmethod
    def require_clean(result: CleanupResult) -> CleanupResult:
        """Raise a structured error when a clean-up result is not clean."""

        if result.clean:
            return result
        ids = ", ".join(str(item["message_id"]) for item in result.failed)
        error = ChatCleanupError(
            "chat %s is not clean: %s. Do not measure in a contaminated chat."
            % (result.chat_id, ids or "old widget marker still visible"),
            failures=result.failed,
            deleted=result.deleted_ids,
        )
        error.result = result  # type: ignore[attr-defined]
        raise error

    def verify(self, chat_id, *, screenshot: str | None = None) -> CleanupResult:
        """Check the ledger and an optional screenshot without deleting."""

        chat_key = str(chat_id)
        result = CleanupResult(
            chat_id=chat_key,
            requested_ids=sorted(self.ledger.pending_ids(chat_key)),
            planned=True,
            screenshot=str(screenshot) if screenshot else None,
        )
        if result.requested_ids:
            result.failed.append({
                "message_id": None,
                "error": "ledger still has %d payload/anchor id(s)"
                         % len(result.requested_ids),
            })
        if screenshot:
            self._verify_screenshot(result, screenshot)
        return result

    def _verify_screenshot(self, result: CleanupResult, screenshot: str) -> None:
        if self.ocr is None:
            result.ocr_error = "OCR is not configured"
            return
        if not getattr(self.ocr, "available", False):
            result.ocr_error = getattr(self.ocr, "error", None) or "OCR unavailable"
            return
        ocr_result = self.ocr.read(str(screenshot))
        if ocr_result.error:
            result.ocr_error = ocr_result.error
            return
        result.screenshot_markers = looks_like_widget_marker(ocr_result.text)


def parse_id_list(values) -> list[int]:
    """Parse repeated and comma-separated message id arguments."""

    ids: list[int] = []
    for value in values or ():
        for piece in str(value).replace(";", ",").split(","):
            piece = piece.strip()
            if not piece:
                continue
            try:
                message_id = int(piece, 0)
            except ValueError as exc:
                raise ConfigError("invalid message id %r" % piece) from exc
            if message_id <= 0:
                raise ConfigError("message id must be positive: %s" % message_id)
            ids.append(message_id)
    return sorted(set(ids))


def read_id_file(path: str) -> list[int]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        raise ConfigError("cannot read message-id file %s: %s" % (path, exc)) from exc
    return parse_id_list(text.split())
