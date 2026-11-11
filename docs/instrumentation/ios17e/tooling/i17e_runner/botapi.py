"""Generic Telegram Bot API client used by the runner.

The bot is selected by the **token**; there is no bot-specific flag or name in
the tool.  The token is never printed, logged or written to a result file; the
safe endpoint forms contain ``<BOT_TOKEN>`` instead.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable

from .errors import BotApiError, ConfigError

API_ROOT = "https://api.telegram.org"

Transport = Callable[[str, dict, float], dict]


@dataclass
class DeleteOutcome:
    message_id: int
    status: str  # "deleted" | "absent"
    description: str = ""

    @property
    def ok(self) -> bool:
        return self.status in ("deleted", "absent")

    def to_dict(self) -> dict:
        return {"message_id": self.message_id, "status": self.status,
                "description": self.description}


@dataclass
class SendOutcome:
    message_id: int
    widget_id: str | None = None
    raw: dict | None = None

    def to_dict(self) -> dict:
        return {"message_id": self.message_id, "widget_id": self.widget_id}


def urllib_transport(url: str, body: dict, timeout: float) -> dict:
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = {"ok": False, "description": raw[:400], "http": exc.code}
        parsed.setdefault("http", exc.code)
        return parsed
    except urllib.error.URLError as exc:
        return {"ok": False, "description": "connection error: %s" % exc}


class BotClient:
    def __init__(
        self,
        token: str | None,
        *,
        api: str = "beta",
        timeout: float = 30.0,
        transport: Transport | None = None,
        api_root: str = API_ROOT,
    ):
        if not token:
            raise ConfigError(
                "no bot token: pass --token or set BOT_TOKEN (never commit it)"
            )
        self._token = token
        self.api = api
        self.timeout = timeout
        self._transport = transport or urllib_transport
        self._api_root = api_root.rstrip("/")

    def __repr__(self) -> str:
        return "BotClient(api=%r, token=<BOT_TOKEN>)" % self.api

    # -- endpoints -------------------------------------------------------
    def endpoint(self, method: str) -> str:
        prefix = "" if self.api == "standard" else "/beta"
        return "%s%s/bot%s/%s" % (self._api_root, prefix, self._token, method)

    def safe_endpoint(self, method: str) -> str:
        prefix = "" if self.api == "standard" else "/beta"
        return "%s%s/bot<BOT_TOKEN>/%s" % (self._api_root, prefix, method)

    # -- call ------------------------------------------------------------
    def call(self, method: str, body: dict) -> dict:
        response = self._transport(self.endpoint(method), body, self.timeout)
        if not isinstance(response, dict):
            raise BotApiError(method, "non-JSON Bot API response: %r" % (response,))
        if not response.get("ok"):
            raise BotApiError(
                method,
                str(response.get("description") or response),
                code=response.get("error_code") or response.get("http"),
            )
        return response

    # -- methods ---------------------------------------------------------
    def delete_message(self, chat_id, message_id: int) -> DeleteOutcome:
        body = {"chat_id": _chat_value(chat_id), "message_id": int(message_id)}
        try:
            response = self.call("deleteMessage", body)
        except BotApiError as exc:
            description = exc.description
            lowered = description.lower()
            if "message to delete not found" in lowered or "message not found" in lowered:
                return DeleteOutcome(int(message_id), "absent", description)
            if "message can't be deleted" in lowered or "message cant be deleted" in lowered:
                raise BotApiError(
                    "deleteMessage",
                    "message %s cannot be deleted anymore (%s); clean the chat "
                    "manually before testing" % (message_id, description),
                    code=exc.code,
                ) from exc
            raise
        return DeleteOutcome(int(message_id), "deleted", str(response.get("description") or ""))

    def send_widget(
        self,
        chat_id,
        html: str,
        *,
        allow_queries: bool = False,
        background_query: bool = False,
        height: int | None = None,
        width: int | None = None,
    ) -> SendOutcome:
        body: dict = {"chat_id": _chat_value(chat_id), "html": html}
        if allow_queries:
            body["allow_queries"] = True
        if background_query:
            body["background_query"] = True
        if height is not None:
            body["height"] = int(height)
        if width is not None:
            body["width"] = int(width)
        response = self.call("sendWidget", body)
        result = response.get("result") or {}
        message_id = result.get("message_id")
        if message_id is None:
            raise BotApiError("sendWidget", "response has no result.message_id: %r" % response)
        widget = result.get("widget") or {}
        return SendOutcome(
            message_id=int(message_id),
            widget_id=str(widget["id"]) if widget.get("id") else None,
            raw=response,
        )

    def send_message(self, chat_id, text: str) -> SendOutcome:
        response = self.call(
            "sendMessage", {"chat_id": _chat_value(chat_id), "text": text}
        )
        result = response.get("result") or {}
        return SendOutcome(message_id=int(result.get("message_id", 0)), raw=response)

    def get_chat(self, chat_id) -> dict:
        response = self.call("getChat", {"chat_id": _chat_value(chat_id)})
        return response.get("result") or {}

    def get_me(self) -> dict:
        response = self.call("getMe", {})
        return response.get("result") or {}


def _chat_value(chat_id):
    if isinstance(chat_id, str) and (chat_id.startswith("@") or not chat_id.lstrip("-").isdigit()):
        return chat_id
    try:
        return int(chat_id)
    except (TypeError, ValueError):
        return str(chat_id)
