"""Redaction of operator-specific values before artifacts are written.

The tool is designed to be copied into a repository.  Result files are
redacted by default: tokens, UDIDs, AppGroup UUIDs, chat ids and the operator
home directory are replaced by the same placeholders used by the campaign
documentation (``<BOT_TOKEN>``, ``<UDID>``, ``<APPGROUP>``, ``<CHAT_ID>``,
``<HOME>``).  ``--no-redact`` keeps the real values for local debugging.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class Redactor:
    pairs: list[tuple[str, str]] = field(default_factory=list)

    def add(self, value, placeholder: str) -> "Redactor":
        if value is None:
            return self
        text = str(value)
        if text and not any(existing == text for existing, _ in self.pairs):
            self.pairs.append((text, placeholder))
        # Longest value first avoids partial replacements (e.g. home prefix).
        self.pairs.sort(key=lambda pair: len(pair[0]), reverse=True)
        return self

    def add_home(self) -> "Redactor":
        return self.add(os.path.expanduser("~"), "<HOME>")

    def text(self, value: str) -> str:
        result = str(value)
        for secret, placeholder in self.pairs:
            if secret in result:
                result = result.replace(secret, placeholder)
        return result

    def obj(self, value):
        """Recursively redact strings and exact scalar matches."""

        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, bool) or value is None:
            return value
        if isinstance(value, int):
            for secret, placeholder in self.pairs:
                if secret.isdigit() and int(secret) == value:
                    return placeholder
            return value
        if isinstance(value, float):
            return value
        if isinstance(value, dict):
            return {self.text(str(k)): self.obj(v) for k, v in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [self.obj(item) for item in value]
        return self.text(str(value))

    def to_dict(self) -> dict:
        return {"enabled": True, "placeholders": sorted({p for _, p in self.pairs})}


def null_redactor() -> Redactor:
    """A redactor that leaves values untouched (``--no-redact``)."""

    redactor = Redactor()
    redactor.text = lambda value: str(value)  # type: ignore[method-assign]
    redactor.obj = lambda value: value  # type: ignore[method-assign]
    redactor.to_dict = lambda: {"enabled": False, "placeholders": []}  # type: ignore[method-assign]
    return redactor
