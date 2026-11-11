"""sendWidget payload inspection.

Bot limits measured on the whitelisted widget bot (see the campaign runbook):
raw HTML <= 32768 bytes and zlib.compress(html, 9) <= 4096 bytes.  Both are
checked before any network call.
"""
from __future__ import annotations

import hashlib
import os
import zlib
from dataclasses import dataclass

from .errors import PayloadError

RAW_LIMIT = 32768
ZLIB_LIMIT = 4096


@dataclass(frozen=True)
class PayloadInfo:
    path: str
    raw: int
    zlib9: int
    sha256: str
    raw_limit: int = RAW_LIMIT
    zlib_limit: int = ZLIB_LIMIT

    @property
    def raw_ok(self) -> bool:
        return self.raw <= self.raw_limit

    @property
    def zlib_ok(self) -> bool:
        return self.zlib9 <= self.zlib_limit

    @property
    def ok(self) -> bool:
        return self.raw_ok and self.zlib_ok

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "raw": self.raw,
            "zlib9": self.zlib9,
            "sha256": self.sha256,
            "limits": {"raw": self.raw_limit, "zlib9": self.zlib_limit},
            "raw_ok": self.raw_ok,
            "zlib_ok": self.zlib_ok,
        }


def inspect_bytes(data: bytes, *, path: str = "<memory>", raw_limit: int = RAW_LIMIT,
                  zlib_limit: int = ZLIB_LIMIT) -> PayloadInfo:
    info = PayloadInfo(
        path=path,
        raw=len(data),
        zlib9=len(zlib.compress(data, 9)),
        sha256=hashlib.sha256(data).hexdigest(),
        raw_limit=raw_limit,
        zlib_limit=zlib_limit,
    )
    return info


def inspect_payload(path: str, *, raw_limit: int = RAW_LIMIT,
                    zlib_limit: int = ZLIB_LIMIT) -> tuple[PayloadInfo, bytes]:
    if not os.path.isfile(path):
        raise PayloadError("payload not found: %s" % path)
    with open(path, "rb") as handle:
        data = handle.read()
    info = inspect_bytes(data, path=os.path.abspath(path), raw_limit=raw_limit,
                         zlib_limit=zlib_limit)
    if not info.raw_ok:
        raise PayloadError(
            "payload raw size %d exceeds the sendWidget limit %d: %s"
            % (info.raw, info.raw_limit, path)
        )
    if not info.zlib_ok:
        raise PayloadError(
            "payload zlib-9 size %d exceeds the sendWidget limit %d "
            "(INPUT_MEDIA_WIDGET_TOO_LARGE): %s"
            % (info.zlib9, info.zlib_limit, path)
        )
    return info, data


def hash_matches(actual: str, expected: str) -> bool:
    """Compare a SHA-256 against a full or abbreviated value.

    Accepts the documentation style ``4906d6f9…101a`` (Unicode ellipsis or
    three dots) and case-insensitive hex.
    """

    actual = actual.strip().lower()
    expected = expected.strip().lower()
    if not expected:
        return True
    for separator in ("…", "...", ".."):
        if separator in expected:
            prefix, suffix = expected.split(separator, 1)
            prefix = prefix.strip()
            suffix = suffix.strip()
            if prefix and not actual.startswith(prefix):
                return False
            if suffix and not actual.endswith(suffix):
                return False
            return True
    return actual == expected
