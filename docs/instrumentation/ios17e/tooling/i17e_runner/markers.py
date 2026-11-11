"""Marker extraction shared by console-log and OCR channels.

The stage-A pages print ``RESULT SS2 ... HIT=<n> LEN=<n>`` (and R/M/PH/NT
fields); the endgame prints ``OK`` in the ``#v`` element.  Failure guards are
short uppercase tokens (``U_NF``, ``NO_RT``, ``NO_BASE``, ``A/D/R/F/M/G/S/P/N/B``).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

_FIELD_PATTERNS = {
    "hit": re.compile(r"\bHIT\s*=\s*(-?\d+(?:/\d+)?)"),
    "len": re.compile(r"\bLEN\s*=\s*(-?\d+)"),
    "r": re.compile(r"\bR\s*=\s*(-?\d+)"),
    "m": re.compile(r"\bM\s*=\s*(-?\d+)"),
    "ph": re.compile(r"\bPH\s*=\s*(-?\d+)"),
    "nt": re.compile(r"\bNT\s*=\s*(-?\d+)"),
    "cal": re.compile(r"\bCAL(\d+)\b"),
}

_TOKEN_PATTERNS = {
    "result": re.compile(r"\bRESULT\b"),
    "ss2": re.compile(r"\bSS2\b"),
    "js_free_rt": re.compile(r"\bjs_free_rt\b"),
    "n17e": re.compile(r"\bN17E\b"),
    "abv": re.compile(r"\bABV\b"),
    "u_rdy": re.compile(r"\bU_RDY\b"),
    "u_nf": re.compile(r"\bU_NF\b"),
    "no_rt": re.compile(r"\bNO_RT\b"),
    "no_base": re.compile(r"\bNO_BASE\b"),
    "len_guard": re.compile(r"\bLEN_[A-Z0-9]+\b"),
    "ok": re.compile(r"(?:^|[\s#])OK(?:[\s.]|$)"),
}

GUARD_TOKENS = ("u_nf", "no_rt", "no_base", "len_guard")

DEFAULT_SUCCESS_MARKERS = (r"HIT=|RESULT\b|N17E|js_free_rt",)


@dataclass
class MarkerSet:
    text: str = ""
    fields: dict[str, str] = field(default_factory=dict)
    tokens: list[str] = field(default_factory=list)
    lines: list[str] = field(default_factory=list)
    first: str | None = None
    guard: str | None = None

    @property
    def found(self) -> bool:
        return bool(self.fields or self.tokens or self.first)

    @property
    def guard_found(self) -> bool:
        return self.guard is not None

    def to_dict(self) -> dict:
        return {
            "found": self.found,
            "text": self.text,
            "fields": dict(self.fields),
            "tokens": list(self.tokens),
            "lines": list(self.lines[:40]),
            "first": self.first,
            "guard": self.guard,
        }


def extract_markers(text: str) -> MarkerSet:
    markers = MarkerSet(text=(text or "").strip())
    if not text:
        return markers

    for line in text.splitlines():
        if not line.strip():
            continue
        hits_here: list[str] = []
        for name, pattern in _FIELD_PATTERNS.items():
            match = pattern.search(line)
            if match:
                markers.fields.setdefault(name, match.group(1))
                hits_here.append(name)
        for name, pattern in _TOKEN_PATTERNS.items():
            if pattern.search(line):
                if name not in markers.tokens:
                    markers.tokens.append(name)
                hits_here.append(name)
                if name in GUARD_TOKENS and markers.guard is None:
                    markers.guard = name
        if hits_here:
            if markers.first is None:
                markers.first = line.strip()
            if len(markers.lines) < 40:
                markers.lines.append(line.strip())
    return markers


def matches_success(text: str, patterns: tuple[str, ...] | list[str]) -> bool:
    if not text:
        return False
    for pattern in patterns or DEFAULT_SUCCESS_MARKERS:
        try:
            if re.search(pattern, text):
                return True
        except re.error:
            if pattern in text:
                return True
    return False


def first_success_line(text: str, patterns: tuple[str, ...] | list[str]) -> str | None:
    for line in (text or "").splitlines():
        if matches_success(line, patterns):
            return line.strip()
    return None


def looks_like_widget_marker(text: str) -> list[str]:
    """Return marker lines that must not be visible in a clean chat.

    Deliberately excludes the generic ``OK`` token: ordinary chat text can
    contain "OK".  A rendered payload shows HIT=/RESULT/#v/N17E or a guard.
    """

    interesting = re.compile(
        r"(HIT\s*=|RESULT\s+SS2|\bN17E\b|\bjs_free_rt\b|\bU_RDY\b|\bU_NF\b|"
        r"\bNO_RT\b|\bNO_BASE\b|\bABV\b|#v\b)"
    )
    return [line.strip() for line in (text or "").splitlines() if interesting.search(line)]
