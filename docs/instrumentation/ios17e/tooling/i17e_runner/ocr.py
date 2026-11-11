"""Optional OCR adapter.

OCR is optional: the runner records markers from the console first and uses
OCR only as a second channel.  When ``rapidocr_onnxruntime`` is not installed
(common on a headless host) the runner records ``ocr.available=false`` and
continues.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class OcrLine:
    text: str
    score: float = 0.0
    x: float = 0.0
    y: float = 0.0

    def to_dict(self) -> dict:
        return {"text": self.text, "score": round(self.score, 3),
                "x": round(self.x, 1), "y": round(self.y, 1)}


@dataclass
class OcrResult:
    available: bool
    path: str
    lines: list[OcrLine] = field(default_factory=list)
    error: str | None = None

    @property
    def text(self) -> str:
        return "\n".join(line.text for line in self.lines)

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            "path": self.path,
            "error": self.error,
            "lines": [line.to_dict() for line in self.lines],
            "text": self.text[:4000],
        }


class OcrEngine:
    def __init__(self, mode: str = "auto", *, engine=None, max_lines: int = 200):
        self.mode = mode
        self._engine = engine
        self._initialized = engine is not None
        self._error: str | None = None
        self.max_lines = max_lines

    @property
    def available(self) -> bool:
        if self.mode == "off":
            return False
        if self._engine is not None:
            return True
        if self._initialized:
            return self._engine is not None
        self._initialized = True
        try:
            from rapidocr_onnxruntime import RapidOCR  # type: ignore

            self._engine = RapidOCR()
        except Exception as exc:  # noqa: BLE001
            self._error = "%s: %s" % (type(exc).__name__, exc)
            self._engine = None
        return self._engine is not None

    @property
    def error(self) -> str | None:
        if self.mode == "off":
            return "OCR disabled (--ocr off)"
        if not self.available:
            return self._error or "rapidocr_onnxruntime is not installed"
        return None

    def read(self, path: str) -> OcrResult:
        if not self.available:
            return OcrResult(available=False, path=str(path), error=self.error)
        try:
            result, _ = self._engine(str(path))
        except Exception as exc:  # noqa: BLE001
            return OcrResult(available=True, path=str(path),
                             error="%s: %s" % (type(exc).__name__, exc))
        lines: list[OcrLine] = []
        for item in result or []:
            try:
                box, text, score = item
                xs = [point[0] for point in box]
                ys = [point[1] for point in box]
                lines.append(OcrLine(
                    text=str(text),
                    score=float(score),
                    x=sum(xs) / len(xs),
                    y=sum(ys) / len(ys),
                ))
            except (TypeError, ValueError, IndexError):
                continue
        lines.sort(key=lambda line: (line.y, line.x))
        return OcrResult(available=True, path=str(path), lines=lines[: self.max_lines])
