#!/usr/bin/env python3
"""OCR a screenshot and print all detected text lines (top->bottom).

Usage: ocr_shot.py <png> [--grep SUBSTR]
"""
import sys

from rapidocr_onnxruntime import RapidOCR

engine = RapidOCR()


def main() -> int:
    path = sys.argv[1]
    grep = None
    if "--grep" in sys.argv:
        grep = sys.argv[sys.argv.index("--grep") + 1]
    result, _ = engine(path)
    lines = []
    for item in result or []:
        box, text, score = item
        ys = [p[1] for p in box]
        xs = [p[0] for p in box]
        lines.append((min(ys), min(xs), text, float(score)))
    lines.sort()
    for y, x, text, score in lines:
        if grep and grep.lower() not in text.lower():
            continue
        print(f"y={int(y):4d} x={int(x):4d} s={score:.2f} | {text}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
