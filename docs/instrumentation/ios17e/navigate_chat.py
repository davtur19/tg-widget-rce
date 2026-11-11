#!/usr/bin/env python3
"""Phone navigation + marker reader for the 17e chat.

Commands:
  back                     left-edge drag to go back
  open <text>              screenshot, OCR-find <text> row, tap it, verify
  shot <path>              screenshot
  read [SUBSTR]            screenshot + OCR, print lines matching SUBSTR
  tap <x_px> <y_px>        tap at pixel coords (1170x2532)
  drag <x1> <y1> <x2> <y2>
"""
import os
import subprocess
import sys
import time

from rapidocr_onnxruntime import RapidOCR

VENV = os.path.expanduser("~/ailocal/Telegram/ios_sideload/venv/bin")
W, H = 1170, 2532
SHOT = "/tmp/opencode/ios17e/_nav.png"
engine = RapidOCR()


def run(cmd, timeout=90):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def screenshot(path=SHOT):
    r = run([f"{VENV}/pymobiledevice3", "developer", "core-device", "screen-capture",
             "screenshot", path, "--userspace"], timeout=90)
    if r.returncode != 0:
        print("shot fail", r.stderr[-200:])
    return path


def ocr(path=SHOT):
    result, _ = engine(path)
    out = []
    for box, text, score in result or []:
        xs = [p[0] for p in box]
        ys = [p[1] for p in box]
        out.append((text, float(score), sum(xs) / 4, sum(ys) / 4, box))
    return out


def tap_px(x, y):
    nx = max(0, min(65535, int(x / W * 65535)))
    ny = max(0, min(65535, int(y / H * 65535)))
    r = run([f"{VENV}/pymobiledevice3", "developer", "core-device", "universal-hid-service",
             "tap", str(nx), str(ny), "--userspace"], timeout=90)
    return r.returncode == 0


def drag_px(x1, y1, x2, y2):
    nx1 = max(0, min(65535, int(x1 / W * 65535)))
    ny1 = max(0, min(65535, int(y1 / H * 65535)))
    nx2 = max(0, min(65535, int(x2 / W * 65535)))
    ny2 = max(0, min(65535, int(y2 / H * 65535)))
    r = run([f"{VENV}/pymobiledevice3", "developer", "core-device", "universal-hid-service",
             "drag", str(nx1), str(ny1), str(nx2), str(ny2), "--userspace"], timeout=90)
    return r.returncode == 0


def find_texts(lines, needle):
    needle = needle.lower()
    return [l for l in lines if needle in l[0].lower()]


def classify(lines):
    """Classify the current screen: chat / list / springboard / unknown."""
    joined = " ".join(l[0] for l in lines).lower()
    if "<BOT_USERNAME>" in joined and any(l[3] < 420 and "<BOT_USERNAME>" in l[0].lower() for l in lines):
        return "chat"
    if "chat archiviate" in joined or ("modifica" in joined and "tutte" in joined):
        return "list"
    if "meteo" in joined or "impostazioni" in joined or "cerca" in joined:
        return "springboard"
    return "unknown"


def openchat(name):
    """From the chat list: search -> type <name> -> tap result -> verify."""
    tap_px(1060, 240)          # magnifier / new message
    time.sleep(2)
    tap_px(553, 444)           # Cerca field
    time.sleep(1.5)
    run([f"{VENV}/pymobiledevice3", "developer", "core-device",
         "universal-hid-service", "type", name, "--userspace"], timeout=90)
    time.sleep(2.5)
    screenshot()
    lines = ocr()
    hits = [l for l in lines if name.lower() in l[0].lower() and l[3] > 380]
    if not hits:
        print("openchat: no result row; lines:", [l[0][:25] for l in lines[:10]])
        return False
    hits.sort(key=lambda l: l[3])
    text, score, cx, cy, box = hits[0]
    tap_px(cx, cy)
    time.sleep(3)
    screenshot()
    lines2 = ocr()
    ok = any(l[3] < 420 and name.lower() in l[0].lower() for l in lines2)
    print(f"openchat: tapped ({int(cx)},{int(cy)}) header_ok={ok} state={classify(lines2)}")
    return ok


def openbot():
    return openchat("<BOT_USERNAME>")


def main() -> int:
    cmd = sys.argv[1]
    if cmd == "openchat":
        print("openchat", openchat(sys.argv[2]))
        return 0
    if cmd == "openbot":
        print("openbot", openbot())
        return 0
    if cmd == "state":
        screenshot()
        lines = ocr()
        print("state:", classify(lines))
        for text, score, cx, cy, box in lines[:8]:
            print(f"  y={int(cy)} | {text[:70]}")
        return 0
    if cmd == "back":
        drag_px(8, H // 2, 620, H // 2)
        print("back gesture sent")
        return 0
    if cmd == "shot":
        path = sys.argv[2] if len(sys.argv) > 2 else SHOT
        print(screenshot(path))
        return 0
    if cmd == "tap":
        x, y = float(sys.argv[2]), float(sys.argv[3])
        print("tap", x, y, "->", tap_px(x, y))
        return 0
    if cmd == "drag":
        print("drag", drag_px(*map(float, sys.argv[2:6])))
        return 0
    if cmd == "taps":
        # tap several pixel coords in sequence
        for i in range(2, len(sys.argv) - 1, 2):
            x, y = float(sys.argv[i]), float(sys.argv[i + 1])
            print("tap", x, y, "->", tap_px(x, y))
            time.sleep(0.6)
        return 0
    if cmd == "read":
        needle = sys.argv[2] if len(sys.argv) > 2 else None
        screenshot()
        for text, score, cx, cy, box in ocr():
            if needle and needle.lower() not in text.lower():
                continue
            print(f"y={int(cy):4d} x={int(cx):4d} s={score:.2f} | {text}")
        return 0
    if cmd == "open":
        needle = sys.argv[2]
        screenshot()
        lines = ocr()
        hits = find_texts(lines, needle)
        if not hits:
            print(f"'{needle}' not found on screen")
            for text, score, cx, cy, box in lines[:25]:
                print(f"  y={int(cy)} x={int(cx)} | {text[:60]}")
            return 1
        text, score, cx, cy, box = hits[0]
        print(f"tap '{text}' at ({int(cx)},{int(cy)})")
        tap_px(cx, cy)
        time.sleep(2.5)
        screenshot()
        lines2 = ocr()
        # verify: header should contain the needle
        top = [l for l in lines2 if l[3] < 420 and needle.lower() in l[0].lower()]
        print("VERIFY_HEADER", "OK" if top else "MISSING")
        return 0 if top else 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
