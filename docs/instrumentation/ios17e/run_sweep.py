#!/usr/bin/env python3
"""Dense-H probe sweep on the 17e with crash recovery.

Usage: sweep.py H1 H2 ...   (probe files hole_stageA_probe_h<H>.html)
Flow per H: delete previous widget msg -> send probe -> screenshot+OCR marker ->
if app crashed: delete msg, relaunch Telegram, search-open <BOT_USERNAME> chat.
"""
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, "/tmp/opencode/ios17e")
import nav  # noqa: E402

VENV = "<HOME>/ailocal/Telegram/ios_sideload/venv/bin"
PAYLOAD = "<HOME>/ailocal/Telegram/telegramandroidwidget/lab/ios_way/payload"
CHAT = 0
TOK = [l.split("=", 1)[1].strip() for l in Path("/tmp/opencode/tgbot/token.env").read_text().splitlines()
       if l.startswith("TG_BOT_TOKEN=")][0]


def api(method, payload):
    req = urllib.request.Request(f"https://api.telegram.org/beta/bot{TOK}/{method}",
                                 data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def send(file):
    extra = [os.environ["SWEEP_SENDER_FLAG"]] if os.environ.get("SWEEP_SENDER_FLAG") else []
    if os.environ.get("SWEEP_QUERIES") == "1":
        extra.append("--allow-queries")
    r = subprocess.run([sys.executable, "/tmp/opencode/ios17e/send_widget.py", file, str(CHAT)] + extra,
                       capture_output=True, text=True, timeout=90)
    out = r.stdout.strip()
    print(out)
    mid = None
    for part in out.split():
        if part.startswith("message_id="):
            mid = int(part.split("=", 1)[1])
    return mid


def delete(mid):
    if mid:
        try:
            ok = api("deleteMessage", {"chat_id": CHAT, "message_id": mid}).get("ok")
            print("delete", mid, ok)
        except Exception as exc:  # noqa: BLE001
            print("delete error", exc)


def launch():
    """Relaunch Telegram with the console attached (appends to console.log)."""
    log = open("/tmp/opencode/ios17e/console.log", "ab")
    subprocess.Popen(
        [f"{VENV}/pymobiledevice3", "developer", "core-device", "launch-application",
         "ph.telegra.Telegraph", "--console", "--userspace"],
        stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
    )
    time.sleep(6)


def marker(lines):
    parts = [l[0] for l in lines
             if any(k in l[0] for k in ("RESULT", "HIT=", "HN=", "ABV", "IOS_N1", "N1IOS", "U_RDY", "U_NF"))]
    return " ".join(parts)


def main() -> int:
    args = sys.argv[1:]
    gap = float(__import__('os').environ.get('SWEEP_GAP', '0'))
    prev = None
    for arg in args:
        if gap:
            time.sleep(gap)
        delete(prev)
        if "/" in arg:
            f = arg
            label = arg.split("/")[-1]
        else:
            f = f"{PAYLOAD}/hole_stageA_probe_h{arg}.html"
            label = f"H{arg}"
        print(f"=== {label} ===", flush=True)
        mid = send(f)
        time.sleep(6)
        shot = f"/tmp/opencode/ios17e/attempt_{int(time.time())}_{label.replace('/', '_')}.png"
        nav.screenshot(shot)
        lines = nav.ocr(shot)
        state = nav.classify(lines)
        mk = marker(lines)
        print(f"{label}: state={state} marker={mk}", flush=True)
        if any(k in mk for k in ("ABV", "IOS_N1", "N1IOS", "U_RDY", "U_NF")):
            print(f"{label}: STAGE-B MARKER; full OCR:", flush=True)
            for text, score, cx, cy, box in lines:
                print(f"  y={int(cy):4d} x={int(cx):4d} s={score:.2f} | {text[:110]}", flush=True)
        if state == "springboard":
            print(f"{label}: CRASH detected; recovering", flush=True)
            delete(mid)
            mid = None
            launch()
            nav.openbot()
            nav.screenshot()
            print("post-recovery state:", nav.classify(nav.ocr()), flush=True)
        prev = mid
    if prev:
        print("last message id (delete after reading):", prev)
    return 0


if __name__ == "__main__":
    sys.exit(main())
