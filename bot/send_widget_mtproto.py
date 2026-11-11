#!/usr/bin/env python3
"""Send a Telegram bot widget (13.2.0 beta layer) via MTProto.

Uses the TL constructor `inputMediaWidget` found in the 13.2.0 APK:

    inputMediaWidget#44fbcf4e flags:# width:int height:int html:string
        public_data:flags.2?string chat_data:flags.3?string
        = InputMedia;

    (flags.0 = allow_queries, flags.1 = shared_widget,
     flags.2 = public_data present, flags.3 = chat_data present)

The server should answer with a normal message whose media is
`messageMediaWidget` carrying the compressed payload; the recipient client
then renders the HTML in its QuickJS widget sandbox.

Examples:
  # bot account, send to the user who started the bot
  python3 send_widget.py --bot-token 123:ABC --to @username --html-file widget_poc.html

  # user account (same account as the phone), send to Saved Messages
  python3 send_widget.py --phone +39... --to me --html-file widget_poc.html

  # offline: only print the serialized InputMedia bytes
  python3 send_widget.py --dry-run --html-file widget_poc.html
"""
import argparse
import asyncio
import os
import struct
import sys

from telethon import TelegramClient, functions
from telethon.tl.tlobject import TLObject

# Telegram app credentials are NOT stored here. Supply them through the
# environment (or config.example.json); any Telegram app api_id/api_hash pair
# works for MTProto.
API_ID = int(os.environ.get("TG_API_ID", "0") or 0)
API_HASH = os.environ.get("TG_API_HASH", "")
API_CRC = 0xFAF846F4  # crc32(b'InputMedia')


class InputMediaWidget(TLObject):
    CONSTRUCTOR_ID = 1157021774  # 0x44fbcf4e
    SUBCLASS_OF_ID = API_CRC

    def __init__(self, html, width=480, height=320,
                 allow_queries=False, shared_widget=False,
                 public_data=None, chat_data=None):
        self.html = html
        self.width = int(width)
        self.height = int(height)
        self.allow_queries = bool(allow_queries)
        self.shared_widget = bool(shared_widget)
        self.public_data = public_data
        self.chat_data = chat_data

    def _bytes(self):
        flags = 0
        if self.allow_queries:
            flags |= 1
        if self.shared_widget:
            flags |= 2
        if self.public_data is not None:
            flags |= 4
        if self.chat_data is not None:
            flags |= 8
        out = [
            struct.pack("<I", self.CONSTRUCTOR_ID),
            struct.pack("<I", flags),
            struct.pack("<i", self.width),
            struct.pack("<i", self.height),
            self.serialize_bytes(self.html.encode("utf-8")),
        ]
        if self.public_data is not None:
            out.append(self.serialize_bytes(self.public_data.encode("utf-8")))
        if self.chat_data is not None:
            out.append(self.serialize_bytes(self.chat_data.encode("utf-8")))
        return b"".join(out)

    def to_dict(self):
        return {
            "_": "InputMediaWidget",
            "html": self.html,
            "width": self.width,
            "height": self.height,
        }


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--html-file", required=True)
    ap.add_argument("--to", help="username, phone, id or 'me'")
    ap.add_argument("--bot-token", help="bot token (bot account mode)")
    ap.add_argument("--phone", help="phone number (user account mode)")
    ap.add_argument("--session", default="widget_poc")
    ap.add_argument("--width", type=int, default=480)
    ap.add_argument("--height", type=int, default=320)
    ap.add_argument("--queries", action="store_true",
                    help="set allow_queries (flags.0)")
    ap.add_argument("--shared", action="store_true",
                    help="set shared_widget (flags.1)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    html = open(args.html_file, encoding="utf-8").read()
    media = InputMediaWidget(html, args.width, args.height,
                             allow_queries=args.queries,
                             shared_widget=args.shared)
    raw = media._bytes()
    print(f"[*] html {len(html)} bytes, InputMedia {len(raw)} bytes: {raw[:24].hex()}...",
          file=sys.stderr)
    if args.dry_run:
        with open("input_media_widget.bin", "wb") as f:
            f.write(raw)
        print("[*] wrote input_media_widget.bin", file=sys.stderr)
        return

    if not args.to:
        sys.exit("--to is required unless --dry-run")

    if not API_ID or not API_HASH:
        sys.exit("set TG_API_ID and TG_API_HASH (see config.example.json)")
    client = TelegramClient(args.session, API_ID, API_HASH)
    if args.bot_token:
        await client.start(bot_token=args.bot_token)
    else:
        await client.start(phone=args.phone)

    peer = await client.get_input_entity(args.to)
    req = functions.messages.SendMediaRequest(
        peer=peer, media=media, message="")
    result = await client(req)
    print("[+] sent:", result.stringify()[:600])
    await client.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
