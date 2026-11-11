#!/usr/bin/env python3
"""Relay an iOS 15 (6s) hole-reuse probe marker into the unified P3 report.

The 6s probe is the device-proven page (it does not carry a request).  The
orchestrator reads its #v marker and runs e.g.

  python3 relay_ios15.py --marker "RESULT ATTR C=34 SZ=957 N=3000 H=400 HN=64 HIT=545 LEN=327744 PH=36 VK=598 NT=21 S2LEN=-1"

and feeds the printed hex to:  bot_two_phase.py --manual-report <hex> --chat <id>

P3 (31 bytes, 64 chars) matches the detector report format:
  platform=2 (iOS15), chain=3 (holes), flags hit/safe, sel=H, n=HIT,
  hd=VK, cb=PH, padM=0, N=3000, SZ=957, UBn=0, UBsz=0, t_rep optional.
No device/bot/network action.
"""
import re
import sys


def parse(marker):
    def g(k):
        m = re.search(r"\b%s=(-?\d+)" % k, marker)
        return int(m.group(1)) if m else None
    d = {k: g(k) for k in ("H", "HIT", "LEN", "PH", "VK", "NT")}
    if d["H"] is None or d["LEN"] is None:
        raise SystemExit("marker lacks H=/LEN=")
    return d


def pack(sel, hit, ln, ph, vk, dpr=0.0, sw=0, sh=0, lang="??", tz=0,
         n=0, sz=0, t_rep=0):
    hitf = 1 if (ln == 327744 and hit is not None and hit >= 0) else 0
    hitv = hit if hit is not None else 0xFFFF
    b = [3, 2, 3, hitf, 0,
         (sel >> 8) & 255, sel & 255,
         (hitv >> 8) & 255, hitv & 255,
         ((vk or 0) >> 8) & 255, (vk or 0) & 255,
         (ph or 0) & 255,
         min(255, round(dpr * 10)), (sw >> 8) & 255, sw & 255,
         (sh >> 8) & 255, sh & 255,
         ord(lang[0]) & 255, ord(lang[1]) & 255,
         min(255, max(0, round(tz / 15) + 128)), 0, 0,
         0, 0,
         min(255, (n or 0) // 100), min(255, (sz or 0) // 4), 0, 0,
         (t_rep >> 16) & 255, (t_rep >> 8) & 255, t_rep & 255]
    assert len(b) == 31
    return "P3" + "".join("%02x" % x for x in b)


if __name__ == "__main__":
    args = sys.argv[1:]
    marker = None
    if "--marker" in args:
        marker = args[args.index("--marker") + 1]
    elif args:
        marker = " ".join(args)
    if not marker:
        raise SystemExit("usage: relay_ios15.py --marker \"RESULT ATTR ...\"")
    d = parse(marker)
    t_rep = int(args[args.index("--t-rep") + 1], 0) if "--t-rep" in args else 0
    rep = pack(d["H"], d["HIT"], d["LEN"], d["PH"], d["VK"], n=3000, sz=957, t_rep=t_rep)
    print(rep)
    print("H=%s HIT=%s LEN=%s PH=%s VK=%s -> hit=%d" % (
        d["H"], d["HIT"], d["LEN"], d["PH"], d["VK"],
        1 if d["LEN"] == 327744 and (d["HIT"] or -1) >= 0 else 0))
