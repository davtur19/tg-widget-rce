#!/usr/bin/env python3
"""First-wins answer server for the parallel universal package (host artifact).

The parallel fan-out sends K widgets; several may forge.  Only the first one
to ask matters: the first widget query becomes the WINNER and its chunks are
answered in order.  Every other widget gets the one-byte STOP sentinel "X"
(<=1024 B text), which the stage-C driver recognises and halts on -- the
losers then stop consuming the per-user+bot answer throttle.

Offline self-test (no network):
  python3 answer_server_first_wins.py --parallel-self-test

Live use (same contract as the proven oob/bot_server.py; the orchestrator
runs it only after explicit approval):
  BOT_TOKEN=... python3 answer_server_first_wins.py --uid 10290 --chunks chunks
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import answer_server as bs  # noqa: E402


class FirstWins(bs.Bot):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.winner = None

    def answer_text(self, qid, text):
        """Answer with an arbitrary short text (the STOP sentinel)."""
        if self.dry:
            self.log("DRY", self.method, "widget_query_id=%s" % qid,
                     "text=%r" % text)
            return {"ok": True}
        fields = [self.good_field] if self.good_field else self.fields
        last = None
        for f in fields:
            last = self.api(self.method, **{"widget_query_id": qid, f: text})
            self.log("ANSWER", self.method, "widget_query_id=%s" % qid,
                     "text=%r" % text, "ok=%s" % last.get("ok"))
            if last.get("ok"):
                if not self.good_field:
                    self.good_field = f
                return last
        return last

    def handle(self, update, t0=None):
        q = bs.find_query(update)
        if not q:
            return
        frm = q.get("from") or {}
        if self.uid and frm.get("id") != self.uid:
            self.log("SKIP uid", frm.get("id"))
            return
        i = bs.parse_index(q.get("data"))
        if i is None:
            self.log("SKIP data", repr(q.get("data")))
            return
        key = ((q.get("chat") or {}).get("id"), q.get("message_id"))
        if self.winner is None:
            self.winner = key
            self.log("WINNER", key)
        if key != self.winner:
            self.log("STOP loser", key, "i=%d" % i)
            self.answer_text(q.get("id"), "X")
            return
        super().handle(update, t0)


def parallel_self_test(chunks_dir, uid):
    """Feed two widgets' queries offline (dry); assert first-wins routing."""
    os.makedirs(os.path.join(HERE, "state"), exist_ok=True)
    log_path = os.path.join(HERE, "state", "selftest.log")
    open(log_path, "w").close()   # each self-test is standalone
    b = FirstWins("-", chunks_dir, uid, "answerWidgetQuery", True,
                  log_path, ["data"])
    def q(qid, data, msg, chat=0):
        return {"update_id": 1, "widget_query": {
            "id": qid, "data": data, "from": {"id": uid},
            "chat": {"id": chat}, "message_id": msg}}
    b.handle(q("qA0", "E0", 10))   # A wins
    b.handle(q("qB0", "E0", 11))   # B loses -> X
    b.handle(q("qA1", "E1", 10))   # A continues
    b.handle(q("qC7", "E7", 12))   # C loses -> X
    b.handle(q("qA7", "E7", 10))   # A continues
    log = open(os.path.join(HERE, "state", "selftest.log")).read()
    ok = ("WINNER (0, 10)" in log and "STOP loser (0, 11)" in log
          and "STOP loser (0, 12)" in log
          and log.count("text='X'") == 2 and log.count("i=0") >= 1)
    print("PARALLEL SELF-TEST", "PASS" if ok else "FAIL")
    print(log[-1200:])
    return 0 if ok else 1


if __name__ == "__main__":
    if "--parallel-self-test" in sys.argv:
        chunks = os.path.join(HERE, "chunks", "parallel")
        if not os.path.isdir(chunks):
            chunks = os.path.join(HERE, "..", "..", "vulns",
                                  "0day-2-RCE-PARSER-SCOPE", "STAG", "payloads",
                                  "universal", "parallel", "chunks")
        if "--chunks" in sys.argv:
            chunks = sys.argv[sys.argv.index("--chunks") + 1]
        sys.exit(parallel_self_test(chunks, int(os.environ.get("BOT_UID", "0") or 0)))
    bs.Bot = FirstWins
    sys.exit(bs.main())
