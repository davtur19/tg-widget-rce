#!/usr/bin/env python3
"""Widget endgame answer server (Telegram Bot API, beta prefix).

Answers TelegramWidget.request("E<i>") with chunk i of the endgame source.

Wire facts (verified statically in the 72801 client):
  client fetch   messages.getBotWidgetQueryAnswer
  bot answer     messages.setBotWidgetQueryAnswer
                 Bot API: answerWidgetQuery(widget_query_id, data=<chunk>)
                 The Bot API parameter is `data` (MTProto `result`):
                 docs/tgw-format.md "`result` | answerWidgetQuery's `data`".
                 `result` is NOT a Bot API parameter and is silently ignored
                 (ok=True with an empty answer).
  update         updateBotWidgetQuery
  request data   1..64 B  -> "E0".."E7"
  answer         <=1024 B -> 950 B chunks
  pacing         one in flight, >=5 s between background requests
  gating         sendWidget allow_queries=true, background_query=true,
                 widget visible, private chat with the bot

Usage:
  python3 bot_server.py --self-test          # offline: validates chunks + payloads
  python3 bot_server.py --dry-run            # online getUpdates, logs answers, sends nothing
  python3 bot_server.py                      # online, answers every chunk

Config: --token / env BOT_TOKEN, --uid <CHAT_ID>, --chunks oob/chunks,
        --method answerWidgetQuery, --offset-file oob/state/offset.json
No third-party dependencies; stdlib only.
"""
import argparse, json, os, sys, time, urllib.error, urllib.request

BETA = "https://api.telegram.org/beta/bot%s/%s"


def load_chunks(d):
    man = json.load(open(os.path.join(d, "manifest.json")))
    chunks = [open(os.path.join(d, "E%d.txt" % i), encoding="utf-8").read()
              for i in range(man["n"])]
    assert "".join(chunks) == open(man["source"], encoding="utf-8").read() if os.path.exists(man["source"]) else True
    return man, chunks


def find_query(update):
    """Return the widget-query dict of an update, defensively.

    The beta Bot API shape is not in the public docs; the wire update is
    updateBotWidgetQuery. Accept any dict value that has id+data+from, and
    known keys first.
    """
    for k in ("widget_query", "shared_widget_query", "bot_widget_query", "widgetQuery"):
        v = update.get(k)
        if isinstance(v, dict) and "id" in v and "data" in v:
            return v
    for v in update.values():
        if isinstance(v, dict) and "id" in v and "data" in v and "from" in v:
            return v
    return None


def parse_index(data):
    if not isinstance(data, str) or len(data) < 2 or data[0] != "E":
        return None
    try:
        i = int(data[1:])
    except ValueError:
        return None
    return i if 0 <= i < 4096 else None


class Bot:
    def __init__(self, token, chunks_dir, uid, method, dry, log_path, fields):
        self.token = token
        self.man, self.chunks = load_chunks(chunks_dir)
        self.uid = uid
        self.method = method
        self.fields = fields
        self.good_field = None
        self.dry = dry
        self.log_path = log_path
        self.sent = 0

    def log(self, *a):
        line = " ".join(str(x) for x in a)
        sys.stderr.write(line + "\n")
        sys.stderr.flush()
        if self.log_path:
            with open(self.log_path, "a") as f:
                f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + line + "\n")

    def api(self, method, **params):
        url = BETA % (self.token, method)
        body = json.dumps(params).encode()
        req = urllib.request.Request(url, data=body,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=40) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            return {"ok": False, "error": e.code, "body": e.read()[:200].decode("utf-8", "replace")}
        except Exception as e:  # network/timeout
            return {"ok": False, "error": str(e)}

    def answer(self, query_id, i):
        chunk = self.chunks[i]
        if self.dry:
            self.log("DRY", self.method, "widget_query_id=%s" % query_id,
                     "i=%d len=%d field=%s" % (i, len(chunk), self.fields[0]))
            return {"ok": True}
        fields = [self.good_field] if self.good_field else self.fields
        last = None
        for f in fields:
            payload = {"widget_query_id": query_id, f: chunk}
            r = self.api(self.method, **payload)
            last = r
            self.log("ANSWER", self.method, "widget_query_id=%s" % query_id,
                     "i=%d len=%d field=%s" % (i, len(chunk), f), "ok=%s" % r.get("ok"),
                     "" if r.get("ok") else repr(r.get("error") or r.get("body"))[:160])
            if r.get("ok"):
                if not self.good_field:
                    self.good_field = f
                    self.log("FIELD", f, "accepted")
                return r
        return last

    def handle(self, update, t0=None):
        q = find_query(update)
        if not q:
            return
        frm = q.get("from") or {}
        uid = frm.get("id")
        if self.uid and uid != self.uid:
            self.log("SKIP uid", uid)
            return
        i = parse_index(q.get("data"))
        if i is None or i >= len(self.chunks):
            self.log("SKIP data", repr(q.get("data")))
            return
        self.sent += 1
        t1 = time.time()
        self.log("LATENCY", "%.1f ms" % ((t1 - (t0 if t0 is not None else t1)) * 1000.0),
                 "since poll return")
        t2 = time.time()
        self.answer(q.get("id"), i)
        self.log("RT", "%.1f ms" % ((time.time() - t2) * 1000.0))

    def run(self, offset_file):
        off = 0
        if offset_file and os.path.exists(offset_file):
            try:
                off = json.load(open(offset_file)).get("offset", 0)
            except Exception:
                off = 0
        self.log("START method=%s uid=%s chunks=%d" % (self.method, self.uid, len(self.chunks)))
        while True:
            r = self.api("getUpdates", offset=off, timeout=25)
            if not r.get("ok"):
                self.log("getUpdates failed", r)
                time.sleep(3)
                continue
            t0 = time.time()
            for u in r.get("result", []):
                off = max(off, u["update_id"] + 1)
                self.handle(u, t0)
            if offset_file:
                os.makedirs(os.path.dirname(offset_file), exist_ok=True)
                json.dump({"offset": off}, open(offset_file, "w"))


def probe_methods(token, method, log=print):
    """Verify the beta method exists without a widget: a bogus query id is
    rejected with a query-level error if the method exists, and with
    'not found'/404 if the name is wrong. Returns True if the method exists."""
    url = BETA % (token, method)
    body = json.dumps({"widget_query_id": "00000000000000000000000000000000"}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            res = json.load(r)
    except urllib.error.HTTPError as e:
        raw = e.read()[:300].decode("utf-8", "replace")
        try:
            res = json.loads(raw)
        except Exception:
            res = {"ok": False, "error": e.code, "body": raw}
    except Exception as e:
        res = {"ok": False, "error": str(e)}
    desc = (res.get("description") or res.get("error") or "").lower() if isinstance(res, dict) else ""
    missing = ("not found" in desc) or ("method" in desc and "invalid" in desc) or res.get("error") == 404
    log("PROBE %s -> %s %s" % (method, "MISSING" if missing else "EXISTS", res))
    return not missing


def self_test(chunks_dir, method, uid):
    man, chunks = load_chunks(chunks_dir)
    print("manifest:", json.dumps(man, indent=1))
    joined = "".join(chunks)
    total = man.get("len") or sum(c["len"] for c in man["chunks"])
    print("joined len", len(joined), "== manifest", len(joined) == total)
    ok = True
    for i in range(len(chunks)):
        upd = {"update_id": 100 + i,
               "widget_query": {"id": "q%d" % i, "data": "E%d" % i,
                                "from": {"id": uid}}}
        q = find_query(upd)
        j = parse_index(q["data"])
        same = (j == i and chunks[j] == chunks[i])
        ok = ok and same
        body = {"widget_query_id": q["id"], "result": chunks[i][:24] + "…"}
        print("E%d -> %s len=%d %s payload=%s" % (i, "OK" if same else "BAD", len(chunks[i]),
                                                  "same" if same else "MISMATCH", json.dumps(body)))
    # negative cases
    for data, why in [("E99", "out of range"), ("X0", "bad prefix"), ("", "empty"), ("E", "no index")]:
        upd = {"update_id": 1, "widget_query": {"id": "q", "data": data, "from": {"id": uid}}}
        q = find_query(upd)
        i = parse_index(q["data"])
        good = i is None or i >= len(chunks)
        ok = ok and good
        print("negative %-12r -> %s (%s)" % (data, "rejected" if good else "ACCEPTED", why))
    # foreign user
    upd = {"update_id": 2, "widget_query": {"id": "q", "data": "E0", "from": {"id": 1}}}
    q = find_query(upd)
    print("foreign uid:", "filtered" if (q and q["from"]["id"] != uid) else "ACCEPTED")
    print("SELF-TEST", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--token", default=os.environ.get("BOT_TOKEN") or os.environ.get("TG_BOT_TOKEN", ""))
    ap.add_argument("--uid", type=int, default=int(os.environ.get("BOT_UID", "0") or 0))
    ap.add_argument("--chunks", default=os.path.join(os.path.dirname(__file__), "chunks"))
    ap.add_argument("--method", default="answerWidgetQuery")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--fields", default="data,result,text",
                    help="candidate parameter names for the chunk, tried in order "
                         "(the Bot API name is `data`; result/text are ignored aliases)")
    ap.add_argument("--probe", action="store_true",
                    help="verify the beta method name (bogus query id; no widget needed)")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--state-dir", default=os.path.join(os.path.dirname(__file__), "state"))
    ap.add_argument("--offset-file", default=None)
    ap.add_argument("--log", default=None)
    ap.add_argument("--simulate", action="store_true",
                    help="offline: feed synthetic updates through handle() (dry answer)")
    a = ap.parse_args()
    if a.offset_file is None:
        a.offset_file = os.path.join(a.state_dir, "offset.json")
    if a.log is None:
        a.log = os.path.join(a.state_dir, "server.log")
    if a.self_test:
        return self_test(a.chunks, a.method, a.uid)
    if a.simulate:
        os.makedirs(a.state_dir, exist_ok=True)
        b = Bot(a.token or "-", a.chunks, a.uid, a.method, True, a.log, [f.strip() for f in a.fields.split(",")])
        for i in range(len(b.chunks)):
            b.handle({"update_id": i, "widget_query": {"id": "SIM%d" % i, "data": "E%d" % i,
                                                       "from": {"id": a.uid}, "chat": {"id": 0}}})
        b.handle({"update_id": 99, "widget_query": {"id": "SIMX", "data": "E99", "from": {"id": a.uid}}})
        b.handle({"update_id": 100, "widget_query": {"id": "SIMF", "data": "E0", "from": {"id": 1}}})
        print("SIMULATED", b.sent, "answers (dry) ->", a.log)
        return 0
    if a.probe:
        if not a.token:
            print("no token (use --token or BOT_TOKEN)", file=sys.stderr)
            return 2
        ok = probe_methods(a.token, a.method) or probe_methods(a.token, "setBotWidgetQueryAnswer")
        return 0 if ok else 1
    if not a.token:
        print("no token (use --token or BOT_TOKEN)", file=sys.stderr)
        return 2
    os.makedirs(os.path.dirname(a.log), exist_ok=True)
    fields = [f.strip() for f in a.fields.split(",") if f.strip()]
    Bot(a.token, a.chunks, a.uid, a.method, a.dry_run, a.log, fields).run(a.offset_file)
    return 0


if __name__ == "__main__":
    sys.exit(main())
