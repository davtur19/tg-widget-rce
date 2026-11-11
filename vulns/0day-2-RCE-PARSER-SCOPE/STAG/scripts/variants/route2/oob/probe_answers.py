#!/usr/bin/env python3
"""Answer-side limit probe for the widget answer channel (beta Bot API).

Answers TelegramWidget.request("P<i>") with canned payloads of known size so the
orchestrator can measure the real per-answer limit on the device:

  P0  1024 x 'A'      = 1024 UTF-8 bytes            expect accepted
  P1  1025 x 'A'      = 1025 UTF-8 bytes            expect refused
  P2  512 x U+00E9    = 1024 UTF-8 bytes (512 chars) expect accepted (bytes, not chars)
  P3  513 x U+00E9    = 1026 UTF-8 bytes            expect refused
  P4  "A\\x00B"        = NUL inside the text          expect refused
  P5  ""              = empty answer                 expect {result:null} or timeout
  P6  1024 x U+0001   = control chars, 1024 bytes    expect accepted (non-NUL)
  P7  "OK64"          = answer to a 64-byte request  expect accepted
  P8  "OK-PACE"       = pacing test answer (P8A/P8B/P8C)
  R*  (any 64 x 'R')  = 64-byte request data test    answered "OK64"

The probe widget sends the request data "P<i>"; the server answers by exact
key.  Every payload is a Python str; json.dumps() UTF-8-encodes it, so len()
in characters and the wire byte count differ only for P2/P3.

Transport facts used here (verified in 72801/72889):
  client fetch  messages.getBotWidgetQueryAnswer(peer, msg_id, data)
  bot answer    answerWidgetQuery(widget_query_id, data=<text>)
  update        widget_query / shared_widget_query with {id, from, data, ...}
  answer text   <= 1024 UTF-8 bytes, no NUL, else INVALID_ANSWER (client) or
                WIDGET_RESULT_TOO_LARGE (server); query id expires in 15 s.

Usage:
  python3 probe_answers.py --self-test
  python3 probe_answers.py --token <token> --uid 10290
  python3 probe_answers.py --token <token> --uid 10290 --dry-run
"""
import argparse, json, os, sys, time, urllib.error, urllib.request

BETA = "https://api.telegram.org/beta/bot%s/%s"

PAYLOADS = {
    "P0": "A" * 1024,
    "P1": "A" * 1025,
    "P2": "\u00e9" * 512,
    "P3": "\u00e9" * 513,
    "P4": "A\x00B",
    "P5": "",
    "P6": "\x01" * 1024,
    "P7": "OK64",
    "P8": "OK-PACE",   # pacing test (the page sends P8 three times)
}


def find_query(update):
    """Return the widget-query dict of an update (same shapes as bot_server.py)."""
    for k in ("widget_query", "shared_widget_query", "bot_widget_query", "widgetQuery"):
        v = update.get(k)
        if isinstance(v, dict) and "id" in v and "data" in v:
            return v
    for v in update.values():
        if isinstance(v, dict) and "id" in v and "data" in v and "from" in v:
            return v
    return None


def api(token, method, **params):
    url = BETA % (token, method)
    body = json.dumps(params).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=40) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        return {"ok": False, "error": e.code, "body": e.read()[:300].decode("utf-8", "replace")}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def payload_for(data):
    if not isinstance(data, str):
        return None
    if data in PAYLOADS:
        return PAYLOADS[data]
    if data.startswith("R"):
        return "OK64"
    return None


def self_test():
    ok = True
    print("payload table (chars / UTF-8 bytes / NUL):")
    for k in ("P0", "P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8"):
        p = PAYLOADS[k]
        b = len(p.encode("utf-8"))
        print("  %-2s chars=%-4d bytes=%-4d nul=%s" % (k, len(p), b, "yes" if "\x00" in p else "no"))
    checks = [
        ("P0 accepted size", len(PAYLOADS["P0"].encode()) == 1024),
        ("P1 refused size", len(PAYLOADS["P1"].encode()) == 1025),
        ("P2 bytes", len(PAYLOADS["P2"].encode()) == 1024 and len(PAYLOADS["P2"]) == 512),
        ("P3 bytes", len(PAYLOADS["P3"].encode()) == 1026 and len(PAYLOADS["P3"]) == 513),
        ("P4 nul", "\x00" in PAYLOADS["P4"]),
        ("P5 empty", PAYLOADS["P5"] == ""),
        ("P6 bytes", len(PAYLOADS["P6"].encode()) == 1024 and "\x00" not in PAYLOADS["P6"]),
        ("P7", PAYLOADS["P7"] == "OK64"),
        ("P8", PAYLOADS["P8"] == "OK-PACE"),
        ("R64", payload_for("R" * 64) == "OK64"),
        ("unknown", payload_for("X0") is None),
    ]
    for name, good in checks:
        print("  %-18s %s" % (name, "OK" if good else "BAD"))
        ok = ok and good
    print("SELF-TEST", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--token", default=os.environ.get("BOT_TOKEN") or os.environ.get("TG_BOT_TOKEN", ""))
    ap.add_argument("--uid", type=int, default=10290)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--state-dir", default=os.path.join(os.path.dirname(__file__), "state"))
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    if not a.token:
        print("no token (use --token or BOT_TOKEN)", file=sys.stderr)
        return 2
    os.makedirs(a.state_dir, exist_ok=True)
    log_path = os.path.join(a.state_dir, "probe.log")
    off = 0
    off_file = os.path.join(a.state_dir, "probe_offset.json")
    if os.path.exists(off_file):
        try:
            off = json.load(open(off_file)).get("offset", 0)
        except Exception:
            off = 0

    def log(*a):
        line = " ".join(str(x) for x in a)
        sys.stderr.write(line + "\n")
        sys.stderr.flush()
        with open(log_path, "a") as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + line + "\n")

    log("START probe uid=%s dry=%s" % (a.uid, a.dry_run))
    while True:
        try:
            r = api(a.token, "getUpdates", offset=off, timeout=25)
        except Exception as e:
            log("getUpdates exception", e)
            time.sleep(3)
            continue
        if not r.get("ok"):
            log("getUpdates failed", r)
            time.sleep(3)
            continue
        for u in r.get("result", []):
            off = max(off, u.get("update_id", 0) + 1)
            q = find_query(u)
            if not q:
                continue
            frm = q.get("from") or {}
            if a.uid and frm.get("id") != a.uid:
                log("SKIP uid", frm.get("id"))
                continue
            data = q.get("data")
            p = payload_for(data)
            if p is None:
                log("SKIP data", repr(data)[:80])
                continue
            n = len(p.encode("utf-8"))
            log("QUERY", repr(data)[:32], "answer_bytes=%d chars=%d" % (n, len(p)),
                "nul=%s" % ("yes" if "\x00" in p else "no"))
            if a.dry_run:
                log("DRY answer", repr(p[:24]))
                continue
            t = time.time()
            res = api(a.token, "answerWidgetQuery", widget_query_id=q.get("id"), data=p)
            log("ANSWER", repr(data)[:32], "bytes=%d ok=%s" % (n, res.get("ok")),
                ("err=%r" % (res.get("description") or res.get("error") or res.get("body"))) if not res.get("ok") else "",
                "rt=%.0fms" % ((time.time() - t) * 1000))
        json.dump({"offset": off}, open(off_file, "w"))


if __name__ == "__main__":
    sys.exit(main())
