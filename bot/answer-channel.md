# Widget answer channel: exact limits, max payload, bypass plan (2026-11-08, host-only)

Scope: Telegram Android `13.x` beta, releases **72801** (device target,
`lab/pixel72801_route2/lib/libtmessages.49.so`, `assets/WidgetSandbox/WidgetJS/sandbox-bundle.js`)
and **72889** (`lab/lib_hunt_dom/bin/libtmessages_72889.so`, `lab/qjs_fork_audit/bundle_72889/WidgetJS/sandbox-bundle.js`).
Everything here is from the shipped artifacts (host-side); nothing was sent to a
device, bot or network by this worker.

The question: how much payload can the answer channel
(`TelegramWidget.request` → `answerWidgetQuery`) carry, how fast, and does it
bypass the widget's 4 KB storage limit.

## 0. Answer in one paragraph

One answer is **at most 1024 UTF-8 bytes of text without a NUL**: enforced by
the server (`WIDGET_RESULT_TOO_LARGE`) and again by the client glue
(`checkRequestAnswer` → `INVALID_ANSWER`). The request data is 1-64 UTF-8
bytes. There is **no total cap**: every request carries its own 1024-byte
answer, so an N-answer chain moves N KiB. The 4 KB figure is Web Storage
(`localStorage`/`sessionStorage`, 4096 bytes per area) and is a completely
separate channel; the answer channel never touches it. Fastest delivery is
**tap-driven**: one request per tap, server floor 5 requests / 5 s per user+bot
→ 8 × 1024 B in two 5 s windows (~5-7 s wall). Background-only (no taps) is
1 request / 5 s → ~40 s for 8 answers. Re-showing the widget resets the 5 s
client pacing (one immediate background request per appearance).

## 1. Verified constants

| constant | value | where verified |
|---|---:|---|
| `MAX_REQUEST_RESULT_BYTES` (answer text) | **1024** UTF-8 bytes, no NUL | client: `checkRequestAnswer`, ARM64 `cmp x23,#0x400; b.hi` at `0x79df68` (72801) / `0x7a1ef4` (72889); UTF-8 loop before it; `memchr(…,0,…)` NUL check at `0x79df48` / `0x7a1ee0`; error builder at `0x78636c` / `0x78a2f8`. server: `WIDGET_RESULT_TOO_LARGE` (`docs/tgw-format.md`) |
| max request `data` | **64** UTF-8 bytes (min 1) | bundle `function ud(t){…let e=Rt(t);return e>=1&&e<=64?t:null}` (72889 bundle, offset 510,093 = 0x7C88D); server `WIDGET_QUERY_DATA_INVALID` |
| client background pacing | **5000 ms** between background requests (from the start of the last one); one free request per appearance | `RequestGate::decide` at `0x79e124` (72801) / `0x7a20b0` (72889): `now-last < 5000.0` → code 8 (`rate-limited`); `show` reset at `0x79e2b0`, called on the false→true visibility transition at `0x78ddc4` |
| server request flood | **5 requests / 5 s** per user+bot → `FLOOD_WAIT_<N>` | `docs/tgw-format.md` (server spec) |
| answer window | **15 s** → `WIDGET_RESPONSE_TIMEOUT`; query id expires **15 s** → `QUERY_ID_INVALID` | `docs/tgw-format.md` |
| client local wait | **30 000 ms** (`i0.h3(gVar, 30000L)`); safety net behind the server's 15 s | Java glue `p.u` (`jadx4b` `org/telegram/utils/twidget/p.java:567-572`) |
| widget storage | **4096 B per area** (`local`, `session`), counted as UTF-8 bytes of key+value; `QuotaExceededError` | bundle storage quota (~526,3xx): `…>4096&&(n.clear(),Zn[r]=0)` and `h>4096` throw `QuotaExceededError` |
| widget HTML payload | 32 768 B raw / 4096 B zlib9 | `notes/widget_bot_limits_20261105.md` (measured) |
| answer wire | client `messages.getBotWidgetQueryAnswer(peer,msg_id,data)` → `messages.botWidgetQueryAnswer(result:flags.0?bytes)`; bot `answerWidgetQuery(widget_query_id, data)` | `docs/tgw-format.md`; `TL_messages_botWidgetQueryAnswer.result` is `String` via `readString` (`NativeByteBuffer.readString` = `new String(bytes,"UTF-8")`, lenient) |
| answer statuses (Java→JNI) | 0 = text answer; 1 = `WIDGET_RESPONSE_TIMEOUT`; 2 = `FLOOD_WAIT*`; 3 = other failure; 5 = empty/null answer | `i.java:33/36`, `k.java:21/25`, `w.java:75`, JNI `answerRequest` `0x98f94c` |

The request-side gate codes (decide function): 0 `foreground`, 1 `background`,
2 `held` (off screen), 3 `granted` (wallet), 4 `disabled`, 5 `no-wallet`,
6 `busy`, 7 `no-activation`, 8 `rate-limited` (tables at `0x2a6430`/`0x2a6490`).

## 2. What the answer check actually does

`checkRequestAnswer` (Rust glue, runs on the bytes the Java glue re-encodes with
`String.getBytes(UTF_8)`):

1. if the answer has no result → `{result:null}` (not an error);
2. validate UTF-8 (multi-byte sequence loop);
3. reject if a NUL byte occurs (`memchr`);
4. reject if the UTF-8 **byte length > 1024** (`cmp …, #0x400; b.hi`).

Consequences:

- **Bytes, not characters.** 512 × `é` (1024 bytes) is accepted; 513 × `é`
  (1026 bytes) is rejected. ASCII is the densest encoding (1 byte/char).
- **NUL is forbidden**, other control characters (0x01-0x1F, 0x7F) are valid
  UTF-8 and pass the check (they are JSON-escaped on the host bridge and
  arrive as the same characters).
- Invalid UTF-8 on the wire is decoded by Java with U+FFFD replacement
  (`new String(bytes,"UTF-8")`), so it can only *shrink* the usable payload;
  never send binary.
- Exactly 1024 bytes is accepted; 1025 is refused.
- An answer that breaks the limits never reaches the widget: the promise
  rejects `INVALID_ANSWER` and the diagnostics record `answer-rejected`.
- A bot that tries to *set* >1024 bytes fails server-side
  (`WIDGET_RESULT_TOO_LARGE`); the client then has no answer and waits until
  the server's 15 s `WIDGET_RESPONSE_TIMEOUT` (or surfaces an immediate error,
  depending on where the server fails). The device probe distinguishes the two
  paths: `INVALID_ANSWER` = the server accepted the text and the client glue
  refused it; `TIMEOUT` = the server refused it.

## 3. Capacity math

Per answer: **1024 B**. Per request (upstream): 64 B. Answers are independent;
the total is limited only by time and the two rate limits.

| path | request spacing | payload rate | 7,469 B endgame |
|---|---|---:|---:|
| background, one widget | 5000 ms | 1024 B / 5 s ≈ 205 B/s | 8 answers ≈ 35-40 s |
| re-show trick | 1 free request per appearance (server 5/5 s) | bursts above 1/5 s, capped at 5/5 s | 8 answers ≈ 5-10 s |
| taps | 1 request per tap (server 5/5 s) | 5 × 1024 B / 5 s = 1024 B/s | 8 answers = 2 windows ≈ 5-7 s |
| taps + 4-answer compressed plan | 1 per tap, 4 in one window | 4 × 1024 B / 5 s | 4 answers ≈ 1-2 s |

Reference: 7469 B = 8 × 950 (current chunks) = 8 × 1024 max; a 7168 B payload
fits 7 answers, 6144 B fits 6.

**Storage bypass:** the 4 KB is `localStorage`/`sessionStorage` only. The
answer channel writes nothing there; 8 KiB (or any multiple of 1024 B) is
delivered without touching the quota. The three limits are independent:
widget HTML (32 KiB raw / 4 KiB zlib9, at send time), storage (4 KiB per area,
at runtime), answers (1 KiB per request, unlimited total).

## 4. Tricks and non-tricks

(a) **Byte vs char**: byte count; keep the answer ASCII (see §2).

(b) **Chaining**: the only real multiplier: E0..En, one answer each, no total
cap. Fastest patterns:
   - **taps**: each tap = one foreground request (gate code 0), bypassing the
     5 s background interval; the server still caps 5 requests / 5 s. A tap
     can be automated with `adb shell input tap` on the widget bubble.
   - **re-show**: `visible(false)` → `visible(true)` calls the gate's `show`,
     which clears the 5 s timer (verified: `show` clears the "has last time"
     byte at `0x79e2b0`; the visibility handler calls it on the transition at
     `0x78ddc4`). Each appearance grants one immediate background request.
     Caveat: while hidden, requests are *held* (code 2), not refused.
   - **background**: strictly one per 5 s; a request earlier than 5 s rejects
     `RATE_LIMITED` client-side (no server hit, no tap consumed).

(c) **Compression/encoding inside the answer**: the check is on the UTF-8
text, so the useful capacity is 1024 ASCII characters per answer. Encodings:
base64 = 768 B binary/answer; base85 (85 safe printable chars) ≈ 819 B;
custom base127 (0x01-0x7F) ≈ 894 B. For the 7,469 B endgame:
   - zlib9 = 3,214 B → base64 4,288 chars (5 answers), base85 ≈ 4,020 chars
     (4 answers), base127 ≈ 3,675 chars (4 answers);
   - a decompressor is required. If it is shipped in the widget HTML (+~1.2 KB
     source ≈ +0.8 KB zlib9; page budget is 4,096 zlib9, current page 1,024) the
     full endgame is **4 answers**. If it must ride the answer channel itself,
     +2 answers (6 total); still better than 8 raw, but the page change is the
     cleaner bet and must be A/B-tested for the stage-A heap layout.
   - raw source stays 8 answers at 1024 B (7,469 > 7,168), so compression is the
     only way below 8 without shrinking the endgame.

(d) **Raising the 1024**: not possible: server and client both enforce it, and
the check is after the answer is already in the client. The only parallel
downstream channels are the state (`chat_data` / `public_data`, 1024 B each;
`editMessageWidgetData` is under `sendMessage` flood, `editWidgetData` ≤1/s per
object and carriers see shared state by polling 5-30 s) and the widget HTML
itself (new messages, 32 KiB raw / 4 KiB zlib each). None of them feeds the
same runtime as fast as an answer chain.

(e) **Answer > storage**: yes, trivially: 8 answers = 8 KiB > 4 KiB; the
storage quota is not involved.

## 5. Payload plans

### A. Single-answer minimal endgame (≤1024 B, ~1 s)

One request (`E0`), one answer of ≤1024 B, executed by the driver. This only
carries a *compact* endgame: a variant of `endgame_72801.js` with the generic
scanner/validator removed and the 72801-specific deltas baked in (the full
7,469 B is generic symbol resolution). A ≤1024 B stager is a research item;
the structural path is proven: page forges stage A, driver `request("E0")`,
answer `eval`'d in the same runtime with `V`/`VAB` live. Timing: one tap or
the appearance request; bot answers in ~0.2-0.5 s.

Server pattern:
```
update widget_query {id, from, data:"E0"}  ->  answerWidgetQuery(widget_query_id=id, data=<stager>)
```
No pacing concern (single request).

### B. Chained full endgame (7,469 B, current, host-validated)

- 8 answers of 950 B (margin 74 B/answer); `oob/chunks/E0..E7.txt`, sha256
  `5200636a47720fe8…`; driver joins, checks `LEN==7469`, evals.
- Background: 5.2 s pacing → ~36-42 s. This is the fallback already in the
  RUNBOOK.
- Fast variant: the same 8 chunks, but **taps** advance the chain: 5 requests
  in the first 5 s window + 3 after the next window → ~5-7 s. The page needs a
  click handler that calls `request("E<i>")` for the next pending chunk (one
  in flight; on `RATE_LIMITED`/`BUSY` keep the chunk pending).
- Re-show variant: scroll away/back between chunks; each appearance allows the
  next background request immediately (server floor still 5/5 s).

Server pattern (unchanged, `oob/bot_server.py`):
```
getUpdates(offset, timeout=25) -> for each widget_query with data ^E[0-7]$ and from.id==uid:
    answerWidgetQuery(widget_query_id=q.id, data=CHUNKS[i])
```
Answer within 15 s, one consumer per token, log latency/RT.

### C. Compressed 4-answer full endgame (optional speed-up)

- `zlib.compress(endgame_72801.js, 9)` = 3,214 B → base85 = 4,020 chars →
  4 answers (1024/1024/1024/948), or base64 = 5 answers.
- Ship a ~1.2 KB minified inflate + base85 decoder in the widget (page zlib9
  ≈ 1.9 KB, still ≤ 4,096) or deliver it in answer 0/1 (6 answers total).
- Driver: concat → base85 decode → inflate → length/sha256 check → eval.
- Host-validate the codec + inflate with the mock host before any device run;
  A/B the page change against stage A (`ABLEN[599]=327744`) because the stage-C
  text shifts the pre-heap.

## 6. Correction to the burst design (`s2oob_burst_device_72801.html`)

The burst driver sends `E0..E4` back-to-back after each answer, assuming the
server's 5/5 s allowance is the only limiter. It is not: the **client** gate
allows one *background* request per 5000 ms, so `E1..E4` are refused locally
with `RATE_LIMITED` (gate code 8) and the driver retries the same chunk after
5.2 s. Net effect: the burst page degrades to the normal 5.2 s chain (~42 s),
not ~6 s; it still completes, but the "5 requests = 5/5 s allowance" claim is
wrong for the background path. To actually burst, drive the requests from
**taps** (one per tap) or from **re-shows** (one per appearance); both still
obey the server's 5/5 s flood.

## 7. Device probe plan (orchestrator)

Artifacts: `oob/s2probe_limits_72801.html` (2,833 B raw / 1,320 zlib9) and
`oob/probe_answers.py` (`--self-test` PASS; live answers the canned payloads;
`data` field only). Send with `allow_queries=true`, `background_query=true`,
private chat; keep the widget visible; one `getUpdates` consumer.

| step | request | answer payload | expected widget marker | what it proves |
|---|---|---|---|---|
| P0 | `P0` | `'A'*1024` | `LEN=1024` | 1024 bytes accepted |
| P1 | `P1` | `'A'*1025` | `ERR:INVALID_ANSWER` (server accepted) or `TIMEOUT` (server refused; check `probe.log ok=false`) | the ceiling is 1024, and where it is enforced |
| P2 | `P2` | `'é'*512` | `LEN=512` | **bytes**, not chars (1024 B accepted as 512 chars) |
| P3 | `P3` | `'é'*513` | `ERR:INVALID_ANSWER`/`TIMEOUT` | 1026 B refused |
| P4 | `P4` | `'A\0B'` | `ERR:INVALID_ANSWER`/error | NUL refused |
| P7 | `R*64`, then 65 B | `OK64` | `D65=TypeError`, `P7 LEN=4` | request data 1-64; 65 throws client-side (no server hit) |
| P8 | `P8` ×3 | `OK-PACE` | `P8A LEN=7 @0`, `P8B ERR:RATE_LIMITED @~4900`, `P8C LEN=7 @~5100` | 5 s background pacing, measured |
| P6 | `P6` | `'\x01'*1024` | `LEN=1024` | non-NUL control chars allowed (1024 B) |
| P5 | `P5` | `''` | `LEN=null` or `TIMEOUT` | empty answer semantics |

Extra observations during the run:

1. **Tap path**: tap the widget during a 5.2 s wait; the next step goes out
   immediately. A success <5000 ms after the previous request (the `@ms` in the
   marker) proves the foreground gate.
2. **Flood**: after the sequence, tap through 6 requests inside 5 s; the 6th
   should reject `RATE_LIMITED` (server `FLOOD_WAIT`); record the wait seconds
   from `probe.log`/logcat.
3. **Re-show reset**: after a request, scroll the widget off and back, then let
   the 5.2 s timer fire a background request early (<5 s since the last one) -
   it should succeed if `show` reset the gate.
4. **Expiry**: add a server variant that delays an answer 16 s; the widget must
   reject `TIMEOUT` at ~15 s and `probe.log` shows the late `answerWidgetQuery`
   failing (expired query id).
5. **Logcat** for the client-side reasons:
   `grep -Ei "background requests at most once per 5 s|a request is already in flight|no background_query|no can_query|INVALID_ANSWER|answer-rejected"`.

Do not run the probe and the endgame consumers on the same token at the same
time (409 `getUpdates` conflict). The probe proves the channel; the endgame
run then uses the same answer server with the chunk table.

## 8. Open items

- The ≤1024 B single-answer stager does not exist yet; the structural path is
  proven, the compact endgame is exploit work.
- Compressed plan C needs the codec/inflate page and a stage-A A/B on device.
- The burst page should be re-labelled: background burst is impossible; taps or
  re-shows are the fast path.
