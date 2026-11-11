# iOS Telegram widget port — investigation and direct-port plan

Date: 2026-11-05. Target: iPhone 6s (`iPhone8,1`, arm64 A9), iOS 15.6,
Dopamine (rootless), root SSH.  Scope: prepare a **separate iOS port** of the
Android 13.2.0 `tgwidget` / QuickJS work, with the endgame moved from
ELF/bionic to Mach-O/dyld.

**Host-only statement.** Everything in this note was produced from files
already on the host (the 13.1.2 decrypted IPA, the macOS 13.1.0 beta DMG, the
Telegram-iOS source tree) plus public App Store metadata.  No install, launch,
AFC pull, SSH command, or other live device operation was performed by this
investigation.  The device commands below are for the orchestrator.

---

## 0. Verdict (short)

1. **The widget engine is not in iOS 13.1.2 (35638).**  The decrypted IPA has
   zero `quickjs` / `WidgetSandbox` / `tgwidget` / `MessageWidget` strings.  The
   feature is 13.2-only.  The 13.1.2 IPA remains useful for bundle/entitlement
   facts, not for the exploit.
2. **iOS 13.2.0 is the right target and is now public.**  The App Store page
   shows version **13.2** released a few hours ago (2026-11-05), minimum iOS
   **15.0**, and the 6s is in the supported-device list.  TestFlight beta
   **35726** already had widgets.  Install/decrypt the stable 13.2.0 build.
3. **The engine is the same quickjs-ng used on Android.**  The iOS design/plan
   in the source tree vendors `third-party/quickjs-ng` v0.17.0 and the same
   `WidgetJS` bundles (`sandbox-bundle.js/qbc`, `validator-bundle.js/qbc`).
   The macOS 13.1.0 beta (283434) is a working proxy: it contains the same
   widget sandbox and a **pre-fix `JS_RegExpDelete`** (`snapshot +0x9c`,
   `lastIndex getter +0xe8`, BC_VERSION 29).
4. **The QuickJS primitive should port unchanged.**  The Android payload
   already uses source-level layout, not build constants: `rt->mf.js_free` at
   `rt+16`, `malloc_state.opaque` at `rt+64`, the five-offset ctx chain, and
   `JSObject.u.array.count` at `+64`.  Those are identical on arm64 iOS.
5. **Only the endgame must be rewritten.**  The 13.1.2 app imports neither
   `system` nor `posix_spawn`, and iOS (very likely) has no `/bin/sh`; the app
   is sandboxed.
   The direct-port payload in `lab/ios_port/` keeps the primitive and replaces
   the Android ELF/`system()` tail with an in-process **`printf(marker)` proof**
   through `rt->mf.js_free`, using the app's imported `printf` stub.  This is
   the smallest, safest first ACE proof and needs only two required offsets
   from the 13.2.0 IPA (`js_def_free`, `printf`; `fflush` is optional).
6. **A full C2 is a later stage.**  The same file provides a gadget finder and
   an allocator-hook design for `connect`/`read`/`write`; the robust fallback
   is a ROP chain built from the app's `__stubs` (A9 has no PAC), or
   `dlopen` of an unsigned agent on Dopamine.  No third-party tunnel is used.

---

## 1. Artifacts already on the host

| Path | What it is | Use |
|---|---|---|
| `ios_sideload/Telegram_decrypted.ipa` | 13.1.2 / 35638, `ph.telegra.Telegraph`, thinned, 72,765,907 B | bundle layout, Info.plist, 13.1.2 negative |
| `ios_sideload/Telegram.ipa` | 13.1.2 store IPA, 208,335,839 B, FairPlay | only for `SC_Info`/signature comparison |
| `macosbeta/Telegram.dmg` | macOS 13.1.0 / 283434, universal, md5 `3d5a7302…` | **QuickJS/WidgetSandbox proxy** |
| `iOS/` (Telegram-iOS source at release-13.1.1) | design + implementation plan | exact widget architecture |
| `ios_sideload/IOS_PROCEDURE.md` | 13.1.2 sideload/session notes | 6s/17 access, app-group layout |

The iOS 13.1.2 IPA:

```
CFBundleIdentifier        ph.telegra.Telegraph
CFBundleShortVersionString 13.1.2
CFBundleVersion           35638
MinimumOSVersion          15.0
UISupportedDevices        iPhone8,1 (6s), iPhone8,4, iPhone9,1/3, …
NSAppTransportSecurity    NSAllowsArbitraryLoads = true
UIBackgroundModes         audio, fetch, location, remote-notification, voip, processing
```

Frameworks and sizes (arm64, decrypted):

```
Telegram                   160,656 B  (thin launcher)
TelegramUIFramework        109 MB     (real UI + most app code)
TelegramCoreFramework       14 MB
PostboxFramework           4.3 MB
MtProtoKitFramework        832 KB
SwiftSignalKitFramework    372 KB
PlugIns: WidgetExtension, BroadcastUpload, NotificationService,
         NotificationContent, Share, SiriIntents
```

No `MessageWidget`, `WidgetSandbox`, `quickjs` or `tgwidget` in any image.
The native WidgetKit extension is Telegram's chat-list widget, **not** the
message HTML sandbox.

---

## 2. iOS widget architecture (from the source design)

Source: `iOS/docs/superpowers/specs/2026-10-13-message-widgets-design.md` and
`iOS/docs/superpowers/plans/2026-10-13-message-widgets.md`.

* **Source format**: a rich message (`RichTextMessageAttribute`) containing a
  code block whose language, after trim+lowercase, is exactly `tgwidget`.  The
  block text is the complete HTML document.  A plain message with a `pre`
  entity stays a code block.
* **Engine**: two QuickJS runtimes on the main thread — the widget runtime
  (`sandbox-bundle.js` + DOM shim) and a trusted validator runtime
  (`validator-bundle.js`); both from `third-party/widget-sandbox`
  (`widget-sandbox version=0.6.0 protocol=1 profile=1 sdk=1`).
* **Renderer**: a fork of litehtml.  The `document_container` is the
  no-network boundary: only `data:` images are decoded; `import_css`, `link`,
  `set_base_url`, and custom fonts never fetch.  The validator is the second
  line of defence.
* **Limits**: `JS_SetMaxStackSize` 2 MB per runtime; memory limit 64 MB;
  `cpuLimitMs` 500 per task, plus a 300 ms/1000 ms `CpuBudget`; 256 timers;
  height clamped 24–900 pt; 50,000 nodes / 200,000 ops per batch.
* **Bridge** (much smaller than Android): `sendMessage(text)` (tap-gated, once
  per tap), `openLink(url)` (confirmation, tap-gated), `onTheme`, `ready`.
  No `request`, no `viewer`, no `localStorage` persistence, no `fetch`/XHR/WS.
* **Gate**: Debug Settings ▸ "Message Widgets (tgwidget)" **and** no
  `ios_killswitch_disable_message_widgets` in the app config.
* **Delivery for testing**: the plan's recipe is a rich message with a
  `# Heading` line followed by a fenced block whose language is `tgwidget`
  (paste/formatting path).  The 13.2 beta also ships in-app widget test tools
  (public reporting); stable 13.2 may keep the Debug Settings toggle.

The plan's own device checklist confirms the app links with
`-stack_size 0x1000000` (16 MB) so JS can run inline on the main thread.

### 2.1 What the 13.2.0 IPA must show

`analyze_bundle.py` (below) should report, for `TelegramUIFramework`:

* `WidgetJS/sandbox-bundle.js`, `validator-bundle.js` (+ `.qbc`);
* `widget-sandbox version=0.6.0 …`;
* QuickJS `BC_VERSION` 29 (`cmp wN, #0x1d` on the
  `invalid version (%d expected=%d)` path);
* the pre-fix `JS_RegExpDelete` order (see §4);
* the allocator stubs `js_def_malloc/calloc/free/realloc/usable_size`;
* the imported stubs for `printf`, `fflush`, `dlsym`, `dladdr`, `socket`,
  `connect`, `read`, `write`, `close`, `fopen`, `fprintf`, `fclose`,
  `mmap`, `mprotect`.

If any of these are missing, stop and re-inventory before touching the
primitive.

---

## 3. QuickJS layout — why the Android payload ports

The Android v7 payload uses only source-level quickjs layout.  Verified against
quickjs-ng 0.18/0.17 source with `clang -Xclang -fdump-record-layouts`
(arm64 LP64 is identical to the x86-64 audit layout):

| object | field | offset |
|---|---|---:|
| `JSValue` | `u` / `tag` | 0 / 8 (size 16) |
| `JSString` | `first_weak_ref`; char data | 16; **+24** (size 24) |
| `JSObject` | `shape` / `prop` / union `u` | 24 / 32 / 48 (size 72) |
| `JSObject.u.regexp` | `pattern` / `bytecode` | 48 / **56 (0x38)** |
| `JSObject.u.array` | `u1.size` / `u.ptr` / `count` | 48 / 56 / **64** |
| `JSShape` | `proto` | **48** |
| `JSRuntime` | `mf` at 0; `mf.js_free` **16**; `malloc_state.opaque` **64** |
| `JSContext` | `rt` | **16** |
| `JSRegExp` | `pattern` / `bytecode` | 0 / 8 |
| `JSTypedArray` | `obj`/`buffer`/`offset`/`length` | 16/24/32/36 (size 48) |
| `JSArrayBuffer` | `byte_length`/`data` | 0 / **16** |

The ctx chain used by the payload is therefore stable:

```
JSObject(candidate) shape +0x30 -> JSShape.proto
JSShape.proto      +0x20 -> JSObject.prop
ctor (function)    +0x30 -> realm = JSContext*
JSContext          +0x10 -> JSRuntime*
```

The Android v7 payload already treats `rt + 16` as `js_free` and `rt + 64` as
`malloc_state.opaque`; both match this table.

### 3.1 The macOS proxy is a validated QuickJS fingerprint

`macosbeta/Telegram.dmg` (13.1.0 / 283434, arm64 slice) was analyzed with the
new tooling.  Results:

```
BC_VERSION      cmp w8, #0x1d  at 0x103116c7c
                mov w9, #0x1d  at 0x103116cf4
JS_RegExpDelete func 0x10314aa28, size 0x67c
                snapshot   +0x9c (0x10314aac4)   ldr x8,[x22,#0x38]
                lastIndex  +0xe8 (0x10314ab10)   mov w3,#0x5d
                -> PRE-FIX (snapshot before the attacker getter)
js_regexp_exec  func 0x103146620, size 0xce0
                snapshot   +0x20c, lastIndex +0x7c
                -> POST-FIX (exec path)
allocator       js_def_malloc 0x3127cd0
                js_def_calloc 0x3127cd4
                js_def_free   0x3127cd8
                js_def_realloc 0x3127ce0
                js_def_malloc_usable_size 0x3127cec
```

This reproduces the earlier 283434/283442 audit (`snapshot +0x9c`,
`getter +0xe8`) and proves the detector works.  **The iOS 13.2.0 build must
show the same pre-fix order**; the tool reports it explicitly.

Note: the 0.18.0+3 source tree on the host has the fixed order in both
functions; the shipped Telegram binary is older/different.  Do not judge the
binary by the local source.

---

## 4. Direct iOS port — what is in `lab/ios_port/`

| File | Purpose |
|---|---|
| `analyze_bundle.py` | IPA/.app/Mach-O triage: Info.plist, WidgetJS, BC_VERSION, RegExp order, allocator stubs, endgame stub offsets |
| `make_ios_payload.py` | takes the Android v7 payload, injects iOS CFG, replaces the `system()` tail with `ios_endgame.js`, optionally reads the IPA for offsets |
| `ios_endgame.js` | iOS tail: Mach-O base, optional `system`, `printf(marker)` + `fflush` proof, hook restore |
| `device_payload_ios_v1.proxy.js` | **proxy build only** with macOS 283434 offsets; not for iOS |
| `device_widget_ios_v1.proxy.html` | proxy wrapper with `#iosout`; not for iOS |
| generated `device_payload_ios_v1.js` / `device_widget_ios_v1.html` | produced by `make_ios_payload.py --ipa`; not present until the 13.2.0 IPA is available |
| `probe_min.html` | tiny widget: JS execution + tap counter, no exploit |
| `probe_ctx.html` | read-only engine probe: BigInt, typed arrays, resizable ArrayBuffer, RegExp getter, synchronous free |
| `macho_gadgets.py` | arm64 pivot/pop/call gadget finder for the ROP stage |
| `test_endgame_node.js` | host-only mock test of the endgame (base/hook/restore/marker) |
| `host/c2_listener.py` | LAN-only exfil listener (no tunnel) |
| `host/frida_probe.js` | ground truth: module bases, `free`/`system`/`dlopen`/`posix_spawn`, `/bin/sh` |
| `host/ssh_pull.sh` | read-only pull plan for IPA, dyld cache, container, crashes |
| `host/post_widget.md` | rich-message/composer/DB-patch delivery guide |
| `run_direct.sh` | one-shot host pipeline: IPA -> analysis -> payload + HTML |
| `ios_commands.md` | orchestrator command sheet (pymobiledevice3/lockdown/DVT/SSH) |

### 4.1 Build the payload for the real build

```sh
cd <HOME>/ailocal/Telegram
VENV=<HOME>/ailocal/Telegram/ios_sideload/venv/bin/python

# 1. triage the decrypted 13.2.0 IPA
$VENV lab/ios_port/analyze_bundle.py \
  --ipa ios_sideload/Telegram_13.2.0_decrypted.ipa --stubs

# 2. build the iOS payload + widget HTML from the Android v7 payload
$VENV lab/ios_port/make_ios_payload.py \
  --ipa ios_sideload/Telegram_13.2.0_decrypted.ipa \
  --out lab/ios_port/device_payload_ios_v1.js \
  --html-out lab/ios_port/device_widget_ios_v1.html

# 3. syntax check (host)
node --check lab/ios_port/device_payload_ios_v1.js
node lab/ios_port/test_endgame_node.js

# or the whole host side in one command:
lab/ios_port/run_direct.sh /path/to/Telegram_13.2.0_decrypted.ipa
```

`make_ios_payload.py` picks the image with `js_def_free` + `_printf` (or
`_puts`), then writes `JS_DEF_FREE`, `JS_DEF_MALLOC`, `STUB_PRINTF`,
`STUB_PUTS`, `STUB_FFLUSH`, `STUB_DLSYM` into `CFG`.  If `js_def_free` is not recognized, it writes 0 and
the endgame falls back to the `js_def_malloc` offset and then to a 16 KiB/4 KiB
Mach-O header scan (slower but version-independent).  If `printf` lives in a
different image than `js_free`, get its absolute address from
`host/frida_probe.js` and rebuild with `--proof-addr 0x…` (and
`--fflush-addr 0x…`).

**Direct-port status.**  The generator, endgame, analyzer and host mock test
are implemented and pass on the macOS proxy.  The only missing input is the
decrypted 13.2.0 IPA.  Once it is on the host, `lab/ios_port/run_direct.sh`
performs the whole host side in one command; the remaining steps are the
orchestrator's widget delivery and DVT launch.

### 4.2 What the generated tail does

```
js_free = rd64(rt + 16)                 # js_def_free (TelegramUIFramework)
base    = js_free - CFG.JS_DEF_FREE     # Mach-O image base
printf  = base + CFG.STUB_PRINTF        # imported __stubs entry
                                        # (puts is the fallback if no printf)
wr64(rt+16, printf); wr64(rt+64, D)     # mf.js_free = printf; opaque = marker
TRIG = null                             # synchronous free of a >512 B block
wr64(rt+16, js_free); wr64(rt+64, opaque0)
wr64(rt+16, fflush); wr64(rt+64, 0); BIG = null
wr64(rt+16, js_free); wr64(rt+64, opaque0)
setres('IOS_OK base=… proof=…')
```

Why it is safe: `js_free_rt` ignores the callee's return value and computes
`free_size` before the hook.  `printf(marker)` and `fflush(NULL)` have no
format arguments and cannot corrupt the runtime; the marker lives at the
victim block `D`, which is why `opaque` is set to `D`.

Expected markers (on-screen `#iosout` and DVT stdout):

```
RT=CTX            (or RT=BOTH / ARENA)
IOS_HOOK_PRINTF base=0x…
IOSPORT_R1827_OK  (stdout, after fflush)
IOS_OK base=0x… proof=0x…
```

Failure markers: `NO_VIEWS`, `NO_WR`, `NO_RT`, `NO_FREE`, `IOS_NO_BASE`,
`IOS_NO_PRINTF_STUB`, `IOS_BAD_PROOF_STUB`.  They localize the failing stage
without a debugger.  `IOS_BAD_PROOF_STUB` means the stub offset points at
non-stub code (wrong image/offset); rebuild with `--proof-addr` from Frida.

### 4.3 Diff vs the Android v7 payload

| Android v7 | iOS v1 |
|---|---|
| `CFG.SYSTEM_DELTA` + ELF program headers + SysV/GNU hash | removed |
| `js_def_free` -> `free@plt` -> GOT -> libc `free` | `js_free - CFG.JS_DEF_FREE` -> Mach-O base (fallback: 64 KiB scan) |
| `resolveSystem(libcFree)` over DT_SYMTAB/DT_STRTAB | app `__stubs` offsets from the IPA (`printf`, `fflush`, …) |
| `js_free = system; opaque = cmd` | `js_free = printf; opaque = marker` (then restore) |
| `CMD` is a shell pipeline | `printf(marker)` + `fflush(NULL)`; optional `--system-addr` keeps the old shape |
| bot 4 KiB compressed limit | rich-message code block; size limit still to be measured |

The #1827 trigger, the heap grooming (`FILL64`, `FILL80`, `NONCE`, `MAGIC`,
`ARENA`), the view scan, the ctx chain and the `rd64`/`wr64` primitives are
byte-for-byte the Android v7 code.  This is deliberate: the iOS library is the
same quickjs-ng, so only the tail changes.

### 4.4 Optional `system()` path

`--system-addr 0x…` makes the tail use the Android shape (`js_free = system`,
`opaque = cmd`) instead of `printf`.  Use it only after confirming `/bin/sh`
exists and the sandbox allows it.  On a rootless Dopamine 6s this is unlikely;
on a rootful bootstrap it may work.  The on-device probe is in
`host/frida_probe.js` (`File.exists('/bin/sh')` and `system` address).

---

## 5. iOS endgame — Mach-O/dyld, sandbox, C2

### 5.1 What iOS gives the in-process payload

The 13.1.2 `TelegramUIFramework` imports (same set expected in 13.2.0):

```
_dlsym _dladdr _open _openat _read _write _send _recv _close
_socket _connect _mmap _mprotect _fopen _fprintf _fwrite _fread
_fclose _printf _fflush _stat _unlink _getaddrinfo _inet_pton
```

It does **not** import `_system`, `_posix_spawn`, `_execve`, `_fork`, `_popen`.
The iPhoneOS16.5 SDK's `libc.tbd` exports `_system` and `_posix_spawn`; iOS 15
uses the same Darwin libc, so `dlsym(RTLD_DEFAULT, "system")` is possible once
there is a call primitive (confirm the symbol on the 6s with Frida).  The
blocker is `/bin/sh` and exec policy, not the symbol.

### 5.2 The `/bin/sh` question

The iOS 27.0 SystemOS listing has only `/bin/df` and `/bin/ps`; no `/bin/sh`,
`/bin/bash`, or `/usr/bin/sh`.  iOS 15.6 must be checked on the 6s:

```sh
ssh root@<LAN_IP> 'ls -l /bin/sh /var/jb/bin/sh /var/jb/usr/bin/sh'
```

A rootless Dopamine bootstrap puts a shell under `/var/jb`, but `system()`
hardcodes `/bin/sh`.  The SSV rootfs is read-only, so a `/bin/sh` symlink cannot
be added.  `posix_spawn("/var/jb/usr/bin/sh", …)` is possible only if the app's
sandbox permits the exec; Dopamine weakens `/var/jb` access for all processes,
but exec is still a separate sandbox operation.  This is a device probe, not an
assumption.

### 5.3 Endgame ladder (in order of effort)

1. **`printf` marker (implemented).**  In-process, no shell, no network,
   sandbox-safe.  Proves arbitrary code execution in Telegram.  Best first
   milestone.
2. **File write.**  The app imports `fopen`/`fprintf`/`fclose`, but the
   allocator-hook argument mapping is awkward: `js_free(opaque, ptr)` passes
   the block **header** as `ptr`, while `fprintf(FILE*, fmt)` needs the format
   string as `x1`.  `js_malloc`/`js_realloc` can capture `fopen`'s return, but
   then the 3-arg/4-arg write calls need a ROP or a `return 0` usable-size
   gadget.  This stage is designed but **not implemented**; the first proof is
   `printf` to stdout (captured with DVT `--stream`).  For a file-only proof,
   use the ROP stage and call `fopen`/`fwrite`/`fclose` from the chain.
3. **Socket C2.**  `js_realloc(opaque, ptr, size)` maps exactly to
   `connect(fd, sockaddr*, len)`, `read(fd, buf, len)`, `write(fd, buf, len)`;
   `js_free` maps to `close(fd)`.  `socket(domain, type, protocol)` needs all
   three small args; use `js_calloc`/`js_malloc` with a `return 0` usable-size
   gadget, or get an fd from `fopen`/`fileno`.  The return value of
   `connect/read/write` is stored as the realloc'd block pointer, so restore
   the ArrayBuffer data pointer from JS immediately (the payload has arbitrary
   write).  A failed `connect` returns `(void*)-1` and would crash the engine;
   ensure the listener is up and the sockaddr is valid before triggering.
4. **ROP (most general).**  A9 is arm64 without PAC.  `js_free` is called with
   `x0 = malloc_state.opaque`, `x1 = block`; point `js_free` at a pivot
   (`mov sp, x0; ret`) and place a chain in a JSArrayBuffer.  The app binary
   contains the imported-function `__stubs` (`socket`, `connect`, `read`,
   `write`, `close`, `dlsym`, `dladdr`, `mmap`, `mprotect`), so a chain can call
   them by stub address without any dyld-cache offset.  `macho_gadgets.py`
   found 23 `mov sp, x0` pivots in the 13.1.2 UI framework; the argument-pop
   and call gadgets are rarer and need IDA/`llvm-objdump` follow-up.  A chain
   also gives `dlsym(RTLD_DEFAULT, "system")` with a proper return, and
   `posix_spawn` if desired.
5. **`dlopen` agent (jailbreak only).**  Dopamine bypasses code signing
   system-wide and gives `/var/jb` access; `dlopen` of an agent dylib from the
   app container is the clean persistent C2.  On stock iOS this fails AMFI.
   Re-signing Telegram with `platform-application` / `no-sandbox` and installing
   via TrollStore is a device-level decision (orchestrator/user), not something
   the widget can grant itself.

### 5.4 C2 transport

The widget itself has no network API.  After ACE the process is a normal
sandboxed Telegram process: outgoing sockets are allowed, `NSAllowsArbitraryLoads`
is true, and the app has audio/fetch/voip background modes.  Use the host's LAN
address and `host/c2_listener.py`; **no third-party tunnels**.  A one-shot
command channel can be rebuilt per widget task; a persistent agent needs a
dylib or a ROP loop.

---

## 6. Access requirements — jailbreak vs App Store

| Capability | Jailbroken 6s (current) | Stock/App Store only |
|---|---|---|
| Install 13.2.0 | App Store / TestFlight | App Store |
| Decrypt the app | TrollDecrypt / dumper | **no** |
| Read app container / Postbox DB | root SSH | AFC app container only (no group DB) |
| Patch a widget into the DB | yes | **no** (container not writable) |
| Frida / DVT / crash logs | yes | DVT only with developer mode; no Frida |
| Post a widget manually | yes | yes (if the gate opens) |
| Verify arbitrary R/W | Frida/LLDB | **no** |
| `dlopen`/exec agent | likely (Dopamine) | **no** |

Without a jailbreak the only meaningful iOS work is UI-level: install 13.2,
open Debug Settings, post benign widgets, observe rendering/taps/crashes.  You
cannot patch the container/DB or confirm memory corruption.  A developer
profile applies to your own app, not to Telegram.

Stock-only options, in order of usefulness:

1. **Manual rich message** to Saved Messages / your own test chat with a benign
   widget (`probe_min.html`, `probe_ctx.html`); no bot needed.
2. **TestFlight beta** if the stable build hides the gate.
3. **Your own bot** (self-hosted, your account) *if* it can send the rich
   message; the public Bot API does not expose the widget block, so this is
   likely a non-starter today.
4. **Developer profile** only for a separate test app; it cannot add
   entitlements to Telegram or read its container.

Forbidden: sending a payload to a third-party bot/chat, using public tunnels,
or testing a device you do not own/are not authorized to test.

**Forbidden in this project**: sending a widget payload to a third-party bot or
chat; using public tunnels; touching a device you do not own/are not authorized
to test.  Use Saved Messages, your own test account, or a self-hosted bot.

---

## 7. Test plan for the 6s (orchestrator)

### P0 — transport and preflight

```sh
ssh root@<LAN_IP> 'uname -a; sw_vers; id'
ssh root@<LAN_IP> 'ls -l /bin/sh /var/jb/bin/sh /var/jb/usr/bin/sh'
ssh root@<LAN_IP> 'ls /var/jb/usr/sbin/frida-server; dpkg -l | grep -Ei "dopamine|ellekit"'
```

Record: iOS build, jailbreak, shell paths, Frida.  If `/bin/sh` is absent, do
not plan on `system`; use the `printf`/ROP paths.

### P1 — version fingerprint

```sh
/tmp/opencode/iosvenv/bin/pymobiledevice3 apps query ph.telegra.Telegraph
# or over SSH: PlistBuddy on the installed Telegram.app/Info.plist
```

Record `CFBundleShortVersionString` / `CFBundleVersion`.  Expected 13.2.x,
build ~357xx.  `MinimumOSVersion` must be ≤ 15.6.

### P2 — decrypt and pull the IPA

Use TrollDecrypt on the 6s, then `scp` the IPA to
`ios_sideload/Telegram_13.2.0_decrypted.ipa`.  Verify the Mach-O magic and
`cryptid=0`:

```sh
unzip -p ... Payload/Telegram.app/Info.plist > /tmp/tg.plist
# check version/build/minOS
unzip -o ... 'Payload/Telegram.app/Frameworks/TelegramUIFramework.framework/TelegramUIFramework'
```

### P3 — static triage

```sh
VENV=<HOME>/ailocal/Telegram/ios_sideload/venv/bin/python
$VENV lab/ios_port/analyze_bundle.py --ipa ios_sideload/Telegram_13.2.0_decrypted.ipa --stubs
```

Pass criteria:

* `WidgetJS` files and `widget-sandbox version=0.6.0`;
* `BC_VERSION cmp wN, #0x1d`;
* `RegExp/exec … -> PRE-FIX`;
* `allocator stubs: js_def_free=0x…`;
* `_printf`, `_fflush`, `_dlsym`, `_dladdr` stub offsets.

If the IPA has no `WidgetJS`/`WidgetSandbox` resources at all, the build is not
the widget build; stop and re-check the version.  If the resources are present
but the `invalid version`/`corrupted bytecode` strings are stripped, the
QuickJS code is still there; inspect `__text`/symbols manually and use the
`WidgetJS` version header plus the js_def_* pattern as the fingerprint.

### P4 — build the iOS payload

```sh
# first run: more markers
$VENV lab/ios_port/make_ios_payload.py --ipa ios_sideload/Telegram_13.2.0_decrypted.ipa --dbg
node --check lab/ios_port/device_payload_ios_v1.js
node lab/ios_port/test_endgame_node.js
```

Once the stage markers are understood, rebuild without `--dbg` (it is slower
and the CPU budget is 500 ms).

### P5 — minimal widget probe

Post `lab/ios_port/probe_min.html` as a rich message with a `tgwidget` code
block (Saved Messages / own test chat).  Expected: `JSRUN ok … bigint=function …`
and `TAP n=1` after a tap.  This validates the delivery/gate, not the exploit.

If the composer does not expose the language, try the Debug Settings built-in
widget tool or the markdown paste recipe (`# Heading` + fenced block).  If the
payload is rejected for size, the 20.8 KB exploit needs the DB-patch path (P7b).

### P6 — engine probe

Post `probe_ctx.html`.  Expected lines: `bigint=function`, `u64_roundtrip=true`,
`rab_ok`, `regexp_getter=true`, `ctx_probe_done`.  A failure here means the
iOS shim/QuickJS build differs; re-read the analyzer output before the exploit.

### P7 — exploit delivery

Post `device_widget_ios_v1.html` (or `device_payload_ios_v1.js` inside the
wrapper).  Expected on-screen progress (the `setres` mirror):

```
RT=…
VIEWS=…
IOS_HOOK_PRINTF base=0x…
IOS_OK base=0x… proof=0x…
```

and on stdout (launch Telegram under DVT):

```sh
pymobiledevice3 developer dvt launch 'ph.telegra.Telegraph' --kill-existing --stream
```

```
IOSPORT_R1827_OK
```

If the widget is too large for the composer: decrypt/root SSH, patch the
message into the Postbox DB (the 13.1.2 layout is in `IOS_PROCEDURE.md §7`;
13.2 adds `MessageMedia.messageMediaWidget`-equivalent fields).  This is a
device operation for the orchestrator; do not guess the schema — dump the
`db_sqlite` schema first.

### P8 — primitive verification

Compare the payload's `RT=` / `VIEWS=` markers with Frida ground truth:

```sh
frida -H <LAN_IP>:27042 -n Telegram -l lab/ios_port/host/frida_probe.js
```

If `RT=` is missing, the #1827 grooming needs tuning for the 64 MB iOS heap
(the payload's `FILL64`/`FILL80`/`NONCE` knobs are still there).  Capture the
crash log with `pymobiledevice3 crash pull`.

### P9 — endgame proof

`IOSPORT_R1827_OK` in the DVT stream and `IOS_OK` on screen = in-process ACE.
Then, if authorized, test the optional `system` path (`--system-addr`) only
after `/bin/sh` is confirmed; otherwise move to the file/socket/ROP stage.

### P10 — C2 (optional, LAN only)

Start `host/c2_listener.py` on the host LAN IP, build the socket-stage payload,
and confirm the listener receives the marker.  No public tunnel.

---

## 8. What to ask the user / decisions

1. Confirm the 6s is the test device and that updating it to 13.2.0 and
   decrypting the app is authorized.
2. Root SSH details (host/port/key or password) and whether usbmux is
   recoverable or Wi-Fi SSH is the only path.
3. May the orchestrator relaunch Telegram under `developer dvt launch --stream`
   (it kills the running app) for the `printf` proof?
4. If the widget source is rejected for size: authorize the DB-patch path, with
   a schema dump first.
5. Is a LAN listener on the host acceptable for the socket stage?  Which
   host IP/port?  (No third-party tunnels.)
6. If `system` is desired: is a rootful bootstrap (palera1n) acceptable, or do
   we stay rootless and use the ROP/file paths?
7. TestFlight vs App Store: stable 13.2 is out; only fall back to TestFlight if
   the stable build lacks the widget gate.
8. Confirm the forbidden items: no third-party bot payload, no public tunnel,
   no patching a non-owned device.

---

## 9. Limits / open questions

* **Size**: the Android v7 payload is 20.7 KB.  The iOS rich-message code
  block may be limited to the normal message text limit; if so, the exploit
  needs a smaller loader or the DB-patch delivery.  Measure with 4/8/16/32 KB
  blocks before assuming.
* **Gate**: stable 13.2 may hide the Debug Settings toggle; the beta 35726
  definitely had widget test tools.  Check both.
* **Heap**: iOS uses a 64 MB limit vs Android's 6 MiB; the #1827 grooming may
  need different `FILL64`/`FILL80` values.  The payload keeps the knobs.
* **Main-thread stack**: the plan's 16 MB `-stack_size` must be confirmed on
  the 13.2 binary; deep JS recursion could otherwise abort before the
  primitive's catchable errors.
* **`/bin/sh`**: unknown on iOS 15.6 until the device probe.  Do not design the
  first proof around `system`.
* **Sandbox**: Dopamine weakens `/var/jb` access but does not grant
  `platform-application`; `dlopen`/exec behavior must be measured, not assumed.
* **Exact build**: the App Store is rolling out 13.2 now; record the build
  number and re-run the analyzer.  All offsets in this note from the macOS
  proxy are illustrative only.

---

## 10. Reproduction commands (host, no device)

The ephemeral `/tmp/opencode` extracts were removed after the investigation.
Re-extract the two large inputs first:

```sh
mkdir -p /tmp/opencode/macdmg /tmp/opencode/iosipa
7z x -y macosbeta/Telegram.dmg \
  'Telegram/Telegram.app/Contents/MacOS/Telegram' \
  'Telegram/Telegram.app/Contents/Resources/WidgetSandbox_WidgetSandbox.bundle/Contents/Resources/WidgetJS/*' \
  -o/tmp/opencode/macdmg
unzip -o ios_sideload/Telegram_decrypted.ipa \
  'Payload/Telegram.app/Frameworks/*' 'Payload/Telegram.app/Telegram' -d /tmp/opencode/iosipa
```

```sh
# analyzer on the macOS proxy (validates the QuickJS detector)
cd <HOME>/ailocal/Telegram
VENV=ios_sideload/venv/bin/python
$VENV lab/ios_port/analyze_bundle.py \
  --macho /tmp/opencode/macdmg/Telegram/Telegram.app/Contents/MacOS/Telegram --stubs

# analyzer on the 13.1.2 IPA (expected: no QuickJS)
$VENV lab/ios_port/analyze_bundle.py \
  --ipa ios_sideload/Telegram_decrypted.ipa

# gadget finder (build-specific)
$VENV lab/ios_port/macho_gadgets.py \
  --macho /tmp/opencode/iosipa/Payload/Telegram.app/Frameworks/TelegramUIFramework.framework/TelegramUIFramework \
  --all --max 20

# endgame mock test
node lab/ios_port/test_endgame_node.js
```

The macOS proxy DMG and the extracted objects are in `/tmp/opencode` only and
are not part of the repository; the analyzer can re-extract from
`macosbeta/Telegram.dmg` with `7z`.
