# VULNS.md: RCE index

This repository is an archive of the **native code execution** bugs found in
the Telegram widget engine. This page is the master index: ID, class, platform,
widget reachability, status, proof, and path.

The IDs are ordinal: `0day-2`, `nday-1`, `nday-2`. Non-RCE findings
are one line each in [`NON_RCE.md`](NON_RCE.md). The old-name mapping is in
[`HISTORY.md`](HISTORY.md).

## Master table

| ID | Class | Platform | Widget | Status | Proof | Path |
|---|---|---|---|---|---|---|
| **0day-2-RCE-PARSER-SCOPE** | RCE (now fixed; n-day) | Android + iOS + Desktop/macOS (host-proven, live pending) | yes | **Device app-level RCE on 72929/72889, 6s, 17e once; 72979/72989 contained in an isolated widget process; tdesktop 7.4.0/macOS 13.1 in-process, host-proven primitive** | Sony 72929 5/5 + 72889 1/1; 6s `RCE_OK`; 17e msg 5725 `rce.txt`; 72979/72989 stage A only; tdesktop stage A + fake `JSVarRef` + typed-array R/W + C-function hijack through the real bundle | `vulns/0day-2-RCE-PARSER-SCOPE/` |
| 0day-2-RCE-PARSER-SCOPE/**XTAG** | RCE 0day route: cross-tag | Android, MTE off | yes | **App-level RCE 5/5 + 1/1 on 72929/72889; 72979/72989 isolated, stage A only** | 185 B `uid=10346`; C2 `tg-10346-XQ-BT52`; 1.913 s; 72979 UID 99017 / 72989 UID 99024 `isolated_app` | `vulns/0day-2-RCE-PARSER-SCOPE/XTAG/` |
| 0day-2-RCE-PARSER-SCOPE/**STAG** | RCE 0day route: same-tag | Android, MTE-safe | yes | **Device stage A; out-of-band `HF HF OK`; inline host-proven** | `ABLEN[599]=327744 VLEN=327744` | `vulns/0day-2-RCE-PARSER-SCOPE/STAG/` |
| 0day-2-RCE-PARSER-SCOPE/**TINY** | RCE 0day route: iOS hole-reuse | iOS 15.8.8 | yes | **Device RCE** | `RCE_OK` 2026-11-08 05:49:24; 64× `N1IOS_6S_OK` | `vulns/0day-2-RCE-PARSER-SCOPE/TINY/` |
| 0day-2-RCE-PARSER-SCOPE/**IOS27** | RCE 0day route: iOS 27 | iOS 27.0 | yes | **Device RCE once** (msg 5725); gated twin host-only | 7 B `RCE_OK\n` sha256 `704984d9…`; app alive | `vulns/0day-2-RCE-PARSER-SCOPE/IOS27/` |
| **nday-1-RCE-V7-RGX-1827** | RCE n-day (fixed) | Android + iOS | yes | **Device RCE on shipped 13.2** | Sony C2 `tg-10357-XQ-BT52`; iOS reads | `vulns/nday-1-RCE-V7-RGX-1827/` |
| **nday-2-RCE-VARREF-1865** | RCE n-day (fixed later) | Android | yes | **Device RCE 10/10; 72879 C2** | proof 5504 | `vulns/nday-2-RCE-VARREF-1865/` |

## 2. 0day-2-RCE-PARSER-SCOPE: parser `ARG_SCOPE_END` (0day, deliverable)

A strict function with an empty destructuring parameter and a direct `eval`
in its parameter initializer leaks the `ARG_SCOPE_END` sentinel (`-2`) into a
runtime variable index. The engine reads a fake `JSVarDef` 1.31 MB past
`b->vardefs`, then writes 8-byte closure records past a live allocation. With
heap grooming, the write forges `ArrayBuffer.byteLength = 327744`. The bug
needs no OOM and was present in QuickJS-ng v0.17.0 and the Telegram 13.x
builds used in this archive.

**The fix is in the current Telegram builds.** The bug was live on the tested
pins and is now an n-day. The routes are techniques, not new bugs.

### XTAG: Android cross-tag (`c2560s`)

The trigger function is compiled with enough float literals that its bytecode
is a large Scudo allocation. A spray of 2,544-byte `ArrayBuffer` data blocks
carries fake `JSVarDef` records; the 1.31 MB far read lands in that spray. The
closure overflow forges `T[599].byteLength = 327744`. A class-24 view pivot
then gives `ctx`/`rt`, the runtime resolves libc `system`, and
`system("id>…/n1")` writes the proof. This route requires MTE off. It is the
most device-proven route: Sony 72929 5/5, 72889 1/1, C2 1/1
(`tg-10346-XQ-BT52`), time-to-C2 **1.913 s**. Those are app-level results on
builds where the widget engine runs in the app UID 10346. On beta **72979** the
engine runs in the isolated process UID 99017 (`u:r:isolated_app:s0`); stage A
still hits (`ABLEN[599]=327744 ATT=1`), but the endgame stops at
`HF ERR NOANCHOR VNC=0 VO=-1` and the app-data write and loopback C2 are
blocked. 72979 is a mitigation of impact, not a parser fix. The current beta
**72989** keeps the same isolated service (UID 99024, `u:r:isolated_app:s0`);
`PING` works, the v3 detector reports `el=55ms`, and the v3 final is
9,190 B / 4,081 zlib9 with the same `HF ERR NOANCHOR` and no `n1`/C2.
72929/72889 remain the app-level baseline.

### STAG: Android same-tag (`route 2`)

The trigger is an anonymous function with no float literals, so its bytecode is
a 344-byte arena block (class 352). The target is exactly 20 × 65,536 bytes
above it, inside a sprayed arena class-512 data block. Both sides are tag 0, so
the access is MTE-safe. The Pixel 72801 stage A is device-proven
(`ABLEN[599]=327744`); the out-of-band endgame produced `HF HF OK`; the inline
v3 endgame is host-proven. The universal parallel four-widget fan-out is host
12/12; the device run is pending. The proof path is app-private
(`/data/data/org.telegram.messenger/files/n1`). On a build whose widget runs in
an isolated process, the same-tag parser primitive still works but the write
is blocked; re-check the process model on the target build.

### TINY: iOS hole-reuse

iOS uses 4 KiB arena blocks and Apple malloc for the 957-byte bytecode (class
976). The payload frees a run of same-class blocks, compiles the trigger into
one hole, and sprays the class so the far target is inside live data. The
closure overflow forges `ArrayBuffer(72).byteLength = 327744`; the same-view
stage B walks to `rt`, and the inline ROP calls `open`/`write`/`pthread_exit`.
The 6s is device-proven: `RCE_OK`, mtime **2026-11-08 05:49:24**, app alive.

### IOS27: iPhone 17e

The same parser bug and the same-view stage B, with iOS 27 constants
(`PIVOT2 = libcFree+0xB6583074`, open `+0xB79B52BC`, write `+0xB79B3B8C`,
pthread_exit `−0x88AC`) and the AppGroup `rce.txt` path. The device is
verified (iOS 27.0 24A437, ECID `<ECID>`, DDI 642.4, stock 13.2/36535). The
0day was proven once on message 5725: `AppGroup/<APPGROUP>/rce.txt` is 7 bytes
`RCE_OK\n` (sha256 `704984d9…`) and the app stayed alive. The winning stage-A
marker was below the fold and is unknown; the 16:22 marker belongs to another
message. The 8,647 B page is the proven one. The gated 9,139 B twin and the
two-phase detector/final are host-only and need a device re-test.

### 73029 / 73039 status (2026-11-11)

- **73029** is vulnerable to the parser 0day; the engine runs in the isolated
  `:widgets` process (UID 99xxx), so the result is native code in that
  process, not app-level RCE. The app-side escape was not demonstrated; the
  surfaces audited (painter, `canvasRun`, `filterPixels`, the 12 binder
  handlers, the 0xB0 Bitmap UAF, the S1 `SkPathRef` race) are memory-safe or
  abort-only. The app-side read path is still missing.
- **73039** patches the parser in both layers (the `JS_FUNC_ASYNC` check and
  the "suspending opcode in a normal function" guard); the five QuickJS-ng
  fixes below are still missing.
- **Five missing QuickJS-ng fixes** in 73029/73039: `3e236cb` (direct-eval
  closure-var truncation, OOB pointer read + JSValue R/W), `8f0d3b6`
  (#1865 captured-var truncation), `3ad65ad` (`Map.clear` UAF), `7ca4ac5`
  (`FR.unregister` UAF), `45c5b9b` (`reset_weak_ref` abort). The 73029
  release build SIGSEGVs on the eval-OOB shape with the shipped bundle.
- **Seccomp is installed in audit mode** (`installSeccomp(0)`): 30 deny
  entries, default ALLOW, denied syscalls return `SECCOMP_RET_TRAP|0x5EED`
  and a SIGSYS handler maps them to `-EPERM`/`-ENOSYS`. The real gate is the
  isolated UID + SELinux `isolated_app`.
- **App-side DoS** from a stock widget: the `canvasRead`/`canvasRelease`
  Bitmap race aborts the app (`Bitmap_getPixels+412`, "Error, cannot access
  an invalid/free'd bitmap here!"); `canvasRun` OOM/hang; `record`/
  `selectableText` JSON StackOverflow. Details in
  [`NON_RCE.md`](NON_RCE.md) and
  [`docs/ANDROID_73029_ISOLATION_FINAL_20261111.md`](docs/ANDROID_73029_ISOLATION_FINAL_20261111.md).

## 3. nday-1-RCE-V7-RGX-1827: v7 / #1827 stale RegExp bytecode (RCE n-day)

`JS_RegExpDelete` snapshots `re->bytecode` before coercing `lastIndex`. A
`lastIndex` object's `valueOf()` recompiles the regexp and frees the bytecode;
the delete path then runs `lre_exec` on the freed program. A fake
`REOP_set_i32` program forges a victim `ArrayBuffer.byteLength`, and a BigInt
view gives arbitrary read/write. The endgame resolves `rt->mf.js_free` to libc
`system` (Android) or `printf`/ROP (iOS).

The fix exists in the Telegram quickjs fork `TelegramMessenger/quickjs`, branch
`fixes-backport` (`2b62af1`; regression test `1a402cb`; upstream `3d5cb14`).
It is **absent from the shipped 13.2 sources**: the iOS vendored
`iOS/third-party/quickjs-ng/quickjs/quickjs.c` at repo commit `24638bc69` still
has the old order, and the Android fork `2dfeee3e` lacks the fork-master
commits. The bug is therefore a **fixed vulnerability that remains exploitable
only because the shipped source lacks the backport**.

Device-proven RCE on the shipped builds: Sony C2 `tg-10357-XQ-BT52`, Pixel 9
release C2 `tg-10290-Pixel_9`, Sony release C2 `tg-10372-XQ-BT52-release`,
iPhone 6s `RCE_OK`, iPhone 17e n-day file reads. Reference only.

## 4. nday-2-RCE-VARREF-1865: #1865 `var_ref_count` truncation (RCE n-day)

`JSFunctionBytecode.var_ref_count` is `uint16_t`; a generator with 65,533
duplicate parameters and a parse-time direct `eval` makes 65,539 captures,
truncated to 3. `get_var_ref()` indexes `sf->var_refs[65533]`, ~524 KB past
the frame. The chain leaks a `JSVarRef`, reuses the frame, builds fake
BigInt/String/Uint8Array objects, walks to `JSRuntime`, resolves libc
`system`, and hooks `js_free`.

The issue is public. PR **#1869** is open; bnoordhuis commented: "This doesn't
seem like a proper fix...". The fix is **not** in `fixes-backport`; it is in
later builds. The 13.2 builds used here are vulnerable. Device-proven 10/10 on
72789, 9-10/10 on 72799, and a full C2 session on 72879 (proof 5504).
Reference/fallback only.

## 5. Non-RCE findings

DoS, read-only, public n-day references, and rejected carriers are one line
each in [`NON_RCE.md`](NON_RCE.md). They are not part of the RCE deliverable
and are not expanded here.

## What this index does not claim

- No root, kernel, or bootloader exploit.
- No iOS process creation or shell.
- No universal single payload across Android MTE-on and iOS.
- No reliability number for a route that was not run 5 times.
- One 17e RCE result (msg 5725). No reliability number for the 17e; the gated
  twin and the two-phase 17e path are host-only.
- No app-level Android RCE on beta 72979 or 72989. Those builds isolate the
  widget in UID 99017 / 99024; the parser result is contained code execution/
  DoS in that process.

The fixed RCEs are `0day-2-RCE-PARSER-SCOPE`, `nday-1-RCE-V7-RGX-1827`, `nday-2-RCE-VARREF-1865`.
