# Devices

The campaign used a small set of devices. Each one proves a different part of
the chain. The device is the arbiter: host results are not device results.

## Summary

| Device | OS | Telegram | Role | Access | MTE / MIE | 0day status |
|---|---|---|---|---|---|---|
| Sony XQ-BT52 (Xperia 10 III) | Android 13 | beta 13.2.1 (72889), beta 13.2.2 (72929), beta 13.2.2 (**72979**, **72989**) | Android cross-tag route; C2 | Rooted; `adb`; app UID 10346; 72979/72989 widget UID 99017/99024 | MTE off | App-level RCE 5/5 on 72929, 1/1 on 72889; 72979/72989 contained in an isolated process |
| Pixel 9 | Android 17 | release 13.2.0 (72801) | Android same-tag route; no-root bot delivery | Stock; Bot API; App UID 10290 | Release APK untagged (0 `mt` mappings) | Stage A proven; out-of-band endgame `HF HF OK`; inline endgame not device-proven |
| iPhone 6s (iPhone8,1) | iOS 15.8.8 | 13.2 (36535) | iOS hole-reuse route; ROP proof | Jailbroken (rootless Dopamine); Frida; Wi-Fi | No MTE, no MIE; app arm64 | Proven: `RCE_OK` |
| iPhone 17e (iPhone18,5) | iOS 27.0 (24A437) | 13.2 (36535), stock | iOS route on a modern device | Stock; CoreDevice / Bot API | MIE-capable hardware, app not MIE-enabled | Proven once (msg 5725); gated twin host-only |
| Samsung (model TBD) | TBD | TBD | Universal first-open test | TBD | TBD | Planned |

## Sony XQ-BT52: Android 13

- Model: XQ-BT52 (Xperia 10 III), arm64.
- Build: `62.2.A.0.533`, Android 13 (SDK 33).
- Telegram beta package: `org.telegram.messenger.beta`. On 72889/72929 the app
  UID is 10346 (`u0_a346`) and the widget runs in the app process. On 72979 the
  widget runs in the isolated process
  `:widgets:org.telegram.utils.twidget.WidgetEngineService`, UID 99017,
  SELinux `u:r:isolated_app:s0`.
- Root is available. It was used to replace `cache4.db` and to read the proof
  file. It was **not** used to execute the payload. A no-root control run used
  the beta `sendWidget` and produced the same proof.
- MTE is off on this device. The cross-tag route requires that: the vulnerable
  bytecode and the sprayed target are different Scudo chunks with different
  tags, so an MTE-on build would fault at the first fake `JSVarDef` load.
- The app-level certification used two builds with the same widget bytes:
  - 13.2.1 (72889): 1/1.
  - 13.2.2 (72929): 5/5.
- The 5/5 means five cold starts, each with a fresh database, a force-stop, a
  deleted proof file, and a message open. All five produced the same 185-byte
  proof (md5 `52258bc776f2f378542d1b2c736840e3`). The app stayed alive.
- C2 (72929): one session, `tg-10346-XQ-BT52`, `uid=10346`, `exec id` → `rc=0`.
- The proof is the `id` line only. The command field is 50 bytes and the forged
  buffer is 64 bytes, so there is no room for a larger marker.

### 72979 and 72989 (13.2.2, isolated widget process)

The beta updated to versionCode **72979** (versionName 13.2.2, update
2026-11-08 18:43:58; previous 72929), then to **72989** (update 18:57:37;
previous 72979). The app stayed alive; the app UID is still 10346. The widget
engine moved to the isolated process
`org.telegram.messenger.beta:widgets:org.telegram.utils.twidget.WidgetEngineService`,
UID **99017** on 72979 and **99024** on 72989, SELinux
`u:r:isolated_app:s0`.

Functional and parser checks:

- `TelegramWidget.request('PING')` reached the host (`SKIP data 'PING'`), so
  the widget and answer channel still work.
- The v3 detector reported `platform=1 chain=1 hit=1 att=0 sel=599 dpr=2.6
  scr=389x300 el=54ms`.
- The v3 parser plus c2560s final hit stage A:
  `ABLEN[599]=327744 ATT=1`; the endgame reported
  `HF ERR NOANCHOR VNC=0 VO=-1`; no `n1`; the app stayed alive.
- On 72989 the same isolated model applies: app UID 10346, root ok, app alive;
  PING works; v3 detector `el=55ms`; v3 final 9,190 B / 4,081 zlib9; same
  `HF ERR NOANCHOR`; no `n1`/C2. Test messages were deleted; no poller active.

Impact: the parser bug is not fixed. Stage A is still demonstrable. The
isolated process has no app-private data access and no network permissions, so
the current stage B write to `/data/data/org.telegram.messenger.beta/files/n1`
and the loopback C2 are blocked even after an anchor fix. 72979/72989 are a
mitigation of impact, not a parser fix. The app-level proof remains 72929
(C2 UID 10346).

## Pixel 9: Android 17

- Model: Pixel 9, arm64.
- Telegram release package: `org.telegram.messenger`, versionCode 72801
  (13.2.0), App UID 10290 (`u0_a290`).
- No root. Delivery is the Bot API `sendWidget` (beta or standard base).
- The release APK has **no MTE-tagged mappings** (`0` `mt` lines in
  `/proc/<pid>/maps`). MTE on/off is therefore not the deciding factor on this
  build today. The same-tag route is insurance for a future memtag build.
- Device results:
  - Corrected stage A probe: `S1 ABLEN[599]=327744 VLEN=327744 END=-`; the
    parser bug and the forge work on the release build.
  - The first inline endgame pages shifted the pre-heap and crashed in stage A
    (`SEGV_MAPERR` at `b+1,310,832`). The endgame was moved out of the page.
  - Out-of-band endgame: `G1/8 … G8/8 | HF HF OK` (campaign record; the host
    mock reproduces the same marker and a 162-byte proof 3/3).
  - The inline v3 endgame (9,186 raw / 3,883 zlib9) is host-proven
    (`END=HF OK`, 154-158 ms) but is not device-proven.
- The universal parallel fan-out (`w_v0`-`w_v3`) is host 12/12. The device run
  is pending.

## iPhone 6s: iOS 15.8.8

- Model: iPhone8,1 (A9), arm64.
- OS: iOS 15.8.8.
- Telegram: 13.2 (36535), `ph.telegra.Telegraph`.
- Jailbreak: rootless Dopamine. The app sandbox still denies `fork`,
  `posix_spawn`, and `execve`. It allows `open`, `read`, `write`, `socket`,
  `connect`, and the AppGroup database.
- Engine: QuickJS-ng v0.17.0, 8 MiB widget heap, 4 KiB arena blocks.
- No MTE, no MIE, no PAC on the app code (A9 is arm64; the app is not arm64e).
- Delivery: Frida insert for new messages; Postbox `t7` rewrite to keep the
  same widget id for the storage seed.
- 0day result:
  - Hole-reuse probe H400 hit: `HIT=545 LEN=327744 PH=36 VK=598 NT=21`.
  - Stage B printf proof: `IOS_N1_OK base=0x10c92c000 printf=0x111ea7c20
    rt=0x103f02600 D=0x11c86ca10 leak=FORGED`, and 64 `N1IOS_6S_OK` lines.
  - Inline ROP wrote `Documents/rce.txt` = `RCE_OK` with mtime
    **2026-11-08 05:49:24**. The app stayed alive.
- The old 2026-11-05 `RCE_OK` was an n-day (#1827) proof. The 2026-11-08 proof
  is the 0day chain.

## iPhone 17e: iOS 27.0

- Model: iPhone18,5, iOS 27.0 build 24A437.
- Telegram: 13.2 (36535), stock App Store app.
- No jailbreak. Frida cannot attach to the stock app. Delivery is the beta
  `sendWidget` or a Postbox `t7` rewrite through CoreDevice.
- USB state: the device enumerates (`05ac:12a8`, bcdDevice 18.05, UDID
  `<UDID>`). The phone-side usbmux listener was mute during
  instrumentation; the recovery is in
  `vulns/0day-2-RCE-PARSER-SCOPE/IOS27/evidence/instrumentation-plan.md` (wake/unlock/trust, then the
  usbmuxd stop → USB reset → start sequence).
- AppGroup:
  `00000000-0000-0000-0000-000000000000`; Postbox path
  `telegram-data/account-<ACCOUNT_ID>/postbox/db`.
- The app code is arm64. The pivot gadget
  `libcFree + 0xB6583074` = `IntelligenceFlowRuntime + 0x64510` is a plain
  `mov sp, x0; ret`. MIE is not enabled for the app (no `checked_allocations`,
  `enhanced_security`, or `hardened_*` entitlement).
- Status: **device-proven once (msg 5725); gated twin host-only**. The 5725
  run wrote `AppGroup/<APPGROUP>/rce.txt` = 7 B `RCE_OK\n` and the app stayed
  alive. The winning stage-A marker was not captured; the 16:22 marker belongs
  to another message. The n-day fallback was proven on this device on
  2026-11-06 (3,039 B file read to the C2), but that is a public n-day, not the
  0day. The 0day detail is in `vulns/0day-2-RCE-PARSER-SCOPE/IOS27/`.

## Samsung: model TBD

The device was expected on Tuesday 2026-11-10. The plan is a first-open,
single-message universal test: send the four parallel widgets (or one v3
widget), open the chat once, and record the first marker. No result exists yet.

## MTE, MIE, and PAC in one paragraph

MTE (Memory Tagging Extension) checks the top byte of a pointer against the
allocation tag on pages mapped `PROT_MTE`. A cross-allocation access between
two differently tagged Scudo chunks faults. The Android cross-tag route needs
MTE off. The same-tag route keeps both sides in the QuickJS arena, which is a
plain `mmap` with tag 0, so it is MTE-safe by construction. MIE (Memory
Integrity Enforcement) is the iOS equivalent on newer hardware; a stock app
must opt in, and Telegram 13.2 does not. PAC (Pointer Authentication) protects
return addresses on arm64e code; the Telegram app code is arm64, and the pivot
is a plain `ret`, so PAC does not block the iOS chain.
