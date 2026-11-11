# iPhone 17e prepared payloads

Docs: `vulns/0day-2-RCE-PARSER-SCOPE/IOS27/`. Status: **device-proven once
(msg 5725); the gated twin is host-only**.

These payloads are the iOS 27 adaptation of the parser `ARG_SCOPE_END` chain.
The proven page is the 8,647 B `payloads/ios27_rel/p0_proven.html`; the files in
this directory are the pre-run probe/final family. They are kept for
provenance. The 17e is a stock device; delivery is the Bot API `sendWidget`
(the Postbox `t7` path is unavailable; see the instrumentation doc).

## Probes

| File | What |
|---|---|
| `probes/probe-h64.html` … `probe-h500.html` | The 6s hole-reuse probes (H64, H100, H200, H400, H500). |
| `compile-first/probe-c34.html` | Compile-first stage-A probe, C=34. |
| `compile-first/probe-c37.html` | C=37 small-zone hypothesis probe. |
| `compile-first/poison-c34.html` | Poison control: crashes only if the far read reaches the spray. |

## Finals

| File | What |
|---|---|
| `finals/final-h64.html` … `final-h400.html` | Early hole-reuse finals. |
| `attribute/probe-h*.html`, `attribute/final-h*.html` | Stage B in a `data-s2` attribute. |
| `attribute/rop-h200.html` | Attribute ROP final (single widget, no storage). |
| `storage/seed-stage-b.html` | Stores the real 3,617-byte stage B. |
| `storage/seed-stage-b-real.html` | Real-stage-B seed variant. |
| `storage/stage-a-2036-h400.html` | The device-proven 2,036-byte stage A. |
| `storage/seed-inline-rop.html` | Seed for the 4,600/2,124 inline ROP. |
| `storage/inline-rop-h200.html`, `inline-rop-h150.html` | 4,600/2,124 inline ROP. |

## iOS 27 ROP

| File | What |
|---|---|
| `rop/srop-ios27.js` | The iOS 27 ROP body: PIVOT2 `libcFree+0xB6583074`, open/write/pthread_exit, AppGroup `rce.txt`. |
| `rop/srop-ios27-wide.js` | Wider UB scan. |
| `rop/srop-ios27-earlyub.js` | UB allocated before the stage-B burst. |
| `rop/srop-ios27-multibuf.js` | Multi-buffer UB variant. |
| `rop/srop-ios27-ubglobal.js` | UB-global variant. |
| `rop/at_rop_final_h100..h600_ios_17e.html` | The 11 attribute ROP finals, one per H. |
| `rop/srop-6s.js`, `srop-6s-min.js` | The 6s reference body. |

## Compile-first

| File | What |
|---|---|
| `compile-first/inline-p0.html` … `inline-p1024.html` | Inline stage-B variants at four pre-heap offsets. |
| `compile-first/rop-compile-first.html` | Compile-first + ROP. |
| `compile-first/rop-compile-first-v2.html` | Second revision. |
| `compile-first/rop-compile-first-wide.html` | Wide-UB revision. |

## Ping tools

| File | What |
|---|---|
| `tools/ping-widget.html` | The benign `CH17E_PING` widget (message 16809). |
| `tools/fetch-ping.html` | One-request answer-channel probe. |
| `tools/fetch-ping-multi.html` | Four-request probe (the engine resolves one). |

## Expected markers

```
HIT=<i> LEN=327744 PH=<p> VK=598 NT=<n>
ABV k=… D=…
IOS_N1_OK base=… printf=… rt=…
N1IOS_6S_OK            (app --console)
U_RDY … PATH=…
rce.txt = RCE_OK       (AppGroup <APPGROUP>)
```

The 5725 run produced `rce.txt`; the stage-A marker of that message was not
captured. The files in this directory are not the 5725 page.
