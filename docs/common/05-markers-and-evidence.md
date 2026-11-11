# Markers and evidence

A device run is only useful if it leaves a marker that can be read after the
fact. This page lists the markers used by each route and where they appear.

## The marker channel

Widget JavaScript can write text into the page DOM:

```js
document.getElementById("v").textContent = "S1 " + marker;
```

The renderer displays that text in the message bubble. A screenshot or the
accessibility tree reads it. On a jailbroken 6s, a Frida hook on `printf` also
captures native output from stage B.

For automation, the same marker can be read from:

- Android logcat: the engine logs `widget payload: zlib, <compressed> ->
  <raw> bytes` for every widget it decrypts/decompresses.
- iOS: the `message-widget` thread writes to the app stdout when launched with
  `--console`; the `.ips` crash report names the thread and the fault.
- The proof file: a successful chain writes a file in the app's private
  directory. Reading that file (root on Sony, AFC/SSH on the 6s, AppGroup on
  the 17e) is the strongest evidence.

## Android cross-tag route (`c2560s`)

| Marker | Meaning |
|---|---|
| `S1 SAFE2560C END=-` | The probe ran. Stage A is safe; no forge attempted. |
| `S1 ABLEN[599]=327744 VLEN=327744` | Stage A forged `T[599].byteLength` from 64 to 327,744 and created a 327,744-byte view. |
| `END=HF READY …` | The debug endgame resolved the anchors and is ready to run the final. |
| `END=HF OK` | The final endgame ran `system()` and wrote the proof file. |
| `END=HF ERR <token>` | A safe failure in the endgame. The token names the failed step. |
| `VNC`, `VO`, `X`, `XG`, `G`, `GS`, `V`, `VK`, `VG`, `P` | Debug fields: view count, view offset, probe steps, guard state, slab count, anchor class, fallback offset. |

Example 5/5 run (72929):

```
S1 ABLEN[599]=327744 VLEN=327744 END=HF OK
```

Proof file:

```
/data/user/0/org.telegram.messenger.beta/files/n1
uid=10346(u0_a346) ... context=u:r:untrusted_app:s0:c90,c257,c512,c768
```

185 bytes, md5 `52258bc776f2f378542d1b2c736840e3`.

The command field is 50 bytes, so the proof is only the `id` line. The
absence of a larger marker is expected, not a failure.

This example is 72929, where the widget runs in the app UID 10346. On beta
72979/72989 the widget runs in isolated UID 99017/99024
(`u:r:isolated_app:s0`); stage A still reports `ABLEN[599]=327744`, but the
endgame stops at `HF ERR NOANCHOR` and no `uid=10346` proof exists. Do not read
a missing proof on 72979/72989 as a delivery failure.

## Android same-tag route (route 2)

| Marker | Meaning |
|---|---|
| `S1 ABLEN[599]=327744 VLEN=327744 END=-` | Stage A forged and the view exists; the endgame was not in the page. |
| `S1 ABLEN[599]=327744 VLEN=327744 END=HF OK` | Inline endgame ran on the host or device. |
| `S1 … \| G1/8 … G8/8 \| HF HF OK` | Out-of-band endgame: eight answer chunks received, joined, evaluated. |
| `… \| F0` | The answer was empty. The server used the wrong field (`result` instead of `data`) or the answer was null. |
| `… \| X3` | The `request()` promise rejected. |
| `… \| F2` | The answer was empty. |
| `END=HF ERR NOV`, `NOANCHOR`, `NOV` | The endgame reached a guard and stopped safely. |
| `HUGE ABLEN` / `TRIG` | Internal stage-B sizes. |

The `ABLEN[599]` index is the victim slot. It is not a device constant; the
payload scans for the first forged `ArrayBuffer`. The `[599]` value appears
because the groom frees and reuses that slot in the working layout.

## iOS hole-reuse route

| Marker | Meaning |
|---|---|
| `RESULT HOLE C=34 SZ=957 N=3000 H=400 HN=64 HIT=545 LEN=327744 PH=36 VK=598 NT=21` | Probe: the far record aligned, the closure overflow wrote a victim `ArrayBuffer(72)`, length 327,744. |
| `RESULT … HIT=-1 LEN=0 PH=-1 VK=-1 NT=25` | Safe miss. The target landed in the spray but no victim matched. |
| `RESULT NO_TOPS` | The engine wrapped the script; the function geometry changed. Do not run the final. |
| `ABV k=… D=…` | Stage B found the class-24 view anchor and the forged buffer. |
| `IOS_N1_OK base=… printf=… rt=… D=… leak=FORGED` | Stage B resolved `rt`, the Mach-O base, and `printf`, and called `printf("N1IOS_6S_OK")`. |
| `N1IOS_6S_OK` | The native printf proof. It appears in the Frida hook log, 64 times in the 6s run. |
| `U_RDY … PATH=…` | The inline ROP chain is built and the arm is about to run. |
| `U_AFTER` | The ROP returned without taking the pivot. This is a failure marker; a successful pivot does not return. |
| `U_NF`, `U_NO_FREE`, `U_NOUB`, `U_EXC` | UB scan, resolver, or chain failure. |
| `RCE_OK` | The ROP wrote the proof file. |
| Crash at `0x3F48820` / `0x3F487E8` | The far target landed outside the spray for that H. Pull the `.ips`, try another H. |

Example 6s success:

```
HIT=545 LEN=327744 PH=36 VK=598 NT=21
IOS_N1_OK base=0x10c92c000 printf=0x111ea7c20 rt=0x103f02600 D=0x11c86ca10 leak=FORGED
N1IOS_6S_OK (64 lines)
Documents/rce.txt = RCE_OK, mtime 2026-11-08 05:49:24
```

The old `RCE_OK` from 2026-11-05 is the n-day proof. Always check the mtime,
not only the content.

## The n-day markers

| Marker | Meaning |
|---|---|
| `VIEWS=8` | The forged `ArrayBuffer` produced eight views. |
| `CTX` | The chain found the `JSContext`. |
| `HOOKED` | `rt->mf.js_free` was redirected. |
| `AFTER` | The endgame returned. |
| `uid=… context=untrusted_app` | The proof file written by `system("id>…")` on 72929 and earlier (app UID). |
| `uid=99017/99024 … context=isolated_app` | A 72979/72989 widget-process result; contained, not an app-data proof. | |
| `N1IOS_6S_OK` | The iOS printf proof for the n-day chain. |

The n-day is reference only. Its markers are kept so the two chains are not
confused.

## What "proven" means here

A claim is marked **proven** only when all of these are true:

1. A named payload file produced the marker on a named device and build.
2. The marker is in a log or file that is in `evidence/`.
3. The proof survives a restart or a repeat run, as stated (5/5, 1/1, 3/3).
4. The app stayed alive, unless the claim is specifically a crash.

A host-only result is marked **host**. A device run that reached a safe guard
is marked **stage A** or **partial**, not proven.

## Evidence layout

```
vulns/0day-2-RCE-PARSER-SCOPE/XTAG/evidence/    proof files, C2 log, certification
vulns/0day-2-RCE-PARSER-SCOPE/STAG/evidence/    stage-A log, crash excerpt, host verify
vulns/0day-2-RCE-PARSER-SCOPE/TINY/evidence/    printf hook, host matrices, H400 screenshot
vulns/nday-1-RCE-V7-RGX-1827/evidence/          n-day C2 and exfil logs
vulns/nday-2-RCE-VARREF-1865/evidence/          #1865 C2/proof notes
```

The per-ID `evidence/` directories contain the long-form engineering logs as
well as the short final artifacts.
