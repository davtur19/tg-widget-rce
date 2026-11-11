# N2 — `get_closure_var()` → -1 → `var_refs[65535]` at `+0x7fff8`

**Assessment as a second RCE (MTE-safe / universal) — 2026-11-08, host-only**

Scope: the `get_closure_var()` -1 unchecked path (inventory row **S1** for the
compile-time read, **N2** for the runtime `var_refs[65535]` access). Question:
can N2 be the second RCE that N1 is not (N1 is device-closed at the fatal OOM)
and that the parser c2560s is not (cross-tag / MTE-off)? Specifically: is it
MTE-safe and universal (Android builds + iOS, no per-build/per-device
hardcodes)?

All work is on the app fork **`2dfeee3e`** (`lab/fork_fuzz/src`, the engine with
`JS_ARENA_SLABS`; the device N1 traces in
`notes/new_0day_mte_specs_20261107.md` §10.2 identify the device engine as this
fork). No device, no Frida, no network. Artifacts:
`lab/rce_candidates/n2/`.

---

## 0. Verdict (short)

**N2 is not a second RCE and is not MTE-safe-universal. It remains DoS-only.**
The negative is stronger than the existing inventory note on three new points:

1. **The runtime access is unreachable in the real engine, not merely
   unconvincing.** The in-engine **OOM** way to get `-1` is a failed
   `js_resize_array()`, and that failure sets the fork's **uncatchable** OOM
   (`JS_ThrowOutOfMemory` → `js_throw_uncatchable`), which aborts the eval
   *before* the class-init closure is instantiated. A faithful diagnostic build
   that returns `-1` **and** sets the real OOM compiles the `0xffff` operand
   (`N2NEG` fires) but never executes it (`N2EXEC` absent; `try/catch` does not
   catch). Host evidence: `logs/evidence/force_oom.log`,
   `logs/evidence/force_oom_catch.log`.
2. **The known filler PoC does not port to the app fork.** On `2dfeee3e` the
   first failing allocation at the boundary is a 24-byte `LabelSlot` growth in
   `new_label_fd()` (from `emit_class_field_init`), and the parse then dies in
   `resolve_scope_var` on `s->vars == NULL` — not on `s->closure_var[-1]`.
   Measured window: `B=6,170,000`, `L=7,429…7,508` (80 values), all the same
   NULL-vars crash. The closure add keeps ~2 KB of slack at that boundary.
   `logs/evidence/oom_real_gdb.log`, `logs/evidence/oom_real_inst.log`.
3. **The non-OOM (cap) route is infeasible in the 6 MiB widget model.** It
   needs a full 65,535-entry closure list on the resolution path. Measured
   on the fork with the bare-var shape: 28,000 entries = 3.37 MB final /
   270 ms; **30,000 entries = OOM at the 6 MiB cap**; 65,535 would need ~8 MB
   and >1 s (O(n²)). The mechanism itself is real: with the cap artificially
   lowered to 4, the `0xffff` operand **does execute** despite the pending
   catchable SyntaxError (`logs/evidence/cap4_demo.log`) — but the real cap
   cannot be reached.

The `+0x7fff8` landing can be made **mapped, tag 0, and byte-controlled**: with
a 1,500-string arena spray the slot lands in an arena slab 8 slabs above the
`var_refs` block, and with a tuned closure count its 8 bytes read exactly the
sprayed string bytes (`first8=4847464544434241` = `"ABCDEFGH"`,
`logs/evidence/slot_ascii_js.log`). This is the strongest positive in the
report — **but it does not help**: a string value is not a valid pointer, and
turning it into one requires a heap-address leak that N2 does not provide.
Byte control ≠ pointer control.

The `-1` index can never hit a same-slab victim: `0xffff * 8 = 0x7fff8 =
8 * 64 KiB - 8`, i.e. 7–8 slabs away from the `var_refs` slab for every
possible in-slab base offset. "Same-slab" is geometrically impossible.

---

## 1. The primitive, exact source shape (`2dfeee3e`)

```c
/* quickjs.c:18111 js_closure2() */
if (b->closure_var_count) {
    /* 8 * closure_var_count bytes; arena if total <= 512 (count <= 63),
       else backing allocator (Scudo on Android) */
    var_refs = js_mallocz(ctx, sizeof(var_refs[0]) * b->closure_var_count);   /* :18125 */
    ...
}
```

```c
/* quickjs.c:34388 add_closure_var() */
if (s->closure_var_count >= JS_MAX_LOCAL_VARS) {   /* 65535 */
    JS_ThrowSyntaxError(...);     /* catchable */
    return -1;
}
if (js_resize_array(...)) {      /* js_realloc -> JS_ThrowOutOfMemory: UNCATCHABLE */
    return -1;                   /* checked nowhere on the goto path */
}
```

The six unchecked sites are in `resolve_scope_var()`; the only one that reaches
the `has_idx` label with `idx == -1` is the direct-eval closure lookup
(`quickjs.c:34911`, `:34925`), because its `goto has_idx` bypasses the
`if (idx >= 0)` guard (`:34957`). At `has_idx` the compiler reads
`s->closure_var[-1]` (`:34959`) and later emits `dbuf_put_u16(bc, idx)`
(`:35034`) = `0xffff`. (Two sibling emits at `:34971`/`:34992` are the
`make_ref` path.)

Runtime (`quickjs.c:19668-19736`):

```c
CASE(OP_get_var_ref):
    idx = get_u16(pc);                 /* 0xffff */
    val = *var_refs[idx]->pvalue;      /* :19674  OOB load + wild deref */
CASE(OP_put_var_ref):
    set_value(ctx, var_refs[idx]->pvalue, sp[-1]);   /* :19684  OOB load + write */
```

Geometry (64-bit, both arm64 and x86-64):

| quantity | value |
|---|---|
| index | `0xffff` (fixed by the `u16` operand; `-1` from `get_closure_var`) |
| displacement | `0xffff * 8 = 0x7fff8 = 524,280 = 8 * 65,536 - 8` |
| `var_refs` base | arena block (tag 0) for `closure_var_count <= 63`; backing malloc (Scudo primary, tagged) for `64…8191`; secondary (>= 64 KiB mapping) for `>= 8192` |
| target slab | base slab **+8** if `base_off >= 8`, else **+7**; target offset = `base_off - 8` (mod 64 KiB) |
| 32-bit build | would be `0x3fffc`; irrelevant for current Android/iOS 64-bit apps |

Two in-engine `-1` sources exist, and they have different exception semantics:

* **OOM** (`js_resize_array` failure): `JS_ThrowOutOfMemory` →
  `js_throw_uncatchable` → `uncatchable_pending`; the eval cannot continue.
* **Cap** (`closure_var_count >= 65535`): `JS_ThrowSyntaxError`; catchable, and
  the parser/body continue (demonstrated with cap=4).

---

## 2. Pointer and tag domain of `var_refs` (measured)

Instrumented fork (`lab/rce_candidates/n2/src_inst/quickjs.c`, built with
`-O2`), app-model harness with the widget's 6 MiB limit:

| closure_var_count | `var_refs` size | base mapping | tag |
|---:|---:|---|---|
| 0 | NULL | no allocation; runtime target is the fixed address `0x7fff8` | n/a |
| 1–4 | 8–32 B | **inside a 64 KiB arena slab** (`JS_ARENA_SLABS`), anon `rw-p`; measured `in_slab=1`, `base_off` 0x5038/0x5078/0x6050 | **0** (the slab `mmap` is `PROT_READ\|PROT_WRITE`, no `PROT_MTE`) |
| 64 | 512 B + 8 | backing malloc → `[heap]` on the host; on Android a Scudo **primary** chunk (tagged) | nonzero (Scudo) |
| 100 | 800 B + 8 | same, `[heap]`; target `base+0x7fff8` is already **unmapped** (`SIGSEGV` at the target itself) | nonzero (Scudo) |

Representative traces:

```
count=2  base=0x7f...7068  base_in_slab=1  basemap=... rw-p 00:00 0
count=64 base=0x55...1b48  base_in_slab=0  basemap=... rw-p [heap]
```

So the answer to "is the `var_refs` base arena/tag 0?" is **yes, only for small
closure counts** — which is exactly the case produced by the OOM `-1` (the
failed add leaves the array at its previous, small size). For the cap route the
array is 512 KiB (secondary, possibly untagged on Android 17 but *not*
guaranteed; see `MTE_safe_hunt_20261107.md` §2.1).

## 3. The `+0x7fff8` landing (measured)

### 3.1 Geometry

`base + 0x7fff8` with `base = slab + off`, `0 <= off < 0x10000`:

* `off >= 8`  → slab `+8`, offset `off - 8`
* `off < 8`   → slab `+7`, offset `0xFFF8 + off`

Never the same 64 KiB slab, never the adjacent one. The target's *offset inside
its slab* is `base_off - 8` (mod 64 KiB): predictable **iff** `base_off` is
known, and `base_off` is the position of the `var_refs` block in its 4 KiB class
page, which depends on allocation history.

### 3.2 Without a spray

`target` is outside the arena and lands in whatever mapping follows: on the
host, libc `.text` (`r-xp`); on a device it can be a Scudo mapping (tagged,
tag-checked), a library, or unmapped. The slot then holds foreign bytes
(measured `slot=53555441d5894155` — libc code), a non-canonical value; the
`pvalue` load faults (`N2FAULT`, the SIGSEGV handler reports `si_addr=0` for
this non-canonical form). Not controllable.

### 3.3 With an arena spray

Payload: 1,500 × 401-char strings (`keep.push(s + i % 10)`), final heap
856 KB, creates **15 slabs (960 KiB)** in one contiguous anon VMA. The base
`var_refs` block lands in the newest slab; the target lands in the slab 8
allocations earlier, **inside the same VMA**:

```
N2EXEC op=get count=2 base=0x7f25cc23f050 target=0x7f25cc2bf048
  in_slab=1 slab=0x7f25cc2b9000 off=0x6048 first8=0000000000000000
  base_in_slab=1 base_off=0x6050 slabs=15 pagecls=29/8 used=8
  map=7f25cc239000-7f25cc31b000 rw-p
```

`pagecls=29` = 480-byte class; the target offset 0x48 falls in block 0's
`JSString` header (`first_weak_ref`, zero), not in the chars. **The first load
does not fault and is tag-0-safe in this configuration.**

### 3.4 Byte control at the slot — demonstrated

Changing the closure count to 3 (`var_refs` class 32, block index 2) moves the
target to `base_off - 8 = 0x5070`, which is 32 bytes into the chars of the
sprayed 401-char string:

```
N2EXEC op=get count=3 base=0x7f07d2979078 target=0x7f07d29f9070
  in_slab=1 off=0x5070 first8=4847464544434241   ("ABCDEFGH")
N2CHAIN slot=4847464544434241 mapP=
N2FAULT sig=11
```

So an attacker **can** place chosen 8-byte values at the OOB slot (string bytes,
including NULs if the string is built with them). What follows is still the
wild dereference of that value. A second layout (closure spray) placed a
block-header word `0x00000000000d0022` at the slot and faulted at `0xd003a`.

## 4. Target controllability — what is missing

For `var_refs[65535]` to be useful, `P = slot[0..8]` must be a valid
`JSVarRef *` and `*(P + 24)` must be an attacker-chosen `JSValue *`:

* **Attacker bytes (strings)**: byte control is proven, but the 8 bytes are an
  address. We do not know any writable/readable address in the widget; a
  guessed value is non-canonical (`#GP`) or tag-mismatched. Writing `0` gives
  the measured `NULL+24` fault (`0x18`).
* **Engine-written pointers**: if the slot lands in a live `JSVarRef **` array
  or a `JSVarRef` body, the value is a real tag-0 pointer. In that case the
  access is MTE-safe and non-faulting — but it only reads/writes another
  function's captured variable (a legal `JSValue` slot). No memory-safety
  violation, no leak, no type confusion.
* **Same-slab victim**: impossible (§3.1).
* **Predictable target**: only the offset *within the target slab* is
  predictable; the slab itself is chosen by the allocator 7–8 steps earlier in
  the arena's allocation order. The spray makes the slab an arena slab, not a
  chosen victim object.
* **The NULL-base case**: if the `-1` occurs before any successful add
  (`s->closure_var == NULL`), the compile-time read itself faults at
  `0xfffffffffffffff8` (`force0` log), so the runtime `0x7fff8` access is
  preempted.

To turn the proven slot-byte control into a fake `JSVarRef` would require
(a) a heap-address leak of the sprayed string's data, and (b) placing
`leak+64` at the slot and `leak+128` at fake+24 — both of which are just more
string bytes. No such leak exists in the N2 primitive, and with the OOM gate
(§5.1) the script that triggers N2 cannot even run the closure.

## 5. Gate analysis

### 5.1 OOM gate: uncatchable, and it precedes the runtime access

`js_realloc` failure → `JS_ThrowOutOfMemory` → `js_throw_uncatchable`
(`quickjs.c:8994-9010`) sets `rt->uncatchable_pending`; the next interrupt poll
aborts the eval. The class-init closure (`OP_fclosure` → `js_closure2`) is
created *during the eval body*, after the failed compile. The `0xffff` operand
always lives in a **nested function** (the eval-closure block only reaches the
unchecked `goto has_idx` when `s` is a child of the eval; for the eval function
itself `fd == s` and `idx = idx1` is valid), so executing it requires a JS
**call** — and the first poll aborts before/at that call. Measured: the closure
is created (`N2CLOSURE count=2`), the call never executes the op (`N2EXEC`
absent). This ordering is platform-independent.

Faithful experiment (`src_force_oom.c`): `get_closure_var()` returns `-1` for
the second eval-closure REF **and** calls `JS_ThrowOutOfMemory(ctx)` first —
exactly what a failed `js_resize_array` does:

```
N2NEG idx=-1 arr=0x...a050 count=2 size=2 hdr=0000000000010001
EXCEPTION: InternalError: out of memory        (no N2EXEC)
```

Wrapped in `try { ... } catch(e) { ... }`: the catch does not run
(`logs/evidence/force_oom_catch.log`). This is the same uncatchable policy the
device matrix proved for N1 (`new_0day_mte_specs_20261107.md` §11), and the
`InternalError.prototype.name` getter bypass of §14 only changes the *engine's*
post-script handling; it does not resume the aborted eval.

**Real filler on the fork.** Sweeping `B` (large filler) and `L` (tuning
filler) at 1-byte steps found the boundary `B=6,170,000, L=7,429…7,508`. In
every hit the first failed allocation is

```
N2OOM malloc size=24 used=6291440 limit=6291456     <- new_label_fd(), emit_class_field_init
```

and the crash is

```
resolve_scope_var ... s->vars == NULL, s->var_count == 0, s->scopes[0].first == 0
```

i.e. a NULL `JSVarDef` read (line 34833), a DoS. The closure array at that
point has `count=1`, so the N2 `-1` was not the failing allocation. At the
last filler that still parses the closure add has ~3 KB of headroom; at the
528-byte `JSFunctionDef` gate it is still ~2 KB. **The prior-project closure
window (d7215b0/7a23d8e, ASan and classic arena) does not reproduce on the app
fork's allocator.**

### 5.2 Cap gate: mechanically real, economically impossible

The `add_closure_var` cap also returns `-1`, but throws a **catchable**
`SyntaxError`; the parser and body continue. Lowering the cap to 4 in a
diagnostic build demonstrates the whole path end-to-end with a *small*
`var_refs` array:

```
N2CAP count=4 size=4
N2NEG idx=-1 arr=0x...0100 count=4 size=4 hdr=0000000000030005
N2EXEC op=get count=4 base=0x...00d8 target=0x...d0d0 (no OOM, class created)
N2FAULT sig=11
```

At the real cap the failing add needs *some* function on the resolution path
(the function that emits the operand, or the parent that `get_closure_var`
recurses through) to hold a **full 65,535-entry closure list**. Cost measured on
the fork (classic eval/class shape, bare var declarations, 6 MiB app model):

| closure vars | result | final heap | time (host x86-64) |
|---:|---|---:|---:|
| 8,192 | ok | 1.06 MB | 28 ms |
| 16,000 | ok | 1.94 MB | 92 ms |
| 24,000 | ok | 2.84 MB | 188 ms |
| 28,000 | ok | 3.37 MB | **270 ms** |
| **30,000** | **OOM (InternalError)** | — | 308 ms |
| 32,000 / 40,000 | OOM | — | 322 / 377 ms |

The 6 MiB cap is hit **below 30,000** entries — less than half of 65,535 —
and the compile is already at the widget's 300 ms boundary at 28,000 on a fast
host. The O(n²) `get_closure_var` scans and the 3.1 MB of runtime `JSVarRef`s
(or 512 KiB+ arrays) make 65,535 unreachable. `logs/evidence/capcost_*.log`.

### 5.3 Getter bypass scope

The device-proven `InternalError.prototype.name` getter bypasses the widget's
`kill("Memory limit exceeded")` *after* the script returns the exception; it
does not make the aborted eval continue (device marker runs in
`new_0day_mte_specs_20261107.md` §14.2 show stage 1 aborted before `var AB`).
For N2 this means: even if the engine survives the OOM at the embedder level,
the `OP_get_var_ref 0xffff` still never executes.

## 6. MTE / iOS-MIE assessment

Android (Scudo + MTE):

* **count ≤ 63** (the OOM-produced case): base is tag 0 in a plain `rw-p`
  `mmap` slab. The first load is safe **iff** the `+512 KiB` landing is an
  untagged mapping. Measured possible with an arena spray (§3.3). It is not
  guaranteed: any landing in a Scudo primary mapping (tagged) or a tag-0 chunk
  header adjacent to a tagged chunk faults; the `+512 KiB` displacement spans
  many mappings and the exact neighborhood is heap-state dependent.
* **count ≥ 64** (large arrays; the cap case is 65,535, a ≥ 64 KiB
  secondary): base is a Scudo chunk with a nonzero tag (primary) or an
  untagged secondary; in the primary case the same tag is used 512 KiB away,
  almost certainly a different tag → synchronous tag fault (or
  `SEGV_MTEAERR`). MTE-unsafe.
* **Second dereference**: `P = slot[0..8]`; if `P` is attacker string bytes its
  top byte is an arbitrary MTE tag (e.g. `0x41` for `"ABCDEFGH"`) → tag fault;
  if `P` is a real tag-0 `JSVarRef *`, safe but only touches a real variable;
  a crafted tag-0 pointer needs an address leak.
* Odd/even chunk-tag tuning does not help: the access is 8 slabs away, not an
  adjacent overflow.

iOS: third-party apps are **not** opted into MIE (`MTE_safe_hunt_20261107.md`
§2.2, §5.2), so tag checks are moot; the same code and the same 64 KiB
`mmap` slabs are used (`JS_ARENA_SLABS` covers `__APPLE__`), and the same
memory-limit/uncatchable-OOM policy applies. N2 is not a better carrier on iOS
than on Android: the OOM gate is identical and the landing/pointer problem is
identical.

**Conclusion: N2 is not MTE-safe in general.** It can be made *first-load*
tag-0-safe with heap grooming (a partial, heap-state-dependent property), but
the second dereference either needs a real engine pointer (harmless) or a
crafted tag-0 pointer (needs a leak). It is not a same-view/same-allocation
pattern like v7.

## 7. Universality

* The **primitive geometry is universal** on 64-bit: `0xffff * 8 = 0x7fff8`
  on arm64 Android, arm64 iOS, x86-64. No per-build constant is involved.
* Universality fails at every other layer:
  * the **trigger** is allocation-accounting-specific: the filler window was
    measured on ASan/classic-arena builds by the prior project and does **not**
    reproduce on the app fork (the first failure is a label array / the 528-byte
    `JSFunctionDef`, and the crash is a NULL `s->vars`);
  * the **landing** depends on whether the arena has a contiguous ≥ 9-slab run
    and where `var_refs` sits in it;
  * the **slot contents** depend on which class page occupies the target slab
    and on the exact `base_off` (we needed a specific closure count and spray
    layout to get string bytes);
  * the **non-OOM route** needs 65,535 closure entries, over the 6 MiB budget
    on every build tested.
* **Payload size**: the diagnostic forced-`-1` PoC is 69 bytes
  (`poc/force_get.js`); the real trigger is a tiny script plus a **~6 MB
  runtime filler** whose value must be re-derived per allocator/build, or a
  source with 65,535 variable names (~400 KB of text) that cannot fit the heap.
  There is no compact universal payload.
* Nothing suggests a cheap per-device hardcode would fix this: there is no
  leak to hardcode against, and the OOM gate is policy, not layout.

## 8. Ranked blockers

1. **Uncatchable OOM precedes the closure instantiation** — the runtime op can
   never execute in the engine that produces the `-1` (strongest, measured with
   the faithful `force_oom` build; `try/catch` ineffective).
2. **The known trigger does not port to the app fork** — the filler boundary
   hits `new_label_fd`/`JSFunctionDef`, then a NULL `s->vars` crash; the
   closure add has ~2 KB of slack. (Host-only; device may differ in base heap,
   but the ordering is the same.)
3. **Cap route infeasible** — 65,535 closure entries > 6 MiB and > 300 ms;
   measured OOM at 30,000.
4. **No pointer control** — slot bytes controllable, but a valid `JSVarRef *`
   /`pvalue` needs an address leak the bug does not give; the NULL-base variant
   crashes at compile time (-8).
5. **Same-slab victim impossible** — 7–8 slab displacement.
6. **MTE only partially satisfiable** — first load tag-0-safe with grooming;
   second load wild; cap case cross-tag.

## 9. Reproduction

```bash
cd lab/rce_candidates/n2
# builds (plain / instrumented / forced -1 / forced -1 + real OOM / cap=4)
cc -O2 -g -I src -o build/n2run_plain src/quickjs.c src/libregexp.c \
   src/libunicode.c src/dtoa.c harness/n2run.c -lm -lpthread
# (instrumented variants: see build.sh; src_inst, src_force, src_force_oom,
#  src_force0, src_force_all, src_cap4, src_diag2)

# 1) forced -1, small arena array, no spray: landing in libc .text
./build/n2run_force poc/force_get.js
# 2) forced -1 with the 1,500-string spray: landing in an arena slab, slot 0
./build/n2run_force poc/spray400.js
# 3) forced -1, count=3: slot bytes are the sprayed string ("ABCDEFGH")
./build/n2run_force poc/slot_ascii.js
# 4) forced -1 with a real OOM exception: N2NEG but no N2EXEC
./build/n2run_force_oom poc/force_get.js
# 5) cap=4 mechanism demo (non-OOM -> the 0xffff operand executes)
./build/n2run_cap4 poc/cap4_demo.js
# 6) real filler on the fork: 24-byte label alloc fails, NULL s->vars crash
./build/n2run_inst poc/oom_real_fork.js        # B=6,170,000 L=7,430
# 7) cap cost scaling
python3 poc/gen_closure_n.py 28000 /tmp/c28k.js bare
./build/n2run_plain -l 6 -m /tmp/c28k.js
```

Note: runs 1–5 are **diagnostic forced builds** (they inject the `-1` that the
engine only produces under OOM/cap); they prove the primitive, not a reachable
exploit.

## 10. Honest limits

* No device run (host-only by task); the Android Scudo tag values and the
  device heap base are not measured here. The MTE statements are derived from
  the source, the host mappings, and the previously measured Pixel smaps
  (`MTE_safe_hunt_20261107.md` §2.4), not from a new MTE-on run.
* The filler sweep is on x86-64 glibc; the device uses Scudo, so the numeric
  window differs. The structural argument (uncatchable OOM before `OP_fclosure`,
  528-byte `JSFunctionDef` gate, ~2 KB closure slack) does not depend on the
  exact window, but a device-side counterexample was not searched.
* A complete fake-`JSVarRef` demonstration (slot → fake in the same string →
  fabricated `JSValue` read/write) was attempted but not completed: the arena
  layout shifts with the source size and the target did not land in the flat
  string's chars in the runtime-built-string variants. The slot-byte control is
  proven; the fake-object step is a research extension that additionally needs
  a leak (and is moot while the OOM gate kills the eval).
* The `s->closure_var[-1]` header read was assessed as a side surface: the
  8 bytes are the arena block header (`block_idx`, `block_size_idx`,
  `ref_count`); `is_const/is_lexical` come from `block_idx` bits and `var_name`
  from `ref_count` (`N2NEG hdr=0000000000010001/0000000000030005/...`). Only the
  `make_ref` path would use `var_name` as an atom, and `ref_count` is small/0;
  no primitive was found, and the OOM aborts the eval anyway.

**What would change the verdict.** (a) A `get_closure_var()` failure path that
does **not** set the uncatchable OOM and does **not** need 65,535 closure
entries (none exists in this source); (b) an independent heap/arena address
leak reachable in the same context, which would upgrade the proven slot-byte
control to a fake-`JSVarRef` read/write — still gated by (a). Without both, N2
cannot carry anything beyond the DoS it already has.

---

### Files

```
notes/rce_candidate_n2_20261108.md          this report
notes/LEMMALOG_FACTS_n2_20261108.txt        facts for the orchestrator
lab/rce_candidates/n2/
  harness/n2run.c                           app-model harness (6 MiB, SIGSEGV addr)
  src/                                      fork 2dfeee3e (unmodified copy)
  src_inst/quickjs.c                        instrumented (slab/map/slot trace)
  src_force.c, src_force0.c, src_force_all.c, src_force_oom.c
  src_cap4.c, src_diag2.c                   diagnostic builds
  tools/n2_instrument.py, tools/n2_chain_reader.py
  build.sh                                  rebuilds every binary
  README.md                                 artifact map / diagnostic notes
  poc/*.js, poc/gen_closure_n.py, poc/sweep_oom_fork.py
  build/                                    binaries
  logs/evidence/                            all traces quoted above
```

Related notes (not modified): `notes/bug_inventory_20261105.md` (S1/N2 rows),
`notes/new_quickjs_rce.md` (original finding), `notes/audit_class_fields.md` §4,
`notes/MTE_safe_hunt_20261107.md` §2/§6/§7,
`notes/new_0day_mte_specs_20261107.md` §10/§11/§14.
