# C2 as a universal same-payload carrier — assessment and host repro

Date: 2026-11-08. Host-only (no device, no Frida, no bot, no network).
Engine: Telegram widget QuickJS fork **2dfeee3e** (`0.17.0`, `libtmessages.49.so`),
`lab/qjs_fork_audit/n1_hookfree/src` (verbatim) plus evidence-only instrumentation.
Artifacts: `lab/rce_candidates/c2/` (README + logs + PoCs + instrumented fork).

Target being assessed (orchestrator brief): one payload, same bytes, working on
the **Sony XQ-BT52 / 72929 beta (MTE off, 6 MiB JS heap)** and the **Pixel 9
release (MTE on, "8 MB" JNI option)**, universal (no per-build/per-device
hardcode), **≤ 4,096 B zlib9**, with a v7-style universal endgame (ELF dynsym /
`rt->js_free` + `system` resolver).

---

## 0. Verdict

**C2 is not a simpler or smaller universal RCE carrier than N1. Deprioritize it.**

The measured C2 primitive is real and, unlike the parser 0day, it is **same-tag
(MTE-safe)**: a 4-byte store into a class-288 arena block, and an
attacker-chosen, in-bounds `fd->vars` index. But it has no capability:

1. **The store value is a small var index** (55/57/58 at the 64-entry table
   boundary; 106+ at the 128-entry one). The table must stay in the arena for the
   write to stay in its class page, which caps the value at ~106.
2. **All same-class string neighbors are longer than that value** (class-288
   strings are 224–255 B; class-512 strings 448–479 B), so the store can only
   *shrink* a length, never grow it. There is no length-corruption → no 2 GB
   window → no arbitrary RW.
3. **The reliable same-slab neighbour is transient.** The parser allocates the
   attacker literal immediately after the 27th var; that atom is freed when the
   failing eval is torn down. A sibling `<script>` that re-creates the literal
   sees fresh `0xFF` bytes (`BAD=[]`).
4. **The second-order index is controllable and in-bounds but cannot be made to
   match.** With a crafted neighbour, `find_var_htab` reads a chosen u32 (60) and
   dereferences `fd->vars[60]` at distance 1200 inside a 1260-byte allocation
   (tag-safe). The tail vardef is stale allocator content (`var_name=0x18000000`),
   so the match fails and the lookup returns −1. Making it match requires
   allocator-specific stale-tail grooming; even then the emitted opcode index is
   ≤ 106, i.e. a few JSValue slots past the frame, not an address.
5. **There is no endgame primitive.** The v7 3,056 dynsym loader needs an
   arbitrary read/write. C2 provides neither a leak nor an address-controlling
   write, so `rt->js_free`/`system` resolution cannot be driven.

The getter bypass, the 6/8 MiB limit difference and the payload size are all
**solvable** (the runtime self-calibrating fill of
`notes/widget_memory_limits_20261108.md` reaches the limit at both 6 and 8 MiB
with one payload; C2 needs a fixed ~2.3–2.5 KB back-off after the fill). They are not
the reason to reject C2. The reason is that the corruption has nowhere to go.

---

## 1. Mechanism (shipped source, `lab/qjs_fork_audit/n1_hookfree/src`)

`update_var_htab()` (quickjs.c:24946) grows the var hash table when
`m = var_count + var_count/5` is a power of two:

```c
m *= 2;
p = js_realloc(ctx, fd->vars_htab, m * sizeof(*fd->vars_htab));
if (!p) return -1;                     /* table size UNCHANGED */
...
insert:
m = UINT32_MAX >> clz32(m);            /* mask from the REQUESTED size */
do {
    i = hash32(fd->vars[k].var_name); j = 1;
    for (;;) {
        p = &fd->vars_htab[i & m];     /* past the old table */
        if (*p == UINT32_MAX) break;
        i += j; j += 1;                /* quadratic probing */
    }
    *p = k++;                          /* 4-byte OOB write */
} while (k < (uint32_t)fd->var_count);
```

`find_var_htab()` (quickjs.c:24982) uses the same too-large mask and
`fd->vars[*p].var_name` (20-byte `JSVarDef`, quickjs.c:861) — the second-order
index.

Trigger used: a non-strict function with a parameter expression and a direct
`eval` (`function f(a=1){eval("0"); var ...}`), 52 body vars + parameter copy =
53; `add_eval_variables()` (quickjs.c:35301) adds `_var_`/`_arg_var_`/`this`/
`new_target`, so `var_count` reaches 54 at the 64→128 grow (512 B request,
`js_realloc_rt` check `malloc_size + 512 − 280 > limit−1`, quickjs.c:2296).

Measured failure condition: the grow fails iff the free heap at `var_count=54`
is **< 233 B** (the old table's usable size 280 is subtracted). Window: 233 B.

---

## 2. Host repro 1 — the clean 4-byte same-slab store (measured)

Logs: `logs/01_clean_write_scudo.log` (clang `-fsanitize=scudo`),
`logs/02_clean_write_gcc.log` (glibc). Identical slots/values/offsets.

```
C2 HTAB_FAIL vc=54 old=0x7f...5d8 cap=64 req=512 msz=6290901 free=555
   SLAB cls=288 blk=5 blksz=288 usz=280 page=7/14
C2 HTAB_FAIL next_payload: dc 00 00 00 b5 1c 1d 4b 71 02 00 00 02 ... ff ff ff ff
C2 UVH_WRITE slot=84  k=55 off=336 NEXT_PAYLOAD+48  SLAB cls=288
C2 UVH_WRITE slot=119 k=57 off=476 NEXT_PAYLOAD+188 SLAB cls=288
C2 UVH_WRITE slot=120 k=58 off=480 NEXT_PAYLOAD+192 SLAB cls=288
```

* The table request is 256 B; `aligned(256)+8 = 264` → `arena_get_size_index`
  picks class **288** (usable 280). The table's own block has 24 B of slack
  (probe slots 64–69); the neighbour header is slots 70–71; the neighbour payload
  starts at slot 72 (htab+288).
* The neighbour is the **0xFF string literal** parsed immediately after the 27th
  var (`dc 00 00 00` = len 220, then hash, then `0xFF` data at payload 24):
  these are the three writes at neighbour payload **48 / 188 / 192**, values
  55/57/58. No crash on either allocator.
* Write value = `fd->var_count − 1` at each insert; the three atoms
  (`_arg_var_`, `this`, `new_target`) have fixed hashes, so the slots are fixed
  **for a given neighbour content**. Changing the neighbour bytes moves the stop
  slot along the same quadratic sequence (measured 84 → 92 when data[24] is set
  to 60), i.e. a discrete set of offsets, not an arbitrary one.

This reproduces the audit result on the shipped snapshot and is the only
same-slab write still in the inventory.

## 3. Host repro 2 — attacker-chosen second-order index (measured)

`logs/03_second_order_scudo.log`, `logs/04_second_order_gcc.log`. The literal
carries u32 = 60 at data[64]; the body uses the predefined identifier `size`
(atom 50, `hash32(50)&127 = 94`), so `find_var_htab` starts in the neighbour
data:

```
C2 FIND atom=50 slot=94 val=0000003c vc=59 cap=64 OOB
C2 FIND_DEREF atom=50 val=60 idx=60 dist=1200 vars=0x... usz=1260 INBOUNDS
   TAIL vn=402653184 sl=599 sn=402653249 kind=5
C2 FIND atom=50 slot=95 val=ffffffff vc=59 cap=64 OOB
```

* The OOB slot read is **attacker-chosen** (60) and the dereference is
  **in-bounds** of the 1260/1264-byte `fd->vars` allocation: offset 1200, i.e. it
  reads `fd->vars[60]` in the uninitialized tail (`var_count=59`, `var_size=63`).
* On Android this is a Scudo primary chunk (< 64 KiB, tagged); the dereference
  uses the chunk's own tag, so it is **MTE-safe**. The original crash variant
  (index 220 from the neighbour's `len` word) is a 4400-byte linear overflow from
  a tagged pointer: that is the cross-tag case the MTE note rejected.
* The tail vardef is stale allocator content: `var_name = 0x18000000`, not an
  atom, so `find_var_htab` returns −1 (the next probe hits `0xFFFFFFFF`). To make
  it return 60 the tail would have to hold `var_name = 50, scope_level = 0`, i.e.
  a fake vardef planted by freeing a same-class buffer with chosen content before
  the compile. That is allocator-specific (Scudo quarantine vs glibc vs Apple
  malloc), so it is **not universal** — and even if planted, the emitted
  `OP_get_loc 60` with `var_count=59` is one JSValue slot past the locals.

## 4. Can the 4-byte store corrupt a same-slab object's length or pointer?

No useful case was found. The write is `*p = k` with `k ∈ [54..106]` (the
arena-resident boundaries) at neighbour payload offsets **48 / 188 / 192** (plus
a few alternative probe-sequence slots).

| neighbour (class 288) | field at 48 / 188 / 192 | effect of a value 54–106 |
|---|---|---|
| `JSString` len 224–255 | data bytes (`data+24`, `+164`, `+168`) | content-only; **len never reached**; can only shrink, value < len |
| `JSObject` 8 inline props | 48 = `u` union low half; 188 = `prop[4].value.tag` high half; 192 = `prop[5].atom` | pointer low half → wild address (no control, crash); tag high half → invalid tag; atom rename → wrong-property lookup, no memory effect |
| fast `JSArray` + 8 props | 48 = `u.array.size` | shrink size below `count`: reads below `count` stay inside the values buffer (sized for `size` ≥ old count); `push` regrows. No OOB |
| `fd->vars` of a 13-var function | 48/188 = `vardef[2/9].scope_next`; 192 = flags/`var_ref_idx` | corrupts a compiler-internal chain; the compile dies with the eval, and the placement is unlanded |
| another 64-entry `vars_htab` | 32-bit entries | a small bogus index in a sibling table; `find` still requires `vars[*p].var_name == atom`, so no lookup change |

**Length growth is structurally impossible** on the arena path: the arena-resident
tables are 64 entries (256 B, class 288) and 128 entries (512 B, class 512),
whose failure values are 53 (measured) and 106 (source formula
`V = ceil(2^n * 5/6)`, `k = V-1`); a class-288 string is 224–255 B and a
class-512 string is 448–479 B, both larger than the value. A table large enough
to produce a value > 448 (256+ entries) is a `js_malloc` block (> 512 B), so the
write leaves the arena/class page — cross-tag on Android MTE and a wild write.

The 4-byte store is therefore **data-only** for every reachable live object: no
length, no controllable pointer, no leak.

## 5. Persistence — the neighbour dies with the eval (measured)

`logs/05_transient_sibling.log`: clean write, then a sibling script parses the
same 220-byte 0xFF literal and prints every non-0xFF character:

```
UVH_WRITE slot=84  ... NEXT_PAYLOAD+48
UVH_WRITE slot=119 ... NEXT_PAYLOAD+188
UVH_WRITE slot=120 ... NEXT_PAYLOAD+192
OK[2]: LEN=220 BAD=[]
WIDGET_ALIVE
```

The write landed in the literal (data offsets 24/164/168), and the sibling sees
a **fresh** literal: the atom was freed when the failed eval was torn down
(`logs/06_alloc_classes.log` shows block 6 freed immediately after the writes,
then the htab block 5). The getter bypass keeps the *widget* alive; it does not
preserve the *eval's* atoms.

A pre-existing live class-288 target (six 240-char strings, four freed) did not
land the htab before the target (`logs/07_groom_attempt.log`): the parser's own
class-288 allocations consume the freed predecessor slots, and the htab goes to
a fresh block. The placement is coupled to the engine-internal class-288
allocation order (the global-object/property-array growth depends on the number
of globals, which differs between builds/bundles), i.e. **not universal without
per-build calibration**.

The only carrier that survives a failed eval is the module `m->func_obj`
(`lab/qjs_fork_audit/c2_tryhard/REPORT_c2_tryhard.md`): it keeps the compiled
function across an OOM/link failure and re-runs it on import. That report's own
arithmetic shows the real bundle's GC policy leaves a ~1.51 MB parse gap that a
≤ 32 KB source can fill only to ~1.26 MB, and even if reached the executed
corruption is a small out-of-frame local index (the §7 `fd->vars[60]` fake
vardef), not an address.

## 6. The OOM getter bypass — what it does and does not do

`Object.defineProperty(InternalError.prototype,'name',{configurable:true,
get(){this.message='x';return 'x';}})` was verified on the Sony (72929):
without it, a refused allocation stops the widget with
`Memory limit exceeded (8 MB)`; with it the engine takes the log branch and the
next sibling `<script>` runs (`lab/qjs_n1/device_run_sony_subagent/REPORT.md`
§14, `bypass.html` 247 zlib9).

Host model of the same boundary is in `harness/c2host.c`: after each eval it
takes the pending exception with `JS_GetException`, reads `name`/`message` with
`JS_GetPropertyStr` (so the prototype getter is honoured) and kills only if the
description contains "out of memory". In `logs/05_transient_sibling.log` the C2
OOM description is `x: x`, the widget survives, and script 2 runs.

Scope: the bypass changes the **post-script decision**, not the aborted script's
control flow or compiler state. For C2 that means the sibling script gets a clean
heap (the local filler is freed on unwind) but **no corruption to use**, because
the only corrupted object died with the eval. The bypass is necessary for any
device payload that wants a second script; it is not sufficient to make C2 a
carrier.

## 7. MTE / tag domain (measured classes; Android and iOS)

| access | allocation | measured | tag check |
|---|---|---|---|
| 4-byte OOB store | htab class 288, `SLAB` (QuickJS 64 KiB mmap, `PROT_READ\|WRITE`, not `PROT_MTE`) | `SLAB cls=288 blk=5 page=7/14` | none: tag 0 → tag 0 |
| neighbour read/write | same slab, class 288 | same | none |
| second-order `fd->vars[*p]` | 1260/1264 B → `js_malloc` → Scudo primary (< 64 KiB) / Apple malloc | `LARGE usz=1260` | **tag preserved if the index is in-bounds** (our 1200 < 1260); a larger index is a linear overflow from a tagged pointer → `SEGV_MTESERR` |
| runtime local access (if the bogus index executes) | JS stack (`stack_buf`) | n/a | stack is untagged |

So C2's measured primitive is **MTE-safe on Android** (same tag domain) — the
opposite of the parser 0day — and would be MIE-compatible on stock iOS by the
same argument (the arena is the same untagged mmap; stock Telegram has no
`checked_allocations`). That is a genuine property, but it does not create a
capability: the only tag-safe index is a small in-allocation one, and the only
tag-safe write is a small integer into a neighbouring arena block.

## 8. Payload size and the 6 MiB / 8 MB "same payload" question

Measured trigger source (getter + 600 pre-interned identifiers + 51 vars +
220-byte literal + pad + local filler):

```
raw JS   4,446 B   zlib9 1,526 B
raw HTML 4,504 B   zlib9 1,582 B     (inside the 4,096 zlib9 bot envelope)
```

This is the measured payload, not a minimized one: the 600 pre-interned
identifiers are the dominant raw term (~2.9 KB raw) but compress to a few
hundred bytes; the rest is the getter, the 54-var function, the 220-byte
literal and the pad knobs.

The shipped 72929 runtime is `JS_SetMemoryLimit(rt, 6291456)` (6 MiB) by
decompile (`notes/new_0day_mte_specs_20261107.md` §10.3); the Pixel release is
treated in this campaign as an 8 MiB JS heap
(`notes/parser_mte_route2_samepayload_20261108.md`). A runtime fill covers
either value, so the exact limit is not a hardcode. The fixed-filler variant
above is tuned to a 6 MiB host heap, so it is **not** directly the dual-profile
payload. The limit difference is solvable with the
orchestrator's runtime fill (`notes/widget_memory_limits_20261108.md` §0.1: the
class-48 self-calibrating fill reaches the gate at 6 MiB **and** 8 MiB with the
same 1,280-zlib9 payload). For C2 the fill must leave a **fixed ~2.3–2.5 KB**
free at the eval start, because the compile must survive the 256-byte grow at
`var_count=27` and the 42→63-entry `fd->vars` resize (~1260 B) before the
512-byte grow fails at `var_count=54`; the measured parse consumption from
vc=27 to vc=54 is **2,291 B (Scudo) / 2,296 B (glibc)** and the failure window is
233 B. That back-off is a payload
constant, not a device constant, so the *trigger* can be universal. The payload
cost is small (a fill loop plus a back-off), and the same bytes would run on
MTE-on and MTE-off because the touched domain is the arena.

This removes the dual-profile objection. It does not remove §4–§6.

## 9. Why the v7 dynsym endgame cannot be driven

The v7 3,056-byte loader (and any `rt->js_free` + `system` resolver) consumes an
**arbitrary read/write primitive**: v7 gets it by corrupting an `ArrayBuffer`
`byte_length` to ~2 GB and scanning the same-view window for `ctx`/`rt`, then
writing `rt->malloc_state.opaque`/`js_free`. C2 has:

* no length corruption (values 53/106 vs 224+ length strings, §4);
* no pointer write with a controlled value (the only pointer-valued field hit is
  a JSValue payload low half, giving `0x7f…0000_0037` — not mappable, no leak);
* no leak (the second-order read is a comparison, not a value returned to JS);
* no execution of corrupted bytecode without the module-retry geometry (§5).

Therefore C2 cannot reach the endgame, universal or otherwise. The endgame
question is moot until a C2 variant yields a length/pointer write or a leak.

## 10. Ranking and exact blockers

| | N1 (incumbent) | C2 |
|---|---|---|
| trigger | refused `js_realloc(scopes,180)` at the cap | refused `js_realloc(vars_htab,512)` at the cap |
| gate solvable at 6 MiB and 8 MB with one payload | yes (runtime fill, job drain; `widget_memory_limits_20261108` §0.1) | yes in principle (fill + fixed ~2.5 KB back-off) |
| tag domain | same-tag arena (real ABUF) | same-tag arena for the store; tagged `fd->vars` in-bounds |
| capability | ABUF length → ~2 GB window → arbitrary RW (v7 pattern) | 4-byte small-int store; no length growth, no pointer control |
| persistence | the corrupted ABUF is a live object | the only reliable neighbour dies with the eval |
| execution after OOM | job compiled before the fill runs after it | plain eval destroys the function; module retry is geometry-blocked |
| endgame | v7 universal dynsym resolver | none (no arbitrary RW/leak) |
| size | gate 1,270 zlib9; full carrier 6,618 zlib9 (staged) | trigger 1,582 zlib9 |
| device status | gate host-proven; fake-chain layout open | primitive host-proven; no carrier |

Exact blockers, in order:

* **B1 — value/offset.** `*p = k`, `k ∈ [54..106]` at the arena-resident table
  boundaries; offsets are the fixed hash-probe slots (measured 48/188/192 in the
  neighbour). No same-class object has a length/pointer field there that a value
  ≤ 106 turns into a capability; string lengths in the same class are larger, so
  the store can only shrink.
* **B2 — target persistence.** The parser places the controllable 0xFF literal
  immediately after the htab; that atom is freed when the failing eval is torn
  down (measured `BAD=[]` in the sibling). A pre-existing live target requires
  reproducing the engine's class-288 allocation/free order, which is coupled to
  the build's global-object growth (measured failed groom).
* **B3 — execution.** A plain `eval` frees the compiled function on the pending
  OOM; only the module `m->func_obj` survives, and the measured real-bundle
  geometry cannot fill the required ~1.51 MB from a ≤ 32 KB source (c2_tryhard
  §5). Even if it did, the effect is `OP_get_loc X` with `X ≤ 106`, a few JSValue
  slots past the frame.
* **B4 — no endgame.** No arbitrary read/write and no leak, so the v7 dynsym /
  `rt->js_free` resolver cannot be driven.
* **B5 — dual-profile fill (solvable, not a blocker).** 6 MiB vs 8 MB requires
  the runtime fill; C2 adds a fixed ~2.3–2.5 KB back-off. Payload stays under
  4,096 zlib9.

**Recommendation:** keep N1 (and the parser route) as the carriers; treat C2 as
a same-tag data-only primitive. Revisit C2 only if a variant yields a *bigger
store value* or a *persistent same-slab target* (e.g. a class-288 object that is
live across the eval, or a table/neighbour geometry where the store hits a
length that is smaller than the value — none exists in this inventory).

## 11. What would change the verdict

1. A same-slab neighbour that is **live across the eval** and has a
   length/pointer at payload 48/188/192 whose corruption a 54–106 value can use
   (not present in the class-288 field map).
2. A table boundary with an arena-resident table and a value larger than a
   same-class string length (structurally impossible: arena tables are ≤ 512 B
   and same-class strings are ≥ 224/448 B).
3. A store offset moved onto a JSString `len`/`hash` word — the header is at
   neighbour payload 0–24, but the probe slots that can stop there read the
   header words, which are never `0xFFFFFFFF` for a valid string, so the write
   cannot land there.
4. A way to keep the corrupted atom alive across the eval (e.g. an atom whose
   refcount is held by a host object) — not available in the widget API.

## 12. Limits of this note

* The measurements are x86-64 host builds of the shipped source, glibc and
  `-fsanitize=scudo`. The QuickJS arena logic is architecture-independent; the
  large-block allocator is modelled, not Android's Scudo with MTE hardware.
* The MTE classification is from the allocator classes (arena mmap vs
  `js_malloc`) plus the prior device measurements; no MTE-on device was touched.
* The module-retry geometry is quoted from `c2_tryhard` (host + real bundle
  harness), not re-run here.
* The `fd->vars` tail content (`0x18000000`) is host-specific; the point is that
  it is **stale allocator data**, not attacker data, and that planting it is
  allocator-specific.
* No RCE is claimed. The negative is the result.

## 13. Repro / evidence

`lab/rce_candidates/c2/README.md` lists the full layout and commands. Key runs:

```bash
cd lab/rce_candidates/c2
python3 poc/gen_c2_variants.py clean 5300 6118000 poc/t.js
C2_DBG=1 ./build/c2host_scudo -l 6 poc/t.js            # 01: 3 UVH_WRITE
python3 poc/gen_c2_variants.py second 1800 6121500 poc/t.js 60
C2_DBG=1 ./build/c2host_scudo -l 6 poc/t.js            # 03: FIND 50/94 -> deref 60 INBOUNDS
C2_DBG=1 ./build/c2host_scudo -l 6 poc/v_transient.js poc/v_readback.sib.js
                                                       # 05: OK[2] BAD=[]
```

Instrumented source: `lab/rce_candidates/c2/src/quickjs.c` (C2_DBG/C2_ALLOC logs
only; semantics untouched). The pristine snapshot is
`lab/qjs_fork_audit/n1_hookfree/src` (2dfeee3e).

Lemmalog handoff: `notes/LEMMALOG_FACTS_c2_20261108.txt`.
