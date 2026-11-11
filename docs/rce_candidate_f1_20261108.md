# F1 (`lre_get_groupnames` UAF read) as a second RCE — assessment

Date: **2026-11-08**. Host-only (no device, no Frida, no bot, no network).
Subagent deliverable for the F1 0day row of `notes/bug_inventory_20261105.md`.

Question: can F1 be a **second RCE** that is easier than N1 (blocked at the big
filler) and than c2560s (cross-tag / MTE-off), i.e. **MTE-safe and universal**
(Android builds + iOS, no per-build/per-device hardcodes)?

## 0. Verdict (short)

**No.** F1 stays a read-only UAF, and on the **shipped Telegram fork** it is not
reachable at all:

1. **The failed `lastIndex` define is OOM-gated** — every failure path in
   `add_property` / `js_shape_prepare_update` is an allocation failure, and the
   failing allocation at the measured window is exactly the 88-byte shape
   clone (`MALLOC_LIMIT_REFUSE size=88` immediately before
   `CTOR_DEFINE_LASTINDEX ret=-1`). There is no logic-only failure mode.
2. **The shipped fork (2dfeee3e) turns that OOM into a runtime-wide poison.**
   Every `InternalError` (including the OOM and its `JS_NULL` fallback) calls
   `js_set_uncatchable_pending()`: it sets `rt->uncatchable_pending` and every
   context's `interrupt_counter = 1`. `__js_poll_interrupts()` then returns
   `-1` at the next poll, and `JS_CallInternal()` polls on entry — so **the
   next JS call aborts**. The malformed instance exists, but `r.exec()` (and
   the `lastIndex` setter it would run) never executes; the bytecode is never
   freed; no UAF. The same code is present in the device binary 72879
   (`JS_ThrowInternalError` @ 0x170a510: `rt+1304 = 1`, each `ctx+524 = 1`).
3. **Where F1 is reachable (upstream 7a23d8e, no poison), the primitive is
   strictly read-only.** Host measurements on the exact app source:
   * the freed object is the raw `lre` bytecode buffer (`len = 34` for the
     trigger pattern); it is reclaimed by the same arena class **48**
     (`align8(len)+8`), sizes 33..40 work, 24/41/48 do not;
   * the fake header controls `flags` (u16) and `bytecode_len` (u32) only, and
     yields a **forward-only relative read** `bc + 8 + u32` (0..4 GiB,
     `SIGSEGV` at large offsets);
   * the read is decoded as UTF-8: a planted 64-bit pointer
     `0x00007f8b12345678` comes out as `"xV4" + 3 × U+FFFD`, length 6 — the
     value is **destroyed**; only the first-NUL position (address width) and
     printable low bytes survive. No ASLR leak;
   * **no write**: the post-free operations are `lre_get_flags`,
     `lre_get_groupnames`, `strlen`, `JS_NewAtom` and property defines on the
     fresh `groups` object; a canary over 200 reclaim buffers reports
     `changed=0`;
   * the stale bytecode is never executed (`lre_exec` runs before the setter;
     `JS_RegExpDelete` breaks after its `SetProperty`).
4. **MTE/MIE**: the fork's arena slabs are `mmap(PROT_READ|PROT_WRITE)` **not**
   `PROT_MTE` (untagged, tag-0 pointers); block frees never retag. F1's
   read is therefore same-tag/untagged, like v7. That is irrelevant in
   practice because the primitive has no write and the fork blocks the trigger.
5. **Universality**: the *reclaim* is arch-independent (class table and bytecode
   length are source-level), but the *trigger* is not: the window is a
   heap-baseline- and script-length-sensitive calibration (measured windows move
   by up to ~4 KB for small source changes), the headroom is charged in
   allocator-size steps, and on the fork a mis-calibrated attempt is fatal
   (poisoned OOM).

F1 is a **dead end** for the second-RCE goal: it is weaker than N1's OOB RW
(no write, lossy read) and additionally closed on the shipped engine by an
unrelated hardening (the uncatchable-pending re-raise).

## 1. Sources, builds, binary

| artifact | meaning |
|---|---|
| `lab/qjs_fork_audit/n1_hookfree/src` (= `2dfeee3e`) | **shipped fork** source (has the 16-slot regexp cache, the mmap slab arena and the uncatchable-pending patch); copied to `lab/rce_candidates/f1/src` + host instrumentation |
| `lab/qjs_regexp_audit/src_7a23d8e` | upstream app snapshot (v0.17.0, no cache, no poison); copied to `lab/rce_candidates/f1/src7a` + instrumentation |
| `lab/qjs_regexp_audit/.build-7a` | release build of 7a23d8e used by the earlier audit |
| `libmessages.49.so` 72879 (13.2.0) | device binary; the existing IDA dump `lab/qjs_regexp_audit/logs/ida_72879_JS_ThrowInternalError.txt` is the static evidence for the poison |

Builds made for this assessment (all in `lab/rce_candidates/f1/`):

* `build-asan` — fork 2dfeee3e, gcc ASan (`__SANITIZE_ADDRESS__` → arena off);
  `run/f1run_asan` (harness `harness/f1run.c` + `f1*` helper bindings).
* `build-rel` — fork 2dfeee3e, `-O2`, arena on; `run/f1run_rel`.
* `build7a` — 7a23d8e copy with the same instrumentation, `-O2`, arena on;
  `run/f1up_7a` (harness `harness/f1up.c`).

The instrumentation only adds `fprintf` events (compile address/length, arena
class/block on free and reclaim, allocation-refusal, new-string free). It does
not change allocation behaviour.

## 2. The bug (both engines, identical shape)

`js_regexp_constructor_internal()` ignores the result of the `lastIndex`
define:

* fork `quickjs.c:50135`: `JS_DefinePropertyValue(ctx, obj, JS_ATOM_lastIndex,
  prop.u.value, JS_PROP_WRITABLE);`
* upstream 7a23d8e `quickjs.c:49308`: same statement.

For a subclass instance (`class R extends RegExp`, or `Reflect.construct` with
a custom prototype) the object's shape is not `ctx->regexp_shape`, so the
define has to clone/resize the shape (`add_property` → `find_hashed_shape_prop`
miss → `js_clone_shape` / `js_shape_prepare_update`), which allocates. When
that allocation is refused the constructor still returns the object: the
instance has **no own `lastIndex`** and the prototype accessor is live.

`js_regexp_exec()` then: prototype getter → `lre_exec` on the live bytecode →
`JS_SetProperty(lastIndex, end)` → **setter** → the setter recompiles the
instance, freeing the bytecode buffer the function cached in the local
`re_bytecode` → `lre_get_groupnames(re_bytecode)` reads freed memory:

* fork `quickjs.c:50545` (`re_bytecode = str8(...)` 50579,
  `lre_get_groupnames` 50635);
* upstream 7a23d8e `quickjs.c:49718` (snapshot 49752, groupnames 49808).

Only two post-free uses exist: `lre_get_flags` (u16 at +0, via
`lre_get_groupnames`) and `lre_get_groupnames` (u32 length at +4, then the
group-name loop `*p` / `strlen` / `JS_NewAtom`). `capture_count`, `alloc_count`
and the control-flow `re_flags` are read **before** the free.

## 3. Gate 1 — the failed define is OOM-gated

The define can fail only through allocation in
`add_property()` (fork 10608): `js_realloc_object_prop`,
`js_clone_shape`, `add_shape_property`/`resize_properties`,
`js_shape_hash_link` (hash grow) — and `js_shape_prepare_update()` (fork 11638)
cloning a shared hashed shape. There is no non-allocation error path: the
object is fresh and extensible, the atom is predefined, and the property does
not exist. So a *logic-only* failed define cannot be constructed.

Measured at the window (fork, ASan build, `evidence/fork_trace_define_ret_minus1.txt`):

```
[F1] COMPILE addr=0x504000000598 bc_len=34 pat_len=7 slot=8 ...
[F1] MALLOC_LIMIT_REFUSE addr=(nil) size=88 used=6291436 limit=6291456
[F1] CTOR_DEFINE_LASTINDEX addr=0x50b00000a288 ret=-1 obj=0x50b00000a288
```

The refused 88-byte request is the shape clone/update; the define returns -1
and the constructor returns the malformed object. (Upstream shows the same
mechanism; the ASan UAF log `evidence/upstream7a_asan_uaf_reclaim_attempt.txt`
is the post-window exec.)

The window is the fill where the constructor's earlier allocations (2+2+49
for the pattern/flags/bytecode, 104 for the object) fit but the 88-byte
shape allocation does not. It is reachable — see the calibrated runs in §5 —
but it is a narrow band (76–88 bytes of headroom) and, as §8 shows, the
headroom moves in page/class-sized steps.

## 4. Gate 2 (decisive) — the shipped fork's uncatchable-pending poison

The fork adds a runtime-wide "uncatchable pending" mechanism that upstream
7a23d8e does not have:

```c
/* fork quickjs.c:8337 */
static void js_set_uncatchable_pending(JSRuntime *rt) {
    rt->uncatchable_pending = true;
    list_for_each(el, &rt->context_list) {
        JSContext *c = ...;
        c->interrupt_counter = 1;      /* force a poll immediately */
    }
}
/* fork quickjs.c:9094 */
static no_inline __exception int __js_poll_interrupts(JSContext *ctx) {
    if (unlikely(rt->uncatchable_pending)) {
        ctx->interrupt_counter = 1;
        if (!JS_HasException(ctx)) JS_ThrowInterrupted(ctx);
        return -1;
    }
    ...
}
/* fork quickjs.c:8928 (the JS_Throw*Error macro) */
    val = JS_ThrowError(...);
    if (JS_INTERNAL_ERROR) {
        js_set_uncatchable_error(ctx->rt->current_exception, true);
        js_set_uncatchable_pending(ctx->rt);   /* even for JS_NULL */
    }
```

`JS_CallInternal()` polls on entry (fork `quickjs.c:18743`), so after the OOM
inside the ignored define, **any** JS call — the `r.exec()` that would run the
setter included — returns `JS_EXCEPTION` and the eval aborts. The eval
boundary then sees the OOM (`SandboxEngine_evalScript` → `JS_HasException` →
JSError; the app-side check is documented in `notes/audit_async_iter.md`
§"Dispatch boundary" and `notes/twidget_interrupt_re.md` §A.1), so the widget
is stopped with `Memory limit exceeded`; the next `<script>` never runs.

Device confirmation (static, existing IDA dump): 72879 `JS_ThrowInternalError`
@ `0x170a510`:

```
*(_BYTE *)(v9 + 1304) = 1;                 /* rt->uncatchable_pending */
for (v11 = ...context_list...; v11 != ...; v11 = *(v11 + 8))
    *(_DWORD *)(v11 + 524) = 1;            /* ctx->interrupt_counter */
```

Measured on the fork (ASan build, calibrated window, `run/poison4.js`):

| run | what the script does after the constructor | result |
|---|---|---|
| `-X 2` (trace) | nothing (trace only) | `CTOR_DEFINE_LASTINDEX ret=-1`; then the eval aborts |
| `-X 0` | first JS call (`hasOwnProperty`) | `EXCEPTION: InternalError: out of memory` |
| `-X 1` | `r.exec("a")` | `EXCEPTION: InternalError: out of memory`; **no setter compile, no `COMPILE_RELEASE_OLD`, no `BYTECODE_STRING_FREE`, no `RECLAIM`** |
| `-T -X 1` (trace on, exec) | `r.exec("a")` | same; only the victim `COMPILE` line exists — the setter never ran |

Logs: `evidence/fork_poison_define_fail_exception.txt`,
`evidence/fork_poison_exec_attempt_exception.txt`,
`evidence/fork_exec_with_trace.err`.

So on the shipped fork the malformed instance is creatable but **inert**: the
only code that could free the bytecode (the setter) cannot be reached.

### 4.1 Secondary fork hurdle (relevant only if the poison were removed)

The fork also has a 16-slot **regexp bytecode cache** holding a strong
reference (`quickjs.c:50063-50105`). The setter's `compile()` frees only the
instance's reference; the cached reference keeps the bytecode alive. Freeing
it requires evicting its slot with distinct patterns. Measured on the fork
(`run/fork_cache_demo.js`, `fork_cache_demo64.js`):

* 24 distinct compiles did **not** evict it: the victim's slot 14 was never
  hit (0 `CACHE_EVICT slot=14`), and the only `BYTECODE_STRING_FREE` for the
  watched buffer is at runtime teardown (after the last compile).
* 64 distinct compiles evicted it during the loop:
  `BYTECODE_STRING_FREE ... data=0x504000000318 len=34 ref=0` appears at log
  line 257, before the last compile (line 643); 4 `CACHE_EVICT slot=14`
  events.

So even a poison-free fork would need: window + ≥48 distinct compiles + spray
inside the setter, i.e. a bigger, more fragile payload than upstream.

## 5. The primitive where it is reachable (upstream 7a23d8e)

The earlier F1 audit proved the UAF on 7a23d8e. This assessment reproduces it
and measures the reclaim/read/write ceiling with instrumented hosts.

### 5.1 UAF

`evidence/upstream7a_asan_uaf_reclaim_attempt.txt` (appmodel 7a ASan):
`heap-use-after-free ... get_u16 ← lre_get_flags ← lre_get_groupnames ←
js_regexp_exec` (read of size 2), freed by `js_regexp_compile` via
`call_setter ← JS_SetProperty ← js_regexp_exec`. (The ASan build quarantines
freed blocks, so the reclaim cannot be shown there; the release build is used
below.)

### 5.2 Reclaim class and fake header — measured

Trigger pattern `(?<x>a)` with `g`: `lre` bytecode **len = 34** (both engines).
Arena class: `total = align8(34)+8 = 48` → `arena_block_sizes[4] = 48`,
usable 40 bytes. The upstream trace at the window
(`evidence/upstream7a_free_reclaim_trace.txt`) shows the free and the reclaim
of the same block:

```
COMPILE addr=...deb0 bc_len=34
COMPILE_RELEASE_OLD addr=...de50 old_ref=1
BYTECODE_STRING_FREE ... data=...de50 len=34 ref=0
FREE     addr=...de50 class_idx=4 block_size=48 block=26
RECLAIM  addr=...de50 class_idx=4 block_size=48 block=26 req=34
```

Reclaim on upstream release (`run/up_reclaim.js`, 200 `ArrayBuffer` spray in
the setter, fake header at data+0):

| reclaim size N | class of `align8(N)+8` | observed `m.groups` keys |
|---:|---:|---|
| 24 | 32 | `[x]` (no reclaim; stale original name) |
| 33 | 48 | **`[F1]`** |
| 34 | 48 | **`[F1]`** |
| 40 | 48 | **`[F1]`** |
| 41 | 56 | `[x]` |
| 48 | 56 | `[x]` |

Logs `evidence/up_class_N*.out`. The `[x]` cases are the freed-but-unreclaimed
block (the arena does not zero on free), a useful control: the free happened,
the class did not match.

A single class-48 buffer was not sufficient in the measured runs: the trace of
a one-buffer attempt shows another class-48 allocation taking the freed block
and releasing it again before the fake buffer's data lands there, so the block
ends up free-but-unreclaimed (`groups=[x]`). The 200-buffer class spray is
what reliably puts the fake header in the victim block. This is the same shape
as v7's "spray the class" step, size ~200 × 34 B.

Fake header (data+0): `u16 flags = 0x80` (`LRE_FLAG_NAMED_GROUPS`),
`u32 bytecode_len = L`, trailer at data+8+L. With `L=0` and `"F1\0"` at +8 the
result is `m.groups = ["F1"]` (`evidence/up_fake_name.out`).

### 5.3 Read semantics: forward-only and a length oracle

The trailer pointer is `bc + 8 + (uint32_t)bytecode_len` — **forward only**,
0..0xFFFFFFFF bytes, no backward, no sign. With the spray filled with `0x41`
(`mode 4`) and `L` varied (`evidence/up_lenoracle_L*.out`):

| L | trailer offset | decoded key | key length |
|---:|---:|---|---:|
| 8 | +16 | `A`×18 | 18 |
| 12 | +20 | `A`×14 | 14 |
| 16 | +24 | `A`×10 | 10 |
| 20 | +28 | `A`×6 | 6 |
| 24 | +32 | `A`×2 | 2 |

The key length is exactly the distance from the chosen offset to the first NUL
(the 34-byte block's zero padding). That is a byte-granular **relative** read
oracle bounded by the first NUL; it leaks no address.

Large `L` is a crash: `L = 0x3fffffff` → `SIGSEGV`
(`evidence/up_crash_bigL.err`, rc=139). No fault recovery in JS → DoS only.

### 5.4 Pointer leak — negative

Planted values at the trailer (a real heap pointer via `plantptr(ab, …, ptr(ab1024))`,
and the synthetic `0x00007f8b12345678`):

```
pointer_plant  groups=[xV4<U+FFFD><U+FFFD><U+FFFD>] klen=6   (0x00007f8b12345678)
real_heap_ptr  groups=[Xa<U+FFFD><U+FFFD>U]        klen=6   (heap data pointer)
```

`JS_NewAtom` decodes the bytes as UTF-8; every byte ≥ 0x80 becomes U+FFFD and
the numeric value is unrecoverable. The only information is the position of the
first NUL (6 for a 47-bit user address on x86-64/arm64) and any printable low
bytes. **No ASLR / heap-pointer leak.**

### 5.5 Write — negative

The stale buffer is read, never written. The post-free code paths are
`lre_get_flags` / `lre_get_groupnames` / the group-name loop and the result
construction (which writes to fresh JS objects, not to the freed block). The
fake `capture_count` byte is not used post-free (`capture_count` is read before
the setter).

Measured: 200 reclaim buffers filled with a deterministic pattern, hashed
before and after `exec` (including the whole result construction):
`changed=0` (`evidence/up_canary_nowrite.out`). In ASan the same run reports
only a 2-byte READ (no write access).

### 5.6 Source audit of every post-free use

| site | op | fake-controlled | effect |
|---|---|---|---|
| `lre_get_flags` (libregexp.c:3451) | read u16 at +0 | yes (flags) | selects named-group walk |
| `lre_get_groupnames` (3461) | read u32 at +4 → pointer | yes (len) | sets the read address |
| group loop (quickjs.c 50738+) | `*p`, `strlen`, `JS_NewAtom` | data at the target | lossy read / atom |
| `JS_DefinePropertyValue(groups, …)` | writes to `groups` | key only | JS-level |
| `JS_RegExpDelete` | no post-`SetProperty` bytecode use (`break`) | — | not a second sink |
| `js_regexp_get_flag(s)` | read before any callback | — | safe |

No path re-executes `lre_exec` on the stale buffer, so the register/capture
write machinery cannot be re-entered with a fake header.

## 6. Can the read be turned into a write? (why not)

* The only fake-controlled fields are `flags` (u16) and `bytecode_len` (u32);
  both are read parameters. `capture_count`, `alloc_count` and the control
  `re_flags` come from the live bytecode before the free.
* The engine never calls `lre_exec` after a user callback in
  `js_regexp_exec` (it is before the setter) and `JS_RegExpDelete` breaks after
  its `SetProperty`.
* A reclaim by a **JSObject** (instead of an ArrayBuffer) cannot help: its
  block header holds GC/refcount fields, not attacker bytes at +0, and its
  first fields are pointers; flags would be the low bits of a GC link. A
  **string** reclaim can set `flags` from its `len` field (e.g. len=128 →
  0x80) only when its block class equals the victim's, which forces a ~128-byte
  victim and merely reads the JSString struct's pointer fields — still lossy
  and still read-only.
* The only state the primitive can change is the JS `groups` object (property
  names/values), i.e. a JS-level gadget for a host consumer, not a native
  write.

## 7. MTE / MIE

* **Fork arena**: `JS_ARENA_SLABS` slabs are `mmap(NULL, 64 KiB, PROT_READ |
  PROT_WRITE, MAP_PRIVATE | MAP_ANON, …)` (fork `quickjs.c:1881`, `JS_ARENA_SLAB_TAG`
  is only a Darwin VM tag). No `PROT_MTE`, so the memory is untagged; all
  block pointers are tag 0; a freed sub-block is returned to the arena free
  list and is never retagged. The stale pointer and the reclaim are in the
  same (untagged) domain. This is the v7 "same-tag/untagged" property and is
  consistent with the Pixel-9 MTE reference (all touched addresses `mt=False`).
* **Upstream 7a23d8e arena**: slabs come from `js_malloc` (Scudo primary on
  Android); the freed block is a sub-block, not retagged, and the stale
  pointer keeps the slab's tag → in-slab access is checked against the same
  tag. The forward read can leave the slab's tag domain, but the fork (the
  shipped engine) uses mmap slabs, so this is moot on device.
* **iOS**: same engine source; third-party apps do not opt into MIE
  (`com.apple.security.cs.checked_allocations` absent in the stock IPA) and
  the slabs are untagged → not tag-checked.

F1's *primitive* is therefore MTE/MIE-safe in the same-tag sense, like v7 —
but it is read-only and, on the shipped engine, unreachable.

## 8. Universality

**Reclaim: universal.** The freed object is the raw `lre` buffer of length
`re_bytecode_len`; its class is `arena_block_sizes[arena_get_size_index(
align8(len)+8)]`, a source-fixed table (31 entries, 16..512) shared by the
fork and upstream. `len` is chosen by the attacker's pattern; no pointer-size,
arch or build constant enters. Reclaim sizes 33..40 for the measured len 34
(one class). A small ladder (e.g. 24..64) covers the neighbouring classes.

**Trigger: not universal.** Measured windows on the same host shift with the
payload source length and with the GC/phase:

| payload | window (fill) |
|---|---|
| final upstream PoC (`run/up_reclaim.js`, current text) | 6,179,808 |
| earlier variants of the same PoC | 6,180,016 / 6,180,128 / 6,182,096 / 6,182,208 / 6,182,240 / 6,182,944 |
| fork poison demo (`run/poison4.js`) + phase P=0 | 6,178,900 |

The constructor's headroom after the fill is charged through
`js_arena_usable_size` (the huge fill via `malloc_usable_size`, small
allocations via the arena class size), so it moves in allocator-size steps and
the 76–88-byte define band is sampled coarsely; a small "phase" allocation
(`new ArrayBuffer(P)`) is what samples it (the runs that located the windows
used the phase knob; the final runs above use `P = 0`). On the fork a
mis-calibrated attempt above the window is fatal (the OOM poisons the
runtime), so a wide/naive search cannot be used. The engine's per-script
budget (500 ms) also bounds an in-script sweep.

Cost measured on the host (release, 6 MiB): the 3.7 k-attempt sweep from
6.12 M to the window at 6.1798 M (16-byte stride, each attempt allocating and
freeing a ~6.18 MB filler) takes **0.2 s**, i.e. ~54 µs/attempt. On the device
(arm64, Scudo, slower interpreter) assume 5–20×: a 500 ms script covers only
~10–25 KB at a 16-byte stride. The sweep length is therefore the problem: the
start must be within a few tens of KB of the window, which is a
per-payload/per-device constant (the heap baseline includes the sandbox bundle
and the widget source). A conservative start at, e.g., half the limit would
need tens of thousands of attempts / many scripts.

Therefore the trigger needs **per-payload/per-platform calibration** (or a
runtime headroom-measurement primitive), which is exactly the "no per-device
hardcode" requirement the task imposes. On iOS the same engine and the same
OOM policy apply; the heap baseline differs again.

**Payload size** (raw / zlib9):

| script | raw | zlib9 |
|---|---:|---:|
| `run/up_reclaim.js` (trigger + eviction-free reclaim + measurements) | 2,279 | 1,067 |
| `run/poison4.js` (fork trigger demo) | 753 | 437 |
| `run/poc_f1_fork.js` (fork sweep + reclaim attempt) | 2,995 | 1,293 |

Small payloads are not the blocker; the gates are.

## 9. Comparison with N1 / v7 / c2560s

| | N1 | **F1** | v7 (#1827) | c2560s |
|---|---|---|---|---|
| primitive | OOB RW (32-bit write) + leak | **UAF read (lossy forward ASCII)** | same-view 64-bit write | cross-tag OOB RW |
| OOM gate | yes (refused `js_realloc`) | **yes (refused shape clone)** | no (`valueOf` recompile) | no |
| surviving in-script after the gate | **no** (abort during compile) | **no on fork** (poison); yes upstream | yes | yes |
| same-tag / MTE-safe | yes | yes (read) | yes (proven) | no |
| universality | no (OOM) | **no (OOM + heap-tuned fill)** | yes | yes (MTE-off) |
| RCE | host-only, device-closed | **none** | device-proven | device-proven |

F1 is not a "second N1": it is strictly weaker (read vs read/write) and its
gate is at least as bad (OOM), with an extra fork-specific poison and a cache
eviction.

## 10. What would change the verdict

* A **non-OOM** way to obtain a `JS_CLASS_REGEXP` instance without an own
  `lastIndex` (none found: the property is non-configurable, the object is
  created fresh, and the define only fails on allocation).
* An engine **without** the uncatchable-pending patch (upstream) **and** a
  consumer that turns the group-name bytes into an address (none), or a second
  bug giving a pointer leak + pointer write (then F1 is redundant).
* A pointer-preserving read (e.g. a non-UTF-8 direct byte exposure) — the
  current path is lossy by construction (`JS_NewAtom`).

## 11. Reproduction

```sh
cd lab/rce_candidates/f1

# fork (2dfeee3e): ASan build, window calibration via -F/-P, poison demo
./run/f1run_asan -l 6 -t 60000 -T -F 6178900 -P 0 -X 2 run/poison4.js
./run/f1run_asan -l 6 -t 60000 -T -F 6178900 -P 0 -X 1 run/poison4.js
#   -> CTOR_DEFINE_LASTINDEX ret=-1, then EXCEPTION: InternalError: out of memory
#      with no COMPILE_RELEASE_OLD / BYTECODE_STRING_FREE / RECLAIM

# upstream 7a23d8e (no poison): trigger + reclaim + measurements
./run/f1up_7a -l 6 -t 480000 -F 34 -P 0  -X 0 run/up_reclaim.js   # groups=[F1]
./run/f1up_7a -l 6 -t 480000 -F 24 -P 0  -X 0 run/up_reclaim.js   # groups=[x]
./run/f1up_7a -l 6 -t 480000 -F 34 -P 8  -X 4 run/up_reclaim.js   # klen=18
./run/f1up_7a -l 6 -t 480000 -F 34 -P 0  -X 5 run/up_reclaim.js   # pointer lossy
./run/f1up_7a -l 6 -t 480000 -F 34 -P 0  -X 2 run/up_reclaim.js   # changed=0
./run/f1up_7a -l 6 -t 60000  -F 34 -P 1073741823 -X 0 run/up_reclaim.js  # SIGSEGV

# ASan UAF (7a23d8e)
ASAN_OPTIONS=detect_leaks=0 ../../qjs_regexp_audit/appmodel_7a_asan \
    run/up_asan_reclaim33.js 6 60000
```

`-F` is the reclaim size / calibration fill, `-P` the phase or fake
`bytecode_len`, `-X` the mode (0 fake name, 1 real pointer, 2 canary, 4 0x41
fill, 5 synthetic pointer, 6 trace-at-F). Helpers (`f1watch`, `f1trace`,
`f1last`, `plantptr`, `opt`, …) exist only in the lab harnesses.

## 12. Artifacts

```
lab/rce_candidates/f1/
  src/                  fork 2dfeee3e + instrumentation (F1 events)
  src7a/                7a23d8e + the same instrumentation
  harness/f1run.c       fork harness (f1* helpers, JS_HasException boundary check)
  harness/f1up.c        upstream harness (ptr/plantptr/mem/opt)
  run/*.js              PoCs: poison4 (fork), up_reclaim (upstream), cache demo
  run/f1run_asan, run/f1run_rel, run/f1up_7a
  evidence/*.out,*.err  all measurements quoted above
  logs/                 build/cmake logs
```

Key evidence files:

* `evidence/fork_trace_define_ret_minus1.txt` — define ret=-1, 88-byte refuse,
  class-48 victim free.
* `evidence/fork_exec_with_trace.err` — exec attempt with trace on: no setter
  compile, no free, no reclaim (poison).
* `evidence/upstream7a_asan_uaf_reclaim_attempt.txt` — ASan UAF.
* `evidence/up_class_N*.out` — class 48 reclaim table.
* `evidence/up_lenoracle_L*.out` — forward read / length oracle.
* `evidence/up_pointer_plant.out`, `evidence/up_real_heap_ptr.out` — lossy
  pointer read.
* `evidence/up_canary_nowrite.out` — no write.
* `evidence/up_crash_bigL.err` — SIGSEGV (rc 139; see `lab/rce_candidates/f1/logs/up_batch.txt`).
* `evidence/fork_cache_demo64.*` — 64-pattern cache eviction (fork hurdle).
* `evidence/upstream7a_free_reclaim_trace.txt` — upstream free + reclaim of the
  same class-48 block at the window.

Instrumentation note: the source copies are lab-only; the shipped sources are
untouched under `lab/qjs_fork_audit/` and `lab/qjs_regexp_audit/`.
