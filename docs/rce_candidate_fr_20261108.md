# FR candidate — `FinalizationRegistry.prototype.unregister` UAF: reclaim / RCE assessment

Date: 2026-11-08. Host-only: no device, no Frida, no bot, no network.
Target: shipped Telegram QuickJS fork **2dfeee3e** (Android 72889/72929 source)
and upstream quickjs-ng **v0.17.0** (the engine the iOS 13.2 widget uses).
Evidence: `lab/rce_candidates/fr/` (builds, PoCs, trace/oracle logs, gdb logs).
This note is new; no shared note or inventory was edited.

## 0. Verdict (short)

**FR is not a second RCE and not a v7-like primitive.** It is a
deterministic, non-OOM, same-tag, platform-independent **native crash/DoS**
with a **122-byte** JS trigger. The freed 88-byte entry **cannot be reclaimed
in the free→stale-read gap**: the gap contains **no allocation at all** except
the FinalizationRegistry job, which is a fixed 72-byte request (arena class
80). A full allocation census over 36 triggers covering every finalizer class
and weak-ref population found **zero class-96 allocations in the gap**.

The hypothetical `list_del` write was measured with a lab-only oracle that
forces one class-96 allocation in the gap: it is exactly
`*(prev+8) = next` / `*(next+0) = prev` with attacker-chosen pointers
(2 × 8-byte write), and the fake block is handed back at exactly the freed
entry's address. But a JS exploit would additionally need: (a) the token
object's heap pointer to forge the token `JSValue` that gates the branch,
(b) two valid pointer values for `link.prev/next`, and (c) a live target with
a matching `JSWeakRefRecord` for the `delete_finrec_weakref()` call that
follows the `list_del`. FR provides **no leak and no pointer construction**,
so it fails all three; the oracle aborts in (c) even when (a)/(b) are handed
to it natively.

Relative to the other candidates: FR passes the two gates that killed the
others (no OOM/filler gate like N1; same-tag/untagged like the v7 pattern, so
MTE-agnostic) but has **no write primitive at all**. It is strictly weaker
than N1, not easier.

## 1. Method and evidence

Two engines were built from source with the same one-file harness
(`scripts/fr_run.c`, 6 MiB heap cap, 1 MiB stack, the widget model):

| build | source | purpose |
|---|---|---|
| `build/fr_rel` | 2dfeee3e, arena ON, `-O2 -DNDEBUG` | device/allocator model |
| `build/fr_dbg` | 2dfeee3e, arena ON, asserts | backtraces |
| `build/fr_asan` | 2dfeee3e, ASan+UBSan, arena blocks via malloc | UAF oracle |
| `build/fr_trace` | 2dfeee3e + `FR_TRACE` event log | allocation census |
| `build/fr_oracle` | 2dfeee3e + `FR_ORACLE` synthetic gap allocation | measure the would-be write |
| `build/fr_v0170_rel/_asan` | quickjs-ng **v0.17.0** (iOS engine) | universality |

`FR_TRACE` logs every `js_malloc_rt`/`js_calloc_rt`/`js_realloc_rt`/`js_free_rt`
event with size, usable size and pointer, plus FR entry register/free events,
`reset_weak_ref` frees and every `unregister` loop visit. It is enabled per
`unregister()` call (`FR_TRACE=1`) and adds no behaviour when unset
(`scripts/instrument_fr.py`). `FR_ORACLE` is a separate, clearly-labelled
synthetic allocation inside `js_finrec_free()`; it is **not reachable from
JS** and is only used to measure the write.

The instrumented source is a copy (`src_inst/`); the shared source tree was
not modified. `src_v0170/` is a `git archive` of the v0.17.0 tag.

## 2. The bug (source walk)

`js_finrec_unregister` (`lab/qjs_fork_audit/zeroday_hunt_parser/src/quickjs.c:64239`):

```c
list_for_each_safe(el, el1, &frd->entries) {          /* 64251 */
    JSFinRecEntry *fre = list_entry(el, JSFinRecEntry, link);
    if (js_same_value(ctx, fre->token, token)) {      /* 64253 */
        list_del(&fre->link);                         /* 64254 */
        delete_finrec_weakref(ctx->rt, fre);          /* 64255 */
        js_finrec_free(ctx->rt, fre);                 /* 64256 */
        removed = true;
    }
}
```

`js_finrec_free` (64126) frees the **held value** first (64128). If that held
value is T's last strong reference, `free_object(T)` calls
`reset_weak_ref()` (`free_object` at 7383, call at 7410), whose FINREC case
unlinks **and frees** another entry E2 of the same registry
(`reset_weak_ref` 2nd pass, `js_finrec_free` at **64393**). But
`list_for_each_safe` already saved `el1 = E2`; after the body it does
`el = el1; el1 = el->next` (`list.h:73` `list_del` zeroes the freed link).
The loop then walks freed memory.

Two crash shapes, both deterministic:

* **E2 with a different token** → the stale `js_same_value` is false, the
  update reads E2's zeroed `next` (NULL), and the next iteration dereferences
  NULL. Observed: `SIGSEGV`, `si_addr=0x8`, `mov 0x8(%reg),%rax` in
  `js_finrec_unregister` (read).
* **E2 registered with the same token** → the stale `token` field survived
  the free (only `link` is zeroed), so the compare is true and the stale
  `list_del` runs with `prev = next = NULL`: the first store is
  `prev->next = next` → `*(u64*)0x8 = 0`. Observed: `SIGSEGV` **write**,
  `si_addr=0x8`, `mov %rax,0x8(%rdx)` with `rax=0`.

This is the "stale `list_del` NULL-derived write" seen in the earlier
campaign: a **fixed zero write to address 8**, not a controllable write.

The trigger is order-dependent: with E2 registered *before* E1 (so E1 is the
last element and `el1 == head`), the loop ends normally and the entry is
removed before it is visited (`poc/fr_safe_order.js` → `FR_SAFE:true`, no
crash on both engines). This is also the trivial fix shape: the registry
finalizer already uses a two-pass scheme; `unregister` does not.

The bug is present, byte-identical, in:
`2dfeee3e` (shipped Android), the fork `origin/master` `1a402cb`, the
`qjs_advisories/src_latest` copy, and quickjs-ng `v0.17.0` (iOS).
No fix for the `unregister` loop exists in any local upstream snapshot.

## 3. Host reproduction

### 3.1 Release/arena (device model), shipped fork

```
poc/fr_uaf_read.js       SIGSEGV  si_addr=0x8  read  js_finrec_unregister+104
poc/fr_uaf_nullwrite.js  SIGSEGV  si_addr=0x8  write js_finrec_unregister+172
poc/fr_safe_order.js     OK: FR_SAFE:true
```
Logs: `logs/gdb_rel_read.txt`, `logs/gdb_rel_nullwrite.txt`,
`logs/trace_baseline_read.log`, `logs/trace_baseline_nullwrite.log`.

The trace of `fr_uaf_read.js` (E1=`0x…4bd8`, E2=`0x…4c38`):

```
EV 4 UNREG visit el=…4bd8 fre=…4bd8 el1=…4c38
EV 5 UNREG match fre=…4bd8 next=…4c38
EV 8 ALLOC ptr=…d588 size=72 usable=72      <- the only allocation: FR job
EV 9 FR_FREE enter fre=…4c38 held_tag=0 …   <- E2 (the dying target's entry)
EV 11 FREE ptr=…4c38 usable=88              <- E2 freed, class 96
EV 14 FREE ptr=…4f88 usable=104             <- T's shape
EV 16 FREE ptr=…4bd8 usable=88              <- E1 freed, class 96
EV 18 UNREG visit el=…4c38 fre=…4c38 el1=(nil)   <- stale iteration
```
No `ALLOC` between EV 11 and EV 18.

### 3.2 ASan

`heap-use-after-free`, `READ of size 8`, at `js_finrec_unregister
quickjs.c:64251` (the `list_for_each_safe` update); freed by
`reset_weak_ref quickjs.c:64393` ← `js_finrec_free` ← `js_finrec_unregister
64256`. Logs: `logs/fr_uaf_read_asan.log`, `logs/fr_uaf_nullwrite_asan.log`.

### 3.3 v0.17.0 (iOS engine)

Same two crashes at `si_addr=0x8` and the same ASan UAF
(`v0.17.0 quickjs.c:63284`, free at 63426):
`logs/gdb_v0170_read.txt`, `logs/gdb_v0170_nullwrite.txt`,
`logs/v0170_uaf_read_asan.log`. The safe-order control also returns true.

### 3.4 Symbol target control

A symbol target is not a lifetime hole: `JS_FreeAtomStruct` calls
`reset_weak_ref()` when the atom's refcount reaches 0 (quickjs.c:3935), so the
entry is removed and freed at that point; a later `unregister(token)` finds
no entry and returns false (`poc/fr_symbol_target_control.js`, both engines,
log not needed). Symbol targets also drive the same unregister UAF when they
are the *held* value (corpus case `symbol_held`).

## 4. The reclaim question (core)

### 4.1 What a reclaim would need

For the stale `list_del(&fre->link)` to become a controlled write, between
E2's `js_free` and the loop update something must allocate **class 96**
(request 81..88 bytes → block 96; `JSFinRecEntry` is 88 bytes, trace
`sizeof=88`) and fill it with:

* `link.prev`, `link.next` at offset 0/8 — two valid pointer values;
* `token`, a 16-byte `JSValue` at offset 48 that `js_same_value` compares
  against the unregister argument;
* `target` at offset 16, later used by `delete_finrec_weakref()`.

Class 96 is the right class: `new Uint8Array(81..88)` allocates a separate
81..88-byte data buffer (measured: `ALLOC size=88 usable=88`), i.e. a
JS-byte-controlled class-96 block. It cannot be placed in the gap because no
JS runs there.

### 4.2 Measured gap: complete allocation census

`poc/gap/` + `scripts/run_gap_corpus.sh` + `scripts/summarize_gap.py`,
36 triggers, one process each. T (the held value whose death frees E2) is
varied over: plain object, array, Map, Set, function, RegExp, ArrayBuffer,
Uint8Array, Promise, generator, FinalizationRegistry (with entries), WeakRef,
Error, Date, String object, Proxy, class instance, 200-property object,
BigInt property, symbol property, 4 WeakMaps with T as key, 8 WeakRefs, 8 FR
entries, mixed WeakRef+WeakMap+2 FR entries, 12 mixed entries, a symbol, and
the three same-token (null-write) variants. Every trigger frees E2 during
`unregister`.

Result (`logs/gap/*.log`, summary in `logs/gap_summary.txt`):

| metric | value |
|---|---|
| triggers | 36 |
| triggers that free E2 inside the unregister call | 35 — the exception is the `registry_full` construction, which keeps the inner registry alive through a second variable so E2 is never freed; `registry_full2` corrects it (E2 freed, crash) |
| allocations in the whole `unregister` window | only `size=72 usable=72` (block 80, class idx 8) |
| max job allocations (12 extra entries on T) | 13 × class 80 |
| allocations **after** E2's free | only later entries' class-80 jobs (0–1) |
| **class-96 allocations in the gap** | **0 in every trigger** |
| other sizes in the gap | none |

The 72-byte request is `JS_EnqueueJob(fre->ctx, js_finrec_job, 2, args)`
(`JS_EnqueueJob` at 2740; size `sizeof(JSJobEntry) 40 + argc*16`; argc=2 →
72 → block 80). In the baseline it is enqueued **before** E2 is freed; when
several entries target T, some of the second pass's jobs fall after E2's free
— all are still class 80 and cannot reclaim a class-96 block.

### 4.3 Static audit: the free path does not allocate

`scripts/audit_free_functions.py` scans every function whose name matches
free/release/finalizer/clear/delete/detach/trim/reset (150 functions) for
`js_malloc/js_calloc/js_realloc/js_new/JS_New*/alloca/JS_EnqueueJob`:

```
functions scanned: 150
reset_weak_ref        ['JS_EnqueueJob']     <- fixed argc=2
JS_RegExpDelete       ['js_malloc']         <- a String.replace helper, not a free path
```
All 31 class finalizers allocate nothing; `free_object`, `free_property`,
`js_free_shape`, `JS_FreeAtomStruct`, `JS_FreeContext`, `JS_FreeRuntime`,
`js_map_finalizer`, `js_finrec_finalizer` allocate nothing
(`logs/audit_free_functions.txt`). The only allocation reachable from any
free is the FR job (class 80).

Note for completeness: the engine does have one **class-96** job allocation —
`JS_EnqueueJob(ctx, js_promise_resolve_thenable_job, 3, args)` (40+48 = 88 →
block 96, `quickjs.c:56796`). It is enqueued only by a JS-triggered promise
resolution, never from a free/finalizer path, and no JS runs in the gap, so it
is not reachable there. This closes the "maybe a 3-arg job" question.

### 4.4 Allocator positive control (reclaim works when JS runs)

`poc/fr_reclaim_control.js`: a registry entry is freed *cleanly* when its
target dies (no unregister), then JS allocates `new Uint8Array(88)`
(`logs/reclaim_control.log`):

```
EV 1197 ALLOC ptr=0x7fe7ccfe9bd8 size=88 usable=88   <- FR entry (class 96)
EV 1199 FR_REG fre=0x7fe7ccfe9bd8
EV 1202 FREE ptr=0x7fe7ccfe9bd8 usable=88            <- entry freed cleanly
EV 1205 ALLOC ptr=0x7fe7ccfe9bd8 size=88 usable=88   <- Uint8Array(88) data
```
The allocator does hand a freed class-96 entry to a JS-controlled 88-byte
data block. The negative is about *when* (no allocation slot in the gap),
not *whether* the allocator can reuse the block.

### 4.5 Oracle: the write that would happen (measured, lab-only)

`FR_ORACLE=1` forces one `js_malloc_rt(rt, 88)` inside `js_finrec_free()`
right after the held-value free — the only position where E2 is the class-96
free-list head. It fills the reclaimed block with `link.prev = &sink`,
`link.next = &frd->entries` (so the loop terminates), and copies the real
token `JSValue`. `logs/oracle_uaf_read_traced.log`:

```
EV 11 FREE ptr=…7c38 usable=88            <- E2 freed
EV 15 ALLOC ptr=…7c38 size=88 usable=88   <- oracle alloc, SAME address
EV 19 UNREG visit el=…7c38 el1=…c068      <- stale visit of the fake entry
EV 20 UNREG match fre=…7c38
ORACLE_AFTER_LISTDEL fake=…7c38 sink_addr=(nil) sink_val=0x…c068
                     head_prev=0x…7360 head_next=0x…c068
```
`sink_addr` is the fake `prev` slot (unchanged); `sink_val` is
`*(prev+8)` = `next` = the registry list head, and `head_prev` is
`*(next+0)` = `prev` = `&sink`. So the stale `list_del` is a genuine
**two 8-byte write** primitive (`list.h:73-82`) with attacker-chosen address
and value — *provided* the block is reclaimed with a matching token
`JSValue`.

The oracle then **aborts in `delete_finrec_weakref`** (`get_first_weak_ref`,
fake `target` invalid) — the `list_del` has already happened, but a real
exploit that wants to return to JS must also satisfy this third check.

### 4.6 Why JS cannot turn it into a write (the four conditions)

1. **An allocation slot in the gap.** There is none (census + static audit).
   The only allocation is a class-80 FR job (before the free in the baseline;
   later in the same second pass when several entries target T — still class
   80).
2. **A forged `token` JSValue.** The stale branch requires
   `js_same_value(fre->token, token)` to be true. For an object/symbol token
   that is a **pointer compare** (`js_strict_eq2`, 16784: objects compare
   `JS_VALUE_GET_OBJ(a) == JS_VALUE_GET_OBJ(b)`; symbols compare atom
   pointers). JS cannot read or construct the token's heap pointer/tag; a
   plain string/`BigInt` fake value has the wrong tag. (The natural
   same-token variant only works because E2's *real* token field survives the
   free — it gives the NULL write, not a controlled one, because `link` was
   zeroed by `reset_weak_ref`'s `list_del`.)
3. **Forged `link.prev/next`.** Both must be valid pointers to writable
   memory. JS has no address leak here (the UAF is a native read; the return
   value is a bool) and no pointer construction (no BigInt view over the
   entry — there is no same-view read; contrast v7 P1/P4).
4. **A survivable `delete_finrec_weakref`.** After the `list_del`, the code
   walks `get_first_weak_ref(fake->target)` looking for a
   `JSWeakRefRecord` with `kind == FINREC` and
   `u.fin_rec_entry == fake_entry`, else asserts/crashes. The fake entry
   would have to carry a live target pointer **and** a matching wr record —
   another pair of unforgeable pointers. (Measured: the oracle aborts here.)

The NULL-write variant is the only shape reachable from plain JS, and its
write is exactly `*(u64*)0x8 = 0` — fixed, unmapped on Android and iOS
(`mmap_min_addr`), MTE-irrelevant, and fatal.

## 5. MTE and universality

### 5.1 Tag domain

* Android (2dfeee3e): the arena uses `JS_ARENA_SLABS` — 64 KiB anonymous
  `mmap` slabs (`arena_slab_take`, 1851; `JS_ARENA_SLAB_TAG` is `-1` on
  Linux, i.e. no tag), carved into 4 KiB arenas; blocks are found by raw
  pointer arithmetic. The FR entry and any class-96 reclaim (Uint8Array data)
  are in these slabs, **tag 0 / untagged**.
* iOS (v0.17.0): no `JS_ARENA_SLABS`; 4 KiB arenas come from
  `rt->mf.js_malloc` and are carved the same way; again raw pointers, tag 0.
* The allocator never assigns MTE tags to pointers (`grep` for pointer
  tagging in the allocator: none). So a same-class reclaim would stay in a
  single tag domain on both platforms — same-tag in the v7 sense.

### 5.2 MTE-safe? The question is moot for FR

The observed fault is at **address 0x8**, before any tag check: MTE/MIE does
not change a NULL-derived read/write. The bug is therefore "MTE-safe" only in
the trivial sense that the crash is tag-independent; it has no write primitive
to protect. If a class-96 reclaim + leak existed, the write targets could be
chosen inside the arena (tag 0) and the write would be same-tag — but that
hypothetical requires the leak FR does not provide.

### 5.3 Universality of the bug (DoS)

* Source: identical `js_finrec_unregister` in 2dfeee3e, fork `origin/master`
  `1a402cb`, `src_latest`, and quickjs-ng `v0.17.0` (iOS engine).
* Binaries: `FinalizationRegistry` atom strings present in both shipped
  Android libs (`apks/…72889.apk` → `lib/arm64-v8a/libtmessages.49.so`, and
  `…/updates/72929/lib/libtmessages.49.so`), 2 occurrences each.
* Reachability: `JS_NewContext` adds `JS_AddIntrinsicWeakRef` unconditionally
  (quickjs.c:3146-3162); nothing in the sandbox sources removes the global
  (no `FinalizationRegistry`/`WeakRef` reference in the tree; the prior
  campaign already reproduced FR behaviour on the shipped engine).
* No per-build/per-device constants: the trigger is plain standard JS, no
  addresses, no sizes, no allocator tuning, no OOM.

**Payload** (`poc/fr_min_*.js`, measured):

| trigger | JS raw | JS zlib9 | with `<div id=v>OK</div><script>…</script>` raw / zlib9 |
|---|---|---|---|
| read variant | 122 B | 101 B | 159 B / 131 B |
| same-token (NULL write) | 124 B | 100 B | 161 B / 130 B |

This is the smallest measured deterministic native crash in the inventory (v7
= 3,056 B zlib9; MB-02 earlier estimate ~160 B zlib9 included the wrapper).

### 5.4 Comparison with the v7 pattern

| v7 property | FR |
|---|---|
| P1 same-view/same-allocation slot (read + write) | **no** — no view over the entry, no leak |
| P2 reclaim in the same arena class | **class exists** (Uint8Array(81..88) → class 96) but **no allocation in the gap** |
| P3 fake objects in the arena | would need forged pointers; none available |
| P4 tag-preserving 64-bit pointer values via BigInt | **no** — no pointer values in JS |
| P5 no cross-allocation OOB | n/a |
| trigger gate | none: non-OOM, 122 B, universal |
| result | fixed NULL read/write at 0x8 → DoS |

## 6. What would change the verdict

The negative is structural, but falsifiable. FR would become a candidate only
if **all** of the following appeared:

1. a JS-reachable allocation in the free→stale-read gap (e.g. a finalizer that
   allocates, or a 3-arg job enqueued from a free path — the thenable job is
   exactly class 96 but JS-triggered only);
2. a heap-address leak of the token object (to forge the 16-byte token
   `JSValue`);
3. a second leaked address (or a same-block-relative trick) for
   `link.prev/next`;
4. a live target with a matching `JSWeakRefRecord` for
   `delete_finrec_weakref`, or a way to make the write useful before the
   process dies.

With (2)+(3) alone the `list_del` is a 2×8-byte write; the oracle in §4.5 is
the measurement of that shape. None of (1)-(4) is available from the FR bug
itself.

## 7. Relation to the other candidates

* **N1**: same-tag and v7-like, host RCE 5/5, but gated on a refused
  `js_realloc` (OOM, fatal on the widget). FR has no OOM gate — it is
  *easier to trigger* but has no write primitive. It does not replace N1.
* **c2560s / parser 0day**: cross-tag (MTE-off). FR is same-tag but DoS-only;
  it does not replace the parser 0day either.
* **v7 (#1827)**: MTE-on proven n-day; FR lacks every read/write ingredient
  of that pattern.
* Only the NULL-address crash is shared with the V1 shape (`list_del` with
  zeroed links): a fixed address-8 access, not exploitable.

## 8. Files / repro

```
notes/rce_candidate_fr_20261108.md            this note
notes/LEMMALOG_FACTS_fr_20261108.txt          facts for the orchestrator
lab/rce_candidates/fr/README.md               layout + repro
lab/rce_candidates/fr/build.sh                fork builds (rel/dbg/asan/trace/oracle)
lab/rce_candidates/fr/build_v0170.sh          iOS-era v0.17.0 builds
lab/rce_candidates/fr/poc/*.js                triggers (incl. 122 B minimal)
lab/rce_candidates/fr/poc/gap/*.js            36-trigger census
lab/rce_candidates/fr/logs/                   ASan, gdb, trace, census, oracle logs
lab/rce_candidates/fr/scripts/                harness, instrumentation, analysis
```

Key logs: `logs/gdb_rel_read.txt`, `logs/gdb_rel_nullwrite.txt`,
`logs/fr_uaf_read_asan.log`, `logs/trace_baseline_read.log`,
`logs/gap/*.log` + `logs/gap_summary.txt`, `logs/reclaim_control.log`,
`logs/oracle_uaf_read_traced.log`, `logs/gdb_oracle_abort.txt`,
`logs/v0170_uaf_read_asan.log`.

## 9. Limits (honest)

* All measurements are x86-64 host builds of the two engines; the device
  engines are AArch64. The FR code path and the arena size classes are
  architecture-independent (page size only changes `slots_per_page`).
* No device/Frida/bot/network was used. The FR trigger is destructive
  (native crash in the widget thread) and must not be sent to a phone.
* The oracle is a synthetic lab allocation; it proves the *shape* of the
  would-be write, not a reachable exploit.
* The census is finite (36 triggers); the static audit (150 free-path
  functions, 31 finalizers) is what generalizes it: no free path allocates
  except the fixed 2-arg FR job.
