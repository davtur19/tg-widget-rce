# Bug inventory / dedup — 2026-11-05

Point-in-time synthesis of the QuickJS/Telegram widget audit. Purpose: avoid
counting the same root cause twice and separate "new bug" from "new trigger",
"policy/DoS" and "RCE".

## Root causes

| id | root cause | class | novelty | RCE status |
|---|---|---|---|---|
| **N1** | `push_scope()` OOM ignored; fake `JSVarScope.parent`; length corruption; OOB RW; live RegExp bytecode → #1827 pivot | OOB RW/length | **unreported** | **RCE host 5/5**; **device-closed 2026-11-07**: the refused `js_realloc` is fatal (engine stops the widget on any OOM; see §"Status update" below) |
| **C1** | `cpool_add()` failure stored as `parent_cpool_idx=-1`; `fd->cpool[-1]` 16-byte OOB write | OOB write | **unreported**; triggers: function decl (parser), class fields (class audit), default ctor | DoS / heap metadata; no RCE |
| **C2** | `update_var_htab()` uses requested-size mask after failed realloc; OOB read + second-order OOB index; clean catchable OOB write with 0xFF class-288 | OOB read/write | **unreported** | no live target; no RCE |
| **F1** | subclass + failed `lastIndex` define; setter after bytecode snapshot; `lre_get_groupnames` UAF read | UAF read | **unreported** | heap-forward ASCII leak only; no write/RCE |
| **F2** | OOM error object cannot allocate → `JS_NULL`; #1810 uncatchable bypassed | policy | **unreported** | tuning tool; app+bundle verified |
| **T1** | atomised slice strings free without releasing parent | leak/DoS | **unreported** | heap exhaustion; no RCE |
| **T2** | stale `ta->length` after RAB resize in `JS_GetTypedArrayBuffer`/`JS_GetUint8Array` | OOB read | **unreported** | embedder-only; widget bridge passes strings/numbers only |
| **T3** | `Atomics` writes through immutable ArrayBuffer | invariant bypass | **unreported** | no native consumer; JS-only |
| **F-A** | `flatMap` calls inner `return()` after `done:true`, ignores `JS_IteratorClose`; pending uncatchable OOM | policy/DoS | **unreported**, not fixed by #1871 | timer catch/finally skip; no memory |
| **S1** | `get_closure_var()` -1 unchecked in `resolve_scope_var()` | OOB read/DoS | **prior project finding** | compile-time crash; no RCE |
| **V1** | `resize_properties()` `list_del()` before fallible `js_realloc`; OOM error GC resurrects the unlinked shape; fixed zero write at 0x8 | GC/UAF DoS | **unreported** (V8-corpus F1) | fixed NULL access; no RCE |
| **V2** | `js_function_bind()` allocates the bound object before `bf`; on `js_malloc` failure the finalizer reads `u.bound_function == NULL`; fixed NULL read at 0x8 | OOM DoS | **unreported** (V8-corpus F2) | fixed NULL access; no RCE |
| **R1** | `re_need_check_adv_and_capture_init()` 2-byte OOB read past a DynBuf when a class-range emit fails (`[a-z]{2,4}?`, flags gy) | OOB read | **unreported** (advisory variant) | read-only in failing compile; no write/RCE |
| **R2** | `is_duplicate_group_name()` 1-byte OOB read of the missing group-name scope byte (`xxx(?<n>a)(?<n>b)`) | OOB read | **unreported** (advisory variant) | read-only in failing compile; no write/RCE |

## Ledger rows added 2026-11-08 (memory-bug campaign)

Full evidence (triggers, ASan/SIGSEGV logs, payload sizes, tag domains,
reachability) in `notes/memory_bug_log_20261107.md`; artifacts in
`lab/membug_ledger_20261107/`. These rows do not change the 18 rows above.

| id | root cause | class | novelty | status |
|---|---|---|---|---|
| **MB-01** | `js_map_finalizer`: per-record `delete_map_weak_ref` + `JS_FreeValueRT(mr->value)`; a value symbol that is also a later record's key frees that record via `reset_weak_ref` while the `list_for_each_safe` cursor points at it | UAF (read, class-96 arena, tag 0) | **n-day** (`ebd139b`, missing in 2dfeee3e; inventory row #1835) | host repro: ASan UAF `quickjs.c:54778` + release SIGSEGV `delete_map_weak_ref:54450`; no OOM; DoS (no reclaim in the gap); payload 143 B zlib9 but destructive → no device probe |
| **MB-02** | `js_finrec_unregister`: frees entry 1's held value while iterating; the value being another entry's target frees that entry via `reset_weak_ref` | UAF (read, class-96 arena, tag 0) | **unreported** (lab FR bug; registry finalizer has the two-pass fix, unregister does not) | host repro ASan `js_finrec_unregister:64251` + release SIGSEGV; DoS only (§12.3.5 gap analysis); 153 B zlib9; no device probe |
| **MB-03** | `js_array_find`: frees loop-carried `val` each iteration without clearing it; the next iteration's `js_poll_interrupts()` failure jumps to the exception label which frees it again | double free / refcount underflow | **n-day** (`e22ce4d`/`f4dd164`, missing in 2dfeee3e; inventory row #1826) | shipped source lacks `val = JS_UNDEFINED`; interrupt-gated (widget 300 ms quota = fatal path); not a controllable carrier |
| **MB-04** | `JS_ReadRegExp` does not `BC_add_object_ref` the deserialized RegExp | UAF/lifetime (BC reader) | **n-day** (`f4fe478`, missing in 2dfeee3e) | not widget-reachable (`JS_ReadObject` is host-bundle only) → ledger only |

The interrupt-loop audit (all 23 `js_poll_interrupts` sites) found only MB-03:
`indexOf`/`lastIndexOf`/`includes` do not free `val` in their exception labels
(at worst a leak on interrupt); `reduce` and `map/filter/every/some` already
clear it.

Shipped-fork delta: `git log app-snapshot..origin/master` is exactly six
commits — four memory fixes (MB-01, MB-03, MB-04, MB-05) and two non-memory
(`b06baf9` fromAsync conformance, `1a402cb` test). Three of the four memory
fixes are widget-reachable; all three are known n-days. No unfixed fork-only
memory fix exists in that delta.

## Known / deduped

- **#1827** `JS_RegExpDelete` stale bytecode (merged 3d5cb14); app 0.17 still has it; primary loader 3,056.
- **#1826/#1792** Array.find ownership (merged e22ce4d).
- **#1865/#1869** var_ref_count truncation; device-proven #1865 loader 3,486 zlib, proof 5504; #1869 open.
- **#1867/#1873** async-OOM bugs reproduced on app+bundle; no memory primitive.
- **#1874** async-generator reentry wrong value.
- **#1844/#1835** WeakMap symbol UAF fixed in latest.
- **#1828/#1829** unicode_script OOM loop fixed.
- **#1852/#1855** runtime OOM DoS.
- **#1892** refcount overflow; not reachable at 6 MiB.
- **GHSA historical** (`js_array_toReversed` RCE, `set_array_length` UAF, RegExp alternation OOM write, etc.): all fixed in 0.15/0.16; app 0.17 is after; variants are being hunted, not counted as new.

## RCE status

- **Working on device:** #1827 3,056 primary (proofs 5489/5492/5493); #1865 fallback 3,486 zlib (proof 5504, reported bug).
- **Host-only:** N1 full chain 5/5, but **device-closed**: any refused allocation is fatal to the widget engine (`Memory limit exceeded`), so N1 cannot run a second script.
- **No other RCE demonstrated.** T2 bridge route closed (ABI strings/numbers only); C1/C2/F1/T1/T3/F-A are DoS/leak/policy only.

## Status update 2026-11-07 late

- **N1 is not an MTE-on 0day carrier.** Its trigger is a refused
  `js_realloc(scopes, 180)`. The widget engine kills the widget on any refused
  allocation (uncatchable OOM; device: `stopped (2): Memory limit exceeded
  (8 MB)`; canonical tests: `widget-sandbox/tests/attacks.spec.ts`). Device
  matrix in `lab/qjs_fork_audit/zeroday_hunt_parser/device/logs/device_parser_rce/script_matrix/`
  shows siblings and catchable throws continue, but the 6.2 MB OOM stops the
  widget before the next script. See `notes/new_0day_mte_specs_20261107.md` §11.
- **Parser 0day** remains the only RCE-capable 0day; it is **cross-tag**
  (`b->vardefs` in tagged Scudo) and MTE-off. Its only MTE-on lead
  (`sizeof(JSFunctionBytecode) > 64 KiB` into an untagged secondary) is
  unproven (MTE note §7.3).
- **v7/#1827** is MTE-on proven but is an **n-day** (merged upstream), used as
  the same-view pattern reference, not counted as a 0day.
- **Open requirement:** a new **same-tag, non-OOM** 0day (arena-slab UAF/type
  confusion, no allocation-failure or near-cap trigger).

## Active campaigns

- QuickJS advisory fix variants (array copy/GC, set_array_length, RegExp OOM write).
- V8 non-JIT regression corpus.
- State-coverage fuzzing.
- **Same-tag non-OOM hunt**: arena-slab UAF/type confusion (`js_free_shape` zombie shapes, `JSVarRef` detach, `JSArrayBuffer.array_list` finalizer order, class-128/192 slot reuse); no allocation-failure gate. **Result 2026-11-07 late: negative for a write primitive** — see `new_0day_mte_specs_20261107.md` §12; the only new same-tag issues are leaks/DoS (async-frame leak, symbol-FR teardown leak), both shared with upstream quickjs-ng.
- Class fields / sync iterators: negative coverage; F1 deduped to C1.
