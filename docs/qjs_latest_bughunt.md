# quickjs-ng latest bug hunt — 2026-11-02

Target: quickjs-ng `d7215b0ad3fc2c562e8317fd9bca058fd4863804`
(tag `v0.18.0`, 2026-11-01; newest commit on `origin/master` when fetched on
2026-11-02). App comparison: `7a23d8e` (2026-10-23), the snapshot linked by
Telegram Android 13.2.0 beta (72789) per `qjs_binary_checks.md`.
Host-only: no phone/emulator, no VMs.

## Result

**New: N1 — parser continues after a failed `push_scope()`, causing an OOB
write/read in the scope array.** It is not #1865, #1827 or q1570, and it is
not filed upstream (GitHub search for `push_scope`, `add_scope_var`,
`pop_scope`, `has_with_scope`: 0 issues/PRs on 2026-11-02).

- `push_scope()` returns -1 when `js_realloc(fd->scopes)` fails, but the
  eval body-scope push (`__JS_EvalInternal`) and the catch variable/block
  pushes in `js_parse_statement_or_decl` ignore it. `fd->scope_level` stays
  -1 (or is walked to -1 by the paired `pop_scope`), and parsing continues.
- Next `try{}catch(e){}`:
  - `add_scope_var()` executes `fd->scopes[-1].first = idx` — ASan
    heap-buffer-overflow **WRITE of size 4** (quickjs.c:24480).
  - `emit_u16(s, scope_level)` stores 0xffff; `get_lvalue()` later calls
    `has_with_scope(fd, 65535)` — ASan SEGV / OOB **READ**
    (quickjs.c:26207).
  - `pop_scope()` reads `fd->scopes[-1].parent` (quickjs.c:24433);
    `js_parse_for_in_of` has a sibling OOB read (quickjs.c:29281).
- Plain-JS reproducers under the 6 MiB app model (no host APIs):
  - `lab/qjs_latest_fuzz/pocs/parser_scope_oob_write.js` — WRITE in
    `add_scope_var`; `'x'.repeat(6152560)` then `eval()` of 100
    `try{a0=1}catch(e){}` lines.
  - `lab/qjs_latest_fuzz/pocs/parser_scope_oob.js` — SEGV in
    `has_with_scope`; 15 lines, filler `6177168`.
  Both 5/5 on `d7215b0` and 5/5 on the app commit `7a23d8e`
  (`build/run_src_app`). GDB confirms `fd->scope_level = -1` and
  `scope_level = 65535`.
- Under **Scudo** (Android's allocator; host `-fsanitize=scudo`), both
  reproducers SIGSEGV 6/6 without ASan (`pop_scope` faults at
  `fd->scopes[scope].parent`), so the target-platform impact is a reliable
  interpreter crash (DoS). The ASan write is a memory-corruption primitive;
  no RCE is claimed.
- Fix verification: adding the three `push_scope` checks in
  `pocs/fix_push_scope.diff` turns both reproducers into a clean
  `InternalError: out of memory` (no crash). Patching only the body-scope
  push is not enough; the catch/block pushes must be checked too.

**Known upstream, verified but not claimed as new:**
- #1792 `Array.prototype.find` double free when the loop-top interrupt check
  fires (`harness/find_repro.c`, api-test from PR #1807; UBSan `list_del`
  null). Open, unmerged, present in `d7215b0` and `7a23d8e`. The existing
  lemmalog memory already records this as `finding_W9`; re-verified only, not
  claimed as new.
- #1782 truncated parser bytecode OOB read in `resolve_variables()` /
  `get_u32` (quickjs.c:35305), reproduced with eval OOM filler. Open,
  unmerged; listed only as deduped.
- Previous F1 WeakMap-symbol leak (`assert(list_empty(&rt->gc_obj_list))` at
  teardown): leak/debug assertion, not memory corruption.

## Fuzzing performed (host, capped)

One fuzzer at a time, `-workers=2`, `-rss_limit_mb=1500`, `-timeout=10`,
`nice -n 19`. Source eval: ~1.25 M execs, no sanitizer crash. OOM-path
replay/fuzzing (`QJS_FUZZ_HEAP_LIMIT` 128 KiB–2 MiB) found 108 parser-OOM
crashes, all deduped to N1 (4 top frames) or #1782. Structured API at 512 KiB
and bytecode loader were short slices (loader stopped by a 1.87 GB
`JS_ReadString` allocation from malformed bytecode; bytecode is out of scope
per SECURITY.md and not JS-reachable). GC-stress and regexp slices are
recorded in the lab report.

## Weaponization attempt (negative)

N1 is not an RCE primitive in the current analysis:

- The write is a fixed 4-byte store at `(char*)fd->scopes - 16` with value
  `fd->var_count - 1` (0…65534). It cannot target an arbitrary address.
- For large `scopes` allocations the store lands in ASan redzone / glibc
  chunk padding / Scudo chunk header, not in a live JS object field. The
  Scudo checksum/class corruption is a reliable abort, not a controlled free.
- For small arena allocations the store lands at the tail of the preceding
  arena block; observed predecessors were padding/free data/`JSString` data,
  not a useful field. Destructuring-catch/vars grooming did not align the
  store with `fd->vars` or another object.
- The embedded `def_scope_array` variant is reachable (26-byte filler window):
  `scope_size` becomes `idx`, and the next `push_scope` writes
  `def_scope_array[4]` into `JSFunctionDef` (`body_scope=-1`,
  `global_var_count=scope_first`, `global_vars` low word `0xffffffff`), then
  `[5]` makes `global_vars` high word `-1` and `byte_code.buf` low word
  `scope_first` with high word 0. It always dies in `js_free_function_def` /
  `free_bytecode_atoms`; no later write restores a valid pointer. No
  read/write/call primitive was obtained.

Fresh campaigns after this result: GC-stress weak fuzzing was too slow
(forced GC per allocation, ~10 exec/s) and produced no crash; normal weak
fuzzing was extended with finalizer re-registration/allocation callbacks
(~43 k execs) and produced no crash; symbol/WeakMap/FinalizationRegistry
cross-graph hand tests, iterator-helper/zip adversarial tests, and RAB/typed
array/BigInt review found no new controllable memory bug. **No novel RCE was
found this round; N1 remains the novel bug and is DoS/allocator-corruption
only.**

## Artifacts

`telegramandroidwidget/lab/qjs_latest_fuzz/` — full report, harnesses,
reproducers, filler-sweep/replay scripts, ASan/GDB/Scudo logs.
