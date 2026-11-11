# quickjs-ng latest audit vs Telegram 72799 widget engine

Date: 2026-11-02. Host-only; no phone/emulator.
Artifacts: `lab/qjs_latest_audit/` (README, exploitability note, PoCs, logs).

## 1. Commit identification

| | commit | date | version |
|---|---|---|---|
| App 72799 | `7a23d8e3fedb010070ef1a03873c55500c7aa1a9` | 2026-10-23 | 0.17.0 |
| Latest | `d7215b0ad3fc2c562e8317fd9bca058fd4863804` | 2026-11-01 | 0.18.0 tag |

The app binary `/tmp/opencode/tg49_72799.so` carries the exact 888-byte
`qjsc_builtin_array_fromasync` bytecode blob from `7a23d8e` at file offset
`4262734`; the `v0.18.0` blob is 890 bytes and does not match. Its
`js_dynamic_import_job` is the pre-#1860 shape (direct
`JS_LoadModuleInternal`, no dynamic-import token), and its `js_map_finalizer`
is the pre-#1844 single pass (prior binary check). `quickjs.c` is unchanged
between `7a23d8e` and `d4cd8f4` (#1860), so the app engine source is
`7a23d8e`.

Delta `7a23d8e..d7215b0` for `quickjs.c`: 86 insertions, 12 deletions.

| commit | area | relevance |
|---|---|---|
| `25a005b` (#1844) | `js_map_finalizer` | fixes the prior WeakMap-symbol UAF (#1835); latest safer than 72799 |
| `d4cd8f4` (#1860) | async dynamic import | new API; unreachable in a plain widget script without a module loader; absent from 72799 |
| `c1ed194` (#1832) | `Array.fromAsync` builtin bytecode | built-in only; absent from 72799 |

No delta in generators/var_refs, BigInt, typed arrays/ArrayBuffer, string
builders/rope, JSON, regexp, Map/Set, proxies, class fields, destructuring,
async/await, parser/bytecode, or atom tables.

## 2. Diff review

* **Generators/closures/var_refs/GC**: no code change. The known #1865
  truncation is untouched; the #1844 map finalizer change is the only GC
  lifetime change and is a fix.
* **BigInt**: no change. Prior review of limb arithmetic (`js_bigint_new`,
  `divrem`, `shl/shr`, `pow`, `asUintN`) found no new edge case.
* **Typed arrays/ArrayBuffer**: no change. The open upstream #1858/#1859 are
  spec-conversion issues (ToIndex vs ToInt64), not OOB: the allocated length
  always matches the stored length; a wrapped `maxByteLength` is rejected by
  the length comparison.
* **Strings/rope**: no change. Repeated review of `string_buffer_*`,
  `JS_ConcatString*`, rope rebalance and linearization found no new defect.
* **JSON**: no change. The v0.17 fixes for array-index conversion and
  `JSON.stringify` leaks are present.
* **RegExp**: no change. #1827 arena is a known/owned finding and was not
  re-reported.
* **Map/Set**: only the #1844 two-pass finalizer. Inspected: first pass
  unlinks weak refs without touching `s->records`; second pass frees values.
  A value symbol that is also a key can no longer free a record the loop is
  about to visit. The fix looks correct.
* **Proxies/classes/destructuring/parser**: no change in the window; prior
  core audit coverage applies.
* **#1860 async import**: reviewed `js_dynamic_import_job`,
  `js_finish_dynamic_import_job`, `JS_FinishDynamicImport`. Token/reject
  ownership is released on the error paths; the job is only reachable with a
  host dynamic-import callback or module loader, neither exposed by the
  widget sandbox.
* **#1832 fromasync**: builtin bytecode only; no C memory-safety change.

## 3. Confirmed PoCs in latest v0.18.0 (and 72799 where noted)

### #1792 — `Array.prototype.find` UAF (confirmed, affects both)

Minimal payload `lab/qjs_latest_audit/poc/find_df_min.js`:

```js
var a = [ {v:1}, {v:2} ];
a.find(function(x) { arm(); return false; });
```

`js_array_find` frees `val` at the end of each iteration but leaves the
variable live. The next loop-top `js_poll_interrupts()` can take the
`exception:` path, which frees `val` again. With a test-only `arm()` hook and
gdb setting `ctx->interrupt_counter = 1`, the next poll is exactly
`quickjs.c:44067` (loop top); the second free is at `quickjs.c:44101`.

Evidence:

* `logs/1792_poll_stack.txt` — interrupt at `js_array_find:44067`, then
  `gc_decref_child: Assertion 'JS_REF_COUNT(p) > 0' failed` in the Debug
  build.
* `logs/1792_asan_uaf.txt` — ASan `heap-use-after-free`, read in `js_dup`
  via `js_get_fast_array_element`, freed by `js_array_find:44101`.

App/latest: `js_array_find` has no delta between `7a23d8e` and `d7215b0`;
the bug is present in 72799 and in the latest tag. Not fixed by #1844/#1860.
A harness linked against 7a23d8e objects trips the same
`gc_decref_child` assertion (`logs/1792_appera_assert.txt`).

Trigger in the real sandbox: the CPU interrupt is sampled every 10,000
`js_poll_interrupts()` calls. The attacker must align the sample with the
`find` loop-top poll and let the deadline expire in a no-poll native region
after the callback's last poll. `poc/poc_timer.js` + `harness/timer_repro.c`
implement that shape; the exact alignment was not found in the time-box, so
the timer-only claim remains a hypothesis. The test-hook reproducer is
verified.

Exploitability: confirmed UAF of an 80-byte `JSObject`; the array retains a
dangling pointer. A reclaim with controlled data would make `p->shape`
attacker-controlled. No reclaim/address leak/RCE was demonstrated. Certain
impact: native crash/DoS. Potential impact: heap type confusion if the arena
block is recycled with a valid fake shape. No RCE claim.

### #1855 — OOM NULL write in `JS_NewObjectFromShape` (confirmed, both)

Pure JS `poc/poc1855.js` under `qjs --memory-limit 8000`:

```js
class C extends Array {}
var shared = Object.create(C.prototype);
var keep = [];
for (var i = 0; i < 200000; i++) {
    try { keep.push("A".repeat(64)); } catch (e) {}
    try { new C(3); } catch (e) {}
}
```

The shared prototype shape has no hashed `length` shape, so
`add_property()` must clone it; when the clone allocation fails, the
unchecked `pr->u.value = js_int32(0)` writes through NULL.

Evidence: `logs/1855_purejs_ubsan.txt` (UBSan null member access at
`quickjs.c:6198`), `logs/1855_purejs_release_sigsegv.txt` (SIGSEGV at
`JS_NewObjectFromShape+715`, `movq $0,0x8(%rax)` / `movq $0,(%rax)`).

App/latest: function unchanged; present in both. Primitive: fixed zero write
to NULL/NULL+8; no controlled address/value; DoS only.

### #1852 — OOM lazy-property value leak (confirmed, both)

`JS_SetPropertyInternal2` returns `-1` when `JS_AutoInitProperty` fails on an
inherited lazy property, without freeing `val`. Controlled-headroom harness
`harness/oom1852.c` (`o = Object.create(JSON); o.stringify = v`):

`logs/1852_assert.txt`: `JS_FreeRuntime: Assertion
'list_empty(&rt->gc_obj_list)' failed`.

Controls `logs/1852_controls.txt`: ordinary own property and pre-initialized
`JSON.stringify` pass at the same headroom; only the autoinit path leaks.

App/latest: function unchanged; present in both. Impact: one valid value
leaked per OOM event; DoS only if the runtime persists across widget
scripts. No UAF/corruption.

## 4. Audited hot spots with no new finding

* `js_array_find` (found #1792 above; also checked findIndex/findLast/
  findLastIndex sharing the same code).
* `js_array_every/reduce/includes/indexOf` ownership on interrupt: they
  clear `val` after freeing or do not free it on the exception path; no
  equivalent stale free.
* `js_iterator_*` helpers/concat/wrap: buffer ownership, done-value
  handling, `IteratorClose` reentrancy; no new memory defect.
* `js_typed_array_sort`, species creation, detach/resize races; no new
  defect beyond the open spec conversions.
* `js_array_sort/toSorted` OOM/write-back cleanup; no new defect.
* BigInt limb edge cases, `asUintN/asIntN`, shifts/pow; no new defect.
* String buffer/rope arithmetic; `js_string_repeat` double conversion; no new
  defect.
* #1844 finalizer two-pass ordering; correct.
* #1860 dynamic-import token/job ownership; no widget-reachable path.

## 5. Ranked shortlist

| rank | finding | confirmed | app 72799 | latest | impact |
|---|---|---|---|---|---|
| 1 | #1792 find stale-value UAF | yes | yes | yes | DoS certain; type-confusion/RCE hypothesis only |
| 2 | #1855 OOM NULL write | yes | yes | yes | DoS |
| 3 | #1852 OOM autoinit leak | yes | yes | yes | DoS if runtime persists |
| — | #1835/#1844 WeakMap symbol UAF | prior finding | yes | fixed | latest fixes it |

No new latest-only memory-safety bug was found. The latest tag is safer than
the app build on the one changed lifetime path (#1844); #1860 is not
reachable from the widget sandbox.

## 6. Method and limitations

* Source/diff first, then small PoC runs against the existing ASan build.
  No second fuzz campaign; no device runs.
* ASan caveat: v0.18.0 has a small-block arena. Clang does not define
  `__SANITIZE_ADDRESS__` for `-fsanitize=address` here, so an ASan build
  keeps the arena and hides freed blocks. The #1792 ASan log uses a
  one-file `quickjs.c` build with `-D__SANITIZE_ADDRESS__` (large-blocks-only
  path); the app release build uses the arena.
* The #1792 timer-only trigger is a precise scheduling hypothesis, not a
  device-verified repro. The test-hook trigger is deterministic.
* No RCE, arbitrary read/write, or address leak was demonstrated.
