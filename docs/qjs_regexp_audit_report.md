# libregexp (quickjs-ng v0.17.0) — deep memory-safety audit

Target: Telegram Android 13.2.0 beta widget sandbox
(`Android_Beta_13.2.0_(72789).apk`, `lib/arm64-v8a/libtmessages.49.so`),
quickjs-ng v0.17.0 source (`libregexp.c` md5 `40754e12c7f59e9c84f4be41224cf881`),
6 MiB JS heap, 500 ms/script CPU budget, no host APIs, attacker-controlled widget JS.

Excluded / owned by other agents: **PR #1827** (`JS_RegExpDelete` stale bytecode /
`REOP_set_i32` unchecked register index), **#1792**, **#1835/#1844**, **#1570**.

Date: 2026-11-01. Local lab only (x86-64 Linux, ASan/UBSan); no phone, no DB.

---

## 1. Verdict

**No new memory-corruption primitive reachable from ordinary pattern/input was found in
`libregexp.c` v0.17.0.** The compile and execution paths were audited line by line and
fuzzed under ASan/UBSan (≈64 M compile+exec cases, all prefixes of a syntax corpus,
every Unicode property/script name, named-group/backreference boundary cases). The one
new memory-safety defect found in the shipped regexp stack is in `libunicode.c`
(`unicode_script()`), and it is **OOM-gated**:

> **F1 (new, present in the shipped binary): `unicode_script()`'s `fail:` label ends in
> `goto fail;`. For `\p{Script_Extensions=...}`/`\p{scx=...}` it repeatedly frees the same
> two `CharRange` buffers (double free) and never returns; for `\p{Script=...}` it spins
> forever. With the 6 MiB heap filled so that an allocation inside the property build
> fails, this aborts the process (quickjs `js_free_rt` malloc-size underflow, or glibc
> double-free detection) or hangs the JS thread. `lre_compile` never calls
> `lre_check_timeout`, so the 500 ms CPU budget cannot stop the loop.**

This is upstream quickjs-ng issue **#1828**, fixed by PR **#1829** only on 2026-10-18 —
after the app's snapshot. It is a *crash/hang* (availability) bug, not a controlled
memory-corruption primitive: the fail loop never exits, so the duplicated arena free-list
entries it creates cannot be handed back to JS.

The task explicitly de-prioritises OOM-only triggers, so F1 is reported as a fallback
finding. Everything else below is coverage evidence and validator-gap notes.

---

## 2. Why the shipped binary has this code (version pinning)

* `libregexp.c` is byte-identical to the upstream `v0.17.0` tag
  (`git show v0.17.0:libregexp.c | md5sum` = local md5). Upstream has **no**
  `libregexp.c` commit between `v0.17.0` (2026-09-18) and master/0.18.0 (2026-11-01).
* `libunicode.c` differs from master only by commit `081d50c` / PR #1829
  (2026-10-18, the F1 fix), which is absent from v0.17.0.
* Binary confirmation in the shipped `libtmessages.49.so` (IDA, stripped):
  `parse_unicode_property()` is `sub_17A83E4` with `unicode_script()` inlined.
  At **`0x17A8C50`** the fail label is emitted exactly as the pre-fix source:

  ```
  0x17a8c50  CBZ  W21, loc_17A8C50       ; is_ext == 0 -> spin forever
  0x17a8c54  LDP  X0, X8, [X24,#0x10]
  0x17a8c5c  LDR  X1, [X24,#8]
  0x17a8c60  BLR  X8                     ; cr_free(cr1)
  0x17a8c64  MOV  X0, X23
  0x17a8c68  MOV  X1, X25
  0x17a8c70  BLR  X28 ; sub_17A1EE0      ; cr_free(cr2)
  0x17a8c74  B    loc_17A8C50            ; goto fail
  ```

  (IDB comment added at that address; database path in §8.)

The upstream atom-table fingerprint (Map/Set/WeakMap/WeakSet = atoms 190–193, `concat`
atom still present) additionally pins the snapshot before `c359cac` (2026-10-09), i.e.
before the fix.

---

## 3. F1 — `unicode_script()` fail label: double free / uninterruptible spin

**Source (v0.17.0 `libunicode.c:1283-1288`):**

```c
 fail:
    if (is_ext) {
        cr_free(cr1);     /* points == NULL or a live CharRange */
        cr_free(cr2);     /* cr_free does not clear ->points */
    }
    goto fail;            /* <-- loops back into the cleanup */
}
```

`unicode_script()` is reached from `parse_unicode_property()` for
`\p{Script=...}` (`is_ext == 0`) and `\p{Script_Extensions=...}` / `\p{scx=...}`
(`is_ext == 1`). Every `goto fail` in the function is an allocation failure
(`cr_add_interval` / `cr_invert` / `cr_op`), so the loop is entered only when the
runtime allocator refuses a request.

**Behaviour:**

* `is_ext == 0`: the `if` is skipped and `goto fail` is an empty infinite loop.
* `is_ext == 1`:
  * first pass frees `cr1->points` and `cr2->points` (if non-NULL);
  * second pass frees the same pointers again. `cr_free()` (libunicode.c:394) does
    `realloc_func(opaque, points, 0)` and does not null the pointer.
  * On the ASan/desktop build this is a heap-use-after-free/double-free
    (`libunicode.c:1285` → `cr_free` → `lre_realloc`).
  * In the device allocator (quickjs arena, `JS_ARENA_LARGE_BLOCKS_ONLY=0`) the
    freed block is either
    - a small (≤512 B) arena block: the second free re-reads the union
      `block_idx/free_next`; if it is `JS_ARENA_FREE_NIL` the block is treated as a
      malloc block and `js_free()` is called on a pointer into the middle of a 4 KB
      arena; otherwise the block is pushed onto the size-class free list twice, and
      the loop keeps freeing; or
    - a large malloc block: a genuine double `free()`.
  * The next iteration's accounting can underflow: `js_free_rt()` (quickjs.c:2028)
    computes a bogus `free_size` from the re-freed header and calls `abort()` when
    `free_size > malloc_size`.

**Why it is a crash/hang and not a corruption primitive:** the `goto fail` never
returns. There is no point at which the duplicated free-list entry can be
reallocated by JS, and no JS callback can run on that thread while it spins.
`lre_compile()` only calls `lre_check_stack_overflow()` (libregexp.c:2459);
`lre_check_timeout()` is called exclusively from `lre_exec_backtrack()`
(libregexp.c:2802). The 500 ms deadline is cooperative and therefore cannot
interrupt the loop (this is upstream issue #1775, still open).

### 3.1 Reproduction under the app model (6 MiB, real JSRuntime/JSContext)

Pure JS (no host API, no fake bytecode, no GC stress):

```js
// Fill the 6 MiB runtime heap, then compile a Script_Extensions property.
// The exact fill size must be tuned to the build/allocator (see harness).
globalThis.hog = new ArrayBuffer(6184000);       // ~6.18 MB live
new RegExp("\\p{Script_Extensions=Latin}", "u"); // allocation fails inside unicode_script
```

Measured with the exact v0.17.0 engine:

* **ASan app-model** (`appmodel_unicode 6 6184200`), JS path through
  `new RegExp(...)`: `heap-use-after-free` / double-free at
  `libunicode.c:1285` (`cr_free`) called from `unicode_script`
  (`libunicode.c:1285`), reached from `parse_unicode_property`
  (`libregexp.c:930`) ← `get_class_atom` ← `re_parse_term` ← `lre_compile`.
  The re-freed region is 384 bytes (`cr1->points` after a few range insertions).
* **Release app-model, direct `lre_compile` with the same context/limit**
  (`appmodel_lre_rel 6 6190400`, 520 bytes of headroom):
  `js_free_rt: malloc_size underflow: freeing 281474976645096 but only 6289648 tracked`
  → `abort()` (SIGABRT).
* **`\p{scx=Common}`** (more ranges, wider failure window): glibc reports
  `double free or corruption (!prev)` / `corrupted size vs. prev_size while
  consolidating` and aborts.
* The abort window is a band of remaining headroom (roughly **0.4–1.6 KB** for
  `scx=Latin`, wider for larger scripts such as `Common`). Outside it the compile
  either succeeds or fails cleanly earlier (ordinary catchable OOM). The attacker
  controls the fill at byte granularity with two allocations (large
  `ArrayBuffer` + small tuning allocation).
* If the app snapshot includes #1810 (OOM uncatchable, merged 2026-10-08 17:21),
  runtime probing with `try/catch` is blocked, but the fill accounting is
  deterministic per build/device and can be tuned offline or with a single blind
  fill that leaves ~1 KB.

### 3.2 Trigger properties that hit the widest window

`\p{scx=Common}` > `\p{scx=Latin}` > `\p{scx=Han}` (number of `CharRange`
reallocations before the script extension pass). `\p{Script=...}` reaches the
empty spin only when the failing allocation happens during the script scan itself;
at typical headrooms the scan completes and a later allocation fails cleanly.

### 3.3 Status / overlap

* Upstream: issue #1828, PR #1829 ("Fix infinite loop on allocation failure in
  unicode_script()"), merged 2026-10-18, `return -1` instead of `goto fail`.
* Not in the "owned" list (#1827/#1792/#1835/#1570). Not previously reported by
  the earlier Telegram audit (it was filed after that audit started).
* Classification: **OOM-gated DoS**, crash (SIGABRT) or uninterruptible hang.
  Violates the task's "no OOM-only" preference; included because it is the only
  new memory-safety defect in the shipped regexp stack and it is deterministic.

---

## 4. Validator gaps in `lre_exec` that need attacker bytecode (subordinate to #1827)

These are unchecked operands in the serialized-bytecode interpreter. **None is
independently reachable**: the normal compile path always produces bytecode whose
operands satisfy the invariants, and the only attacker-controlled-bytecode path
reported for this target is PR #1827 (stale `re->bytecode` after
`lastIndex.valueOf()` recompiles). They are listed for completeness; a second bug
that needs #1827's fake bytecode adds nothing to #1827's primitive (which already
allows a controlled OOB 8-byte read/write and `pc` control).

| # | Site | Missing check | Effect with fake bytecode |
|---|------|---------------|---------------------------|
| V1 | `REOP_save_reset` (libregexp.c:3097) | `val` (`pc[0]`) is not checked against capture_count/`val2` | `val > val2` makes `2*(val2-val+1)` wrap to ~4 GiB; `stack_realloc` fails → `LRE_RET_MEMORY_ERROR`. No write. |
| V2 | `REOP_range`/`range32` (3289/3330) | `n = get_u16(pc)` not checked for 0 / against bytecode length | `n == 0` → `idx_max = 0xFFFFFFFF`, `get_u16(pc + idx_max*4 + 2)` reads at a wild 32-bit-wrapped address. Crash/OOB read only. |
| V3 | `REOP_back_reference*` (3232) | operand count `n` not checked against remaining bytecode | reads up to 255 operand bytes past the buffer, then executes at `pc+n`; subsumed by arbitrary-bytecode execution. |
| V4 | `lre_get_groupnames` + `js_regexp_exec` name walk (quickjs.c:49844) | trailer length/termination not validated | `strlen()` walks past the fake bytecode buffer; OOB read (potentially a leak) but #1827 already gives arbitrary read. |
| V5 | `REOP_goto`/`split` (3037/3003) | jump targets not validated | arbitrary `pc` inside `lre_exec_backtrack`; already the strongest consequence of fake bytecode. |
| V6 | `lre_exec_backtrack` default (3374) | unknown opcode → `abort()` | crash only. |

`lre_check_bytecode()` (libregexp.c:3435) validates only `RE_HEADER_LEN` and
`bytecode_len ≤ bc_buf_len - 8`; it is used by BJSON deserialization, which the
widget sandbox does not expose (source-only JS).

The unchecked register operands `REOP_set_i32`/`loop`/`set_char_pos`/`check_advance`
(3115–3193) are precisely PR #1827's finding and are not repeated here.

---

## 5. Why the obvious candidates are safe (audit coverage)

### 5.1 Header, counts and sizing

* `capture_count` and `register_count` are u8 header fields, but the compiler
  refuses >255 (`CAPTURE_COUNT_MAX`/`REGISTER_COUNT_MAX`, libregexp.c:71–72, checked
  at 2059 and 2520), so `lre_get_alloc_count()` = `2*cc + rc` ≤ 765 pointers; no
  truncation of the stored header byte for valid patterns.
* `lre_exec()` (3386) zeroes exactly `2*capture_count` entries; quickjs sizes the
  capture array with `lre_get_alloc_count()` in **both** `js_regexp_exec`
  (quickjs.c:49760) and `JS_RegExpDelete` (quickjs.c:49978), so the register area is
  inside the allocation. (The old `capture_count*2` sizing is not in v0.17.0.)
* `lre_exec()` computes `cbuf_end = cbuf + (clen << cbuf_type)`; quickjs passes
  `str->is_wide_char` (0/1) and `str->len` from a live `JSString`, so the end is
  exact. The public API's internal type 2 is never passed by quickjs.
* Stale header/bytecode reads after a JS callback exist only in `JS_RegExpDelete`
  (bytecode pointer taken before `JS_ToLengthFree`), i.e. #1827.

### 5.2 Capture ops

* `REOP_save_start`/`save_end`: `val < capture_count` enforced at runtime
  (3092), `idx = 2*val + 0/1` ≤ `2cc-1`.
* `REOP_save_reset`: `val2 < capture_count` enforced (3103); from valid bytecode
  `val = last_capture_count ≤ val2`, and `CHECK_STACK_SPACE(2*(val2-val+1))` is
  within the backtracking stack.
* Backreferences: `val < capture_count` enforced per index (3248); positions are
  NULL-initialized by `lre_exec`; start/end pairs are read in the correct order.
* Backtracking stack: every push goes through `CHECK_STACK_SPACE`; `stack_realloc`
  grows to `max(1.5x, needed)` and fixes up `sp`/`bp`; `sp >= bp` and even parity
  of the undo pairs hold through split/lookahead/negative-lookahead paths; the
  positive-lookahead compaction rewrites each state's third slot with a valid
  region end before copying (`REOP_lookahead_match`, 2932).
* The `REOP_check_advance`/`loop*` register indices come from
  `compute_register_count()` (2499), which assigns them from a linear push/pop
  model. Every emission site pushes exactly the registers its loop opcode pops
  (1 for `loop`, 2 for `loop_check_adv_split_*`), and the atom's own pairs are
  balanced; the model's `assert(stack_size > 0)` never fired in ≈64 M compiles.
  `register_count` is capped at 255 *before* the byte is stored.

### 5.3 Parser / compiler

* All pattern buffers are consumed as exactly `len+1` NUL-terminated allocations,
  matching `JS_ToCStringLen2`'s output (fast ASCII path returns the `JSString` data
  with its single terminator; slow path always terminates). Reads of `p[1]`,
  `p[2]`, `p[3]` are always guarded by a preceding byte match, so they can reach
  the terminator but not past it. Every prefix of a syntax corpus (single-byte
  and code-point boundaries), embedded-NUL variants, truncated escapes
  (`\x`, `\u`, `\u{`, `\c`, `\k<`, `\p{`, `\q{`), nested `v` classes and
  `(?<`/`(?<=` forms were run under ASan with exact buffers: no OOB.
* `utf8_decode_len()` is only called on the compiler-owned UTF-8/CESU-8 encoding
  of a JS string, which is complete (lone surrogates are encoded as complete
  3-byte CESU-8 sequences), so it never reads a partial sequence at the end.
* `dbuf_insert()` / the backward-direction term rotation use positions
  `start`/`last_atom_start` that are always ≤ `size`, and the rotation's
  `memcpy` source region is preserved by the preceding `memmove` (verified by
  simulation and by the passing lookbehind tests).
* Quantifier insertions are size-checked, patch positions are validated against
  `dbuf_error()` (the c2f37ec OOM fixes are present in v0.17.0), and `{0}`
  truncation only removes the current atom.
* Group names: `re_parse_group_name()` bounds `q + UTF8_CHAR_LEN_MAX + 1` against
  the 128-byte buffer; the 255-scope cap (#1591) is present; the name/backref
  trailer walk (`find_group_name`, `is_duplicate_group_name`) is NUL-terminated
  per entry. Tested with 1–200-char ASCII/2/3/4-byte names, `\u`/surrogate-pair
  escapes, 300-alternative scopes and 300 duplicate backrefs: no OOB.
* Unicode properties: every name in the generated tables (`libunicode-table.h`:
  gc, script, binary property, sequence property; 535 names × 13 pattern forms ×
  4 flag sets) compiled and executed under ASan: no crash. The case-folding table
  used by `cr_regexp_canonicalize` is sorted and non-overlapping (checked
  programmatically: 378 entries, no overlap), so the forward table scan cannot
  run past it for any `cr_inter` point.

### 5.4 `v` flag / class set operations

`\q{}` string lists, nested classes, `&&`/`--`, negation, case folding and empty
strings (`[\q{}]`) were exercised directly and via the fuzzer; `CharRange`
operations (`cr_op`, `cr_invert`, `cr_realloc`, `cr_sort_and_remove_overlap`) keep
`len` even and in-bounds, and `UINT32_MAX` sentinels are only used as range ends.
The only defect found on this path is F1 (allocation-failure cleanup).

### 5.5 quickjs glue

`js_compile_regexp` (49258), `RegExp.prototype.compile` (49425), `exec` (49714),
`source`/`flags`, `Symbol.match/matchAll/replace/search/split` and
`js_regexp_get_source` were reviewed for borrowed pointers across JS callbacks.
Only `JS_RegExpDelete` snapshots the bytecode too early (#1827); the exec path
takes `lastIndex` first and then snapshots. Slices/ropes/INDIRECT strings are
linearized or resolved to a live parent before use. A JS-API fuzz (4 000
iterations × 8 seeds of compile/exec/test/replace/split/matchAll/compile with
random flags `d g i m s u v y`, astral/lone-surrogate inputs, 6 MiB + 500 ms)
produced no ASan report.

---

## 6. Reproduction and tooling

All artifacts in `/tmp/opencode/qjs_regexp_audit/` (copy in the project lab, §8).

```sh
# clean ASan+UBSan build of v0.17.0
cd /tmp/opencode/qjs017
cmake -B build_regaudit -DCMAKE_BUILD_TYPE=Debug -DQJS_ENABLE_ASAN=ON -DQJS_ENABLE_UBSAN=ON
cmake --build build_regaudit -j

# direct libregexp fuzzer (grammar + mutation + register/lookaround templates)
clang -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all \
  -I /tmp/opencode/qjs017 lre_fuzz.c \
  /tmp/opencode/qjs017/libregexp.c /tmp/opencode/qjs017/libunicode.c -o lre_fuzz
./lre_fuzz 5000000 21        # 8 seeds were run; see §7

# coverage-guided fuzzer (libFuzzer)
clang -g -O1 -fsanitize=fuzzer,address,undefined -I /tmp/opencode/qjs017 \
  lre_target.c /tmp/opencode/qjs017/libregexp.c /tmp/opencode/qjs017/libunicode.c -o lre_fuzzbin
./lre_fuzzbin corpus -max_total_time=420 -max_len=512 -jobs=4 -workers=4

# systematic prefix / embedded-NUL / Unicode-name / named-group harnesses
./lre_prefix          # 8 305 cases (every prefix, 8 flag sets, NUL insertions)
./lre_unicode unicode_names.txt   # 27 820 property cases (535 names × 13 forms × 4)
./lre_names           # 3 948 name/backref boundary cases

# F1: pure-JS app model (6 MiB, 500 ms), ASan
clang -O1 -g -fsanitize=address,undefined -I /tmp/opencode/qjs017 \
  appmodel_unicode.c /tmp/opencode/qjs017/build_regaudit/libqjs.a -lm -lpthread -o appmodel_unicode
./appmodel_unicode 6 6184200      # double free in cr_free/unicode_script

# F1: release app model, direct lre_compile
clang -O2 -I /tmp/opencode/qjs017 appmodel_lre.c \
  /tmp/opencode/qjs017/build_rel/libqjs.a -lm -lpthread -o appmodel_lre_rel
./appmodel_lre_rel 6 6190400      # js_free_rt malloc_size underflow -> abort()
```

Observed (release): `js_free_rt: malloc_size underflow: freeing 281474976645096
but only 6289648 tracked` then SIGABRT. `\p{scx=Common}` gives glibc
`double free or corruption (!prev)`.

---

## 7. Coverage numbers (this audit)

| Harness | Cases | Result |
|---|---|---|
| `lre_fuzz` grammar+mutation+stress, 8 seeds × 5 M | 40 000 000 iterations (≈16 M compiles, ≈16 M execs, ≈5.7 M matches) | no ASan/UBSan hit |
| earlier `lre_fuzz` run, 8 seeds × 3 M | 24 000 000 iterations (≈9.5 M compiles/execs) | no hit |
| libFuzzer, 4 workers × 420 s | ≈1.5 M units (crashed out early on a harness alignment bug; rerun clean) | no hit |
| `lre_prefix` | 8 305 compile+exec cases | no hit |
| `lre_unicode` | 27 820 cases | no hit |
| `lre_names` | 3 948 cases | no hit |
| `prefix_test.js` (ASan qjs) | 7 787 cases | no hit |
| JS-API fuzz (6 MiB/500 ms, ASan) | 12 000 iterations, 8 seeds | no hit |
| line coverage of `libregexp.c` (gcov, one 300 k-iteration run) | — | 91.9 % of 1 915 lines |

Uncovered lines are OOM/error branches, `DUMP_REOP` debug code, and the
bytecode-error checks reachable only with fake bytecode (V1–V6).

---

## 8. Artifacts

* Report: `/tmp/opencode/qjs_regexp_audit/REPORT.md`
* Copy: `<HOME>/ailocal/Telegram/telegramandroidwidget/notes/regexp_new_bugs_audit.md`
* Harnesses/PoCs: `/tmp/opencode/qjs_regexp_audit/` →
  `<HOME>/ailocal/Telegram/telegramandroidwidget/lab/qjs_regexp_audit/`
  * `lre_fuzz.c`, `lre_target.c`, `lre_prefix.c`, `lre_unicode.c`, `lre_names.c`
  * `appmodel_unicode.c` (pure-JS 6 MiB PoC runner), `appmodel_lre.c`,
    `appmodel_lre2.c` (release/allocator variants)
  * `regexp_fuzz.js`, `prefix_test.js`, `unicode_names.txt`
  * `poc_f1828.js`, `widget_poc_f1828.html` (tunable widget payload)
  * `fuzzlog*.txt`, `fuzzbin.log`, `test_builtin.log`
* IDA: `<HOME>/ailocal/Telegram/.opencode/idbs/libtmessages_49_arm64_widget_annotated.i64`
  (comment at `0x17A8C50`, function comment on `sub_17A83E4`).

---

## 9. Limitations / honesty

* No device run. The release reproducer uses glibc + quickjs's arena allocator;
  Android uses Scudo for large blocks. The double free is in quickjs's own arena
  for ≤512 B blocks and reaches `js_free_rt`'s `abort()` on the malloc-size
  accounting; on Scudo the large-block path is a genuine double `free()`, which
  Scudo may report as a crash. Either outcome is a process abort or an
  uninterruptible spin; **no controlled primitive is claimed**.
* F1 is OOM-gated and therefore outside the requested reachability class
  ("plain JS, no OOM-only"). It is included because it is new, deterministic and
  present in the shipped binary; it should not be ranked above #1827.
* "Crash" ≠ "RCE". No new RCE or arbitrary read/write is claimed.
* The `\p{scx=...}` abort window is allocator/build dependent; the PoC takes the
  fill size as a parameter and must be tuned (values measured here are for the
  x86-64 lab build, not the phone).
* The fake-bytecode validator gaps (V1–V6) are reachable only with #1827's
  attacker bytecode and add nothing to that primitive; they are documented, not
  weaponized.
