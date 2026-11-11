# quickjs-ng security advisories: fix verification and adjacent variants

Targets: the Telegram widget JS snapshot **7a23d8e** (quickjs-ng master,
2026-10-23, v0.17.0-era) and **latest e22ce4d** ("Clear Array.find value
ownership after release (#1826)"). Pre-fix baseline: **a07a918** (the commit
named by 8 of the 10 advisories; master before the 0.16.0 fix batch).
v0.15.1 / v0.14.0 / v0.13.0 were also built to place each fix in a release
line; they were only needed as baselines for the advisories that predate
0.16.0 (m53g, r6vf) and were removed from the lab after use.

Lab: `lab/qjs_advisories/`. Date: 2026-11-05. Local only, no device, no bot.

---

## 1. Verdict

All ten advisories are patched in the 0.16.0 release line and present as
fixed on 7a23d8e and e22ce4d; of the eight reachable on 64-bit, the original
PoCs no longer crash (the two 32-bit integer-overflow advisories are out of
scope for arm64/x86_64).  **Two new, JS-reachable out-of-bounds reads were
found in the
RegExp compiler's OOM paths; both are incomplete-fix variants of
GHSA-rxpx-wj25-jhqq (the OOM class fixed by c2f37ec).**  They read 2 bytes and
1 byte past a DynBuf allocation during a compile that is already failing; the
compile cannot produce a usable RegExp afterwards, so the impact is an ASan
crash (and a latent logical OOB in production), not a leak or a write.
Everything else tested (array copy constructors, set_array_length, external
ArrayBuffer transfer, ropes, Error/Promise/async OOM) was clean, including
under GC-stress.

No duplicate upstream report was found for either new sighting (GitHub issue
search 2026-11-05). The known parser OOB (#1782 / `resolve_variables`) is
re-observed and explicitly deduped; it is a different buffer and different
code path.

---

## 2. Advisory map and PoC verification

Fix commits were located in the local full clone of `quickjs-ng/quickjs` by
grepping the v0.15.1..v0.16.0 history and the v0.14.0 tag.

| GHSA | what | fix commit | version | pre-fix / regression evidence | 7a23d8e | e22ce4d |
|---|---|---|---|---|---|---|
| GHSA-m53g-qx47-3h38 | dense-array copy ctor GC/RCE (`with`/`toReversed`/`toSpliced`/`toSorted`) | `64e64eb` | 0.15.0 | no attachment; fix regression test + 883 variants¹ | clean | clean |
| GHSA-r6vf-p8wr-4vg9 | `set_array_length` shrink/grow + push UAF | `da49a37` (0.14.0), `d98ff10` (0.16.0) | 0.14.0/0.16.0 | inline PoC + fix tests + 224 variants² | clean | clean |
| GHSA-rxpx-wj25-jhqq | RegExp alternation OOM OOB write (`re_parse_disjunction`) | `c2f37ec` | 0.16.0 | **OOB write `put_u32` @111616b** | clean | clean |
| GHSA-v647-xff9-jxf7 | Error stack CallSite insertion OOM UAF | `c846cb1` | 0.16.0 | **UAF `JS_FreeValueRT` @108512b** | clean³ | clean³ |
| GHSA-crgj-9jv8-xfhq | Promise resolving-functions OOM UAF | `776d724` | 0.16.0 | **UAF `gc_decref_child` @106496b** | clean³ | clean³ |
| GHSA-3jf7-4qfx-xc2h | JSON rope indentation heap leak | `35e195c` | 0.16.0 | fix diff + 539 differential cases⁴ | clean | clean |
| GHSA-52gx-967m-hxp3 | external ArrayBuffer transfer UAF | `6a2c5f3` (realloc_func API) + `4369dd6` | 0.16.0 | fix diff + C embedder free accounting⁵ | clean | clean |
| GHSA-wm7w-r6qf-3c9w | Atomics.store BigInt ref leak on detach | `62951e1` | 0.16.0 | fix diff + code audit⁶ | fixed | fixed |
| GHSA-9wv5-5cgr-grj6 | 32-bit TypedArray sort index overflow | `e93cca6` | 0.16.0 | out of scope (arm64/x86_64) | — | — |
| GHSA-jp52-chwg-2p9p | 32-bit Proxy ownKeys overflow | `252209d` | 0.16.0 | out of scope (arm64/x86_64) | — | — |

¹ `tests/test_array_to_gc.js` passes, plus 883 array-copy/mutation variants
(§5.1).
² `tests/bug1562.js`, `tests/fix_set_array_length-uaf.js`, `tests/bug1430.js`
pass; 224 shrink/grow variants (§5.2).
³ Advisories' own PoCs were swept over 60 000–200 000 bytes in 32-byte steps
(4376 limits each) on both snapshots: CallSite 0 hits, RegExp 0 hits. The
Promise PoC produced exactly one hit each, and its stack is
`resolve_variables` / `js_create_function` — the known #1782 parser
truncated-bytecode OOB, not the Promise UAF (deduped in
`notes/audit_parser.md` §2). Any other limit in the range is clean.
⁴ 539 differential rope-consumer cases × 7 rope shapes (§5.4).
⁵ C embedder tests with counted `realloc_func` frees (§5.3).
⁶ Code audit: the fixed `js_atomics_store` frees its converted value on both
detach/shrink paths; `js_atomics_op`, `wait`, `notify` hold no converted
JSValue, so the same leak does not exist there.

Evidence: `logs/verify/prefix_a07a_*.txt` (pre-fix crashes),
`logs/verify/fixed_7a_*.txt`, `logs/verify/fixed_latest_*.txt`,
`logs/fixed_sweep.txt` (limit sweeps).

Reproduction caveat: the OOM windows are byte-precise and the executable
path length shifts the initial heap, so the same `--memory-limit` can move in
or out of a window between `./qjs` and `qjs`. The sweep runner passes the
binary path as given; all reported limits are for the invocation shown.

---

## 3. New finding F1 — OOB read in `re_need_check_adv_and_capture_init`

**Class:** incomplete fix of GHSA-rxpx-wj25-jhqq.  The advisory fixed the
4-byte branch-offset *write* after a failed `dbuf` grow; the same "truncated
bytecode, then scan it" pattern exists one function away.

**Sink.** `libregexp.c:1617` (7a23d8e and e22ce4d):

```c
case REOP_range:
case REOP_range_i:
    val = get_u16(bc_buf + pos + 1);   /* no pos+3 <= bc_buf_len check */
```

called from `re_parse_term()` at the quantifier (`libregexp.c:2315` / 7a
equivalent) with `bc_buf = s->byte_code.buf + last_atom_start` and
`bc_buf_len = s->byte_code.size - last_atom_start`.

**Trigger.** A class range (`[a-z]`) is emitted with `re_emit_op_u16`; when
the following `dbuf_put_u16` growth fails, the opcode byte is present but its
operand was never written. The quantifier path (`{2,4}`) then scans the atom
and reads the operand out of bounds. `dbuf_error()` is only checked at the
*top* of `re_parse_term`, not before this in-term scan.

Minimal pattern: `new RegExp("[a-z]{2,4}?", "gy")` (flags only control the
early bytecode shape; the array-index PoC uses `0x21` = global|sticky).

**Evidence.**

* Allocation-countdown harness (`variants/lre_oomfuzz.c`, fixed patterns and
  random grammar): crash at `[a-z]{2,4}?`, flags `0x21`, allocation #7:
  `logs/lre_oomfuzz_latest.txt`, `logs/needcheck/lre_min_7a.txt` —
  `SUMMARY: heap-buffer-overflow ... cutils.h:328 in get_u16`,
  `#1 re_need_check_adv_and_capture_init libregexp.c:1617`.
* Real runtime, headroom sweep (`variants/re_headroom.c`): both 7a23d8e and
  e22ce4d crash at `DEATH_HEADROOM=37` (window 37..43):
  `logs/needcheck/headroom_7a.txt`, `headroom_latest.txt`.
* Pure-JS 6 MiB PoC (`poc/regexp_needcheck_appmodel.js`): fill the heap with
  `{}` until the F2 catchable OOM, release four filler objects, then sweep
  the remaining headroom **one byte at a time** by allocating a flat string
  whose length grows by one per iteration (ASan reports the requested size as
  usable, so each length step changes the limit headroom by one byte) and
  retrying the compile.  Result: 3/3 ASan crashes on the app model
  (`appmodel_7a_asan`, 6 MiB, 500 ms) **and** on the qjs CLI at
  `--memory-limit 6m`, for both 7a23d8e and e22ce4d:
  `logs/needcheck/final/f1_*.txt`.

The 6 MiB trigger is heap-shaping sensitive: the fill leaves the headroom in
a fixed residue class modulo the filler object size, so a PoC that frees a
single object or sweeps ArrayBuffer sizes in 8-byte steps can skip the
7-byte window depending on the baseline (the executable path length alone
shifts it).  The string-length sweep removes that sensitivity; the earlier
single-free variant was only reliable for one filename.

**Impact.** READ of 2 bytes (the u16 range count) past the bytecode DynBuf;
the value only feeds `need_check_adv` / `need_capture_init` booleans, and the
compile aborts later because `dbuf_error()` is set, so no bytecode is
returned or executed. ASan-only crash; on a release build the read stays
inside the allocator's block/arena. No leak to JS, no write.

**Suggested fix.** Either check `dbuf_error(&s->byte_code)` before calling
`re_need_check_adv_and_capture_init()`, or bound every operand read:

```c
if (pos + reopcode_info[opcode].size > bc_buf_len)
    break;
```

(`reopcode_info[opcode].size` is the opcode+operand size; the range case
additionally needs the variable-length part.)

---

## 4. New finding F2 — OOB read in `is_duplicate_group_name`

**Class:** same incomplete-fix family, second buffer.  `group_names` is a
DynBuf built in parallel with the bytecode; the advisory fix never looked at
it.

**Sink.** `libregexp.c:1843`:

```c
while (p < buf_end) {
    len = strlen(p);
    if (len == name_len && memcmp(name, p, name_len) == 0) {
        scope1 = (uint8_t)p[len + 1];   /* len+1 may be buf_end */
```

**Trigger.** For a named capture, `re_parse_term` appends `name\0` and then
the scope byte with two separate `dbuf` calls (lines 2040-2047).  If the name
append succeeds and the scope append fails (one-byte growth at zero
headroom), the buffer ends after the NUL.  The next named group's duplicate
check walks the incomplete entry, computes `strlen` on the name (in bounds)
and reads `p[len+1]` one byte past the allocation.  The parser must have
enough spare bytecode capacity to reach the second group, otherwise the
top-of-`re_parse_term` `dbuf_error()` check aborts first.

Minimal pattern after padding the bytecode buffer: `xxx(?<n>a)(?<n>b)`.
The padding is what leaves the bytecode buffer with spare capacity when the
group-name buffer fails.

**Evidence.**

* `variants/lre_oomfuzz.c` (patched for F1 so F2 is visible):
  `DEATH_CASE pattern=(?<n>a){0,3}...(?<n>a)... flags=0x16 countdown=8` →
  `SUMMARY: heap-buffer-overflow libregexp.c:1846 in is_duplicate_group_name`.
* Minimal allocation-countdown repro: `variants/lre_min.c` with
  `(?<n>a)(?<n>b)` flags 0, countdown 8 → same summary.
* Real runtime headroom sweep (`variants/pattern_sweep.c`):
  `xxx(?<n>a)(?<n>b)` → `DEATH_HEADROOM=51` on both 7a23d8e and e22ce4d
  (window 51..~59).
* Pure-JS 6 MiB PoC (`poc/regexp_dupgroup_fill.js`, same fill / four frees /
  one-byte string-length headroom sweep as F1, with the padded pattern):
  3/3 ASan crashes on `appmodel_7a_asan` 6 MiB **and** on the qjs CLI at
  `--memory-limit 6m`, on both 7a23d8e and e22ce4d:
  `logs/needcheck/final/f2_*.txt`.

**Impact.** READ of 1 byte (the missing scope byte) past a 2-byte
`group_names` allocation.  If the read value differs from the current scope,
the duplicate check returns false; the rest of the group-name appends fail
(the DynBuf error flag is sticky), the compile either fails at the trailer
append or, if that fits in bytecode spare, `js_regexp_constructor_internal`
still fails to allocate the RegExp object at zero headroom.  In every path
tested the constructor throws, so the malformed trailer never reaches
`exec`.  ASan-only; release arena keeps the read inside the block.
No leak/write found.

**Suggested fix.** Bound the record walk and check the buffer state:

```c
if (p + len + LRE_GROUP_NAME_TRAILER_LEN > buf_end)
    break;                       /* incomplete trailing record */
```

and refuse to continue parsing a named group when
`dbuf_error(&s->group_names)` is set (or, at minimum, do not run the
duplicate check on an incomplete buffer).

**Dedup.** GitHub issue/PR search for `re_need_check_adv`,
`is_duplicate_group_name`, "regexp OOM", "truncated bytecode" returns no
matching report.  #1354 is an input-buffer OOB in `re_parse_char_class`;
#1375 is exec-time deserialized-bytecode validation.  #1782 is the JS
*parser* (`js_create_function`), same shape but different buffer and code.

---

## 5. Negative results (tested, no finding)

All of these ran on both 7a23d8e and e22ce4d, in plain ASan and in an ASan +
`QJS_ENABLE_GC_STRESS` build for the JS suites; the C embedder and the
headroom sweeps are ASan-only (noted below).  Files under
`lab/qjs_advisories/variants/`, logs under `logs/`.

### 5.1 Dense-array copy constructors (GHSA-m53g class)

`variants/array_gc.js` (834 cases), `variants/array_gc2.js` (49 cases):

* `with`/`toReversed`/`toSorted`/`toSpliced`/`slice`/`concat`/`flat`/
  `flatMap`/`map`/`filter`/`sort`/`reverse`/`splice`/`copyWithin`/`fill` on
  array-likes whose index getters call `gc()` + heap churn at the first,
  middle or last index; lengths 1..1024;
* getters that shrink/grow/delete/mutate the source during the copy;
* `@@species` returning the source itself (aliasing destination/source),
  sparse sources, species constructors that gc;
* `Array.from` (array-like and iterator), `Symbol.isConcatSpreadable`
  getters, Proxy sources;
* TypedArray `toReversed`/`toSorted`/`with`/`slice` on all element types,
  including detach/resize from `valueOf` and comparator, and species
  returning overlapping views;
* JSON on shrunk/grown arrays.

0 ASan reports.  The four fixed sinks now pre-initialise every published
slot (`js_allocate_fast_array`), and all other fast-array writers publish
`count` only after writing the slot.

### 5.2 `set_array_length` / fast-array shrink-grow (GHSA-r6vf class)

`variants/array_len.js` (224 cases): shrink to k, grow back, then
push / push-same-freed-value / unshift / splice / copyWithin / fill / sort /
reverse / pop / shift / delete+push / species toSpliced, plus delete-last +
push loops, length `valueOf` with gc, push-many-after-grow, accessor-index
arrays.  0 ASan reports; upstream regression tests pass.

### 5.3 External ArrayBuffer transfer (GHSA-52gx class)

`variants/ab_external.c` (C embedder, ASan only, counted `realloc_func`/free):
transfer same length, transfer bigger, `transferToFixedLength`,
`transferToImmutable`, resizable external buffers, unmanaged buffers
(`realloc_func == NULL`), detach-then-GC, transfer under a TypedArray,
slice, and 100× transfer/GC stress.  Free counts are exactly 1 per detach
and 100/100 in the stress loop; unmanaged memory is never freed; no double
free.  `JS_DetachArrayBuffer` clears `realloc_func`/`opaque` and the transfer
source neutering clears them too.

### 5.4 Rope consumers (GHSA-3jf7 class)

`variants/rope_consumers.js`: 539 differential cases per build, 7 rope
shapes (plain, nested, empty-left/right, mixed, wide, emoji), comparing rope
vs flat results for 50+ APIs: string methods, regexp match/replace/split,
`JSON.stringify` (value, key, replacer, `space` rope and boxed rope),
`JSON.parse` reviver, `RegExp`/`RegExp.escape`, encode/decode/btoa/atob,
`Date.parse`, `BigInt`, property keys, Map/Set/WeakMap keys, template/eval/
`new Function`.  0 mismatches, 0 ASan.

### 5.5 Error.stack / CallSite and Promise OOM (GHSA-v647 / GHSA-crgj class)

Headroom sweeps with a precompiled victim (`variants/oom_sweep.c`,
`variants/oom_sweep_multi.c`, ASan only), for every headroom 0..3000/768 — every
allocation inside the call is made to fail in turn:

* `Error.prepareStackTrace` returning frames / a custom object / reading
  every CallSite getter; `stackTraceLimit` 64/128; `captureStackTrace`;
  `cause`; `AggregateError`; stack getter/setter; throwing inside
  `prepareStackTrace`;
* Promise constructors, `withResolvers`, `resolve`/`reject` with thenables
  and hostile `then` getters, `all`/`allSettled`/`race`/`any` over reused
  iterables, async functions/generators, `await`, async iterator helpers;
* 500 generated multi-operation victims (`tools/gen_oom_victims.py`,
  two seeds) mixing Error/Promise/JSON/array/Map/Set/Proxy/RegExp/TypedArray
  operations.

0 ASan reports.  The fixed CallSite/Promise bugs are genuinely fixed, and no
adjacent ownership bug was reached.

---

## 6. Impact and disposition

Both new items are **OOB reads in a compile that is already failing**:

* no bytecode is returned/executed after the failure (the `dbuf` error is
  checked before `lre_compile` returns; F2's malformed trailer cannot reach
  `exec` because the RegExp object allocation fails at zero headroom);
* no attacker-controlled data reaches JS (unlike the rope leak, no string is
  built from the read bytes);
* on a production build (arena small blocks, 4 KiB) the 1–2 byte
  over-read stays inside the arena block; they are ASan-visible latent bugs,
  not production crashes.

They are still worth reporting upstream as an incomplete fix of
GHSA-rxpx-wj25-jhqq: the fix covered the bytecode patch sites but not the
two scanners that consume a partially-written buffer.  A single guard at the
start of `re_parse_term` (`dbuf_error(&s->byte_code)`) is not sufficient
because the failure can happen *inside* the same term call; the scanners
need their own bounds checks.

No RCE/UAF/write variant was found in the array, length, transfer, rope or
Error/Promise families in this pass.

---

## 7. Lab layout and repro

```
lab/qjs_advisories/
  src_a07a918/            pre-fix baseline (a07a918)
  src_7a23d8e/            app snapshot
  src_latest/             e22ce4d
  build-asan-*/  build-rel-*/  build-gcs-*  (cmake, QJS_ENABLE_ASAN /
                      QJS_ENABLE_GC_STRESS)
  build/              re_headroom_*, pattern_sweep_*, lre_min_*,
                      lre_oomfuzz_*, ab_external_*, oom_sweep/multi
  poc/                advisory PoCs + the two new 6 MiB triggers
  variants/           array_gc*.js, array_len.js, rope_consumers.js,
                      ab_external.c, lre_oomfuzz.c, lre_min.c,
                      re_headroom.c, pattern_sweep.c, oom_sweep*.c,
                      libregexp_oom_bounds_exploration.patch (debug aid only)
  tools/              sweep.py, gen_oom_victims.py
  logs/               evidence (see paths above); final/ holds the 10
                      F1/F2 ASan logs
```

Key commands:

Run from the project root (`notes/../`).  The fixed-path binaries are under
`lab/qjs_advisories/`.

```sh
Q=lab/qjs_advisories; A="ASAN_OPTIONS=detect_leaks=0:abort_on_error=1"

# fixed-vs-prefix advisory PoCs
env $A $Q/build-asan-a07a/qjs -C --memory-limit 111616b \
  $Q/poc/regexp-disjunction-oom-oob-write-poc.js   # pre-fix OOB write
env $A $Q/build-asan-a07a/qjs -C --memory-limit 108512b \
  $Q/poc/callsite-array-insertion-oom-uaf-poc.js   # pre-fix CallSite UAF
env $A $Q/build-asan-a07a/qjs -m --memory-limit 106496b \
  $Q/poc/promise-resolving-functions-oom-uaf-poc.js  # pre-fix Promise UAF

# F1 and F2 on the app snapshot (app-model 6 MiB, 500 ms)
env $A lab/qjs_regexp_audit/appmodel_7a_asan \
  $Q/poc/regexp_needcheck_appmodel.js 6 120000
env $A lab/qjs_regexp_audit/appmodel_7a_asan \
  $Q/poc/regexp_dupgroup_fill.js 6 120000

# F1 and F2 through the qjs CLI at the app memory limit
env $A $Q/build-asan-7a/qjs -C --memory-limit 6m \
  $Q/poc/regexp_needcheck_appmodel.js
env $A $Q/build-asan-7a/qjs -C --memory-limit 6m \
  $Q/poc/regexp_dupgroup_fill.js
# same two against $Q/build-asan-latest/qjs

# headroom proof (deterministic; prints DEATH_HEADROOM then ASan aborts)
env $A $Q/build/re_headroom_7a \
  $Q/variants/re_needcheck_setup.js 64            # F1, h=37
env $A $Q/build/pattern_sweep_7a \
  'xxx(?<n>a)(?<n>b)' 200 "" 51                   # F2, h=51
```

The `appmodel_*` runners come from `lab/qjs_regexp_audit/` (same 7a23d8e
source, 6 MiB, 500 ms interrupt); the new lab builds its own ASan binaries
with `-DQJS_ENABLE_ASAN=ON` and an extra GC-stress build with
`-DQJS_ENABLE_GC_STRESS=ON`.
