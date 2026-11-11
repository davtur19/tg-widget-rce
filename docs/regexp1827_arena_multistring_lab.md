# PR #1827 multi-string scan payload — lab result

Deliverable: `telegramandroidwidget/lab/regexp1827_arena/widget_poc_1827_multistring.html`
(device constants inline; same code as `multistring_device.js`).
Lab twin: `multistring_lab.js` / `widget_lab_multistring.html`
(lab constants only). Device/DB untouched.

## 1. Payload geometry

* `capture_count=4, register_count=1` → `alloc_count=9` → 72 B capture →
  **class 80**.
* Inside `valueOf`, after `re.compile('x','g')` and the 11,623-byte
  `Uint8Array` reclaim:
  `big = new Uint8Array(4096)` (pre-allocated trigger block) → `filler`
  (`FILL=512` plain objects, class-80 defrag) → `strs = []` →
  `tmp = {}` → **8 × 47-char class-80 strings** → `ta = new Uint8Array(80)` →
  `v1 = [1,2,3,4,5]` → `v2 = [0,0,0,0,0]`; then `tmp = null` so the capture
  reuses `tmp`'s block.
* Fake bytecode (97 B inside the 11,623-byte reclaim):
  * `save_start 0; save_end 0`;
  * 8 × `set_i32 pc0 = 10n-8` (`n=1..8`) writes `0x7fffffff` at block `n`+0
    → string `len`;
  * 6 × `set_i32 pc0 = 10b` (`b=9..14`) writes `0x7fffffff` at block `b`+64
    → `u.array.count` candidates (this is required: without a count write the
    `ta[i]` byte window does not exist);
  * `match`.
* After `replace`:
  1. anchor by indexing: `ta[80]=0x41; ta[80]===0x41` (`NO_ANCHOR`
     otherwise);
  2. scan the 8 strings for `.length > 1e6`; the first corrupted string is the
     forward OOB window (`NO_WINDOW` if none);
  3. from the window, scan class-80 blocks at `80k` for flags `0x1a` +
     `class_id 24` (the `Uint8Array` JSObject) and then `class_id 2` (v1/v2);
     leak `JSTypedArray*`, `u.ptr`, shape, prop, values;
  4. t12 chain: fake `INDIRECT` string (arbitrary read) → fake `Uint8Array`
     (arbitrary write) → `rt->mf.js_free=system`, `rt->malloc_state.opaque=cmd`
     → `big = null` frees the pre-allocated 4 KB block → `system(cmd)`.

Device CFG: `js_def_free=0x1739aec`, `free@GOT=0x1960430`,
`system-free=0x26df0`, command
`id > /data/user/0/org.telegram.messenger.beta/cache/rce_proof`, `FILL=512`.

## 2. Lab result (x86-64 glibc release build, `verify_build/lab_regexp_rel`)

Final payload, 5/5 runs (`FILL=512`): **proof file written**, markers
`R1827:HOOKED` → `R1827:AFTER`.

Geometry from the instrumented run (`ms_dbg_512.out`):

```
DBG forged=7 win=0
DBG taK=9 v1k=10 v2k=11 taData=... offV1=88
R1827:HOOKED
R1827:AFTER
```

Interpretation: there is one live hole at block 1, so the strings start at
block 2; `win=0` is the string at block 2, `ta` is block 11 (= winning block
+ 9), `v1/v2` at 12/13, values buffers adjacent (`offV1=88`). The count write
at candidate block 11 hit `ta.u.array.count`; the first 7 of 8 strings got
their length forged (the 8th sits outside the `n=1..8` write range because of
the hole). This matches the bug-hunt agent's observation that consecutive
blocks can be short; the `FILL=512` defrag raises the run to 6–7 consecutive
blocks, and the scan tolerates the hole.

`FILL` sweep (0..1024 step 32): 23/33 proof; 5 `NO_ANCHOR`; 1 `NO_WINDOW`;
4 crash/other. Large `FILL` (1280..4096): 7/8 proof. The failures are slab-phase
dependent (the chain must fit inside one class-80 slab); on a different heap,
retry with a different `FILL` (0/128/256/512/1024/2048).

The post-`AFTER` SIGSEGV in the lab is the **harness**: `main` →
`JS_ComputeMemoryUsage` loops over the v1/v2 `u.array.count` values that the
count candidates set to `0x7fffffff`. The proof file is already written and
`AFTER` is printed before that call. The device runtime does not need to run
that accounting; the command runs at `big = null`.

Device-constant payload on the lab build: stops at `R1827:NO_CTX` (expected,
wrong PIE), performs no writes.

## 3. Device procedure

1. Run `widget_poc_1827_multistring.html` in the widget (one synchronous
   `replace`, 6 MiB).
2. Expect `R1827:HOOKED` then `R1827:AFTER`; check
   `/data/user/0/org.telegram.messenger.beta/cache/rce_proof` (contains `id`).
3. Failure markers and action:
   * `NO_ANCHOR` — no count candidate hit `ta`; change `CFG.FILL` (phase) and
     retry; if persistent, extend `COUNT_BLOCKS` (costs stack slots; keep
     `NSTR + COUNT_BLOCKS.length ≤ 14` to stay under the 32-element static
     executor stack);
   * `NO_WINDOW` — no string got a forged length, or the scan did not find
     `ta`/v1/v2 in the window; change `CFG.FILL`, keep `NSTR=8`;
   * `NO_CTX` — leaks worked but the device `JS_DEF_FREE`/`FREE_GOT`/delta or
     the pointer range check failed;
   * `NO_FAKE` — fake `Uint8Array` not recognized;
   * `EXC_REPLACE` — fake bytecode did not execute (reclaim/header).
4. A process crash after `AFTER` is expected/acceptable: the allocator hook is
   destructive and the command has already run.

## 4. Files

* `lab/regexp1827_arena/widget_poc_1827_multistring.html` — device payload.
* `lab/regexp1827_arena/multistring_device.js`, `multistring_lab.js`,
  `multistring_template.js`, `gen_multistring.py`.
* Evidence: `notes/evidence_regexp1827_arena/ms_dbg_512.out`,
  `ms_final_1.out`, `html_lab.out`, `ms_dev_on_lab.out`.
