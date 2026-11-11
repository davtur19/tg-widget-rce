# PR #1827 cc=4 bisection — files, lab results, marker interpretation

Context: `execprobe_char` returned `EXEC 0` on the device (fake bytecode
execution confirmed); the cc=1/rc=1 in-bounds and OOB sweep all returned with
no hang. The strfill hang is therefore tied to the **cc=4 geometry and/or the
high/multiple `set_i32` indices**. These probes bisect that.

All files use the fast-path trigger (3000-char pattern, `re.compile('x','g')`,
`Uint8Array(11623)` reclaim), `flags=0`, `bytecode_len=0`, cc=4, rc=1,
subject `'a'`, and the rAF marker. Device/DB untouched.

## 1. Marker interpretation

For these `save_start 0; save_end 0; [set_i32...]; match` programs the match is
**empty**, so the replace returns the original `'a'` — length 1.

| marker | meaning |
|---|---|
| **`EXEC 1`** | returned without hanging (the expected result for any probe that executes *or* falls back to the old bytecode; it does **not** distinguish the two) |
| no marker update (div keeps `bisect single ...` / `bisect prefix N`) | **hang** (outer `JS_RegExpDelete` loop did not terminate) |
| `ERR ...` | JS exception (e.g. bytecode error) |
| process death / no widget update at all | native abort/crash |

Fake execution itself is established separately by
`widget_poc_1827_execprobe_char.html` → `EXEC 0`.

## 2. Files

**A. cc=4 single writes** — `widget_poc_1827_bisect_single_pc0_<X>.html`,
`X ∈ {2,10,12,22,72,90,140}`; program
`save_start 0; save_end 0; set_i32 pc0=X 0x7fffffff; match`.

| pc0 | idx = 8+pc0 | target |
|---|---|---|
| 2 | 10 | capture+80 = block 1 + 0 (len) |
| 10 | 18 | capture+144 = block 1 + 64 (count) |
| 12 | 20 | block 2 + 0 (len) |
| 22 | 30 | block 3 + 0 (len) |
| 72 | 80 | block 8 + 0 (len) |
| 90 | 98 | block 9 + 64 (count) |
| 140 | 148 | block 14 + 64 (count) |

**B. strfill prefixes** — `widget_poc_1827_bisect_prefix_<N>.html`,
`N ∈ {2,4,6,8,10,12,14}`; the first N of the exact strfill writes in order:

```
lens:   2, 12, 22, 32, 42, 52, 62, 72      (pc0 = 10*b-8, b=1..8)
counts: 90, 100, 110, 120, 130, 140        (pc0 = 10*cb, cb=9..14)
```

N=2 → lens 2,12; N=4 → +22,32; N=6 → +42,52; N=8 → all lens;
N=10 → +counts 90,100; N=12 → +110,120; N=14 → full 14 writes.

Every HTML has the rAF marker:
`<div id="t">bisect ...</div>` + `requestAnimationFrame(... RESULT ...)`.

## 3. Lab results

`timeout 10 ./verify_build/lab_regexp_rel <probe>_lab.js 6` — **all 14
returned `RESULT=EXEC 1`**, no hang, no abort, no ERR. The lab's class-80
neighbourhood tolerates every single write and every prefix, so the device
layout is still the differentiator (as expected from the cc=1 sweep).

## 4. Device procedure

1. Run the A singles in the listed order. The first file whose marker stops
   updating is the first hanging index. This distinguishes:
   * hang at `pc0=2` → even the first len write into block 1 is fatal;
   * hang at `pc0=10` → the block-1 **+64 count** write is fatal;
   * hang only at high `pc0` (72/90/140) → the fault is the far block or the
     count region.
2. If all A singles return, run B prefixes N=2,4,6,8,10,12,14. The first N
   whose marker stops updating is the smallest cumulative set that hangs;
   N≤8 isolates the len writes, N≥10 adds the count writes.
3. Record `EXEC 1` vs no marker vs `ERR` for each. `EXEC 1` = returned.

The probes intentionally have **no grooming** (no filler/strings/ta/v1/v2), so
they exercise the raw class-80 neighbourhood of the capture; a hang here is a
direct write/corruption effect, not a strfill-phase artifact.
