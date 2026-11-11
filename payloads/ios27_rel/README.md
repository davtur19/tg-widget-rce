# ios27_rel — iPhone 17e / iOS 27.0 parser-0day reliability set

Source of truth: `notes/ios27_reliability_20261108.md`.
Device: iPhone 17e (iPhone18,5), iOS 27.0 24A437, stock Telegram 13.2 (36535).
Bug: quickjs-ng 0.17.0 parser `ARG_SCOPE_END` (unreported; not #1827).

## Files

| file | role | raw | zlib9 | sha256 |
|---|---|---:|---:|---|
| `p0_proven.html` | **RCE-proven bytes** (5725 run) | 8,647 | 3,680 | `bf31f2f66485174d086d520cbbf8f0434eed674c7282c0a87d731d46015248f8` |
| `p1_pad768.html` | pad order 768-first | 8,647 | 3,682 | `a0b17e90940c26895c506b668a2b9a2afd6e8a7938bb36abf1bfbeab711cd8a8` |
| `p2_pad384.html` | pad order 384-first | 8,647 | 3,681 | `746bc0148ee29b84d0a8a38163a99d749a6a192bb183f96792fabc3d12baf221` |
| `p3_n3000.html` | N=3000, proven pad order | 8,647 | 3,684 | `f19604f3515b632906fd72f08867c8d541b0b705efe42c50e8b067e49ec35f1e` |
| `p4_n3000_pad768.html` | N=3000, 768-first | 8,647 | 3,685 | `c94861adca4ce2115ef35a2be784b389114a4ad41096c0f85d72631514fa456d` |
| `srop_v5_min.js` | stage-B/endgame source (S2 = 6,099 chars, inlined) | 6,099 | – | `e36b6dff8e4f4410c406fd6f7c678efb166d2f9e2e3f70c23255d6f2f2e2726e` |
| `gen_ios27_rel.py` | rebuilds p1..p4 and `MANIFEST.json`, asserts the invariants | – | – | – |

## Invariants (asserted by the generator)

```
page raw length       == 8,647 B
stage-A script length == 8,524 chars
S2 length             == 6,099 chars
```

Only length-neutral sweep parameters may change: the `MS` pad list is a
**permutation of the same 15 values** (same literal length) and `N` stays
4-digit (2600→3000). Any code edit changes the compiled top-level function,
shifts the pre-stage-A heap and re-rolls the geometry — that is what killed
the 6s `text/plain` final and the 17e 9.4 KB shapes.

Known cosmetic bug: the stage-A marker prints `N=2600` as a **literal**; p3/p4
execute N=3000. Trust the file name, not the marker field.

## Platform notes

* **No safe detector on iOS 27.** A stage-A forge writes a real
  `ArrayBuffer.byteLength = 327744` and corrupts a QJS arena block header; if
  the endgame does not reach `pthread_exit`, the app aborts at widget teardown
  (`js_free_rt: malloc_size underflow`). Use the final and retry.
* Marker channel: fast burst 8–12 screenshots at 0.25–0.3 s from ~0.6 s, OCR
  for `RESULT SS2` / `HIT=` / `S:`; launch the app with `--console` and treat a
  `js_free_rt:` line as forge-positive.
* Device order (decision tree in the note §4): `p0` → `p1` → `p3` → `p2` →
  `p4`, max 8 attempts; on a forge followed by an endgame guard, **stop
  switching variants** (that is an endgame defect, not geometry).

## Host validation

qjs-ng 0.17.0, 8 MiB model (`app_multi.c`): all five variants forge 3/3 at the
first pad round with `HIT=545 LEN=327744`; 20/20 identical for p0. The host
cannot validate the Apple tiny-region geometry — it is contiguous there.
