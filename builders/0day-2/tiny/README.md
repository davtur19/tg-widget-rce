# TINY builders (iOS 15 hole-reuse)

Build the iPhone 6s payloads. Output directory:
`vulns/0day-2-RCE-PARSER-SCOPE/TINY/payloads/`. Override with
`TINY_PAYLOAD_DIR`.

## Files

| File | What |
|---|---|
| `build_ios_way.py` | Builds the probe and final for a given H. |
| `gen_hole_stage_a.py` | Standalone stage-A generator (`N H HN VK OUT`). |
| `make_inline_rop.py` | Inline ROP body. |
| `make_inline_ub_pair.py` | Builds the 4,600/2,124 seed/exploit pair. |
| `make_inline_set_4600.py` | Builds the H variant set. |
| `pad_inline_z.py` | Pads an HTML file to a target compressed length. |

## Check

```sh
cd builders/0day-2/tiny
python3 build_ios_way.py --H 400 --outdir /tmp/opencode/tiny --check
```

Expected: `RESULT: PASS`. The probe is 1,929 raw / 890 zlib9, SHA-256
`a522f06b143ca8f3be88b034ffd251c535ec3e5fe21ccb2b7087f18b71ebeb5c`.
The final is 5,583 raw / 2,356 zlib9, SHA-256
`fce1d2f6b6ac1c58340169984c32a945660238fc6d23d533d49c258d6f748fa2`.

## Build

```sh
python3 build_ios_way.py --H 400
```

Writes `probe-h400.html` and `final-h400.html` into the canonical payload
directory. Use `--outdir` for a test directory.

Stage A alone:

```sh
python3 gen_hole_stage_a.py 3000 400 64 598 /tmp/opencode/stage-a-h400.js
```

## Inline pair

`make_inline_ub_pair.py` and `make_inline_set_4600.py` are the historical
builders for the 4,600/2,124 set. They expect the original lab payload names
(`ls_final_inline_*`, `ls_seed_inline_*`). The canonical files are
`inline-rop-h200.html` and `seed-inline-rop.html`. The scripts are kept for
provenance; the shipped files are the source of truth.
