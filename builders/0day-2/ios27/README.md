# IOS27 builders (iPhone 17e)

Build the 17e probe and ROP variants. Shared iOS builders are in
`../tiny/`: `gen_hole_stage_a.py`, `build_ios_way.py`, `make_inline_rop.py`,
`make_inline_ub_pair.py`, `pad_inline_z.py`.

## Files

| File | What |
|---|---|
| `gen_probe.py` | Compile-first probe (`OUT N H HN PHBASE`). |
| `gen_probe_geometry.py` | C/SZ geometry probe (`OUT C SZ N H HN`). |
| `make_at_rop_dense.py` | Dense attribute ROP set. |

## Check

```sh
cd builders/0day-2/ios27
python3 gen_probe.py /tmp/opencode/ios27-probe.html 3000 400 64 0
python3 gen_probe_geometry.py /tmp/opencode/ios27-geom.html 34 957 3000 400 64
```

Expected: the first is 1,928 raw / 889 zlib9; the second is 1,935 raw /
892 zlib9 with `fsize 957`.

## Build

The 17e payload tree is `vulns/0day-2-RCE-PARSER-SCOPE/IOS27/payloads/`.
The prepared variants are already copied. The shared builders write into the
TINY payload tree by default; use `TINY_PAYLOAD_DIR` to redirect.

The 17e is device-proven once (msg 5725). The gated twin and the two-phase
path are host-only; a live re-test is a separate task.
