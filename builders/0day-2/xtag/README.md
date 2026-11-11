# XTAG builders (`c2560s`)

Build the Android cross-tag widgets. Output directory:
`vulns/0day-2-RCE-PARSER-SCOPE/XTAG/payloads/`. Override with
`XTAG_PAYLOAD_DIR`.

## Files

| File | What |
|---|---|
| `build_widgets.py` | Builds the six canonical widgets and checks the SHA-256 pins. |
| `build_c2_widget.py` | Builds the C2 variant from a final. |
| `endgame-stage-b.js` | Stage-B source used by `build_widgets.py`. |
| `original/gen_c2560s.py` | Original lab builder. Kept for provenance. |
| `original/gen_c2_widget.py` | Original C2 builder. Kept for provenance. |

## Check

```sh
cd builders/0day-2/xtag
python3 builders/0day-2/xtag/build_widgets.py --check
```

Expected:

```
final-sony-beta-72929.html             9946    4023 PIN-OK
debug-sony-beta-72929.html             9946    3009 PIN-OK
probe-sony-beta-72929.html             9946     959 PIN-OK
final-host-twin.html                   9946    4014 PIN-OK
debug-host-twin.html                   9946    3009 PIN-OK
probe-host-twin.html                   9946     959 PIN-OK
RESULT: PASS
```

## Build

```sh
python3 builders/0day-2/xtag/build_widgets.py
```

This rewrites the six files. It needs `terser` with `-c passes=2`; a single
pass produces a 7,212-byte stage B and breaks the pins.

C2:

```sh
python3 builders/0day-2/xtag/build_c2_widget.py \
  --src vulns/0day-2-RCE-PARSER-SCOPE/XTAG/payloads/final-sony-beta-72929.html \
  --out /tmp/opencode/c2560s-c2.html
```

## Hashes

| File | Raw | zlib9 | SHA-256 |
|---|---:|---:|---|
| `final-sony-beta-72929.html` | 9,946 | 4,023 | `992a51267a385c57635f5aed835aa29a1006ca8c584ca3843b265cd2c71318b4` |
| `probe-sony-beta-72929.html` | 9,946 | 959 | `b9104faef8be5e06fc451fc11c62aea546b8e995d56585a13c53b897cdeae41f` |
| `debug-sony-beta-72929.html` | 9,946 | 3,009 | `ef87921f72081d812e55a73bc1f2b2d597d1ec4c69d6c3b2defeeb496fe47b19` |
| `c2-final-sony-beta-72929.html` | 9,946 | 4,025 | `26f670aeaf6e6043b18bbb76eeb0ed7933c50748ee4c7fa359da51c539bac40b` |

The original `gen_c2560s.py` expects the old `device/widget/` layout. Use
`build_widgets.py` for a reproducible build. The original is kept as evidence.
