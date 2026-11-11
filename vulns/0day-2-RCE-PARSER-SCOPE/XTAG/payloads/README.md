# Android cross-tag payloads (`c2560s`)

Docs: `vulns/0day-2-RCE-PARSER-SCOPE/XTAG/README.md`.

## Files

| File | Raw | zlib9 | What |
|---|---:|---:|---|
| `final-sony-beta-72929.html` | 9,946 | 4,023 | Device final: forges the AB and writes the `id` proof. |
| `probe-sony-beta-72929.html` | 9,946 | 959 | Safe probe: `S1 SAFE2560C END=-`. |
| `debug-sony-beta-72929.html` | 9,946 | 3,009 | Debug endgame: `HF READY` and field values. |
| `c2-final-sony-beta-72929.html` | 9,946 | 4,025 | C2 variant (44-char loopback bootstrap). |
| `final-host-twin.html` | 9,946 | 4,014 | Host twin; proof at `/tmp/hf_proof`. |
| `probe-host-twin.html` | 9,946 | 959 | Probe, host. |
| `debug-host-twin.html` | 9,946 | 3,009 | Debug, host. |
| `c2-final-host-twin.html` | 9,946 | 4,023 | C2, host. |
| `fallback-4096/final-sony-beta-72929.html` | 9,956 | 3,832 | 4,096-byte-class fallback, host-only. |
| `fallback-4096/probe-sony-beta-72929.html` | 9,956 | 962 | Fallback probe. |
| `fallback-4096/debug-sony-beta-72929.html` | 9,956 | 3,008 | Fallback debug. |
| `src/endgame-stage-b.js` | - | - | Stage-B source (minified to 7,182 B by the builder). |
| `builders/0day-2/xtag/build_widgets.py` | - | - | Rebuilds and SHA-pins the six canonical widgets. |
| `builders/0day-2/xtag/build_c2_widget.py` | - | - | Rebuilds the C2 variant. |

## Rebuild

```sh
cd vulns/0day-2-RCE-PARSER-SCOPE/XTAG/payloads
python3 builders/0day-2/xtag/build_widgets.py
python3 builders/0day-2/xtag/build_c2_widget.py \
  --src final-sony-beta-72929.html \
  --out /tmp/opencode/c2.html
```

`build_widgets.py` needs `terser` and `node` on `PATH`. It asserts the SHA-256
of every shipped widget; a mismatch is a geometry change.

## Use

- Sony 72929: `final-sony-beta-72929.html`.
- Sony 72889: the same file (1/1).
- Probe before a final after any build change.
- C2: `c2-final-sony-beta-72929.html` plus the server in
  `docs/c2/c2560s/`.

## Names

The original names are in `docs/common/06-glossary.md`.
