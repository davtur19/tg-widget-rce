# Two-phase builders

Build the **ungated P2** detector, inline final, and fallback page. The
**gated P3** pages in `payloads/two_phase/` are a different package; they are
not produced by this builder. Use `scripts/two_phase/gen_two_phase.py` for the
P3/gated source (it currently expects lab inputs; see the critique).

The bot is in `bot/bot_two_phase.py` (P2) and
`scripts/two_phase/bot_two_phase.py` (P3).

## Files

| File | What |
|---|---|
| `gen_two_phase.py` | Builds `detector.html`, `final_inline.html`, `final_fallback.html`, mocks, and chunks. |

## Check

```sh
cd builders/two_phase
python3 gen_two_phase.py --check
```

Expected: `RESULT: PASS`.

## Build

```sh
python3 gen_two_phase.py
```

Outputs are written in the current directory. The detector and the final have
the same raw length (9,176 bytes). Only stage C differs.

For the Sony beta proof path:

```sh
python3 gen_two_phase.py --pkg beta
```

This writes `chunks_beta/` and `endgame_beta.js`.

## Hashes

These are the P2/ungated pins. They do not match the gated P3 pages.

| File | Raw | zlib9 | SHA-256 |
|---|---:|---:|---|
| `detector.html` | 9,176 | 1,489 | `35f8698e…` |
| `final_inline.html` | 9,176 | 3,988 | `7aae63e7…` |
| `final_fallback.html` | 2,151 | 1,024 | `245f4dc4…` |

Current P3/gated pins are in `docs/PAYLOAD_HASHES.json`; run
`python3 scripts/verify_payloads.py`.

## Inputs

- `STAG/payloads/route2/endgame-72801.js`
- `STAG/payloads/route2/endgame-host.js`
- `STAG/payloads/route2/out-of-band-72801.html`

Set `STAG_PAYLOAD_DIR` to redirect the input tree.
