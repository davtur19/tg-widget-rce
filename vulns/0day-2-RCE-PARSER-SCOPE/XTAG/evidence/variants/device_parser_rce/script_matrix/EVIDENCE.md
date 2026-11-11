# Widget script matrix: device evidence (Sony <SERIAL>, Telegram 13.2.2 / 72929)

Date: 2026-11-07 22:05-22:07. One DB with messages 80345-80356, one widget per
variant, opened in the bot chat (peer <CHAT_ID>). Files here are the raw
screenshots, filtered logcat, the exact HTML (`m*.html`), the DB builder
(`build_db_mid.py`) and the runner (`run_matrix.sh`).

## Variants and observed results

| mid | id | script A | script B | observed | meaning |
|---:|---|---|---|---|---|
| 80345 | m1 | `textContent="M1 A"` | `textContent="M1 B"` | **M1 B** | sibling scripts run |
| 80346 | m2 | `repeat(3000000)`, `M2 A3M` | `M2 B3M` | **M2 B3M** | 3 MB live alloc fine; loop continues |
| 80347 | m3 | `repeat(6200000)` | `M3 B` | blank/frozen; `Widget stopped` | alloc refused; B never runs |
| 80348 | m4 | `throw new Error("boom")` | `M4 B` | **M4 B** | catchable throw does not kill the widget |
| 80349 | m5 | `throw new InternalError("boom")` | `M5 B` | (not captured; viewport) | JS-level InternalError, not the C OOM path |
| 80350 | m6 | plain `<script>`, no id | - | (not captured) | - |
| 80351 | m7 | id + strict + newlines | - | (not captured) | - |
| 80352 | m8 | id + strict + IIFE | - | (not captured) | - |
| 80353 | m9 | no id + strict | - | (not captured) | - |
| 80354 | m10 | id, no strict | - | (not captured) | - |
| 80355 | m11 | `repeat(5500000)` | `M11 B55` | (not captured) | - |
| 80356 | m12 | `M12 PRE`, `repeat(6200000)`, `M12 POST` | `M12 B` | (not captured) | - |

The decisive four are visible in `m1.png` (the chat viewport at the m1 open):
`M1 B`, `M2 B3M`, blank+`Widget stopped`, `M4 B`.

## The stop line

```
11-07 22:05:30.068 19662 19662 D tmessages: widget tg-widget:0/<CHAT_ID>/<CHAT_ID>/-1156798021 stopped (1): Memory limit exceeded (8 MB)
11-07 22:05:38.542 19662 19662 D tmessages: widget tg-widget:0/<CHAT_ID>/<CHAT_ID>/-1156798021 stopped (2): Memory limit exceeded (8 MB)
```

The engine reports the message with the option value `8 MB`; the 6.2 MB
allocation is refused (runtime + baseline + the 6.2 MB string exceed the
runtime cap), and the widget is stopped. See `m1.log`/`m2.log`/`m3.log`.

## Interpretation

A refused allocation is fatal to the widget (uncatchable OOM, engine dead,
last render frozen). This is the canonical engine policy as well
(`lab/qjs_fork_audit/widget-sandbox/tests/attacks.spec.ts`, memory-limit
tests). N1's gate is a refused `js_realloc`, so it cannot be used to run a
second script; see `notes/new_0day_mte_specs_20261107.md` §11.

Hashes: `md5sum m1.png m2.png m3.png m4.png` in this directory.
