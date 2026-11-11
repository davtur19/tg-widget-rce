# Sony b0 size sweep — aborted partial result (2026-11-02 01:05)

The b0 sweep was stopped on request after the 1024 KB retest, to switch to the
A/T groom. Full details, variant table and per-run evidence:
`telegramandroidwidget/lab/qjs_postsnapshot/loaders/size_variants/sony_sweep/REPORT.md`.

## Tested sizes

| size | result | signature |
|---|---|---|
| 768 KB | FAIL (re-confirmed, 00:32) | `pc 0x1714b3c`, fault `0x890` |
| 1024 KB | FAIL with the A_mangle_only/SONY payload (6 attempts: 5 OOB crashes, 1 silent S1 miss) | `0x1714b3c`; faults `0x890` ×5, `0xffffffff64030000`, `0xfffffffffffffffb` |
| 640 / 704 / 832 / 896 / 960 / 1152 / 1280 KB | not run (aborted) | — |

No SONY/A-payload run wrote `/sdcard/Android/data/org.telegram.messenger.beta/files/p`.
The only command execution in the session was the old **h79460** loader
(original v2 payload, full inflate, internal `cache/rce_proof`), at a *clipped*
widget geometry (canvas lower edge under the input bar, rows 1493–2029),
`rce_proof` mtime 00:48:56. At true bottom (rows 1290–1826) the same old loader
crashed with `0xfffffffffffffffb`.

## Correlate with the A/T design

- Identical B5 HTML alternated between silent no-leak and `0x890` across runs,
  so one run per size is not a measurement.
- Success correlated with the old 420 dp shell and the input-bar-clipped widget
  position, not with b0 size: renderer/sandbox allocations tied to widget
  height/visible area perturb the groom.
- All crashes land at the same generator OOB PC `0x1714b3c`; `0x890` is the
  groom-slot-missed signature, not a later-stage failure.

## Device state

Restored and left healthy: 79461 = `B5_lzss_A_golf.html`, 79468/79469 = their
original PIXEL9 variants (blobs byte-identical to the 00:36 base DB), app
running (pid 6340), DB integrity `ok`, no `p` file, `rce_proof` touched back to
its 23:49:15 mtime, auto-rotate restored, `/sdcard/Download` temp files removed.
