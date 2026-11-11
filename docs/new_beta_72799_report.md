# New beta 72799 — compatibility and campaign (2026-11-01)

Target: `org.telegram.messenger.beta`, versionName 13.2.0, **versionCode 72799**
(previous 72789). Installed 19:05 on the rooted Sony XQ-BT52 / Android 13.

## Native difference

| | 72789 | 72799 |
|---|---|---|
| `libtmessages.49.so` size | 26,997,240 B | **27,016,000 B** |
| md5 | `567fa78add23b2f2f1d061399a3d31f5` | `2c0caa68a07fc26f79d13519af6c3526` |
| build ID | `5cda53ca390c540072a1f421302486bd03dea2ed` | `645cce3998197329915f6cbfcc9ffd7f124d9f86` |
| `.text` / `.rodata` | baseline | +0x2618 / +0x2000 |
| toolchain | — | clang 18.0.3 (`+pgo, +lto`) |

The `.so` name is unchanged; the native library was rebuilt. The exploit's runtime
PLT/GOT resolver still found `free`/`system`; no APK address constant was needed.

## OTA run

The update restart re-ran the v2 widget from message 79415:

```
S0 | S1a V=0x76cdf992d8 off=446344 | S2 pv=… hl=516
   | S3 … | S3b PLT free=0x7af2db7f70 sys=0x7af2dded60
   | S4 writer ok | S5 rt16=0x7af2dded60 | S6
```

Proof at 19:05, 203 B (the new `id` includes group `1079(ext_obb_rw)`), md5
`d52d36e407fc0d0bb1daaf9a46dc552a`.

## Controlled campaigns (72799)

| Payload | Runs | S6 | `S3b PLT` | Proof | Crash |
|---|---|---|---|---|---|
| **v2** | 10 | 10 | 10 | **10** | 0 |
| v3 | 3 | 3 | 3 | **0** | 0 |
| **v4** | 10 | 9 | 9 | **9** | **1** |

- v2 `S1 off`: 511880 ×8, 446344 ×1, 249736 ×1; `S1b` never used; `hl=516`.
- v4 `S1 off`: 511880 ×5, 446344 ×2, 380808 ×1, crash ×1; `hl=516` all successes.
- Proof path every success: `/data/user/0/org.telegram.messenger.beta/cache/rce_proof`
  (203 B); `/data/data` alias same file; external fallback not used.
- v2 is the most reliable device payload on 72799; v4 is the most feature-complete
  (runtime PLT, wide S2, fallback paths) but has one residual crash.

## v3 dynamic proof-path defect

v3 reached `S3b PLT`/`S6` 3/3 but wrote **0/3** proofs. The dynamic command
`u=$(id -u); p=$(cat /proc/$PPID/cmdline | tr '\0' '\n' | head -n1); …` failed on
the Android shell. v4's hardcoded beta/release fallback wrote the proof every time.
Next candidate: extract the package from `/proc/$PPID/maps` with
`grep -o 'org\.telegram\.messenger[^/]*'` + `${p%%-*}` instead of `tr`/`\0`.

## v4 crash (tombstone_20)

Run 10: SIGSEGV `SEGV_MAPERR`, fault `0xfffffffffffffffb`, `widget.sandbox`, pid
22177, PC `0x1714b3c` (new BuildId); registers `x2/x9/x23 = 0xfffd` (the 65,533
var-ref index). This is in the BigInt/var-ref path family, not the command/endgame.
One crash in 10; v2 had zero. The app restarted normally; no proof in that run.

## Final device state

- Benign DB `e4cf55a5d12b8d0a4cb5daab2f61b67f`; chat restored; app running.
- Live proof file was removed before the crashing v4 run; the exact 203-B content is
  archived in `evidence/evidence_20261101/new_beta_72799/`.
- No uninstall/data clear.

## Evidence

`evidence/evidence_20261101/new_beta_72799/`:
`rce_proof_72799.txt`, `proof_content_72799.txt`, `ota_markers_72799.png`,
`nb_v2_run*.png`, `nb_v3_run*.png`, `nb_v4_run*.png`, `nb_v4_run10.log`,
`nb_final_restored.png`, `v2.db`/`v3.db`/`v4.db`, `tombstone_20.txt/.pb`,
`MANIFEST.md`.

Full report: `REPORT_COMPLETE.md`; technical history:
`notes/qjs_postsnapshot_f1865_report.md`; lemmalog facts `campaign_72799`,
`new_beta`, `universal_v4`.
