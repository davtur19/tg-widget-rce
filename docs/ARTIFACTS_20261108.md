# Persistent artifacts 2026-11-08

Durable copy of the campaign artifacts that were produced under `/tmp`. The
raw tree is not part of this repository: it may contain bot names, chat ids,
device ids and other identifiers. This page is the sanitized manifest.

## Location

`<LAB>/artifacts_20261108/`, 6.5 GB. Raw; do not publish.

| path | size | content |
|---|---:|---|
| `kernel_0day/` | 3.8G | Negative 0day search: 4.19 Binder/ashmem source analysis, KASAN harness, QEMU logs, `REPORT.md`. |
| `kernel_nday/` | 60M | CVE matrix, measured results, PoCs, tools, stock vmlinux and ELF. |
| `escape_host/` | 409M | Isolated-process IPC inventory, host Binder findings, tombstones 27/28/29, Frida scripts, reports; source audit and second-stage wallet/BOC payloads. |
| `android_src/` | 685M | Public Telegram 13.2.1 and widget-sandbox v0.6.1 trees plus `SOURCE_INVENTORY_20261108.md`; diff vs beta 72989. |
| `ui_webview/` | 184K | Host UI/RenderNode/WebView/service audit: report, DEX bytecode evidence, AOSP excerpts, LT-1 payloads. |
| `host_file_read/` | 131M | Host file/session read audit (in progress). |
| `host_fuzz/` | 86M | Full host Binder fuzz (in progress). |
| `ios17e/` | 860M | iOS 27 17e payloads, crash logs, `rce_proof_5725.bin` (`RCE_OK`, sha256 `704984d9...`). |
| `fuzz_html/` | 26M | HTML host-side fuzzing, in progress. |
| `fuzz_css/` | 16K | CSS host-side fuzzing, in progress. |
| `sony_test/` | 60K | v3 two-phase detector and final payload directory. |
| `beta_gen/` | 284K | Beta-package generation and beta pair. |
| `forward_test/` | 128K | Standard/beta sendWidget, shared-widget, forward/copy matrix. |
| `misc/` | 460M | Screenshots, logs, helper scripts, Android evidence, desktop minidump. |

## Removed from `/tmp`

Only caches, builds and duplicates already present in the lab tree were
removed: the `kernel_nday` SDK (15G), the goldfish kernel trees (7.8G), the
NDK/cmdline/bt/plat zips, the venv, and the stock vmlinux/ELF builds. The
duplicated `kernel_0day`, `ios17e` and `escape_host` trees were removed after
the lab copy was verified. The `fuzz_html` and `fuzz_css` working trees stay in
`/tmp` while the fuzzing agents run and are copied here.

PoCs and documents are kept in this tree. The token is not here.

## Token

`<HOME>/.config/tgbot/token.env`, mode 600. The lab scripts were updated to
read this path. The token is not in this repository.

## Current state

- Android beta **72989** (13.2.2), app UID 10346. The widget engine is an
  isolated process (`WidgetEngineService`, UID 990xx, `u:r:isolated_app:s0`).
- Parser stage A still hits: `platform=1 hit=1 att=0 sel=599`, about 55 ms.
  The app-level chain is blocked by the isolated process.
- Host Binder is the only reachable Telegram IPC surface. The app services,
  providers, broadcasts and filesystem are blocked by AMS/SELinux; seccomp
  traps execve and ptrace. The shared SkPath race in
  `WidgetSandboxBackend.record`/`z0.d` is triggered end-to-end from the
  isolated process (16 pthreads, Scudo chunk-header write, 8-byte UAF write;
  tombstones 02/03, 30/31). The first heap-shaping attempt (500 Bitmaps,
  20k/50k paths) found no HIT; the small-object spray and the leak search are
  negative; pre-growing the Path removes the growForVerb realloc/Scudo UAF but
  not the SkPath null-read. The alternate host audit is negative
  (filterPixels unreachable; Paint/Shader, cross-canvas and Bitmap-lifetime
  races no; bitmap parcel safe; canvasRun/i.b/z0 bounds). The reverse
  IWidgetEngine direction is negative: the host client reads only
  exception+long; no Parcelable/Bundle/IBinder/fd; foreign binder blocked; the
  only gap is session id 0 robustness. The source audit and the host
  UI/WebView/service audit are complete and negative: no app-process RCE, no
  app-data/session read. They add a Wallet BOC parser panic (host DoS if the
  Rust panic crosses JNI), wallet `signData` blind signing, latent `Browser`
  autologin exposure, a cross-session callback amplifier, and host-only
  defects H-1/H-2/H-3. Final wall: host heap leak, reliable SkPathRef reclaim
  with fake fPoints, or a host OOB read folded into canvasRead; none. The
  end-to-end effect is a host DoS/native heap corruption, not an escape. No
  app-data read and no host code execution. See
  `docs/SECOND_STAGE_AUDITS_20261108.md`.
- iOS 27 message 5725 and iOS 15 6s proofs stand. Android 72929/72889 remain
  the app-level baseline.
- HTML and CSS host-side fuzzing is running. See the lab directories.

## Related pages

- `KERNEL_CVE_COVERAGE.md` for the CVE matrix, the measured lab results and the
  negative 0day search.
- `HOST_BINDER_ESCAPE_20261108.md` for the isolated-process host Binder work.
- `SECOND_STAGE_AUDITS_20261108.md` for the source and UI/WebView/service audits.
- `PAYLOAD_CHAIN.md` for the end-to-end chain and evidence status.
