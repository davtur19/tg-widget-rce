# Second-stage audits — Telegram Android beta 72989 (2026-11-08)

Scope: from a parser RCE already achieved in the isolated widget process,
find a Telegram bug that yields app-process (UID 10346) code execution or an
app-data/session read. Host/static only; live tests are requests to the device
owner. No repository files were modified by the audit agents. This page
consolidates the source audit and the host UI/WebView/service audit.

## Verdict

No app-process RCE and no app-data/session read were found in the source or in
the UI/WebView/service paths. The wall is unchanged: no host file API takes a
widget path or URI; the isolated→host callbacks are Java-safe; the reverse
`IWidgetEngine` reply carries an exception int and one `long`; the shared
`z0` SkPath race is the only widget→host native memory corruption and has no
leak, reclaim, or output.

One new host-native parser issue is reachable from a stock widget: a Telegram
Wallet BOC root-index check is missing in Rust `ton_core`. The parser panics.
If the panic crosses the JNI boundary the host app aborts; otherwise the call
returns false. This is at most a **new host DoS**, not RCE. The device test
decides (section 2).

## 1. Source versions and the 72929 → 72989 diff

| tree | version | commit | relation to target |
|---|---|---|---|
| `DrKLO/Telegram` | 13.2.1 (7291) | `7be672ead283d022812d75c729d3a04dd4c2a2c6` | older than the beta |
| `TelegramMessenger/widget-sandbox` | v0.6.1 | `3959d4089a8f21b05b99dbd2a73e5aacd743e39a` | demo/renderer only; no Android `WidgetEngineService`/AIDL |
| target APK `tg72989.apk` | 13.2.2 (72989) | sha256 `63819c1c…a40675` | closed `twidget` code in `classes4.dex` |
| baseline `tg72929.apk` | 13.2.2 (72929) | sha256 `fe19d515…26ffc3` | pre-isolation app-level baseline |

The diff adds 29 `org.telegram.utils.twidget` classes and exactly one manifest
component: `WidgetEngineService`, `exported=false`, `process=":widgets"`,
`isolatedProcess=true`. Widget assets and bundles are byte-identical. The
refactor moves the engine out of process; it adds no host file/component
surface. Reverse reply parsing remains `[exception-int][long]` for create and
`[exception-int]` for conformance; the long is used only as the service
session argument.

## 2. Wallet BOC parser panic (host DoS)

Path:

```
TelegramWidget.wallet.signData
  -> WidgetSandboxBackend.signal (code 19)
  -> ni.b case 19
  -> org.telegram.ui.Wallet.c1 case 16   (jg/c1.java:653-690)
  -> e2.G                                 (Wallet/e2.java:590-611)
  -> WalletEngine2.isValidCellBoc
  -> libtmessages.49.so Java_..._isValidCellBoc @ 0x60ffd4
  -> Rust ton_core 0.1.4
```

`ton_core/src/cell/boc/raw_boc.rs:170` indexes
`cells[cells_len - 1 - root_index]` without checking
`root_index < cells_cnt`. A 20-byte BOC `te6ccgEBAQEAAP8AAA==` makes the index
`18446744073709551361`. The public crate reproduces the panic locally:

```
thread 'main' panicked at src/cell/boc/raw_boc.rs:170:29:
index out of bounds: the len is 1 but the index is 18446744073709551361
```

`e2.G` runs before the wallet confirmation sheet and before any user click.
Impact depends on the JNI boundary:

- panic crosses `extern "C"` → SIGABRT/tombstone in the host app (DoS);
- JNI wraps the call in `catch_unwind` → returns false, no impact.

Preconditions: initialized Telegram Wallet, a wallet/canQuery widget, app in
the foreground. A second unbounded value, `cells_cnt` up to `2^32-1`, can
request a multi-GB allocation before the cell loop. Rust cell parsing uses safe
code and contains no `unsafe`; this is not a memory-corruption primitive.

## 3. Wallet `signData` blind signing (phishing, not RCE)

`jg.c1` case 16 passes the widget-controlled `payload` to `u2.c`. For
`type:"text"`, `u2.c:57` displays only `payload.text`, i.e. attacker text; for
`binary`/`cell` it shows a generic message with no bytes, hash, or domain.
`WalletEngine2.signData` (`WalletEngine2.java:244-249`) signs a TON Connect
proof over the actual payload with domain `"bot"+bot.id`. The result callback
returns only status codes 3/5, not the signature.

Impact: a widget can make the confirmation sheet describe one thing while the
wallet signs another. This is a wallet-security/phishing bug, not app RCE and
not a session read.

## 4. `Browser` autologin token (latent)

`Browser.java:449-455` appends `autologin_token` to any URL whose host is in
the server-provided `autologinDomains`. A widget can auto-open a `t.me` URL
without a dialog. The token is appended, but `t.me/iv` does not auto-redirect
or forward the query in the tested HTML, so no leak was demonstrated. Latent
credential exposure only; see `frida_browser_url_capture.js` in the lab.

## 5. Cross-session callback (amplifier only)

All widget sessions share the single `:widgets` process, and the host
`IWidgetEngineCallback` path has no caller check. A compromised session can
call another session's callback binder and read that widget's canvas pixels or
inject callbacks. This is an amplifier after an isolated RCE; it yields no app
data, session file, or key.

## 6. Host UI / WebView / service audit

### 6.1 `a0` / `i1.b` RenderNode and UI thread — negative

`record` allocates a new `a0` per call
(`WidgetSandboxBackend.record:916-925`). `i1.b:173` discards only the previous
pending `I` under `synchronized(i1.s)`. `b1:39-58` takes `I`, nulls it, and
writes `H` under the same lock. The discarded node is never `H`, is never a
child of a drawn node, and two `b1(0)` runnables cannot alias `I`/`H`.

AOSP 13 confirms the mechanism: `discardDisplayList()` clears only the staging
list (`RenderNode.cpp:77-85`); `syncDisplayList`/`deleteDisplayList` run only
for nodes visited by `prepareTree`; a drawn node is kept alive by
`RenderNodeDrawable`'s `sp<RenderNode>` (`SkiaRecordingCanvas.cpp:147-168`,
`RenderNodeDrawable.h:106`). Calling `discardDisplayList()` from the Binder
thread is a contract violation, but benign for a thread-confined pending node.
The previous 200-page `o0F` probe produced no crash.

### 6.2 `layers()` / backdrop / filter — negative

Filter/backdrop state is per call: `a4.k` is created at the top of `z0.d` and
`x0` inside op 15; neither is stored on the shared `z0`. Layer `c0`s are reused
only by int content-version and are never discarded. `pendingLayers` is keyed
by array index, not layer id; a mismatch is attacker data only. The `a0.c`
ImageReader software path is not reached by a hardware bubble. Its bytecode
cleanup is null-guarded; JADX printed an unconditional `close()`. The `z0`
filter Bitmap cap is a 64-bit `mul-long` of at most 16,777,216 px; the JADX
int-overflow rendering is wrong.

### 6.3 WebView / Chromium — negative

The app does not ship the SDK WebView renderer: zero
`org/telegram/widgetsandbox` in all dex files, no `RendererWebView`, no
`tgwidget.invalid`, no `__twReceive`, no class named `WidgetHost`. The only
widget→WebView path is `signal(5)` `openLink`/`openTelegramLink` →
`vf.c.s`, which requires one host confirm tap, https-only, an LDH host,
foreground, and quota. The in-app browser's Chromium renderer is the separate
`sandboxed_process0`; file and content access are off.

The only Telegram-owned bridge is `TelegramWebviewProxy`
(`x0.java:868-879`). For normal tabs `G0 == null`, so the origin check in
`r31 case 7` is skipped. Reachable events are `actionBarColor`,
`navigationBarColor`, `siteName`, `allowScroll`, `oauth_request` only. This is
host-only hardening gap **H-1**, with no file or exec surface. The
server-supplied `pageBlockEmbed` WebView is not widget-reachable, and
`BotWebViewProxy` is not reachable from a widget.

### 6.4 Service lifecycle — negative

`r0`/`q0`/`o0`/`i1`/`v0`: session create/destroy, generation counters,
`linkToDeath`, refcount, and rebind are all under `r0.b`. Destroyed-during-create
posts a `p31` destroy (`bi/d0.java:145-200`), so there is no leak. No cast is
performed on anything but construction; no type confusion.

Two host-only defects remain:

- **H-2** `i1.c1.doFrame` leaves the frame gate `o` set when `o0.h1()` returns
  null (connection generation changed), permanently stopping the widget's
  frame callbacks.
- **H-3** `WidgetSandboxBackend.record` keeps painting the attacker display
  list after the session is destroyed (`i1.w=true`) and only then discards the
  node; a destroyed session's backend remains drivable through the held `o0`
  binder. CPU/GPU DoS only.

### 6.5 Read channels — negative

Only `defineFont` `float[6]`, `textWidth` `float`, and `canvasRead` pixels of
attacker-created canvases are returned. Host `loadImage` and `formatIntl` are
dead (no caller); `typeface` is a family name only. No host file, database, or
pointer value is exposed. No session/file read.

## 7. Corrections to earlier notes

These are JADX rendering artifacts, not real bugs:

- `z0.d` filter Bitmap cap is a 64-bit multiply, not a 32-bit overflow.
- `a0.c` ImageReader cleanup is null-guarded in bytecode.
- `canvasRead` index errors for negative origins throw a Java
  `ArrayIndexOutOfBoundsException`, not a native OOB.

## 8. Exact wall

A controlled app-process primitive still requires one of:

1. a host heap leak;
2. a reliable `SkPathRef` reclaim with a fake absolute `fPoints` pointer;
3. a host OOB read folded into `canvasRead`.

None exists on 72989. The isolated process cannot read app-private data or
open a network socket, and the app-process entry points it can reach are
Java-safe or DoS-only.

## 9. Live tests and status

| item | test | status |
|---|---|---|
| Wallet BOC panic | Frida `isValidCellBoc("te6ccgEBAQEAAP8AAA==")` on the host, then stock widget `widget_wallet_boc.js` | pending |
| Wallet blind signing | `widget_wallet_blind_sign.js`, inspect the sheet and callback | optional |
| Browser autologin | `widget_openlink_autologin.js` + `frida_browser_url_capture.js` | optional |
| H-1 browser bridge | `lt1.html` + `widget_lt1.js`, one confirm tap | pending, cosmetic/oauth only |
| H-2/H-3 | source-only; no stock primitive | recorded |

The Wallet BOC test is analysis-only and kills the app if the panic crosses
JNI. Run it on a wallet-initialized account with the app in the foreground;
record `returned false` vs SIGABRT/tombstone.

## 10. Artifacts

- `lab/artifacts_20261108/escape_host/SECOND_STAGE_SOURCE_AUDIT_20261108.md`
- `lab/artifacts_20261108/escape_host/second_stage_20261108/` — BOC probe,
  widget triggers, autologin/blind-signing scripts, local panic output.
- `lab/artifacts_20261108/android_src/20261108/SOURCE_INVENTORY_20261108.md`
  and the two source trees.
- `lab/artifacts_20261108/ui_webview/REPORT_host_ui_webview_72989.md`,
  `LEMMALOG_FACTS_ui_webview_20261108.txt`, `evidence/`, `payloads/lt1.html`.
