# Telegram Web K — widget isolation (2026-11-09)

Status: **negative for a session path.** The stock web widget is a QuickJS
**wasm** VM in a module worker, rendered into an **open shadow root**; the
session `localStorage` is unreachable from the widget. No device action.

## Rendering path

- Web K vendors `widget-sandbox v0.6.2`; the widget's zlib HTML is inflated
  (`payload.ts:38–45`), parsed by linkedom **inside a QuickJS wasm VM**, and
  its `<script>`s are compiled/run by QuickJS (`glue.ts:693–722`).
- Stock transport is `worker`: one/two module workers, one QuickJS VM per
  widget; the validator is in the worker JS (`engine-worker.ts:1–9,58–62,
  107–113`).
- Stock renderer is an **open shadow root in the page**
  (`shadow-renderer.ts:62–79`), not the iframe. The `IframeRenderer`
  (`sandbox="allow-scripts allow-forms"`, `no-referrer`, nonce CSP) is only
  for debug `sab`/`frame` transports.

## Boundary and session

- No separate origin in the stock path; same-origin DOM, but **no widget
  code runs there**.
- Widget JS has no browser globals: `fetch`/XHR/WebSocket/Worker throw,
  `document.cookie` is `''`, no IndexedDB/caches; `localStorage` is a
  per-message shim (`globals.ts:403–427,918–919,944`).
- Web K's MTProto auth key is in **page `localStorage.accountN`**
  (`dcX_auth_key` 512 hex + salt; `sessionStorage.ts:66–74`,
  `types.d.ts:24–41`, `apiManager.ts:510–526`). A widget has no path to it.
- Only plausible web path: validator→renderer bypass → page-realm script →
  `localStorage.accountN`. No such bypass is known; the page CSP does not
  restrict `script-src`/`connect-src`, so it would not stop exfiltration if
  one were found.

## QuickJS / iOS issue #1902

- The web engine is the same QuickJS fork family in **wasm**.
- Measured against the deployed wasm and repo `v0.6.2` wasm (8 MiB heap,
  1 MiB stack):
  - finding 3 (`await using`): compiles and runs (`COMPILED|secret=24301`),
    but the native calibration does not reproduce a hit in wasm;
  - finding 4 (`var_ref_count`): **aborts** the shipped engine
    (`free_var_ref` assertion) in both builds;
  - finding 5 (`FinalizationRegistry`): hangs the engine (`rc=124`).
- Impact is bounded by the **wasm sandbox**: in-VM corruption/worker DoS,
  not page JS, not `localStorage`, not the session.

## Deployment

- Production Web K is **v0.6.1** (engine wasm `8e7d8ff…`, commit `904ca11f`),
  not repo `v0.6.2` (`5d2c9007…`); the parser-scope hardening is not live
  yet.
- Web A (`telegram-tt 6002824b`, 2026-10-26) has **no
  `messageMediaWidget`** in its TL schema/union and no widget renderer.

## Ranking for a stock session read

iOS (device-proven in-process) → tdesktop → macOS → Android (isolated
process) → **Web K** (wasm+validator) → Web A (no widgets).

Artifacts: `lab/web_widget_isolation/REPORT_web.md`, `evidence/`,
`work/qjsrun/`.
