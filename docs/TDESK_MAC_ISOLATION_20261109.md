# tdesktop 7.4.0 / macOS — widget QuickJS is in-process (2026-11-09)

Status: **verified against the exact pinned sources: no process/OS isolation
on either platform.** No desktop/macOS exploit is claimed; the session
impact is architectural. Source verification: `lab/tdesk_mac_isolation/VERIFY.md`
(555 lines); the earlier `REPORT.md` is superseded where they differ.

## tdesktop 7.4.0

- Tag `v7.4.0` = `6d7e0ab348cb2a5520776de442e215833f4573c0`; pins
  `widget-sandbox d6f39f3…` (= tag **v0.6.0**), `twidget 759fcaf…`, nested
  `quickjs c24d6b0…` (0.17.0, BC 29).
- Negative grep over all 12 `packages/desktop/sandbox` `.cpp` + `tgw` +
  cmake: **no** `CreateProcess`, AppContainer, Job Object, `fork`/`exec*`,
  seccomp, namespace, XPC, or `sandbox_init`.
- Three long-lived threads: `twidget-host` (`widget_host.cpp:83`),
  `widget.sandbox` (`sandbox_engine.cpp:101`), `widget.validator`
  (`trusted_validator.cpp:7–10`); `_beginthreadex`/`pthread_create` at
  `js_thread.cpp:21/36`.
- Widget `<script>` reaches `JS_Eval` via `pumpScripts`/`evalScript`
  (`sandbox_engine.cpp:900–921`, `:896–898`; `quickjs_context.cpp:142–147`).
  The engine shares the address space with `Main::Session`/`tdata`; a QuickJS
  memory bug gets the process, not just the widget API.

## macOS Telegram 13.1 (283434)

- Swift `SandboxEngine`/`QuickJSContext`/`JSThread` are **in-process**; no
  XPC/spawn/fork/exec/`sandbox_init` imports; only `TelegramShare.appex`;
  app-sandbox entitlement **false** for the DMG; `CS_RUNTIME` (hardened) set;
  `WKWebView` runs only the renderer bundle (nonce CSP, `connect-src 'none'`,
  http/https/ws/wss/ftp blocked). Widget JS is evaluated by QuickJS, never
  sent to WebKit.
- **Public source pin ≠ shipping binary.** The public
  `TelegramMessenger/telegram-macos` 13.1 source pins widget-sandbox
  `38862fe…` (pre-0.6.0; WidgetJS `9c589ea9…`, 561,010 B; quickjs
  `7d1085a1…`). The DMG 283434 contains all five WidgetJS files
  **byte-identical to `d6f39f3` (v0.6.0)** and the binary has
  `WidgetSandboxVersion 0.6.0`, `BundleStamp`, `mainBudget` (absent from
  `38862fe`). So the beta binary matches **widget-sandbox v0.6.0**, quickjs
  **c24d6b0 (0.17.0)**; the exact compiled QuickJS is not
  disassembly-proven.
- The public macOS source **excludes the widget integration**
  (`buildbox/verify-no-labs.py:10–16`; `verify-build.sh:17`). The app
  message-media/account wiring is binary-only; the Swift engine source is
  available in widget-sandbox v0.6.0. `telegram-ios` at `fb0e62ba…` has zero
  widget paths.

## QuickJS

- Both iOS 0day classes are present at `c24d6b0`: `await using` in a class
  static block (`quickjs.c:23767–23771`, `26434–26435`, `29841–29852`,
  `21588–21590`, `21691–21705`, `18045–18080`) and the `uint16_t`
  `var_ref_count` truncation (`:477`, `:929`, `:34633`, `:37877`). #1827 at
  `:50776`, `:50799`, `:50804–50810`; `libregexp.c:3426–3430`.
- The `await using` stage A was host-proven through the **actual
  `sandbox-bundle.js` 0.6.0**: 3/3 clang -O2, 2/2 gcc -O3; the real bundle
  in global and module mode gives `RESULT HIT N=16 slot=9 before=1009
  after=PWN9`; controls SAFE. Assert builds print the DOM marker before
  aborting at `JS_FreeRuntime`/`free_var_ref`.
- #1827 is already live-crash-proven on 7.4.0; finding 4 is present but
  heap-gated (≥65,536 captures, unproven at 8 MiB).

## tdesktop exploit progress (2026-11-09)

Working dir `lab/tdesk_exploit/` (`REPORT.md`; host-side only). The
`await using` stage A and the second stage were reproduced **through the real
`sandbox-bundle.js` 0.6.0** (pinned quickjs `c24d6b0`):

- widget `<script>` → `nextScript` → `JS_Eval`:
  `RESULT HIT N=16 slot=9 before=1009 after=PWN9` (slot 10 on clang);
- address-free fake `JSVarRef` (a heap `BigInt` at `sf->var_refs[0]`;
  32-bit limbs at +4, `tab[3]`→`is_detached`, `tab[5..6]`→`pvalue`) —
  arbitrary 8-byte read/write with **no absolute address needed to build the
  primitive**: `RESULT W1 READ 0x4142434445464748 WRITE2 0x1122…`;
- typed-array takeover (`Float64Array.u.array.u.ptr`, offset 56) →
  stable arbitrary R/W: `RESULT W2 OOB 0x4142…`;
- C-function pointer hijack (`print.u.cfunc.c_function`) → `HOST_PWN`;
- Windows x64 ROP page (CreateFileW/ReadFile/CreateFileW/WriteFile/
  ExitThread) generated and host dry-run; the session read path is
  `tdata\key_datas` → `%LOCALAPPDATA%\Temp\tg_widget_proof.bin`, in-process,
  no root/Frida.

**Boundary:** the MSVC port needs one ASLR anchor — the widget thread's
stack high 32 bits (or a full 64-bit pointer). Every captured slot is
16-byte aligned while the raw spills (`argv`, `arg_buf`, `var_refs`, saved
regs) are 8-mod-16, so the iOS argv-leak slot does not exist; the 0day gives
only 32-bit stack leaks on this target. The `done_generator` `sf->cur_sp`
leak is host-observed but the class machinery reuses that slot. The runbook
(`runbook/WIN11_RUNBOOK.md`) has L1/L2 leak-only, W1 dry-run and W2 full
page; **no Windows 11 VM/live run is available in this environment**, so the
live proof is pending. This is not a desktop session claim yet.

## Ranking for a stock session read

1. iOS 17e — device-proven in-process primitive; stage-A reliability is the
   blocker.
2. **tdesktop 7.4.0 — strongest new deterministic engine proof** (no
   process boundary, NDEBUG, CFG off, source-verified bug, stage A + fake
   `JSVarRef` + typed-array R/W + C-function hijack host-proven through the
   real bundle; Windows ROP page host dry-run). The live Windows 11 run is
   pending and needs the stack-high-32 ASLR anchor; no Windows VM here.
3. macOS — same architecture, hardened/asserts, binary-only wiring, needs a
   Mac.
4. Android 73029 — the only target with a real process boundary (isolated
   UID 99xxx, SELinux), hence the W2 work.

## Caveats

No desktop/macOS exploit is claimed; MSVC/Windows geometry is untested; the
exact compiled macOS QuickJS is inference from v0.6.0/DMG files, not
disassembly-proven; the session impact is architectural, not demonstrated.
