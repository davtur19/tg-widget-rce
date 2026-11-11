# Telegram Widget RCE

Native code execution in Telegram's in-chat widget engine (QuickJS-ng).

A `sendWidget` message carries HTML and JavaScript. The app renders it with
litehtml and QuickJS-ng when the chat is open. The widget executes on message
layout; no tap is required.

The bugs in this repository were live on the old builds listed below. They
are now fixed in the current Telegram builds; this repository is the
technical research record (n-days).

> Redaction policy: [`REDACTION.md`](REDACTION.md). RCE index:
> [`VULNS.md`](VULNS.md). Non-RCE index: [`NON_RCE.md`](NON_RCE.md).

---

## Bugs

| ID | Bug | CVSS | Old build |
|---|---|---|---|
| BUG-1 | parser 0day `ARG_SCOPE_END` (RCE) | 9.6 / 8.8 | Android 72889/72929/73029/73039, iOS 13.2, tdesktop 7.4.0, macOS 13.1 |
| BUG-2 | direct-eval closure-var truncation (`3e236cb`) | 8.1 | Android 73029/73039 |
| BUG-3 | #1865 captured-var truncation (`8f0d3b6`) | 5.8 | Android 73029/73039 |
| BUG-4 | `Map.clear` UAF (`3ad65ad`) | 6.5 | Android 73029/73039 |
| BUG-5 | `FR.unregister` UAF (`7ca4ac5`) | 6.5 | Android 73029/73039 |
| BUG-6 | `reset_weak_ref` abort (`45c5b9b`) | 6.5 | Android 73029/73039 |
| NDAY-1 | #1827 stale RegExp bytecode (RCE) | 8.8 | Android 13.2.0, iOS 13.2, tdesktop 7.4.0 |
| NDAY-2 | #1865 `var_ref_count` truncation (RCE) | 8.8 | Android 13.2.0 |
| QJS-DOS | other QuickJS n-days | 5.3 / 3.1 | Android 13.2.0 |
| LH-DOS | litehtml, SVG and CSS DoS | 5.3 / 3.1 | Android 13.2.0 |

Full details, per-client status and evidence: [`VULNS.md`](VULNS.md),
[`vulns/`](vulns/), [`NON_RCE.md`](NON_RCE.md).

---

## The parser 0day

Component: QuickJS-ng parser and compiler (`js_parse_for_in_of`, `OP_eval`,
`add_closure_variables`).

A strict function with an empty destructuring parameter and a direct `eval`
in a parameter initializer leaves the argument scope end marker
(`ARG_SCOPE_END = -2`) in place: strict mode skips `add_arguments_arg()`. The
compiler emits `first + 1 = -1` as a 16-bit operand (`0xFFFF`); the runtime
subtracts 1 and uses 65,534 as a variable index.

```js
"use strict";
function f([] = eval("1")) {}
f();
```

The read is 1.31 MB past `b->vardefs`; the write is 8-byte closure records
past a live allocation. The forged `ArrayBuffer.byteLength` is the primitive
for native code execution.

The parser check and the interpreter guard are now in the current builds.

---

## QuickJS-ng fixes

The fixes that closed the engine bugs in this archive. All links point to the
Telegram QuickJS fork (`https://github.com/TelegramMessenger/quickjs`).

| Fix | Bug | Commit |
|---|---|---|
| parser check + interpreter guard | parser 0day `ARG_SCOPE_END` | [`ca3594d`](https://github.com/TelegramMessenger/quickjs/commit/ca3594dae5fd0dd6d667be74a322e8e935a2d217) |
| direct-eval closure-var truncation | BUG-2 | [`3e236cb`](https://github.com/TelegramMessenger/quickjs/commit/3e236cb0ac077fbf47ca1ae500978964f90a3d47) |
| #1865 captured-var truncation | BUG-3 | [`8f0d3b6`](https://github.com/TelegramMessenger/quickjs/commit/8f0d3b6193a01bda29d69b0cab4f03320bcaa027) |
| `Map.clear` UAF | BUG-4 | [`3ad65ad`](https://github.com/TelegramMessenger/quickjs/commit/3ad65ada33124cb975e89163f9b53c6bf446e421) |
| `FinalizationRegistry.unregister` UAF | BUG-5 | [`7ca4ac5`](https://github.com/TelegramMessenger/quickjs/commit/7ca4ac52a862e307b81d97319b1f31382d823beb) |
| `reset_weak_ref` abort | BUG-6 | [`45c5b9b`](https://github.com/TelegramMessenger/quickjs/commit/45c5b9b734a30f8f61a06c434e6a8c9aceee334f) |
| #1827 stale RegExp bytecode | NDAY-1 | [`2b62af1`](https://github.com/TelegramMessenger/quickjs/commit/2b62af194afa1c0779b0ad7cd4b28b339c635c05) |
| #1827 regression test | NDAY-1 | [`1a402cb`](https://github.com/TelegramMessenger/quickjs/commit/1a402cb7e812d8b188b90538b23dadd59e14af33) |

Archive pins: Android 73029 `09bb809`, Android 73039 `b02310a` + `ca3594d`,
Windows/macOS `c24d6b0`.

---

## Evidence

- [`vulns/0day-2-RCE-PARSER-SCOPE/`](vulns/0day-2-RCE-PARSER-SCOPE/): the
  parser 0day, four routes (XTAG, STAG, TINY, IOS27), payloads, evidence.
- [`vulns/nday-1-RCE-V7-RGX-1827/`](vulns/nday-1-RCE-V7-RGX-1827/): #1827.
- [`vulns/nday-2-RCE-VARREF-1865/`](vulns/nday-2-RCE-VARREF-1865/): #1865.
  candidate, not a carrier.
- [`docs/`](docs/): engine, delivery, answer channel, instrumentation,
  dated research notes.
- [`docs/PAYLOAD_CHAIN.md`](docs/PAYLOAD_CHAIN.md): end-to-end chain and
  verification checklist.

Device proofs: Sony XQ-BT52 on 72929/72889 (app-level, UID 10346, C2 in
1.913 s), iPhone 6s on iOS 15.8.8 (`RCE_OK`), iPhone 17e on iOS 27.0 (msg
5725, `RCE_OK`), iOS 13.2 first-window session capture 10/10.

---

## Repository map

```
README.md                  this page
VULNS.md                   RCE index
NON_RCE.md                 one-line index of every non-RCE finding
HISTORY.md                 old-name mapping
REDACTION.md               placeholders and redaction policy
non-rce/                   single fixtures referenced by NON_RCE.md
builders/                  payload builders per route
payloads/                  unique payloads not in vulns/
scripts/                   delivery, gate, two-phase and verification scripts
bot/                       sendWidget/answerWidgetQuery, servers, runbook
docs/                      engine, delivery, instrumentation, research notes
vulns/                     per-ID README, payloads, scripts, evidence
```

---

## Prerequisites

Host tools:

- Python 3.10+. The delivery and database tools use only the standard
  library.
- `git`, `ssh`, `curl`, `zlib` (Python standard library).
- For payload rebuilds: `node` and `terser` (`npm install -g terser`).
- For host QuickJS tests: a C compiler and the QuickJS-ng v0.17.0 source. The
  harness is in `docs/common/tools/quickjs-widget-harness.c`.

Bot API:

- A Telegram bot allowed to send widgets. Both the beta base
  (`https://api.telegram.org/beta/bot<TOKEN>/sendWidget`) and the standard
  base (`https://api.telegram.org/bot<TOKEN>/sendWidget`) serve `sendWidget`.
  A bot or account that is not whitelisted gets
  `INPUT_MEDIA_WIDGET_NOT_ALLOWED`.

---

## Disclosure

All findings in this repository are now n-days: they were live on the old
builds listed above and are fixed in the current Telegram builds. The
non-fixed findings are kept in the private archive. A vendor-facing
disclosure report exists and is not part of this repository.

Account identifiers, device serials, chat ids and tokens are redacted per
[`REDACTION.md`](REDACTION.md).
