# Common documentation: index

Start here. These pages are shared by every finding.

| Page | What |
|---|---|
| `01-the-widget-engine.md` | What a widget is, the two engines, the sandbox, the limits. |
| `02-widget-delivery.md` | Bot `sendWidget`, Postbox `t7`, Frida/local, Android `cache4.db`. |
| `03-the-answer-channel.md` | `answerWidgetQuery`, the `data` field, limits, pacing, chunks. |
| `04-devices.md` | Sony, Pixel, iPhone 6s, iPhone 17e, Samsung. |
| `05-markers-and-evidence.md` | The marker protocol and what “proven” means. |
| `06-glossary.md` | Terms and the original-to-new file name mapping. |
| `07-methodology.md` | Host first, one device at a time, reproducibility, negatives. |
| `08-authorization-and-ethics.md` | Scope, disclosure, data handling, legal. |
| [`docs/c2/overview.md`](../c2/overview.md) | The local C2, the implant, the loopback rules. |
| [`docs/PAYLOAD_CHAIN.md`](../PAYLOAD_CHAIN.md) | End-to-end chain, delivery, evidence and checklist. |
| [`docs/CRITIQUE_20261108.md`](../CRITIQUE_20261108.md) | Prioritized audit of this repository. |
| [`docs/INDEX.md`](../INDEX.md) | Current runbooks vs dated research notes. |

## The one-paragraph version

Telegram renders bot widgets as HTML/JavaScript, using litehtml for layout and
QuickJS-ng for scripts. On Android the process model is build-dependent: 72929
and earlier run the engine in the app process, while 72979 and 72989 run it in
an isolated widget process (UID 99017/99024, `u:r:isolated_app:s0`). A widget is
delivered by a bot (`sendWidget`), by a local database row (Android
`cache4.db`), by an iOS Postbox `t7` rewrite, or by a Frida insert on a
jailbroken 6s. A widget can ask the bot a question through
`TelegramWidget.request`; the bot answers with `answerWidgetQuery` and the
`data` field, at most 1,024 bytes per answer. The sandbox has a 6-8 MiB JS
heap and a short CPU budget. A memory-safety bug in QuickJS or litehtml can
escape the JavaScript sandbox. On 72929 and earlier that gives app-level code
execution; on 72979/72989 it gives code execution contained in the isolated
process.
The campaign tested this on a Sony XQ-BT52, a Pixel 9, an iPhone 6s, and
an iPhone 17e, and prepared a Samsung test.

## Other docs

| Path | What |
|---|---|
| [`docs/instrumentation/`](../instrumentation/) | 17e USB/DDI/Frida/chat-open, 6s Frida tools. |
| [`bot/`](../../bot/) | `sendWidget` / `answerWidgetQuery`, servers, chunks. |
| [`docs/c2/`](../c2/) | c2560s server/loader/bootstrap, #1827 C2 reference. |
| [`VULNS.md`](../../VULNS.md) | RCE index. |
| [`NON_RCE.md`](../../NON_RCE.md) | one-line non-RCE index. |
| [`HISTORY.md`](../../HISTORY.md) | old-name mapping. |
