# What the widget engine is

A Telegram widget is a message that contains an HTML document. Telegram
renders that document inside the chat, above or below the message text. The
document can contain CSS, images, and JavaScript. The scripts run when the
message is laid out. The user does not have to tap anything.

The feature uses the TL types `inputMediaWidget` (what a bot sends) and
`messageMediaWidget` (what a client stores and renders). The protocol layer is
233 in the 13.2 builds used here.

## Two engines, one design

Telegram does not use a full browser for widgets. It uses:

- **litehtml** for HTML and CSS parsing and layout. Telegram maintains a fork
  sometimes called `twidget` or `twlite`.
- **QuickJS-ng** for JavaScript.

On Android both live in `libtmessages.49.so`. The widget sandbox is a Java
object pool (`widget.sandbox` threads) around a native `twidget` runtime. The
JavaScript world is a QuickJS runtime created per widget.

On iOS both live in `TelegramUIFramework`. The widget runtime is a native C++
DOM (`wr::WidgetRuntime`, `wr::WidgetContainer`) on top of QuickJS, laid out by
the litehtml fork and drawn with CoreGraphics. It is not WebKit and not
JavaScriptCore. JavaScriptCore appears in the exploit only as a source of a
stack-pivot gadget.

The JavaScript engine is QuickJS-ng:

| Build | Engine source | Heap limit |
|---|---|---|
| Android beta 72789 (13.2.0) | quickjs-ng snapshot `7a23d8e`, v0.17.0-era | 6 MiB |
| Android beta 72889 / 72929 (13.2.1 / 13.2.2) | fork snapshot `2dfeee3e` | 6 MiB |
| Android release 72801 (13.2.0) | same v0.17.0-era engine in `libtmessages.49.so` | 8 MB (the engine reports `Memory limit exceeded (8 MB)`) |
| iOS 13.2 (36535) | quickjs-ng v0.17.0 | 8 MiB |

The parser bug in `0day-2-RCE-PARSER-SCOPE` is present in all of them. The public
n-days `nday-1-RCE-V7-RGX-1827` and `nday-2-RCE-VARREF-1865` are also present in all of
them, because the app snapshots predate the fixes.

## What a widget message looks like

A minimal widget:

```html
<!doctype html>
<body>
  <div id="v">hello</div>
  <script>
    document.getElementById("v").textContent = "script ran";
  </script>
</body>
```

The engine evaluates each `<script>` block as a separate global script. A
script that throws does not stop the next sibling script. This matters for
multi-stage exploits: stage A can throw a marker after it has done its work,
and stage B still runs.

The engine also accepts `type="text/plain"` script blocks as data, but the
Telegram iOS build may parse or atomize their text before the first script
runs. The iOS route therefore prefers HTML attributes or widget storage for
stage B (see `vulns/0day-2-RCE-PARSER-SCOPE/TINY/README.md`).

## What the sandbox allows

Available to widget JavaScript:

- `eval`, `Function`, `Proxy`, `Reflect`, `async`/`await`, generators.
- `ArrayBuffer`, typed arrays, `DataView`, `BigInt`, `BigInt64Array`.
- `RegExp`, `JSON`, `Map`, `Set`, `WeakMap`, `FinalizationRegistry`.
- `localStorage` / `sessionStorage`, 4,096 bytes per area.
- `document`, `getElementById`, `createElement`, `innerHTML`, `textContent`,
  `style`, events, `canvas`.
- `TelegramWidget.request` (the answer channel; see
  `docs/common/03-the-answer-channel.md`).

Blocked or throwing:

- `fetch`, `XMLHttpRequest`, `WebSocket`, `Worker`.
- The native host bridge (`__host*`) is deleted before user code runs.
- Process creation on iOS. The app sandbox denies `fork`, `posix_spawn`, and
  `execve` even after native code execution.

Limits:

- JS heap: 6 MiB on Android beta, 8 MB on Android release, 8 MiB on iOS.
- CPU: a few hundred milliseconds per script, with a quota window. The exact
  values are build-specific; the widget is stopped when it exceeds them.
- 64 timers, 1,000 scripts.
- Widget HTML: 32,768 bytes raw and 4,096 bytes after zlib level 9 at the bot
  endpoint. The local database path accepts the same blob.

## Why this is an attack surface

The widget HTML comes from a bot or from a message. It is untrusted input. On
72889/72929 and earlier the engine parses it in the app process, next to the
app's own memory. On 72979/72989 it parses in an isolated process. The
JavaScript sandbox is not itself a process boundary; on 72979/72989 the Android
isolated process is the boundary that contains a memory-safety failure. Any
memory-safety bug in QuickJS or litehtml that is reachable from a script can
corrupt the engine heap in either case.

The two bugs in this repository are both in QuickJS:

- The 0day is a parser/compiler bug. It runs during `eval` and needs no host
  API.
- The n-day is a RegExp lifetime bug. It also needs no host API.

A successful exploit ends with native code execution in the widget process.
What that process is depends on the Android build:

| Android build (measured) | Widget process | UID | SELinux | Impact |
|---|---|---:|---|---|
| beta 72889, 72929 and earlier | app process `org.telegram.messenger.beta` | 10346 | `u:r:untrusted_app:s0` | app-private data and app network permissions |
| beta **72979** | `org.telegram.messenger.beta:widgets:org.telegram.utils.twidget.WidgetEngineService` | 99017 | `u:r:isolated_app:s0` | contained process; no app-private data, no network permissions |
| beta **72989** (current) | same isolated service | 99024 | `u:r:isolated_app:s0` | same containment; PING works, v3 detector `el=55ms` |

On 72889/72929 and earlier, a sandbox escape means app-level native code under
the app UID. On 72979/72989, the same parser bug gives native code in an
isolated process. That is real code execution and a DoS surface in that
process, but it is not app-level RCE. App-level Android impact on 72979/72989
requires an isolated-process escape. iOS is unchanged: the widget runs in the
app process as `mobile`.

## Where the code runs

Android:

- Process on 72889/72929 and earlier: `org.telegram.messenger` or
  `org.telegram.messenger.beta` (app UID).
- Process on 72979/72989:
  `org.telegram.messenger.beta:widgets:...WidgetEngineService`
  (isolated UID 99017 on 72979, 99024 on 72989,
  `u:r:isolated_app:s0`).
- Thread: `widget.sandbox` (a pool of render threads).
- Native library: `/data/app/.../lib/arm64/libtmessages.49.so`.
- App data: `/data/user/0/<package>/files/`; not reachable from the 72979/72989
  isolated process.

iOS:

- Process: `ph.telegra.Telegraph`.
- Thread: `message-widget.0` / `.1`.
- Framework: `TelegramUIFramework` inside the app bundle.
- App data: the app container and the shared AppGroup container
  (`telegram-data/account-<id>/postbox/db_sqlite`).

## Version check

Before running any payload, confirm the build:

```sh
# Android
adb shell dumpsys package org.telegram.messenger.beta | grep versionCode
adb shell getprop ro.product.model
adb shell getprop ro.build.version.release

# Android widget process and containment (72979 and later)
adb shell ps -A | grep -E 'WidgetEngineService|org.telegram.messenger.beta'
adb shell cat /proc/<pid>/status | grep -E 'Uid|Gid'
adb shell cat /proc/<pid>/attr/current

# iOS (jailbroken 6s)
ssh mobile@<phone> 'plutil -p /var/containers/Bundle/Application/*/Telegram.app/Info.plist | grep CFBundleVersion'
```

The payloads in `vulns/0day-2-RCE-PARSER-SCOPE/` are tied to the engine generation named in
their README. A new Telegram release can change struct offsets, heap layout, or
the parser code. Re-verify on the host before a device run.
