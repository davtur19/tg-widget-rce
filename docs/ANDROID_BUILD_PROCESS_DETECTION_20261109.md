# Android build/process-model detection (2026-11-09)

The question is how to tell the **old app-level build** from the **new isolated
build** so one payload can choose the right endgame. The answer is the
process context after the parser RCE, not a JS build string.

## The two models

| model | builds | widget process | parser RCE lands in | endgame |
|---|---|---|---|---|
| app-level | 72929/72889 and older | app process | UID 10346, `u:r:untrusted_app:s0` | direct session stealer |
| isolated | 72979/72989+ | `:widgets` service | UID 990xx, `u:r:isolated_app:s0` | W2 second stage, then session stealer |

## Definitive runtime check (after parser RCE)

From the native payload, call Java/JNI or read `/proc`:

```text
android.os.Process.myUid()
android.os.Process.isIsolated()
/proc/self/attr/current      -> u:r:untrusted_app:s0 | u:r:isolated_app:s0
/proc/self/cmdline           -> org.telegram.messenger.beta
                                org.telegram.messenger.beta:widgets:...WidgetEngineService
```

Rules:

- `myUid() == 10346` and `isIsolated() == false` and cmdline is the app
  package → **app-level build**: run the session stealer directly.
- `myUid() >= 99000` (observed 99017/99024/99062/99064), `isIsolated() ==
  true`, SELinux `isolated_app`, cmdline contains `:widgets` → **isolated
  build**: the isolate cannot read app data; run the W2 app-process escape,
  then the same session stealer.

This branch is reliable and needs no leak. The UID is per-process-generation
but always in the isolated range; the cmdline/`isIsolated` check is stable.

## What does *not* work as a build gate

- `TelegramWidget.profile` is the **API version** constant `1`; it is not the
  app version/build.
- `navigator.userAgent`/`platform` are sandbox stubs; the real device/version
  is not exposed.
- The host `create` context carries widget data (`canQuery`, `chatType`,
  viewer, theme, locale, screen), not the app versionCode.
- `PackageManager`/`BuildConfig` can be read in the app-level process, but
  package-manager access is not reliable from `isolated_app`; do not gate on
  it.
- A JS-only widget cannot tell the model before RCE. Use the runtime check
  after the parser reaches native code, or a server-side per-build delivery
  decision.

## Payload shape

A single payload can ship both branches:

```
parser stage A (same for both builds)
  -> native probe: isIsolated / uid / cmdline
     -> app-level: session stealer
     -> isolated: W2 second stage -> session stealer
```

The app-level branch is device-proven (72929, UID 10346, session files). The
isolated branch is the W2 chain under active work; its force/timing harness is
the current blocker.
