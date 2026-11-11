# Update-surviving app-data loader — Telegram 72799 audit

Date: 2026-11-02. Scope: **host/source/native only**; no device or emulator was
used for this audit. Target: `org.telegram.messenger.beta` 13.2.0 beta,
versionCode **72799**, arm64, Sony XQ-BT52 (Xperia 10 III), Android 13,
build 62.2.A.0.533, UID **10357**. The first exploit is assumed to give app-UID
code execution and arbitrary app-data write; the widget chat/QuickJS path is
excluded by the task.

Question: is there a **Telegram-specific component that loads/executes code
from app data**, reachable after an app update by a surviving alarm/job or
another system event, **without** the widget chat?

**Verdict: no such loader was found.** The *trigger* layer is real: alarms and
jobs survive `pm install -r`, and `AppStartReceiver`, `KeepAliveJob` and
`NotificationRepeat` can start the Telegram process without user interaction.
The *loader* layer is closed: within Telegram's own component/startup code the
only app-data code-load paths are

1. `ks.g`'s `System.load(files/lib/libtmessages.49loc.so)`, which is reached
   only inside `catch (Error)` after `System.loadLibrary("tmessages.49")`
   fails, and app data cannot force that failure; and
2. the ART runtime app image `cache/oat_primary/arm64/base.art`, which is a
   genuine startup code load but is keyed to the absolute
   `/data/app/~~<hash>/.../base.apk` path; an update changes that path, and the
   device logs show the change.

The in-app updater installs APKs through `ACTION_VIEW` + `FileProvider`; it is
user-gated and signature-checked by `PackageManagerService`. AppCenter
Distribute is a **dead manifest component** (its classes are absent from all
four dex files). There is no split/dynamic-feature loader, no `DexClassLoader`
on app data, and no `app_process`/`linker64` call from any Telegram component.

Status: **host/source/native only.** The `ks` gate has a device positive
control from the prior lab (forced primary failure → app-data `.so` loaded);
the ART update gate has device path-change evidence but the T4 rejection run is
pending; the trigger-survival (T1), installer-gate (T5) and AppCenter (T6)
device tests are planned, not executed in this session. The note distinguishes
source-proven from device-pending rather than claiming a device run.

This note does not modify the main report. Lab artifacts:
`lab/loader_update_trigger_audit/` (ranked table, exact refs, no-go list,
reproducible scans, new trigger helper, device plan).

---

## 0. The two layers, kept separate

| Layer | Question | Answer |
|---|---|---|
| Trigger | Can a system event after an update start Telegram code without the user? | **Yes.** Inexact alarms (`windowLength = -1`; the exact-alarm revocation predicate is `windowLength == 0`) and JobScheduler jobs survive an update; `AppStartReceiver` (an explicit `org.telegram.start` broadcast), `KeepAliveJob` (a persisted job) and `NotificationRepeat` (a service PendingIntent) all start the process. A `BOOT_COMPLETED` PendingIntent is **not** usable: it is a protected broadcast and the send is attributed to the creator UID (§2.1). |
| Loader | Does any code that runs at that point load code from app data? | **No.** The process start reaches `w0.onCreate` → `ks.g` (primary `System.loadLibrary`, app-data fallback only on `Error`) and the ART app image (rejected after the update's new `/data/app/~~<hash>`). Nothing else in the startup/component path loads app data as code. |

The rest of this note proves the second row and records the exact gates. The
trigger row is useful because it means the negative is not "the app never
wakes"; it is "the app wakes and still does not load the file".

---

## 1. Telegram's own APK update/install path

### 1.1 The update state object `k1`

`org.telegram.messenger.k1` holds the downloaded-update state:

* constructor `k1.smali:37` reads `version`, `versionCode`, `changelog`,
  `path`, `lastCheck` from `SharedPreferences("beta")` (`:88`, `:107`, `:123`,
  `:139`, `:155`);
* `k1.a(Runnable, boolean)` (`:436`) is the update **check**;
* `k1.b(boolean)` (`:585`) is the **download**;
* `w0.g()` is the abstract "downloaded APK file" accessor (`w0.smali:2201`),
  implemented by `ApplicationLoaderImpl.g()` (`ApplicationLoaderImpl.smali:90`),
  which returns `new File(k1.d)` if it exists (`:113–:137`).

The server response parser is in `ng.smali:4230` (`pswitch_15`):
`version` (`:4278`), `version_code` (`:4290`), `file_url` (`:4302`),
`changelog` (`:4314`); it stores `file_url` into `k1.f` (`:4469`) and clears
the old local path `k1.d` (`:4457`) when a new version is found. The download
callback `e4.run()` sets `k1.d` to the downloaded file's absolute path
(`e4.smali:2266`) and persists it with `k1.f()`.

**Critical build fact:** in 72799 the update check is disabled. `k1.a` builds
the URL as the literal string `"null"` (`k1.smali:565`) and passes it to the
generic HTTP task `c1`; `new URL("null")` throws and the callback receives
`null`. There is no server-driven update in this beta build. `k1.d` can only be
set by an app-data writer (the `path` preference) or by `ng` parsing a server
response; the latter is unreachable because the check URL is the literal
`"null"`.

### 1.2 The download

`k1.b(true)` creates `HttpGetFileTask`, sets the override extension to `"apk"`
(`k1.smali:704–:749`), and writes the response body to a `File` obtained from
`vh/n5.w(account, "apk")` → `b8.K(...)` (`HttpGetFileTask.smali:409–:459`).
That path is under the app's cache/files tree, i.e. **app-data writable**. The
file is a plain APK; nothing loads it as code.

### 1.3 The install helper

There is no `PackageInstaller` session in Telegram. The install is an
`ACTION_VIEW` intent with MIME `application/vnd.android.package-archive` and a
`FileProvider` URI:

* `i0.t2(File, name, mime, Activity, ..., boolean)` at `i0.smali:35719`:
  * `canRequestPackageInstalls()` at `:35950`;
  * `FileProvider.getUriForFile` at `:36004` / `:36098`;
  * `startActivityForResult(..., 500)` at `:36074` / `:36129` / `:36138`.
* `ApplicationLoaderImpl.v(Activity, TLRPC$Document)` at
  `ApplicationLoaderImpl.smali:198` is the "open APK document" variant:
  `package-archive` at `:274`, `FileProvider` at `:292`,
  `startActivityForResult` at `:337`.
* All `i0.t2` call sites are UI: `xh/z.smali:126`, `rh/u1.smali:195`,
  `bh/f.smali:2695`, `ag/e0.smali:3203`, `av.smali:2455`, `sr.smali:1337`,
  `t7.smali:1514`; the `w0.g()` (downloaded file) call sites are
  `c61.smali:528`, `b61.smali:801`, `bh/f.smali:2665`. There is no
  receiver/service/job call site.

`REQUEST_INSTALL_PACKAGES` is declared (manifest line 155). `INSTALL_PACKAGES`
is **not** a requested permission; the only occurrence is the
`android:permission` attribute on `RefererReceiver` (manifest line 823), which
restricts who may send that broadcast. There is no `sharedUserId`.

### 1.4 The platform gates

`PackageInstallerSession.computeUserActionRequirement()` (AOSP 13,
`PackageInstallerSession.java:829–:883`) only skips the confirmation UI when the
installer holds `INSTALL_PACKAGES`, `INSTALL_PACKAGE_UPDATES` (for an update),
`INSTALL_SELF_UPDATES`, `UPDATE_PACKAGES_WITHOUT_USER_ACTION` (with
`USER_ACTION_NOT_REQUIRED` and installer-of-record/self-update), or
`INSTALL_DPC_PACKAGES` (device owner), or is root/system. Telegram holds none of
these and is not a device owner, so `computeUserActionRequirement()` returns
`USER_ACTION_REQUIRED`: the system installer UI is mandatory.

`InstallPackageHelper.preparePackageLI()` (`InstallPackageHelper.java:1269–:1290`)
checks the upgrade key set and calls
`PackageManagerServiceUtils.verifySignatures(...)`. A different signing key
throws `INSTALL_FAILED_UPDATE_INCOMPATIBLE` before the package is replaced. The
installed certificate is `CN=Nikolay Kudashov, OU=VK, O=VK,
L=Saint-Petersburg`, SHA-256
`49c1522548ebacd46ce322b6fd47f6092bb745d0f88082145caf35e14dcc38e1`
(`apksigner verify --print-certs` on 72799).

**Consequence.** An app-UID attacker can place an APK at `k1.d`, but cannot
silently install it, cannot install a different-signature update over Telegram,
and cannot make Telegram load it in-process. The OS gates are user action and
the Telegram signing key; neither is app-data controlled.

### 1.5 PackageInstaller / SourceDir / loadedApk

A full smali scan of all four dex trees:

* `PackageInstaller` appears only in `k6/g.smali:1259–:1314`
  (`getPackageInstaller().getAllSessions()` to detect a GMS install session).
  There is **no** `createSession`, `SessionParams`, `commit`, or
  `installExistingPackage`.
* `SplitInstall` / `SplitCompat` / `AssetPackManager` / `splitSourceDirs` /
  `splitPublicSourceDirs` / `splitNames`: **0 hits**.
* `ApplicationInfo.sourceDir` is only **read** in `ks.smali:2634` (the APK
  `ZipFile` used by `ks.k`) and `r4/d.smali:5984` (ProfileInstaller reading the
  APK asset). There is no write to `sourceDir`, `loadedApk`, `mPackageInfo`,
  `mClassLoader`, or `mInitialApplication`.
* `ActivityThread` reflection exists in `e0/e.smali` only for `mMainThread`,
  `mToken` and activity-lifecycle calls, not for the class loader or
  `LoadedApk`.

A split/APK cannot be injected into the running class loader from app data:
ART builds the loader from `ApplicationInfo` at process start, and an app-UID
process cannot alter that `ApplicationInfo` before `Application.onCreate`.
Even a `PackageInstaller` session (which Telegram does not create) would be
user-gated and signature-gated as above.

---

## 2. Manifest components and surviving triggers

The manifest has 95 components (parsed in
`lab/loader_update_trigger_audit/outputs/04_components.tsv`). The relevant ones:

### 2.1 `AppStartReceiver` — the best broadcast trigger, but `BOOT_COMPLETED` is protected

`org.telegram.messenger.AppStartReceiver` (manifest line 799, `exported=false`)
has an intent filter with **two** actions: `org.telegram.start` (line 804) and
`android.intent.action.BOOT_COMPLETED` (line 805). Its `onReceive`
(`AppStartReceiver.smali:25`) only acts when the action equals
`BOOT_COMPLETED`; it then posts `lag/f3(9)` on a background executor. That
runnable calls `uz.t()` and `w0.x()` (`ag/f3.smali`, case 9 = `pswitch_13`),
which starts or stops `NotificationsService` according to the push/keep-alive
prefs; it does not load app data.

A PendingIntent created by UID 10357 and sent by `AlarmManagerService` is
attributed to the creator UID. `PendingIntentRecord.sendInner()` passes the
creator `uid` to `broadcastIntentInPackage()`; `ActivityManagerService`
then treats that as `callingUid` in `broadcastIntentLocked()` and rejects a
protected broadcast from a non-system caller
(`ActivityManagerService.java:13667–:13701`). `BOOT_COMPLETED` is a protected
broadcast, so the `BOOT_COMPLETED` variant is **source-blocked**. This is a
correction to the earlier re-trigger note, whose helper's `broadcast` mode used
`BOOT_COMPLETED` and was not device-tested.

The non-protected `org.telegram.start` action is delivered. The receiver ignores
it, but **the process has already started**, so `Application.onCreate` →
`ks.g` has run. That is enough to test the loader; it does not run `uz.t()`.
The new helper `lab/loader_update_trigger_audit/helper/Retrigger2.java` uses
`org.telegram.start` (`wake` mode) and keeps `BOOT_COMPLETED` as a `boot`
negative control.

### 2.2 `KeepAliveJob` — the most robust job trigger

`org.telegram.messenger.KeepAliveJob` (manifest line 712, `exported=false`,
`BIND_JOB_SERVICE`) extends `support.JobIntentService`. `onHandleWork`
(`KeepAliveJob.smali:176`) holds a `CountDownLatch` for 60 s
(`Utilities.e.d(runnable, 0xea60)`); it does not load code. On API 26+ the
`JobIntentService` is a JobScheduler job. A job scheduled by UID 10357 for
`KeepAliveJob` survives an ordinary update: `JobSchedulerService` cancels jobs
only on `ACTION_PACKAGE_FULLY_REMOVED` (`:910–:919`) or
`ACTION_PACKAGE_RESTARTED` (force-stop, `:967–:974`), not on
`PACKAGE_REMOVED` with `EXTRA_REPLACING` / `PACKAGE_ADDED`. Jobs are persisted
in `/data/system/job/jobs.xml`.

### 2.3 `NotificationRepeat` — a service PendingIntent trigger

`org.telegram.messenger.NotificationRepeat` (manifest line 727,
`exported=false`) is an `IntentService`. `onHandleIntent`
(`NotificationRepeat.smali:29`) reads `currentAccount`, checks
`e20.r(account)`, and posts `xd(account, 2)`; that runnable repeats
notifications. No code load. A `PendingIntent.getService` created by UID 10357
can start it (same UID, no protected-action check), so it is a valid
update-surviving trigger.

### 2.4 `BringAppForegroundService` — process start, BAL-gated activity

`org.telegram.messenger.BringAppForegroundService` (manifest line 717,
`exported=true`) is an `IntentService`. `onHandleIntent`
(`BringAppForegroundService.smali:25`) starts `LaunchActivity` with
`FLAG_ACTIVITY_NEW_TASK`. The service itself starts the process (so
`Application.onCreate`/`ks.g` runs), but the activity start is subject to the
Android 13 background-activity-launch check; a foreground service is not an
exemption, and the only normal-app exemption Telegram could use is
`SYSTEM_ALERT_WINDOW` (declared at manifest line 133, a special access not
granted by default). This is a process trigger, not a loader.

### 2.5 `ProfileInstallReceiver` — profile write, not code

`androidx.profileinstaller.ProfileInstallReceiver` (manifest line 1214,
`exported=true`, `android:permission="android.permission.DUMP"`) handles
`INSTALL_PROFILE` / `SAVE_PROFILE` / `SKIP_FILE` / `BENCHMARK_OPERATION`.
`onReceive` (`ProfileInstallReceiver.smali:21`) calls `r4/d.s(...)`
(ProfileInstaller). `r4/d` reads the APK's `assets/dexopt/baseline.prof` and
writes `/data/misc/profiles/cur/0/<pkg>/primary.prof`; it contains no
`DexClassLoader`/`System.load`/`System.loadLibrary`. The app UID does not hold
`DUMP`; a shell test can invoke it, but it is not an app-UID trigger and it is
not code.

### 2.6 `DownloadManagerReceiver` — a dead AppCenter component

`com.microsoft.appcenter.distribute.DownloadManagerReceiver` (manifest line
250, `exported=true`, no permission) would be an attractive exported trigger:
it handles `DOWNLOAD_COMPLETE` / `DOWNLOAD_NOTIFICATION_CLICKED`. But the class
is **absent from all four dex files**. `dexdump -l plain` over
`classes.dex`/`classes2.dex`/`classes3.dex`/`classes4.dex` reports zero
`com/microsoft/appcenter` class descriptors; `strings` over the dex files
reports zero `com/microsoft/appcenter` hits. The same is true for
`com.microsoft.appcenter.distribute.DeepLinkActivity` (manifest line 233). The
SDK classes are not in the APK; only the manifest entries remain (consistent
with a manifest-merger/plugin leftover, but the cause does not matter here:
the component cannot be instantiated). A broadcast to the receiver fails with
`ClassNotFoundException` / "Unable to instantiate receiver"; a deep link to the
activity fails with "Unable to instantiate activity". These are DoS surfaces,
not loaders.

### 2.7 Other receivers/services

The remaining exported receivers are either permission-protected
(`RefererReceiver` requires `INSTALL_PACKAGES`, `FirebaseInstanceIdReceiver`
requires `com.google.android.c2dm.permission.SEND`), exported=false, or
process only app code:

* `GcmPushListenerService` (exported, FCM) processes a `RemoteMessage`; it can
  download media but does not load code.
* `SmsReceiver` (exported) parses an SMS Retriever result; no code load.
* `WearAuthListenerService`, `AuthenticatorService`,
  `ContactsSyncAdapterService`, `MusicBrowserService`,
  `TelegramConnectionService` are Binder/service entry points; no code load.
* `VideoEncodingService`, `StoryUploadingService`, `ImportingService`,
  `LocationSharingService`, `MusicPlayerService`, `NotificationsService` are
  exported services; the forward call-graph scan finds no `System.load` /
  `DexClassLoader` / `PackageInstaller` sink from them (the only "load" hits
  are the shared `w0.w()` startup path, §3).
* `ChatsWidgetProvider` / `ContactsWidgetProvider` are `exported=false` app
  widgets; `RemoteViews` only.
* `AlarmManagerSchedulerBroadcastReceiver` (datatransport) is
  `exported=false`; it schedules an analytics upload, no code load.

The forward call-graph scan
(`lab/loader_update_trigger_audit/outputs/06_component_sinks.txt`) finds **no
code-load sink at depth 14** from `AppStartReceiver`, `KeepAliveJob`,
`BringAppForegroundService`, `NotificationRepeat`, `SmsReceiver`,
`RefererReceiver`, `ProfileInstallReceiver`, or the exported media services.
The only `System.load` hits from other components are the shared
`w0.w()` → `ks.g` startup path, which is conditional (§3).

---

## 3. Startup: `Application.onCreate`, providers, WebView, twidget

### 3.1 `w0.onCreate` → `ks.g`

`ApplicationLoaderImpl` extends `w0` and overrides only `b` (`:21`), `g`
(`:90`), `q` (`:175`) and `v` (`:198`); it has no `onCreate` and no static
initializer. `w0.onCreate` is `final` (`w0.smali:2263`). The startup order is:

```
w0.onCreate
  getApplicationContext / getPackageInfo / Typeface / Build.*   (no app-data read)
  w0.smali:2734   ks.g(context)
  w0.smali:2740   ConnectionsManager.native_setJava(false)
```

`w0.w()` (the receiver/service entry helper) calls `ks.g` at `w0.smali:1405`.
`w0` and `ApplicationLoaderImpl` have no `<clinit>`; the pre-`ks.g` code reads
no app-writable file (the beta log file is write-only). This matches the
prior `native_appdata_audit.md` §1 and the smali scan.

`ks.g` (`ks.smali:1439`):

```
1480–1484  System.loadLibrary("tmessages.49")      in try
1507       .catch Ljava/lang/Error;                (the fallback gate)
1611–1625  files/lib/libtmessages.49loc.so        if exists
1655–1672  System.load(absolutePath)               (the app-data load)
1769       ks.k(context, files/lib, loc, arch)     extraction from sourceDir
1831       retry System.loadLibrary("tmessages.49") if ks.k returned false
```

`ks.k` (`ks.smali:2556`) deletes `files/lib/*`, opens
`ZipFile(getApplicationInfo().sourceDir)`, extracts
`lib/<Build.CPU_ABI>/libtmessages.49.so` to
`files/lib/libtmessages.49loc.so`, and `System.load`s it (`:2803`). The local
file is consulted **before** `ks.k` does any cleanup; on a normal start
(primary load succeeds) nothing under `files/lib` is touched.

### 3.2 The `ks` gate, exactly

`System.loadLibrary("tmessages.49")` is resolved from install-owned paths:

* `DexPathList.findLibrary` searches `ApplicationInfo.nativeLibraryDir`
  (`/data/app/~~<hash>/<pkg>/lib/arm64`) and the APK's
  `base.apk!/lib/arm64-v8a` (`LoadedApk.makePaths`, AOSP 13
  `LoadedApk.java:546,558`; `DexPathList` element dump in
  `lab/loader_update_trigger_audit/evidence/`).
* If `findLibrary` returns null, `Runtime.loadLibrary0` retries
  `dlopen("libtmessages.49.so")` by name; the linker namespace's **search**
  path is the same `library_path` (the two install-owned entries), not app
  data. App data is on the namespace's **permitted** path
  (`/data:/mnt/expand:/data/user/0/pkg`), which is why an absolute
  `System.load("/data/user/0/...")` is allowed, but `dlopen` does not search
  it.

The Sony device log confirms the exact search path and the successful primary
load after the 19:05 update:

```
11-01 19:17:11.143  nativeloader: Configuring clns-5 for other apk
  /data/app/~~r1vDzV8CpQVWKXLwu8aDPA==/org.telegram.messenger.beta-JVB3quhnKMMIKSJdj4fj2A==/base.apk
  library_path=/data/app/~~r1vDzV8.../lib/arm64:/data/app/~~r1vDzV8.../base.apk!/lib/arm64-v8a
  permitted_path=/data:/mnt/expand:/data/user/0/org.telegram.messenger.beta
11-01 19:17:11.235  nativeloader: Load /data/app/~~r1vDzV8.../lib/arm64/libtmessages.49.so ... ok
11-01 19:17:11.xxx  tmessages: loaded normal lib
```

(`evidence/evidence_20261101/new_beta_72799/nb_v2_run10.log:15288–15317`;
`nb_v4_run2.log:14593–14594`.)

The fallback is real when the primary is forced to fail. The root-assisted
positive control (prior lab, 2026-11-01) moved the install-owned library aside:

```
nativeloader: Load libtmessages.49.so ... dlopen failed: library "libtmessages.49.so" not found
System.err: java.lang.UnsatisfiedLinkError: dlopen failed: library "libtmessages.49.so" not found
tmessages: Load local lib
System: Attempt to load writable file: /data/user/0/.../files/lib/libtmessages.49loc.so ...
nativeloader: Load /data/user/0/.../files/lib/libtmessages.49loc.so ... ok
```

(`evidence/evidence_20261101/persistence/fallback_test.txt:14–18`.)

**The gate is the primary `System.loadLibrary` failure.** App data cannot
produce it: the native lib is install-owned (`system:system`, read-only), the
APK entry is install-owned, the linker search path is fixed, `JNI_OnLoad`
registers compile-time literal classes/methods, and no pre-`ks.g` app-data
read can influence the load. The only app-data file in this path is the ART
image (§4); using it to break `JNI_OnLoad` is the same-artifact circularity
already documented in `notes/loader_ks_fallback.md`.

### 3.3 Providers and `androidx.startup`

The startup providers are `androidx.startup.InitializationProvider`
(manifest line 1114, `exported=false`), `FirebaseInitProvider`,
`MlKitInitProvider`, `FileProvider` (`exported=false`),
`androidx.car.app.connection.provider` (class absent), and
`androidx.credentials...MetadataHolder`. `InitializationProvider.onCreate`
(`InitializationProvider.smali:81`) discovers initializer class names from
**manifest metadata** and calls `Class.forName`; the names are fixed to
`EmojiCompatInitializer`, `ProcessLifecycleInitializer`,
`ProfileInstallerInitializer`. `EmojiCompatInitializer` loads a font asset,
`ProfileInstallerInitializer` schedules a profile write,
`ProcessLifecycleInitializer` registers lifecycle callbacks. None loads a dex
or native library from app data. The other providers initialize Firebase/MLKit
from APK resources and metadata; `FileProvider` serves files but does not load
them. `androidx.startup` cannot add an initializer from app data because the
class list is in the APK manifest.

### 3.4 WebView at startup

There is **no startup WebView**. `w0.smali`, `ApplicationLoaderImpl.smali`,
`LaunchActivity.smali` and `AppStartReceiver.smali` contain zero `WebView`
references. The eight construction sites are UI (BotWebView, InstantView,
ArticleViewer, PhotoViewer, group-call/video UI); `WebViewAssetLoader` and
`javascript:` are absent. Bot/IV/proxy set file access false; the ArticleViewer
`r1` sets content access true but not file access, and targetSdk 36 defaults
file access off. The forward component scan finds WebView construction only
from `LaunchActivity`, `BubbleActivity`, `ExternalActionActivity` and
`VoIPService` (via the PhotoViewer/group-call UI); none loads an app-data HTML
file at startup. A WebView would be a JS sandbox, not app-UID native code, and
there is no startup trigger.

### 3.5 twidget / QuickJS

`WidgetSandboxNative` (`WidgetSandboxNative.smali`) has no `<clinit>`; its
native methods are registered by `JNI_OnLoad` when `libtmessages.49` loads.
The sandbox bundles are the APK assets `assets/WidgetSandbox/WidgetJS/*`,
extracted to `files/widget-sandbox/<hash>/` by `b0.a(Context)`; the engine is
created by `k0` and is started from the chat view (`ChatMessageCell` →
`WidgetSandboxNative.create`). No job/receiver/provider starts it. This is the
excluded path; it is not a startup loader.

---

## 4. The ART app image: real startup code load, but update-fragile

`cache/oat_primary/arm64/base.art` is the only app-data file ART maps as an app
image at process start. The device tombstone shows it mapped:

```
6a000000-6a4a3fff rw-  [anon:dalvik-/data/user/0/org.telegram.messenger.beta/cache/oat_primary/arm64/base.art]
```

(`evidence/evidence_20261101/new_beta_72799/tombstone_20.txt:386`.)

The image is accepted on the **same install** (the prior lab reached
`w0.onCreate` with a forged `ks` class; the remaining blocker was a
`mirror::Class` layout bug in `InitializeClass`, not the image loader). The
update blocker is the image's `DexCache` location string:

```
/data/app/~~r1vDzV8CpQVWKXLwu8aDPA==/org.telegram.messenger.beta-JVB3quhnKMMIKSJdj4fj2A==/base.apk
```

(`lab/loader_startup_components/outputs/art_update_path_check.txt`).

ART's `ImageSpace::OpenAndSetDexFiles()` reads each `DexCache` location and
calls `OatFile::OpenOatDexFile(location)`
(`art17/runtime/gc/space/image_space.cc:3100–:3135`);
`OatFile::GetOatDexFile()` first looks up the **exact** string in the current
oat dex table, then tries `DexFileLoader::GetDexCanonicalLocation`
(`art17/runtime/oat/oat_file.cc:2240–:2290`). An update installs to a new
`/data/app/~~<new-hash>` directory. The old absolute path is neither an exact
key in the new oat table nor a resolvable symlink (the old directory is
system-owned and removed), so `OpenAndSetDexFiles()` fails and ART falls back
to the APK dex / regenerates a legitimate image.

The device proves the path change: before the 19:05 update the app loaded from
`/data/app/~~GZ-XxU3O9EXLwdaRBQnJag==/...` (`logcat_survB.txt:13707`,
`logcat_fastpath.txt:14497`), after the update from
`/data/app/~~r1vDzV8CpQVWKXLwu8aDPA==/...`
(`nb_v2_run10.log:15288`, `nb_v4_run2.log:14593`). The `am_kill` reason is
`installPackageLI` (`nb_v2_run10.log:13457`). The image file survives the
update, but the executable image does not.

The only ways to make it survive would be to know the new random
`~~<hash>` before the update, to create a symlink at the old system-owned path,
or to rewrite the image after the update but before the next process start.
None is available from app data: the path is generated by
`PackageManagerService`, `/data/app` is not app-writable, and the first process
start after the update loads the image before any Telegram/attacker code runs.
Rewriting the image after the update requires the code execution that the
image was supposed to provide (circular).

An ART/Mainline update is a second invalidation: `InitAppImage` checks the boot
image checksum (`image_space.cc:1289–:1332`), so a new boot image rejects the
forged image even on the same app install.

---

## 5. `System.load` / `app_process` / `linker64` from a job or receiver

A full scan of all four dex trees (`outputs/03_code_load_sinks.txt`):

* `System.load(String)`: **only** `ks.g` (`ks.smali:1672`) and `ks.k`
  (`ks.smali:2803`). Both are the `ks` path; both are reached only after the
  primary `System.loadLibrary("tmessages.49")` fails or inside `ks.k`.
* `System.loadLibrary(String)`: `ks.g` (`:1484`, `:1831`),
  `org.webrtc.NativeLibrary$DefaultLoader` (`:78`, name from the fixed
  `NativeLibrary.initialize("jingle_peerconnection_so")`), and
  `ThickLanguageIdentifier` (`:234`, literal `"language_id_l2c_jni"`). No
  variable/app-data name.
* `DexClassLoader` / `InMemoryDexClassLoader` / `DexFile.loadDex` /
  `defineClass`: **0 hits**.
* `PathClassLoader` / `DelegateLastClassLoader`: only `y6/e.smali:2347`,
  `:2380` (GMS Dynamite). The path comes from the GMS
  `com.google.android.gms.chimera` provider, not Telegram app data; a UID
  10357 process cannot write GMS data. `y6/h` is the pre-API-29 fallback with
  the same GMS path.
* `Runtime.exec` / `ProcessBuilder`: only `o6.smali:1564`/`:1592`, the
  EmuDetector running the fixed `/system/bin/netcfg` with no argument and
  working directory `/system/bin`. No `app_process`, `linker64`, `sh`, or
  variable command in Telegram's Java code.
* Native `dlopen` in `libtmessages.49.so`: the only real call sites are WebRTC
  NetworkMonitor's fixed `libnetd_client.so`/`libandroid.so`; the generic
  `sub_181CA18` wrapper has data-only xrefs. No `android_dlopen_ext`.
  `liblanguage_id_l2c_jni.so` imports `dlopen` for TFLite delegates but only
  system-library literals. (Prior IDA audit:
  `lab/loader_startup_components/outputs/native_dlopen_sites.txt`,
  `notes/twidget_native_audit.md`.)

The first exploit's one-call `system()` primitive *can* run
`/system/bin/linker64 /data/user/0/<pkg>/files/loader.so` or
`app_process` as UID 10357 (the prior `loader_app_process.md` and
`loader_tgs_native.md` prove the SELinux policy). But that is the **exploit**,
not a Telegram component: it is a new app-UID process in the app's cgroup, it
dies on `pm install -r` (`notes/android_update_daemon_survival.md`), and no
Telegram JobService/BroadcastReceiver calls it. It does not satisfy "triggerable
after an update by a surviving alarm/job" because the surviving event starts
Telegram's component, not the attacker's helper.

---

## 6. Ranked table

Ranking: real code load first, then automatic startup/trigger, then app-data
input, then update survival. "Code" means executes code, not parses data.

| # | Surface | Exact entry | Code | Trigger after update | App-data | Update | Verdict | Sony test |
|---|---|---|---|---|---|---|---|---|
| 1 | `ks` app-data native lib | `files/lib/libtmessages.49loc.so`; `ks.g` `System.load` at `ks.smali:1672` | **yes** (`System.load`) | yes: process start via `KeepAliveJob`/`NotificationRepeat`/`AppStartReceiver` (`org.telegram.start`) | **yes** (file survives) | file yes, **trigger gated** | **NO-GO**: only inside `catch (Error)` after `System.loadLibrary("tmessages.49")` fails; app data cannot force the failure | T1/T2/T3 |
| 2 | ART runtime app image | `cache/oat_primary/arm64/base.art` | **yes** (ART image + Dalvik `<clinit>`) | yes: loaded at every process start | **yes** | **no**: absolute `/data/app/~~<hash>/.../base.apk`; new hash after update (`nb_v2_run10.log:15288` vs `logcat_survB.txt:13707`) | **NO-GO**: `OpenAndSetDexFiles` fails on the new oat table | T4 |
| 3 | AppCenter `DownloadManagerReceiver` | manifest line 250, `DOWNLOAD_COMPLETE` | would be an APK install, not in-process code | exported, yes | DownloadManager cache | manifest yes, **class no** | **NO-GO**: class absent from all four dex (`dexdump` 0) | T6 |
| 4 | In-app updater | `k1`/`HttpGetFileTask`/`i0.t2`/`ApplicationLoaderImpl.v` | installs an APK, not in-process code | user tap only | `k1.d` path is app-data | n/a | **NO-GO**: `REQUEST_INSTALL_PACKAGES` only; user action + signature gate (§1.4); check URL is literal `"null"` | T5 |
| 5 | PackageInstaller / split / dynamic feature | `PackageInstaller.createSession`, `SplitInstall` | would install a split/APK | user action | session file | n/a | **NO-GO**: 0 `createSession`/`commit`/`SplitInstall` hits; signature gate | T5/T9 |
| 6 | GMS Dynamite `PathClassLoader` | `y6/e.d` `y6/e.smali:2028` | **yes** (dex load) | on demand | **no** (GMS path) | n/a | **NO-GO**: path from GMS, not Telegram app data | source-only |
| 7 | `androidx.startup` / providers | `InitializationProvider.onCreate` | APK classes only | process start | no | n/a | **NO-GO**: class list is manifest metadata | T0 |
| 8 | WebView | UI sites only | JS sandbox, not app-UID | no startup WebView | no startup file load | n/a | **NO-GO** | T0 (negative) |
| 9 | twidget / QuickJS | `WidgetSandboxNative.create` | JS engine | widget bind only | bundle asset | n/a | **NO-GO** (excluded) | none (excluded) |
| 10 | SQLite `load_extension` | `cache4.db` | native extension if enabled | DB open | yes | no | **NO-GO**: disabled at runtime | source-only |
| 11 | `System.load`/`app_process`/`linker64` from a component | none | — | — | — | — | **NO-GO**: only `ks` and fixed WebRTC/MLKit libs; `Runtime.exec` only `/system/bin/netcfg` | T1/T7 |

The full table with component-level detail is in
`lab/loader_update_trigger_audit/ranked_table.md`. The `Sony test` codes map to
`device_test_plan.md`: T1 trigger survival, T2 canary negative, T3 forced
primary failure, T4 ART image, T5 installer gate, T6 AppCenter, T7 exported
services/BAL, T0 baseline.

---

## 7. No-go list (false loaders)

| Surface | Why it is not a loader |
|---|---|
| `ApplicationLoaderImpl` / `w0` update flow | It reads `k1` and starts `ACTION_VIEW`; it never constructs a class loader or `System.load`s the downloaded APK. |
| `REQUEST_INSTALL_PACKAGES` | It permits the installer UI, not silent install. `PackageInstallerSession` still returns `USER_ACTION_REQUIRED` without `INSTALL_PACKAGES`/`UPDATE_PACKAGES_WITHOUT_USER_ACTION`; `InstallPackageHelper` still verifies the Telegram certificate. |
| AppCenter Distribute | Manifest lines 233/250 are dead: `com.microsoft.appcenter.distribute.DeepLinkActivity` and `DownloadManagerReceiver` are absent from all four dex. |
| `DownloadManagerReceiver` fake broadcast | Even if the class existed, the install would be user-gated and signature-gated; the class does not exist. |
| `ProfileInstallReceiver` | Writes a baseline profile; no `DexClassLoader`/`System.load`; app UID lacks `DUMP`. |
| `BringAppForegroundService` | Starts `LaunchActivity`; BAL-gated; no code load. |
| `AppStartReceiver` | Only starts the process / `NotificationsService`; no app-data load. `BOOT_COMPLETED` is protected; `org.telegram.start` is ignored by the receiver but still starts the process. |
| `KeepAliveJob` / `NotificationRepeat` | Keep-alive / notification rerun; no code load. |
| `GcmPushListenerService` / `SmsReceiver` / exported media services | Process app code and data; no `System.load`/`DexClassLoader` sink. |
| `y6/e` GMS Dynamite | Real `PathClassLoader`/`DelegateLastClassLoader`, but the path is the GMS module path, not Telegram app data. |
| `j6/e` custom `ClassLoader` | Maps `com.google.android.gms.iid.MessengerCompat` to a built-in class; no file/dex path. |
| WebView / `WebViewAssetLoader` | No startup WebView; no `WebViewAssetLoader`; no `javascript:`; Bot/IV/proxy file access false. |
| twidget / QuickJS | Engine starts from the chat view; bundle is an APK asset; excluded. |
| TGS/tlottie/media decoders | Parse data; no `dlopen`/`System.load`/`DexClassLoader`. |
| SQLite `load_extension` | Compiled but disabled; Telegram never calls `sqlite3_enable_load_extension`. |
| `tgnet.dat` | Native config parser; no code load. |
| `base.odex`/`base.vdex` | Install-owned `/data/app/.../oat/arm64`; no app write path. |
| `code_cache`/profileinstaller | Profile metadata, not code. |
| `app_process`/`linker64` from the first exploit | Real app-UID native host, but it is the exploit's process, not a Telegram component; it dies with the app cgroup on update and no component calls it. |

---

## 8. Device test plan (Sony XQ-BT52, Android 13, 72799, UID 10357)

The detailed commands and expected outputs are in
`lab/loader_update_trigger_audit/device_test_plan.md`. Summary:

* **T0 baseline**: record `nativeLibraryDir`, `libtmessages.49.so` md5
  (`2c0caa68a07fc26f79d13519af6c3526`), the current `/data/app/~~<hash>`,
  `cache/oat_primary/arm64/base.art`, `files/lib`, and `beta.xml`; confirm the
  normal start logs `Load .../lib/arm64/libtmessages.49.so ... ok` and
  `loaded normal lib`.
* **T1 trigger survival**: schedule `Retrigger2 wake` (alarm PendingIntent to
  `AppStartReceiver` with `org.telegram.start`, 180 s), `Retrigger2 job`
  (`KeepAliveJob`, 210 s), and `Retrigger2 service` (`NotificationRepeat`,
  240 s); run `pm install -r` of the same APK at T+30 s; capture
  `am_kill ... installPackageLI`, then the trigger wake and
  `Application.onCreate`/`ks.g`. This proves the trigger survives; it must
  **not** log `Load local lib`.
* **T2 canary negative**: place a canary `libtmessages.49loc.so` (constructor
  writes `files/.loader_fallback_proof`) at `files/lib`, chmod 0400; run T1;
  verify the marker is **absent** and `loaded normal lib` is present. This
  proves the app-data file is not loaded on a normal update.
* **T3 positive control (root)**: move the install-owned
  `libtmessages.49.so` aside, run T1, verify `dlopen failed` →
  `Load local lib` → `Load .../files/lib/libtmessages.49loc.so ... ok` →
  marker; restore the lib and verify its md5. This proves the loader is real
  and that the only gate is the primary failure.
* **T4 ART update fragility**: deploy the forged `base.art` (prior
  `lab/loader_art`), record the current `~~<hash>`, `pm install -r`, start the
  app, and capture the `OpenAndSetDexFiles`/`Failed to find OatDexFile`
  rejection; the payload must not run. Restore the original image.
* **T5 installer gate**: set `beta.xml` `path` to a canary APK in app data and
  a high `versionCode`; open the update UI; verify the system installer is
  shown and rejects the different signature
  (`INSTALL_FAILED_UPDATE_INCOMPATIBLE`); no silent install.
* **T6 AppCenter dead component**: `am start` the `appcenter://updates/`
  `DeepLinkActivity` and `am broadcast` `DOWNLOAD_COMPLETE` to
  `DownloadManagerReceiver`; expect `ClassNotFoundException` / "Unable to
  instantiate ..."; no install.
* **T7 exported services/BAL**: start `BringAppForegroundService` from a
  background UID; verify the `LaunchActivity` start is blocked unless
  `SYSTEM_ALERT_WINDOW` is granted; start `NotificationsService` and verify
  only the normal startup logs.
* **T8 ProfileInstallReceiver**: shell `am broadcast` `INSTALL_PROFILE`;
  verify profile write only; the app UID is denied by `DUMP`.
* **T9 split/PackageInstaller**: verify no `SplitInstall` classes and no
  `createSession`; an `app_process` session with a canary APK is user-gated and
  signature-rejected. This is a platform-gate check, not a Telegram loader.

Safety: remove the canary `.so`/marker, restore `beta.xml`, restore any moved
install-owned lib and `base.art`, and verify a normal start (`loaded normal
lib`) before finishing.

---

## 9. Corrections to prior notes / claims not to repeat

1. **`BOOT_COMPLETED` PendingIntent is not a usable trigger.** The prior
   `post_update_retrigger.md`/helper used `BOOT_COMPLETED` in its `broadcast`
   mode but was not device-tested. `PendingIntentRecord.sendInner` attributes
   the broadcast to the creator UID, and `ActivityManagerService` rejects a
   protected broadcast from a non-system caller
   (`ActivityManagerService.java:13667–:13701`). Use `org.telegram.start`
   (`wake`), a `KeepAliveJob` job, or a `NotificationRepeat` service
   PendingIntent.
2. **AppCenter Distribute is not a fallback updater.** Its manifest components
   are present but its classes are absent from all four dex. Do not count
   `DownloadManagerReceiver` as an exported install trigger.
3. **The in-app update check is disabled in 72799.** `k1.a` passes the literal
   URL `"null"` (`k1.smali:565`). `k1.d` can be set by app-data preferences,
   but the install remains user- and signature-gated.
4. **`ks.g` consults the local file before `ks.k` cleanup.** The app-data
   `.so` is loaded if it exists (`:1611–:1672`), not only after extraction.
   This does not change the gate: the local load is inside the `catch (Error)`
   for the primary `System.loadLibrary`.
5. **The ART image survives as a file, not as an executable image.** The
   `base.art` in `cache/oat_primary` survives `pm install -r`, but its
   `DexCache` location is the old `/data/app/~~<hash>`; the device log shows
   the path change (`~~GZ-Xx...` → `~~r1vDzV8...` at 19:17). Do not claim
   update survival without the T4 device test.

---

## 10. Evidence index

Path convention: `smali/...` is relative to the apktool tree
`/tmp/opencode/dbgbuild/smali72799/`; `raw/`, `outputs/` and `aosp/` are
relative to `lab/loader_update_trigger_audit/`;
`evidence/evidence_20261101/...` and `lab/...` are relative to the workspace
root.

| Claim | Evidence |
|---|---|
| Update state/check/download | `smali/org/telegram/messenger/k1.smali:37,88,107,123,139,155,436,565,585,704,741,775`; `ng.smali:4230–:4469`; `e4.smali:2266` (download path) |
| Install helper | `smali/org/telegram/messenger/i0.smali:35719,35950,36004,36074`; `ApplicationLoaderImpl.smali:90,198,274,292,337` |
| UI-only install call sites | `xh/z.smali:126`; `rh/u1.smali:195`; `bh/f.smali:2665,2695`; `ag/e0.smali:3203`; `av.smali:2455`; `sr.smali:1337`; `t7.smali:1514`; `c61.smali:528`; `b61.smali:801` |
| `REQUEST_INSTALL_PACKAGES`, no `INSTALL_PACKAGES` | `raw/manifest_base72799.xmltree.txt:155,823` |
| No PackageInstaller write | `k6/g.smali:1259–:1314`; `outputs/02_package_installer.txt` |
| User-action gate | `aosp/PackageInstallerSession.java:829–:883` |
| Signature gate | `aosp/InstallPackageHelper.java:1269–:1290`; `apksigner verify --print-certs` |
| Alarms survive update | `aosp/AlarmManagerService.java:5151–:5157` |
| Jobs survive update | `aosp/JobSchedulerService.java:910–:919,967–:974` |
| `BOOT_COMPLETED` protected-broadcast attribution | `aosp/PendingIntentRecord.java:508–:509`; `ActivityManagerService.java:13667–:13701` |
| `AppStartReceiver` | `smali/org/telegram/messenger/AppStartReceiver.smali:25`; `raw/manifest_base72799.xmltree.txt:799–:805` |
| `KeepAliveJob` | `smali/org/telegram/messenger/KeepAliveJob.smali:176`; `raw/manifest...:712` |
| `NotificationRepeat` | `smali/org/telegram/messenger/NotificationRepeat.smali:29`; `raw/manifest...:727` |
| `BringAppForegroundService` | `smali/org/telegram/messenger/BringAppForegroundService.smali:25`; `raw/manifest...:717` |
| `ProfileInstallReceiver` | `smali/androidx/profileinstaller/ProfileInstallReceiver.smali:21`; `raw/manifest...:1214` |
| AppCenter classes absent | `outputs/05_dead_components.txt`; `outputs/07_appcenter_dex_check.txt` |
| `w0.onCreate` → `ks.g` | `smali/org/telegram/messenger/w0.smali:2263,2734,2740`; `w0.smali:1365–:1405` |
| `ks.g` / `ks.k` | `smali/org/telegram/messenger/ks.smali:1439,1484,1507,1611,1672,2556,2803` |
| Loader search path | `lab/loader_update_trigger_audit/evidence/{loadedapk_makepaths,runtime_loadlibrary0,nativeloader_namespace*,dexpathlist_findlibrary}.txt` |
| Normal primary load on Sony | `evidence/evidence_20261101/new_beta_72799/nb_v2_run10.log:15288–15317`; `nb_v4_run2.log:14593–14594` |
| Forced fallback positive control | `evidence/evidence_20261101/persistence/fallback_test.txt:14–18` |
| ART image mapped | `evidence/evidence_20261101/new_beta_72799/tombstone_20.txt:386` |
| ART image path / update gate | `lab/loader_startup_components/outputs/art_update_path_check.txt`; `art17/runtime/gc/space/image_space.cc:3100–:3135`; `art17/runtime/oat/oat_file.cc:2240–:2290` |
| Device install-path change | `logcat_survB.txt:13707` (`~~GZ-Xx...`) vs `nb_v2_run10.log:15288` (`~~r1vDzV8...`); `am_kill ... installPackageLI` at `nb_v2_run10.log:13457` |
| No DexClassLoader / split / exec | `outputs/03_code_load_sinks.txt`; `outputs/02_package_installer.txt` |
| Component reachability | `outputs/06_component_sinks.txt`; `tools/callgraph.py`, `tools/forward_paths.py` |

Lab: `lab/loader_update_trigger_audit/` — `README.md`, `ranked_table.md`,
`no_go.md`, `evidence_refs.md`, `device_test_plan.md`, `raw/`, `outputs/`,
`aosp/`, `evidence/`, `helper/`, `tools/`.
