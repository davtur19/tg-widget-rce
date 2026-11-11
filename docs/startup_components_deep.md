# Telegram startup components — deep pass (72799)

Date: 2026-11-02
Target: `org.telegram.messenger.beta` 13.2.0 beta, versionCode **72799**,
arm64, Sony XQ-BT52 (Xperia 10 III), Android 13, build 62.2.A.0.533,
UID 10357.

Scope: **host/source/native only; no device was used for this pass.** The first
exploit is assumed to give app-UID (10357) code execution and arbitrary
app-data write. This note is the component-by-component follow-up to
`notes/loader_startup_components.md`; it is deliberately separate from the main
report (`REPORT_20261102.md`), which is not modified.

Artifacts: `lab/startup_components_deep/` (call graph, 94-row component matrix,
exact refs, ranked table, no-go list, device plan, boot-media audit, scans,
scripts).

Conventions:

* `S/` = `/tmp/opencode/dbgbuild/smali72799`
* `J/` = `/tmp/opencode/jadx72799_c1/sources`
* `A/` = `/tmp/opencode/art17`
* `N/` = `<HOME>/ailocal/Telegram/Android/TMessagesProj/jni`
* `L/` = `telegramandroidwidget/lab/startup_components_deep`
* manifest line numbers are from
  `/tmp/opencode/base72799_manifest.xmltree.txt` (aapt2 xmltree of the release
  APK, versionCode 72799).

---

## 0. Verdict

**No Telegram manifest component loads app-data code at startup without user
action.** The 94 manifest components were enumerated and each lifecycle method
was inspected. The result is negative for a new component-level loader:

* The only app-data **code** surfaces in the startup execution graph are:
  1. the **ART runtime app image** `cache/oat_primary/arm64/base.art`, loaded by
     ART before `Application.onCreate` (not by a Telegram component); and
  2. the **`ks.g` local-native fallback** `files/lib/libtmessages.49loc.so`,
     loaded only after `System.loadLibrary("tmessages.49")` throws `Error`.
* Every other automatic component loads **data or config**: SharedPreferences,
  `cache4.db` (SQL), `files/tgnet.dat` (DC config), APK resources/metadata,
  fonts, profiles, notification/media data.
* There is **no** `DexClassLoader` / `InMemoryDexClassLoader` /
  `BaseDexClassLoader` / `DexFile` in any of the four dex files or in
  `libtmessages.49.so`.
* There is **no** `System.load` outside `ks`; **no** `Runtime.exec`; **no**
  `app_process`/`linker64`; **no** startup WebView; **no**
  `sqlite3_enable_load_extension`.
* The two real app-data loaders both fail one requirement today: the ART image
  is update-fragile and its device PoC crashes before `<clinit>`; the `ks`
  fallback cannot be triggered from app data because the primary APK library
  load succeeds.
* **No startup component passes crafted `cache4.db` message/media bytes to a
  TGS/FFmpeg/Opus/MediaCodec parser at boot.** `NotificationsService` →
  `w0.w()` initializes controllers/DB only; widget update constructs
  `MessageObject` (text/entities/SVG-path metadata) and decodes **avatars** with
  `BitmapFactory`, not message media; the providers decode nothing at boot.
  Details in §3.8 and §5.4.

The component pass therefore **confirms** the prior audit’s two-candidate
result and closes the remaining component-level “what about …?” questions. It
does not produce a new working loader.

### Corrections / new facts from this pass

1. **`androidx.car.app.connection.provider` is not a provider component.** It
   is a `<provider>` entry inside `<queries>` (manifest line 196 `<queries>`,
   line 212 the provider), used only for package visibility. It is never
   instantiated. The real provider count is **six**, not seven.
2. **AppCenter and GMS measurement components are dead manifest entries.** The
   classes `com.microsoft.appcenter.distribute.DownloadManagerReceiver`,
   `DeepLinkActivity`, `com.google.android.gms.measurement.AppMeasurementReceiver`
   and `AppMeasurementService` are absent from all four dex files; the two
   measurement components are also `android:enabled="false"`. `DownloadManagerReceiver`
   is exported but cannot run (ClassNotFound), so it is not an auto-update path.
3. **`NotificationsService` is exported with no permission.** Any app can start
   it and force `w0.w()` — a full Telegram cold start — without user action.
   This is a process-start amplifier, not a code loader.
4. **`CallNotificationSoundProvider` is exported with no permission.** It
   streams the VoIP ringtone; data only.
5. **`AppStartReceiver` does not act on `org.telegram.start`.** The filter
   contains it, but `onReceive` returns unless the action is exactly
   `android.intent.action.BOOT_COMPLETED` (`AppStartReceiver.smali:29-53`).
6. **`SharedConfig` has a WebView debugging toggle** (`uz.K()` at
   `uz.smali:1175-1235`, `WebView.setWebContentsDebuggingEnabled` at 1195).
   It is a debug-menu/user action, not a startup path; it creates no WebView
   and loads no URL. This is not a WebView startup path.
7. **`ks.g` is called twice** — `w0.onCreate` (`w0.smali:2734`) and
   `w0.w()` (`w0.smali:1405`); the `ks.a` guard makes the second a no-op.
8. **The ART `<clinit>` is not limited to the APIs referenced by the APK dex.**
   A forged `<clinit>` runs as Dalvik bytecode with method references resolved
   through the real `classes.dex` DexCache. `java.lang.System.load` **is** in
   that dex (it is used by `ks` at `ks.smali:1672/2803`), so the forged
   `<clinit>` can call `System.load("/data/user/0/.../files/lib/payload.so")`
   and load app-data native code directly. `dalvik.system.DexClassLoader` is
   not referenced by the APK dex, so a dex-loader call would need an additional
   method reference (or a different DexCache); it is not available “for free”
   the way `System.load` is. The important point stands: the ART image can load
   an app-data `.so` at startup without the `ks.g` fallback gate. It does not
   fix the device crash.
9. **No boot/widget message-media parse.** `NotificationsService` → `w0.w()`
   initializes controllers/DB but contains no media decoder;
   `ChatsWidgetProvider`/`h4` construct `MessageObject` text/SVG-path metadata
   and decode **avatars** with `BitmapFactory`; the providers decode nothing at
   boot. No TGS/photo/video/Opus/MediaCodec parse. See §3.8/§5.4.

---

## 1. Method

* **Manifest inventory.** `aapt2 dump xmltree` on the release APK; a parser
  (`L/scripts/parse_manifest.py`) extracts only components inside
  `<application>` and records `exported`, `permission`, `directBootAware`,
  intent actions and authorities. 94 components: 22 activities, 7
  activity-aliases, 6 providers, 27 receivers, 32 services. The
  `androidx.car.app.connection.provider` entry is under `<queries>` and is not
  one of the 94 (see the corrections in §0). See `L/outputs/components.tsv`.
* **Lifecycle bodies.** For every component class,
  `L/scripts/dump_component_methods.py` dumps `onCreate`, `onReceive`,
  `onStartCommand`, `onHandleWork`, `onHandleIntent`, `onBind`, `onStartJob`,
  `onUpdate`, `attachInfo`, etc. with file:line. 11 classes are missing; 7 are
  activity-alias names (not classes) and 4 are dead AppCenter/measurement
  entries. See `L/outputs/component_methods.txt` and
  `L/outputs/component_lifecycle_index.tsv`.
* **Per-component storage/loader scan.** `L/scripts/scan_component_io.py`
  greps each component class for `File`/`getFilesDir`/prefs/SQLite/assets/zip/
  `System.load*`/`DexClassLoader`/`WebView`/`Class.forName`. See
  `L/outputs/component_io_scan.txt`. **No component class contains a loader,
  SQLite, or WebView primitive.**
* **Global primitive scan.** All four smali trees for every dex/so/js/wasm/
  exec primitive; see `L/outputs/loader_primitives.txt`.
* **Boot-media scan.** `L/outputs/media_api_scan.txt` greps the boot/widget
  chain for `RLottieNative`, `MediaCodec`, `BitmapFactory`, `ImageDecoder`,
  `MediaMetadataRetriever`, `ImageReceiver`, FFmpeg/Opus; see §3.8/§5.4.
* **Native.** IDA on `libtmessages.49.so` (`dlopen`/`dlsym` imports, call
  sites, `JNI_OnLoad`), `nm -D`, and `/data` string scan; cross-checked with
  `notes/native_appdata_audit.md`.
* **ART.** The ART 17 (`android17-release`) tree at `/tmp/opencode/art17` for
  the runtime-image path, load/validation, `DexCache` lookup and `<clinit>`
  invocation; the pulled 72799 image for the embedded `/data/app` path.
* **Prior evidence.** Tombstones/logcat from the 72799 runs; the root-assisted
  native-fallback proof; the SQLite trigger device result; the tgnet parser
  audit. No new device run was made.

---

## 2. The startup execution graph

### 2.1 Cold start (no user action)

```
fork
 └─ ActivityThread.makeApplication
    ├─ ART loads the runtime app image (classloader creation)
    │    cache/oat_primary/arm64/base.art               [code, app-data]
    ├─ ApplicationLoaderImpl.attachBaseContext
    │    w0.attachBaseContext → super only              (no MultiDex/split)
    ├─ installContentProviders (before Application.onCreate)
    │    ├─ FileProvider.attachInfo → APK provider_paths XML
    │    ├─ NotificationImageProvider.onCreate → NotificationCenter
    │    ├─ CallNotificationSoundProvider.onCreate → true
    │    ├─ MlKitInitProvider.onCreate → manifest metadata
    │    ├─ FirebaseInitProvider.onCreate → APK resources/metadata
    │    └─ InitializationProvider.onCreate
    │         EmojiCompatInitializer / ProcessLifecycleInitializer /
    │         ProfileInstallerInitializer (Class.forName on APK names)
    └─ w0.onCreate
         ├─ ks.g(context)                               [code]
         │    ├─ System.loadLibrary("tmessages.49")     [APK lib, normal]
         │    └─ catch (Error) → files/lib/libtmessages.49loc.so
         │         System.load(...)                     [app-data, gated]
         ├─ ConnectionsManager.native_setJava(false)
         └─ posted runnables (u0 lifecycle, media session, etc.)
```

Exact refs:

* ART image: `A/runtime/runtime_image.cc:1846-1861`,
  `A/runtime/oat/oat_file_manager.cc:353-367`,
  `A/runtime/gc/space/image_space.cc:3100-3135`,
  `A/runtime/oat/oat_file.cc:2240-2290`.
* `w0.attachBaseContext`: `S/smali/org/telegram/messenger/w0.smali:2186-2196`.
* `w0.onCreate`: `S/smali/org/telegram/messenger/w0.smali:2263`.
* `ks.g`: `S/smali/org/telegram/messenger/w0.smali:2734`;
  `S/smali/org/telegram/messenger/ks.smali:1439`.
* `native_setJava`: `S/smali/org/telegram/messenger/w0.smali:2740`.
* Providers: manifest 866, 874, 879, 1062, 1085, 1113; bodies as cited in §4.

### 2.2 Boot path (BOOT_COMPLETED, after first unlock)

```
BOOT_COMPLETED
 └─ AppStartReceiver.onReceive                  (exported=false)
    └─ ag/f3.run case 9
       ├─ SharedConfig.t()                     [prefs only]
       └─ w0.x()
          ├─ pushService/keepAliveService true
          │   └─ startService(NotificationsService)
          │       └─ NotificationsService.onCreate
          │           └─ w0.w()
          │               ├─ ks.g (2nd; ks.a no-op)
          │               ├─ ConnectionsManager → files/tgnet.dat [config]
          │               └─ account/controller init
          │                    (cache4.db is opened on the normal startup
          │                     path, §6)                       [SQL data]
          └─ false → stopService(NotificationsService)
```

Exact refs:

* `S/smali/org/telegram/messenger/AppStartReceiver.smali:25-77`
  (`onReceive`), `:33` (BOOT_COMPLETED string), `:70` (post to `i0.g3`).
* `S/smali_classes3/ag/f3.smali:39` (`run`), `:1339-1380` (`pswitch_13`,
  case 9), `:1344` (`uz.t`), `:1375` (`w0.x`).
* `S/smali/org/telegram/messenger/uz.smali:3744` (`SharedConfig.t`).
* `S/smali/org/telegram/messenger/w0.smali:2046-2182` (`w0.x`);
  `S/smali/org/telegram/messenger/NotificationsService.smali:31-46`
  (`onCreate` → `w0.w` at line 40).
* `S/smali/org/telegram/messenger/w0.smali:1365-2045` (`w0.w`), `:1405`
  (`ks.g`), `:1749/1784/1830/2028` (`e20`/`ConnectionsManager`/`u1` init).
* manifest 812-820: `AppStartReceiver` exported=false, `BOOT_COMPLETED`
  filter, no `directBootAware`; manifest 137: `RECEIVE_BOOT_COMPLETED`.
* manifest 735-738: `NotificationsService` exported=true,
  `foregroundServiceType=1`.

**Boot caveats:** `AppStartReceiver` is not `directBootAware`, so it receives
`BOOT_COMPLETED` only after the first unlock (not `LOCKED_BOOT_COMPLETED`). A
force-stopped app receives no broadcast. `startService` from a background
receiver can be rejected on Android 13; `w0.x` catches `Throwable` and returns
(`w0.smali:2147-2155`). If the service start is rejected, the boot path stops
after `SharedConfig.t()`; `ks.g` still ran in `w0.onCreate`, so the ART/native
surfaces are unaffected.

### 2.3 Push path (no user action, network)

```
FCM push
 └─ FirebaseInstanceIdReceiver (SEND permission)
    └─ FirebaseMessagingService
       └─ GcmPushListenerService.c (RemoteMessage)
          └─ PushListenerController (data only)
```

`GcmPushListenerService` has no `File`/`Dex`/`System.load`/`WebView` primitive
in its class (`L/outputs/component_io_scan.txt`). The process start still runs
§2.1.

### 2.4 Widget path (automatic only if a widget already exists)

```
APPWIDGET_UPDATE
 └─ ChatsWidgetProvider.onUpdate → a()
    ├─ w0.w()                       [full init]
    └─ RemoteViews via ChatsWidgetService
       └─ app DB/file data
```

Same for `ContactsWidgetProvider`. The widget must have been placed by the user
at some earlier time; the update itself needs no further user action. It loads
data, not code. `ChatsWidgetProvider.smali:19,26,856-894`;
`ContactsWidgetProvider.smali:19,26,864-902`; `ChatsWidgetService.smali:21`;
`ContactsWidgetService.smali:21`.

---

## 3. Automatic components — exact audit

“Automatic” means the lifecycle runs without a user tap. Only these qualify:
the six providers (every process start), `AppStartReceiver` (BOOT_COMPLETED),
`NotificationsService` (started by `w0.x` on boot when `pushService` /
`keepAliveService` is true, or by any app because it is exported), FCM
(`GcmPushListenerService` on a push), and the two widget providers (only if a
widget exists). Everything else needs an event, a bound client, or a user
action.

### 3.1 Providers (instantiated before `Application.onCreate`)

| Provider | Entry | What it loads | Code? |
|---|---|---|---|
| `androidx.startup.InitializationProvider` | `onCreate` 81-258 | `ProviderInfo.metaData` from the installed APK; `Class.forName` on the three `androidx.startup` initializer names | no |
| `com.google.firebase.provider.FirebaseInitProvider` | `onCreate` 175-269 | `FirebaseApp.initializeApp`: `google_app_id` from APK resources; `ComponentDiscoveryService` metadata | no |
| `com.google.mlkit.common.internal.MlKitInitProvider` | `onCreate` 92-161 | `MlKit.initialize`: `MlKitComponentDiscoveryService` metadata | no |
| `androidx.core.content.FileProvider` | `attachInfo` 1305-1491; `onCreate` 1754-1762 | `res/xml/provider_paths` via `loadXmlMetaData` (APK); later read-only file serving on grant | no |
| `org.telegram.messenger.NotificationImageProvider` | `onCreate` 274-323 | subscribes to `NotificationCenter`; `openFile("r")` serves `final_path` to a granted caller | no |
| `org.telegram.messenger.voip.CallNotificationSoundProvider` | `onCreate` 51-59 | returns true; `openFile("r")` streams the VoIP ringtone | no |

**`InitializationProvider` detail.** `onCreate` calls
`PackageManager.getProviderInfo(new ComponentName(pkg, InitializationProvider.class), 0x80)`
and passes `ProviderInfo.metaData` to `v4/a.a(Bundle)`
(`InitializationProvider.smali:160-184`). `v4/a.a` iterates the bundle keys,
reads the string value, compares it to `"androidx.startup"`
(`v4/a.smali:257-265`), and calls `Class.forName(name)` (`v4/a.smali:277`).
The names come from the **installed APK manifest**; app data cannot add a
metadata key or a class. The three initializers are the only ones
(manifest 1117-1126).

**`FirebaseInitProvider` / `MlKitInitProvider` detail.** Both initialize their
libraries from APK resources/metadata; component registrar class names are
manifest values (`com.google.firebase.components.ComponentDiscoveryService`,
`com.google.mlkit.common.internal.MlKitComponentDiscoveryService`). No
app-data path/dex. They do read Firebase/MLKit SharedPreferences and model
caches later, but those are data.

**`FileProvider` detail.** `attachInfo` calls `getPathStrategy(context,
authority)`, which reads `android.support.FILE_PROVIDER_PATHS` metadata with
`PackageItemInfo.loadXmlMetaData` (`FileProvider.smali:796,835`) — an XML
resource inside the installed APK. The provider is exported=false;
`openFile` is read-only and only for granted URIs. It does not load code.

**`NotificationImageProvider` / `CallNotificationSoundProvider` detail.**
`onCreate` does no file I/O. `openFile` is the only data path; the former takes
`final_path` from the URI and returns a `ParcelFileDescriptor` for a read; the
latter writes the VoIP ringtone bytes to a pipe. Both are data providers, not
code loaders. `CallNotificationSoundProvider` is exported=true with no
permission; an external app can read the ringtone during a call, but not code.

### 3.2 `AppStartReceiver` — the boot trigger

`S/smali/org/telegram/messenger/AppStartReceiver.smali:25-77`:

```
onReceive(context, intent):
  if intent != null && "android.intent.action.BOOT_COMPLETED".equals(intent.getAction()):
      post(new ag/f3(9))          # i0.g3 thread pool
```

It ignores `org.telegram.start` even though the manifest filter lists it
(manifest 816-820). `ag/f3.run` case 9 (`ag/f3.smali:1339-1380`) calls
`SharedConfig.t()` (prefs) and `w0.x()` (start/stop `NotificationsService`).
This is a **trigger**, not a loader: the only code load it can cause is the
normal `ks.g`/ART path that every process start already executes.

`SharedConfig.t()` (`uz.smali:3744`) is a 1240-instruction prefs loader
(`background_activity`, `userconfing`, passcode fields, proxy list, etc.). It
reads XML shared_prefs; it does not load code.

### 3.3 `NotificationsService` — the boot amplifier

`NotificationsService.onCreate` (`NotificationsService.smali:31-46`) calls
`w0.w()` at line 40. `w0.w()` is the full post-init: `ks.g` at 1405,
`ConnectionsManager` at 1784/1830, `UserConfig` at 1749/1836, `u1` at 2028.
It is reached at boot only if `w0.x()` successfully starts the service; it is
also reachable by **any app** because the service is exported=true with no
permission (manifest 735-738). That makes it a remote cold-start trigger, but
the code load it reaches is still the same `ks.g` (normal APK library); the ART
image was already loaded at process start. It does not read a loader from app
data.

### 3.4 `GcmPushListenerService` — push trigger

`GcmPushListenerService` is a `FirebaseMessagingService`; its message handler is
the obfuscated `c(Lxa/l;)V` (`GcmPushListenerService.smali:25-408`). It reads
`RemoteMessage` keys (`from`, `google.*`, `gcm.*`, `message_type`,
`collapse_key`) and dispatches to `PushListenerController`. The class contains
no `File`, `Dex`, `System.load`, `WebView` or SQLite primitive
(`L/outputs/component_io_scan.txt`). Push data can include notification text
and custom payloads; it is data. A push can start the process (no user action),
which runs §2.1; it does not load code from app data.

### 3.5 Widget providers

`ChatsWidgetProvider.a()` calls `w0.w()` at line 26 and builds `RemoteViews`
for the chat list (`ChatsWidgetProvider.smali:19-585`); `onUpdate` iterates the
widget IDs and calls it (`:856-894`). `ContactsWidgetProvider` is analogous
(`:19-585`, `:864-902`). `ChatsWidgetService`/`ContactsWidgetService` are
`RemoteViewsService` factories (`:21`). No `WidgetSandboxNative`, no
`evaluateJavascript`, no loader. They load app DB/contact/photo data. The
widget must already exist; after that, the launcher's `APPWIDGET_UPDATE` at
boot is automatic.

### 3.6 Everything else that is *not* automatic

* `KeepAliveJob` (`onHandleWork` 176-355): 60 s latch; `JobIntentService`
  enqueued by `w0.w()`; not persisted across boot; no file access.
* `NotificationRepeat` (`onHandleIntent` 29-92): notification refresh; data.
* `BringAppForegroundService` (`onHandleIntent` 25-66): starts `LaunchActivity`;
  user-visible.
* `FilesMigrationService` (`onStartCommand` 1117-1253): moves media files.
* `VoIPService` (`onCreate` 38620): call state/ringtone.
* `MusicPlayerService` (`onCreate` 5075): media playback.
* `MusicBrowserService` (`onCreate` 21-73): `w0.w()` on a system media-browser
  bind; media metadata.
* `AuthenticatorService` / `ContactsSyncAdapterService` /
  `WearAuthListenerService` / `TelegramConnectionService` /
  `ChooserTargetServiceCompat` / `CredentialProviderMetadataHolder` /
  `TransportBackendDiscovery` / `JobInfoSchedulerService` /
  `RevocationBoundService` / `ReconnectionService` /
  `ComponentDiscoveryService` / `SessionLifecycleService` /
  `MlKitComponentDiscoveryService`: system/library binders; account/metadata/
  media data; no loader.
* All notification/media/SMS/Wear/share receivers: event-gated; data. Some call
  `w0.w()` (e.g. `AutoMessageHeardReceiver:33`, `NotificationCallbackReceiver:33`,
  `PopupReplyReceiver:33`, `WearReplyReceiver:460`,
  `NotificationsDisabledReceiver:145`), but that only reaches the normal
  `ks.g`/config/DB path.
* `ProfileInstallReceiver` (`onReceive` 21-544): `DUMP` permission; writes
  `baseline.prof` from the APK asset and a `code_cache` sentinel
  (`ProfileInstallReceiver.smali:485`; `r4/d.smali:5984,6305,6314,6327`).
  Profiles are compilation metadata, not code.
* `RefererReceiver` (`onReceive` 21-104): `INSTALL_PACKAGES` permission;
  system-only install referrer.
* `SmsReceiver`, `CallReceiver`, `NotificationsDisabledReceiver`,
  `MusicPlayerReceiver`, `VoIPMediaButtonReceiver`, `MediaIntentReceiver`,
  `CarAppNotificationBroadcastReceiver`,
  `AlarmManagerSchedulerBroadcastReceiver`, `FirebaseInstanceIdReceiver`:
  event/telephony/media/push data.
* Activities and activity-aliases: user action (launcher, share, widget
  config, call UI, billing, sign-in, credentials, car permission).
* `AppMeasurementReceiver/Service` and AppCenter
  `DownloadManagerReceiver`/`DeepLinkActivity`: classes absent from all four
  dex files; measurement is also disabled. Dead entries.
* `CarAppMetadataHolderService`: `android:enabled=false` (manifest 1092).

### 3.7 Component families explicitly checked and absent / inert

| Family | Finding |
|---|---|
| `TileService` (quick settings) | absent: no `android.service.quicksettings.action.QS_TILE` in the manifest, no `TileService` subclass in the dex |
| `VpnService` | absent: no `BIND_VPN_SERVICE` permission/service |
| `AccessibilityService` | absent: no `BIND_ACCESSIBILITY_SERVICE` permission/service |
| `DeviceAdminReceiver` | absent: no `BIND_DEVICE_ADMIN` permission/receiver |
| `MediaSessionService` | absent; only `MusicPlayerService` / `MusicBrowserService` (MediaSessionCompat/MediaBrowserService), data-only |
| `DownloadManager` receiver | the only one is AppCenter's `DownloadManagerReceiver`; class absent from the dex and cannot run |
| `ShareReceiver` | `ShareBroadcastReceiver` (`onReceive` 21-108) — share-result data; no code |
| `Car`/Auto | `CarAppMetadataHolderService` disabled; `CarAppPermissionActivity` user; `CarAppNotificationBroadcastReceiver` notification data |
| `NotificationListenerService` | absent (no `BIND_NOTIFICATION_LISTENER_SERVICE`) |
| `JobService` with `setPersisted(true)` | `KeepAliveJob` is a `JobIntentService`, not persisted; `JobInfoSchedulerService` is datatransport job scheduling (metadata), no code load |
| `BOOT_COMPLETED` / `MY_PACKAGE_REPLACED` | only `AppStartReceiver` for `BOOT_COMPLETED`; no `MY_PACKAGE_REPLACED` receiver |

### 3.8 Media parsing at boot outside the chat list

The follow-up question is whether a crafted `cache4.db` **message/media** is
parsed by `NotificationsService` (`w0.w()`), the widget providers, or the
notification/file providers at boot/widget update **without opening the chat**.

**No.** The exact chains:

**`NotificationsService.onCreate` → `w0.w()`.** `NotificationsService.smali:31-46`
only calls `w0.w()` (line 40); it never calls `NotificationManager.notify`,
`NotificationCenter.showNotification`, or `startForeground`. `onStartCommand`
(`:119-127`) returns 1. `w0.w()` (`w0.smali:1365-2045`) initializes
controllers; their constructors contain no media decoder:

| Init call | Line | Constructor | Media parser |
|---|---|---|---|
| `LocaleController` (`dd`) | 1411 | singleton | none |
| `UserConfig` (`e20`), `s()` | 1749/1757/1836 | `e20.smali:141-234` | none |
| `MessagesController` (`wp`) | 1762/1856 | `wp.smali:1076-6317` | none |
| `ConnectionsManager` | 1784/1830 | native tgnet config | none |
| `rz` message-send helper | 1869 | `rz.smali:140-411` | none |
| `MediaController` | 1969 | `MediaController.smali:488-1117` | none |
| `ContactsController` (`i5`) | 1979 | `i5.smali:201-765` | none |
| `MediaDataController` (`b6`) | 2015 | `b6.smali:92-1554` | none |
| billing controller (`u1`) | 2028/2036 | `u1.smali:89-400` | none |

The `cr` runnable (`w0.smali:533-538`) reaches `is.C0()`
(`is.smali:12616-15010`) / `wp.W0()` (`wp.smali:64830`) / `wp.X2`
(`wp.smali:65708-67081`), all of which were scanned for media APIs and contain
none. `MediaController`'s `MediaMetadataRetriever` calls
(`MediaController.smali:1490-1547`) are in the static `MediaController.E`
helper, not the constructor, and are not called by `w0.w()`; the `MediaCodec`
calls at 7402+ are encoder helpers; the Opus natives at 3656/5688/5889 are not
called. **`w0.w()` loads DB/account/controller metadata, not message media.**

**`ChatsWidgetProvider` / `ChatsWidgetService`.** `ChatsWidgetProvider.a()`
(`ChatsWidgetProvider.smali:19-585`) calls `w0.w()` at line 26, queries
`shortcut_widget` via `is.q0` at line 333 (`xr.smali:90`), and sets a
`RemoteViews` remote adapter (lines 441/451, update 571/576). No media decoder.
The adapter factory `h4` (`ChatsWidgetService.smali:21`) runs
`h4.onDataSetChanged` (`:3289`): `sr` loads `shortcut_widget` (`sr.smali:466`),
`wp.V3/P3` load users/chats (`h4.smali:3456/3469`), and `new kj`
(`:3495/3535`) builds the **last-message `MessageObject`**. `MessageObject`'s
constructor (`kj.smali:751-1215`) parses text/entities and, for a document with
a `TL_photoPathSize` thumbnail, calls `v5.f` (`:1189`) → `e00.j`
(`e00.smali:3662`), a Java/Skia path parser. It does **not** call
`RLottieNative`, `BitmapFactory`, `MediaCodec`, `ImageDecoder`,
`MediaMetadataRetriever`, or `ImageReceiver`; there is no `AnimatedEmoji`/
`RLottie` reference in `kj.smali`.

`h4.getViewAt` (`:87`) sets the row text from `MessageObject` fields
(`setTextViewText`, e.g. `:828`) and decodes the **user/chat avatar**:
`BitmapFactory.decodeFile` at `h4.smali:866`, `setImageViewBitmap` at `:1229`.
The avatar `photo_small` comes from `UserProfilePhoto` (`:498/506`) or
`ChatPhoto` (`:667/675/735/743`), not from the message. So a crafted DB
**message** is turned into `MessageObject` text/SVG-path metadata, but its
TGS/photo/video is not decoded. A crafted **user/chat photo** could reach
`BitmapFactory` at widget update (avatar image only; §5.4).

**`ContactsWidgetProvider`.** `ContactsWidgetProvider.smali:864-902` updates
RemoteViews; `k5.getViewAt` (`k5.smali:109`) decodes a contact avatar with
`BitmapFactory.decodeFile` (`:871`) and sets it at `:1266`. No message media.

**Providers.** `NotificationImageProvider.onCreate` (`:274-323`) only subscribes
to `NotificationCenter`; `openFile` (`:325`) returns a file descriptor on
request (the system decodes). `CallNotificationSoundProvider.onCreate`
(`:51-59`) returns true; `openFile` (`:61`) streams the VoIP ringtone during a
call. `FileProvider.onCreate` (`:1754-1762`) returns true; `attachInfo`
(`:1305-1491`) parses APK `provider_paths`. No media decode at boot.

**The one native decode at widget update** is the avatar
`BitmapFactory.decodeFile` (`h4.smali:866`, `k5.smali:871`). It is a Skia image
decode from an app-data avatar file, not message media and not code execution.
A crafted DB user/chat photo plus an app-UID-written file at the `FileLoader`
path could reach it; that is a JPEG/PNG/WebP parser surface at most. It does
not parse TGS/video/Opus/FFmpeg and cannot load code.

Full call chains and the API scan: `L/media_boot_audit.md`,
`L/outputs/media_api_scan.txt`; device tests T12-T15 in `L/device_plan.md`.

---

## 4. Global loader-primitive audit

Full output: `L/outputs/loader_primitives.txt`.

### 4.1 Dex/class loaders

```
DexClassLoader                 0
InMemoryDexClassLoader         0
BaseDexClassLoader             0
DexFile                        0
PathClassLoader                2   y6/h.smali:2,59; y6/e.smali:2380
DelegateLastClassLoader        2   y6/a.smali:11; y6/e.smali:2347
URLClassLoader                 1   jlatexmath URLAlphabetRegistration.smali:219
```

* `y6/e` is GMS `DynamiteModule`; the module path is assigned from the
  `com.google.android.gms.chimera` provider cursor (`y6/e.smali:3415-3928`).
  A Telegram UID cannot write GMS data. `y6/h` is the pre-API-29 fallback.
* `android:appComponentFactory` is `androidx.core.app.CoreComponentFactory`
  (manifest 235). The class has only a constructor in the APK
  (`CoreComponentFactory.smali:1-17`); it inherits the framework’s
  `instantiateActivity`/`instantiateProvider`/… which use manifest class names
  and the app classloader. No app-data class path.
* `URLAlphabetRegistration.register(URL, ...)` is a public jlatexmath API; the
  only constructor call is inside the class itself. No Telegram call site, not
  startup. (It would be a real `URLClassLoader` if called.)
* `Class.forName` sites in Telegram (`i0.smali:13542/27554/29020`,
  `NotificationBadge$XiaomiHomeBadger:37`, `EditTextBoldCursor:880`,
  `p80:521`, `uk0:513`) use constant class names or XML attributes from APK
  layouts; `Class.forName` cannot load an app-data dex without a dex loader.
* `AppCompatViewInflater` (`g/r.smali:4964`) and `m/l2.smali:1987` load a
  `class=` attribute from layout XML; layouts come from APK resources
  (`addAssetPath` is absent), not app data.

### 4.2 Native loads

```
System.loadLibrary   ks 1484/1831 (tmessages.49)
                     org/webrtc/NativeLibrary$DefaultLoader 78 (jingle_peerconnection_so)
                     MLKit ThickLanguageIdentifier 234 (language_id_l2c_jni)
System.load          ks 1672, 2803 (files/lib/libtmessages.49loc.so)
```

The WebRTC and MLKit libs are fixed APK libraries loaded on call/translation,
not at startup. `ks` is the only app-data native path.

### 4.3 `dlopen` in `libtmessages.49.so`

IDA on `libtmessages_49_arm64_media_annotated.i64`:

* `dlopen` import at `0x1cb8b58`.
* Real call sites: `0xA45F5C` and `0xA45FAC` in `sub_A45BD0` — fixed
  `"libnetd_client.so"` (mode 6) and `"libandroid.so"` (mode 2), WebRTC
  NetworkMonitor only.
* Generic wrapper `sub_181CA18` (`0x181CA18`) does
  `dlopen(path, 258)`; its four xrefs (`0x19CA348/3F0/498/540`) are **data**
  (a function-pointer table), no code caller.
* `JNI_OnLoad` `0x16EFA34` calls `GetEnv` and RegisterNatives
  (`sub_74ECC0`, `sub_7529D4`, `sub_755ABC`, `sub_A5801C`, `sub_987CAC`) and
  returns `0x10006`; no file API. This is consistent with
  `notes/native_appdata_audit.md` (depth-5 call graph, no file API).
* The `.so` has no `/data/...` path strings and only the fixed system `.so`
  names above; no `DexClassLoader`/`loadDex` strings.
* `liblanguage_id_l2c_jni.so` also imports `dlopen` (TensorFlow Lite delegate
  loading), but its strings contain no `/data` path; it is loaded by a literal
  `System.loadLibrary("language_id_l2c_jni")` on MLKit language ID
  (translation), not at startup.

### 4.4 `Runtime.exec` / `app_process` / WebView / SQLite extension

* `Runtime.exec`: 0. The only `ProcessBuilder` is `o6`:
  `/system/bin/netcfg` (`o6.smali:1538,1564,1592`), called from
  `ConnectionsManager.getInitFlags` (`ConnectionsManager.smali:1718,1726`).
  Fixed command, fixed `/system/bin` directory, no app-data argument.
* `app_process` / `linker64`: 0 in dex and in the `.so` strings.
* `WebViewAssetLoader`: 0; `javascript:`: 0.
* Eight `new WebView` sites, none in `w0`, `ApplicationLoaderImpl`,
  `AppStartReceiver`, providers or initializers; see
  `L/outputs/startup_classes_webview_counts.txt`. The first WebView is created
  by opening an Instant View, bot web app, article, video or reCAPTCHA.
  `SharedConfig` has a WebView debug toggle (`uz.smali:1195`,
  `WebView.setWebContentsDebuggingEnabled`), but it is a debug-menu action, not
  startup, and creates no instance or URL.
* `sqlite3_enable_load_extension` / `loadExtension`: 0 in dex. SQLite 3.39.3
  compiles `load_extension` but runtime-disables it (`sqlite3.c:123886`,
  `130807`); triggers get `unsafe use of load_extension()` (device evidence
  `notes/sqlite_trigger_rce.md:89-94`).

---

## 5. The two real app-data code loaders

### 5.1 Rank 1 — ART runtime app image

**What.** ART 17 creates a runtime app image at
`<app_data>/cache/oat_primary/<isa>/<basename(dex)>.art`
(`A/runtime/runtime_image.cc:1846-1861`). For 72799 it is
`/data/user/0/org.telegram.messenger.beta/cache/oat_primary/arm64/base.art`.
The device tombstone maps it at every app start:

```
evidence/evidence_20261101/new_beta_72799/tombstone_20.txt:386
  00000000'6a000000-00000000'6a4a3fff rw- ... [anon:dalvik-.../cache/oat_primary/arm64/base.art]
same:2926
  ... r-- ... /data/data/org.telegram.messenger.beta/cache/oat_primary/arm64/base.art
```

**Why it is code.** The image contains `Class`, `ArtMethod`, `DexCache` and
class-def data. ART maps/relocates it before `Application.onCreate`, and
`ClassLinker::InitializeClass` (`A/runtime/class_linker.cc:6197-6203`) invokes a
class initializer directly. `ks` has a real `<clinit>` (`ks.smali:27-80`) and
is initialized by the static `ks.g` call at `w0.smali:2734`, so a forged
`ks.<clinit>` runs before the real `ks.g` body.

**Crucial consequence.** The forged `<clinit>` is Dalvik bytecode whose method
references resolve through the real `classes.dex` DexCache (the prior PoC uses
the real `classes.dex` DexCache at image offset `0x140`). `System.load` is in
that dex (used by `ks` at `ks.smali:1672/2803`), so the `<clinit>` can call
`System.load("/data/user/0/.../files/lib/payload.so")` and load an app-data
`.so` directly, without waiting for `ks.g` to fail. `DexClassLoader` is not
referenced by the APK dex; a dex-loader call would need an added method
reference or a different DexCache, so the native-`.so` route is the immediately
available one. Either way, the ART image is a **full code loader**, not merely
a `<clinit>` hook. This does not change the device status: the current forged
image crashes before the `<clinit>` executes.

**Startup / reboot.** The image is loaded at process start; `AppStartReceiver`
starts the process at `BOOT_COMPLETED` (after first unlock), so the payload is
same-install reboot-surviving **if the image executes**. The process start does
not depend on `w0.w()` or the DB.

**Update.** The image contains the absolute install path in its `DexCache`
location data. The pulled 72799 image has
`/data/app/~~r1vDzV8CpQVWKXLwu8aDPA==/org.telegram.messenger.beta-JVB3quhnKMMIKSJdj4fj2A==/base.apk`
at offset `0x160` (`L/scripts/art_update_path_check.py`). ART's
`ImageSpace::OpenAndSetDexFiles()` reads that string and
`OatFile::GetOatDexFile()` looks it up exactly in the image's oat table
(`A/runtime/gc/space/image_space.cc:3100-3135`,
`A/runtime/oat/oat_file.cc:2240-2290`). A normal `pm install -r` installs to a
new `/data/app/~~<new-hash>`; the old absolute path is not a key in the new oat
table, so the image is expected to be rejected and ART regenerates a
legitimate one (`A/runtime/startup_completed_task.cc:53-61`). This is the
update-survival blocker. Device test T2 is the authority; if the Sony reuses
the old code path, the conclusion changes.

**Device status.** The forged image is accepted and reaches
`ClassLinker::InitializeClass` from `w0.onCreate`, but crashes before the
forged `<clinit>` runs:

```
#00 art::ClassLinker::InitializeClass(...)+980
    called from org.telegram.messenger.w0.onCreate+478
signal 11, fault addr 0x60, x0=0, x1=0x11d (dex_class_def_idx 285)
x2=0x6a00117c (fake Class)
```

(`notes/persistence_local_existing_rce.md` §7.3.) No marker, no RCE. The
failure is a fake-`Class` layout/class-def-substitution problem, not an image
load rejection. The obvious next experiment is to keep the real `ks` class def
(5862) and patch only its `<clinit>` code item, rather than substituting a
one-class fake.

**What would change the verdict.** Fixing the fake-`Class` layout would make
the ART image a working same-install/reboot code loader. A stable `DexCache`
location key that the new oat table also contains (e.g. a self-contained image
whose location is an app-data path) would be needed for update survival; it is
not demonstrated. An ART/Mainline update also invalidates the image via the
boot-image checksum (`image_space.cc:1289-1332`).

### 5.2 Rank 2 — `ks.g` `files/lib` native fallback

`ks.g` (`ks.smali:1439-1907`):

1. `System.loadLibrary("tmessages.49")` in a `try` (`:1484`);
2. on success, `ks.a = true`, log `loaded normal lib`, return (`:1489-1505`);
3. on `Error` (`:1507`), `getFilesDir()/lib` (`:1585-1593`),
   `libtmessages.49loc.so` (`:1611`); if it exists, `System.load(path)`
   (`:1672`); on its own `Error`, delete and continue;
4. otherwise `ks.k` extracts the APK lib to the same path and `System.load`s it
   (`:2556-2803`);
5. final `System.loadLibrary("tmessages.49")` retry (`:1831`).

**Why it is gated.** The primary load resolves through the app's
`nativeLibraryDir` (`/data/app/.../lib/arm64`, install-owned/read-only), not
app data. App-UID 10357 cannot write `/data/app`, cannot remove/rename the APK
lib, and cannot make `dlopen` fail deterministically. `ks.g` catches only
`java.lang.Error`; a `SecurityException` would not take the fallback. Filling
`/data` with app data does not make `dlopen` of an already-extracted 27 MB
library fail (no write is needed), and no **attacker-controlled** allocation
happens before `ks.g` in `w0.onCreate` (the pre-`ks.g` code is logging,
`PackageManager` metadata and `w0.u()`, a no-op — `w0.smali:2427`; logging may
touch `files/logs`, but not with attacker-controlled size/content).

**Update.** The file survives an update in `files/`, but the name is versioned
(`libtmessages.49loc.so`); a future `tmessages.50` makes it inert, and `ks.k`
deletes entries in `files/lib` when it runs (`ks.smali:2571-2575`). The
primary-load failure is an install/build condition, not an app-data trigger.

**Positive control.** The prior root-assisted proof (rename the APK lib, plant
a `JNI_OnLoad` `.so` in `files/lib`) confirms the loader; it is not a no-root
path (`notes/native_appdata_audit.md`, `notes/persistence_20261101.md`).

### 5.3 Why the other “loader” candidates fail

* **GMS Dynamite** (`y6/e`): real `DelegateLastClassLoader`/`PathClassLoader`,
  but the module path comes from the GMS `com.google.android.gms.chimera`
  provider (`y6/e.smali:3415-3928`). GMS data is not writable by UID 10357.
* **SQLite `load_extension`**: compiled but runtime-disabled; Telegram never
  calls `sqlite3_enable_load_extension`. `cache4.db` is app-writable, but a
  trigger/view gets `unsafe use of load_extension()` (prior device evidence).
* **WebView app-data HTML/JS**: no startup WebView; the first WebView is a user
  action; file access is off for BotWebView/InstantView/TelegramWebProxy; no
  `WebViewAssetLoader`; no `javascript:`.
* **twidget QuickJS**: the JS/QBC bundle is an APK asset
  (`assets/WidgetSandbox/WidgetJS/*.qbc`); the engine is created when a chat
  bubble is rendered (user opens a chat). It is not a startup component.
* **Update APK / AppCenter**: `ApplicationLoaderImpl.g()` returns a file from
  the `beta` prefs; installation uses `ACTION_VIEW` + `FileProvider` and the
  Telegram signature. AppCenter classes are absent; the `DownloadManagerReceiver`
  cannot run.

---

### 5.4 Media-parser reachability at boot — no ACE

The media follow-up (§3.8) found **no** path from a crafted `cache4.db`
message/media to a TGS/FFmpeg/Opus/MediaCodec parser at boot:

* `w0.w()` controller constructors (`MediaController`, `MessagesController`,
  `MediaDataController`, `ContactsController`, `UserConfig`, `rz`, `u1`, `wp`)
  contain no media decoder; their `MediaMetadataRetriever`/`MediaCodec` helpers
  are outside the constructors and not called from `w0.w()`.
* `NotificationsService` posts no notification and decodes nothing.
* Widget update constructs `MessageObject` (text/entities/SVG path metadata)
  and decodes **avatars** with `BitmapFactory.decodeFile`; it does not decode
  the message's TGS/photo/video.
* Providers decode nothing at boot; `openFile` returns data on request.

The only native parser in the widget path is the avatar `BitmapFactory` call
(`h4.smali:866`, `k5.smali:871`). It is an image decoder for the avatar file,
not message media, and it does not load code. A crafted DB user/chat photo
plus an app-UID avatar file could reach it; a crafted **message** cannot.

Therefore the boot/widget media path is **not a new ACE surface**. Any future
claim would need a concrete `RLottieNative`/`MediaCodec`/`ImageDecoder`/FFmpeg
call reachable from `w0.w()` or the widget row path, with an app-data message
media file — neither exists in 72799.

## 6. Config and data surfaces (explicitly not code)

| Surface | Where | Why not code |
|---|---|---|
| SharedPreferences (`mainconfig`, `userconfing`, `background_activity`, `themeconfig`, `beta`, …) | `uz.t` (`uz.smali:3744`), `w0.x` (`w0.smali:2046`), `w0.w` | XML key/value; no class/lib path; `pushService`/`keepAliveService` only start/stop a service |
| `cache4.db` | `is.V0` (`is.smali:51047`), `new SQLiteDatabase("cache4.db")` (`:51270`); opened on the normal app startup path | SQL data; `load_extension` disabled; triggers cannot load native code |
| `files/tgnet.dat`, `dc*.dat` | `N/tgnet/Config.cpp:18-20`; `ConnectionsManager.cpp:367,481` | native `Config` parser; DC/address config (C2) but no `dlopen`/`System.load` |
| Fonts (system/custom) | `Typeface.createFromAsset` (`i0.smali:31887`), photo-editor `ig/h0` | font parsing (FreeType), not CPU code |
| Themes / `.attheme` | `LaunchActivity` theme load; `t6` | parsed data; user applies/opens |
| Profiles | `ProfileInstallReceiver`, `r4/d` | `baseline.prof` from APK; compilation metadata |
| MLKit models / TFLite | `assets/models`, MLKit model download | model data interpreted by a fixed native engine; not arbitrary code |
| `code_cache/gl-programs` | MLKit GL shader cache | GPU shader metadata, not CPU code; not startup |
| Notification/media files | `NotificationImageProvider`, `FileProvider`, media decoders | data parsed by fixed codecs |

None of these can place a **new** dex/so/js/wasm/executable in the startup
execution graph.

---

## 7. Ranked table (copy)

Full table: `L/ranked_table.md`.

| # | Surface | Code | Startup | App-data | Reboot | Update | Status |
|---|---|---|---|---|---|---|---|
| 1 | ART runtime image `cache/oat_primary/arm64/base.art` | yes | yes | yes | yes | no | candidate, device crash |
| 2 | `ks.g` `files/lib/libtmessages.49loc.so` | yes | conditional (`Error`) | yes | file yes, trigger no | file yes, trigger no | candidate, gated |
| 3 | GMS Dynamite `y6/e` | yes | on demand | no | n/a | n/a | no-go |
| 4 | SQLite `load_extension` | yes if enabled | yes (DB) | yes | yes | yes | no-go (disabled) |
| 5 | WebView app-data HTML/JS | JS | no | n/a | n/a | n/a | no-go |
| 6 | twidget QuickJS | JS | no | message data | n/a | n/a | no-go |
| 7 | jlatexmath `URLClassLoader` | yes | no call site | theoretical | n/a | n/a | no-go |
| 8 | Update APK / AppCenter | APK | user tap | yes | n/a | n/a | no-go |
| 9 | Fixed `System.loadLibrary` (WebRTC/MLKit) | yes | on use | no | n/a | n/a | no-go |
| 10 | Native `dlopen` (netd/android) | yes | WebRTC only | no | n/a | n/a | no-go |
| 11 | Fonts/profiles/TFLite/tgnet/prefs | no | partial | yes | yes | yes | no-go |
| 12 | `Runtime.exec`/`app_process` | fixed netcfg | after `native_setJava` | no | n/a | n/a | no-go |
| 13 | Boot/widget message-media parse (`w0.w`, `h4`, providers) | no (TGS/photo/video/Opus/MediaCodec absent) | yes | yes | yes | yes | no-go (avatar `BitmapFactory` only; `MessageObject` text/SVG path) |

---

## 8. Device test plan (summary)

Full commands and interpretation: `L/device_plan.md`.

| Test | Goal | Expected |
|---|---|---|
| T0 | preflight/backup | `versionCode=72799`, UID 10357, `pm path`, `base.art` copied |
| T1 | ART same-install | marker `files/.art_started` at cold start; currently `InitializeClass` crash instead |
| T2 | ART after `pm install -r` | new `/data/app/~~<hash>`; stale image rejected; no marker (unless codePath is stable) |
| T3 | ART at reboot | `BOOT_COMPLETED` → `AppStartReceiver` → process start → marker (same install) |
| T4 | native fallback negative | no `.loc_proof`, `loaded normal lib` |
| T5 | native fallback positive (root) | `.loc_proof`, `Load local lib` after renaming the APK lib |
| T6 | provider/exported-service cold start | providers run before `Application.onCreate`; `NotificationsService` starts `w0.w`; no app-data code |
| T7 | FCM cold start | `GcmPushListenerService` data only |
| T8 | SQLite trigger | `unsafe use of load_extension()`; no native marker |
| T9 | `tgnet.dat` | DC redirect (C2), no code |
| T10 | WebView negative | no Telegram-PID WebView lines on cold start |
| T11 | update APK | user tap + signature; no silent install |
| T12 | `NotificationsService` + crafted TGS/photo/video | no message-media decoder; controller/DB logs only |
| T13 | widget update with crafted TGS/photo/video | avatar `BitmapFactory` only; no TGS/MediaCodec/FFmpeg |
| T14 | control: open chat | TGS/photo/video decoder tags appear |
| T15 | providers at boot / on request | no Telegram-side media decode |

---

## 9. Proven vs not proven

**Proven on the host:**

* 94 manifest components; the only components that can run automatically on a
  cold start or boot without an external binder are the six providers,
  `AppStartReceiver`, `NotificationsService`, FCM `GcmPushListenerService`, and
  the two widget providers (widget present). None contains a code loader. The
  system-bound services in §3.6 are also user-action-free, but only run when
  the system binds them; they are data-only too.
* No `DexClassLoader`/`InMemoryDexClassLoader`/`DexFile` in the four dex files
  or in `libtmessages.49.so`.
* The only `System.load` app-data path is the gated `ks.g` fallback; the only
  `System.loadLibrary` sites are `ks`, WebRTC, MLKit.
* `libtmessages.49.so` `dlopen` call sites are fixed system libraries; the
  generic wrapper has no code caller; `JNI_OnLoad` only registers natives.
* No `Runtime.exec`; the only `ProcessBuilder` is fixed `/system/bin/netcfg`.
* No startup WebView; the only WebView reference in `SharedConfig` is a
  debug-menu toggle (`uz.K`), not a page load.
* SQLite `load_extension` is compiled but runtime-disabled; no Java enable API.
* ART image path/load/`<clinit>` and the absolute `/data/app` path at `0x160`;
  the device PoC crashes in `InitializeClass`.
* `androidx.startup`/Firebase/MLKit/FileProvider/ProfileInstaller load only
  APK metadata/resources; `NotificationImageProvider`/`CallSound` are data
  providers.
* No message-media parser at boot: `w0.w()` constructors have no decoder;
  `NotificationsService` posts nothing; widget update builds `MessageObject`
  (text/SVG-path metadata) and decodes avatars with `BitmapFactory`, not the
  message's TGS/photo/video; providers decode nothing at boot.

**Not proven / device-dependent:**

* Whether the fake-`Class` layout can be fixed so the ART `<clinit>` executes.
* Whether the Sony accepts a stale `base.art` after `pm install -r` if the
  code path is stable; T2 settles it.
* Whether `NotificationsService` is actually started from `BOOT_COMPLETED` on
  Android 13 (background-service restriction); T3 logcat settles it. This does
  not affect the ART/`ks.g` surfaces, which run in `w0.onCreate`.
* Whether a future Telegram build adds a real app-data `DexClassLoader` or a
  new startup initializer; re-audit after each update.
* Whether a crafted DB user/chat **avatar** path reaches
  `BitmapFactory.decodeFile` on the Sony at widget update; T13. This is an image
  parser surface at most, not message media or ACE.
* The root-only native fallback positive control on the exact Sony build.

---

## 10. What would change the verdict

* **A working ART image.** Fixing the fake-`Class` layout would make rank 1 a
  real same-install/reboot code loader. For update survival, the image would
  need a `DexCache` location key that survives a new `/data/app/~~<hash>` (or a
  self-contained oat table entry for an app-data dex); not demonstrated.
* **A `System.loadLibrary` failure reachable from app data.** None found; the
  primary load is install-owned and app data cannot make it fail
  deterministically.
* **A future `DexClassLoader`/`InMemoryDexClassLoader`** in an automatic
  component. Absent in 72799; re-audit each build.
* **A future `sqlite3_enable_load_extension` call.** Absent; re-audit.
* **A future startup WebView** that loads `file://`/app-data HTML. Absent.
* **A boot/widget message-media decoder.** A concrete
  `RLottieNative`/`MediaCodec`/`ImageDecoder`/FFmpeg call reachable from
  `w0.w()` or the widget row path with an app-data message-media file is absent
  in 72799; the only native decode is avatar `BitmapFactory`.
* **A parser memory-corruption chain** in TGS/SQLite/media/font/tgnet. These
  are memory-corruption surfaces, not loaders; they still need a full exploit.

No false loader is promoted. The two real app-data loaders (ART image, `ks`
fallback) fail one requirement each today, and no manifest component adds a
third.

---

## 11. Evidence index

`L/evidence_refs.md` has the full table. Key anchors:

* Startup: `S/.../w0.smali:2186,2263,2734,2740,1365,1405,2046`;
  `S/.../AppStartReceiver.smali:25-77`; `S/smali_classes3/ag/f3.smali:1339-1380`;
  `S/.../NotificationsService.smali:31-46`.
* Native fallback: `S/.../ks.smali:1439,1484,1507,1585-1611,1672,1831,2803`.
* Providers: manifest 866/874/879/1062/1085/1113;
  `InitializationProvider.smali:81-258`; `v4/a.smali:257,277`;
  `FirebaseInitProvider.smali:175-269`; `MlKitInitProvider.smali:92-161`;
  `FileProvider.smali:1305-1491,835,1754-1762`;
  `NotificationImageProvider.smali:274-323`; `CallNotificationSoundProvider.smali:51-59`.
* ART: `A/runtime/runtime_image.cc:1846-1861`;
  `A/runtime/oat/oat_file_manager.cc:353-367`;
  `A/runtime/gc/space/image_space.cc:3100-3135`;
  `A/runtime/oat/oat_file.cc:2240-2290`;
  `A/runtime/startup_completed_task.cc:53-61`;
  `A/runtime/class_linker.cc:6197-6203`;
  tombstone_20:386,2926; `base_72799_original.art` path at `0x160`.
* Native: IDA `dlopen` `0x1cb8b58`, call sites `0xA45F5C/0xA45FAC`,
  `sub_181CA18` `0x181CA20`; `JNI_OnLoad` `0x16EFA34`;
  `notes/native_appdata_audit.md`.
* Config: `N/tgnet/Config.cpp:18-20`;
  `N/tgnet/ConnectionsManager.cpp:367,481`;
  `S/.../is.smali:51047,51270`; `N/sqlite/sqlite3.c:123886,130807`;
  `notes/sqlite_trigger_rce.md:89-94`.
* Media-at-boot: `S/.../NotificationsService.smali:31-46`;
  `S/.../w0.smali:1365-2045` (init calls 1411/1749/1762/1784/1830/1869/1969/1979/2015/2028);
  `S/.../MediaController.smali:488-1117` (ctor), 1490 (static helper);
  `S/.../ChatsWidgetProvider.smali:19-585`;
  `S/.../h4.smali:3289,3495,3535,866,1229`;
  `S/.../k5.smali:871,1266`;
  `S/.../kj.smali:751-1215,1189`; `S/.../v5.smali:428`;
  `S/.../e00.smali:3662`;
  `S/.../NotificationImageProvider.smali:274-323,325`;
  `S/.../CallNotificationSoundProvider.smali:51-59,61`;
  `S/.../FileProvider.smali:1305-1491,1754-1762`;
  `L/media_boot_audit.md`, `L/outputs/media_api_scan.txt`.
