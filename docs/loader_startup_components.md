# Startup code-load / code-execute surfaces — Telegram Android 72799

Date: 2026-11-02
Target: `org.telegram.messenger.beta` 13.2.0 beta, versionCode **72799**,
arm64, Sony XQ-BT52 (Xperia 10 III), Android 13, build 62.2.A.0.533,
UID 10357.
Scope: **host/source/native only**; no device or emulator was used for this
audit.  The first exploit is assumed to give app-UID (10357) code execution and
arbitrary app-data write.  The goal is a component that loads/executes a loader
from app data **at app startup, surviving an app update**, without root and
without QuickJS.

This note is deliberately separate from the main report
(`telegramandroidwidget/REPORT_20261102.md`), which is not modified.

Artifacts: `lab/loader_startup_components/` (ranked table, exact refs, scan
outputs, host checks, device test plan).

## Method

* **APK baseline:** `aapt2 dump badging` and `xmltree` on
  `/tmp/opencode/base72799.apk` (package/versionCode 72799; manifest
  components); outputs in `lab/loader_startup_components/outputs/`.
* **Java surface:** `rg` over all four smali trees
  (`smali`, `smali_classes2..4`) for every dex/class-loader API, `System.load*`,
  `dlopen`, `Runtime.exec`, WebView, provider/startup, ART and data-parser
  patterns; exact hits are in the per-surface output files.
* **Native surface:** IDA on `libtmessages.49.so` (md5 `2c0caa68…`) for
  `dlopen`/`dlsym` xrefs and the WebRTC call site; `readelf` for imports;
  `liblanguage_id_l2c_jni.so` strings/imports.
* **ART:** the ART 17 (`android17-release`) source tree at `/tmp/opencode/art17`
  for image version 119: runtime image path, load/validation, DexCache
  lookup, class-init, and startup-task behavior.
* **Host checks:** `art_update_path_check.py` (absolute path in the pulled
  `base.art`), `sqlite_extension_check.py` (VxWorks/`load_extension`
  correction), `manifest_startup.sh`.
* **Device evidence:** the existing 72799 tombstones/logcat and the prior
  root-assisted fallback proof; no new device run was made.

---


## 0. Verdict

**No audited surface meets all four requirements at once:**

1. the loader lives in app data writable by UID 10357;
2. it is reached automatically at app startup (process start / boot / before
   or during `Application.onCreate`);
3. it actually loads or executes code, not merely parses data;
4. it survives an app update (`pm install -r` / package replace).

Two surfaces are **real app-data code loaders** and are worth ranking:

| Surface | Meets | Fails |
|---|---|---|
| ART runtime app image `cache/oat_primary/arm64/base.art` | app data; ART maps/relocates it at process start; `ks.<clinit>` is a direct class-initializer trigger | **update survival**: the image embeds the absolute `/data/app/~~<hash>/.../base.apk` path in its DexCaches; an update changes that path; current device PoC also crashes in `InitializeClass` before executing the payload |
| local native lib `files/lib/libtmessages.49loc.so` | app data; real `System.load()` native code path; survives an app update as a file | **startup trigger**: loaded only in `ks.g`'s `catch (Error)` after `System.loadLibrary("tmessages.49")` fails; no app-data-only way to force that failure |

The remaining surfaces are **not loaders** for app data: APK class loading,
GMS Dynamite (path supplied by Google Play services), fixed-name
`System.loadLibrary`, fixed `dlopen`, fixed `/system/bin/netcfg`,
WebView JavaScript with no startup WebView, ART AOT files in read-only
`/data/app`, profile/font metadata, or pure parsers (tgnet, TGS/tlottie,
media, SQLite schema).  Details and exact refs follow.

**Critical corrections to earlier notes appear in the relevant sections;
the main ones are:**

* `base.art` survives *reboot* on the same install, but the earlier
  “survives an app update unless ART regenerates it” wording is too strong:
  the image is keyed to the old install path and is expected to be rejected
  after an update.
* `y6.h` is **not** an unused `PathClassLoader`; it is the pre-API-29 fallback
  in the GMS Dynamite loader.  It still does not load app data.
* `#define SQLITE_OMIT_LOAD_EXTENSION 1` at `sqlite3.c:158` is inside the
  VxWorks branch, not the Android build.  3.39.3 compiles `load_extension()`;
  it is disabled at runtime, and Telegram never enables it.

---

## 1. Ranked table

Legend: **Code** = actually loads/executes code (not data parsing);
**Startup** = reached at process start, boot, or before/inside
`Application.onCreate`; **App-data** = a UID 10357-writable file is the
input; **Update** = expected to keep working after a normal `pm install -r`.

“App-data yes” means the first exploit can create/replace the input at the
stated path: `files/`, `cache/`, `shared_prefs/`, and databases are app-owned
(0700).  “No” means the path is install-owned (`/data/app`), GMS-owned, or a
system path — app data cannot place the file there.

| # | Surface | Exact entry | Code | Startup | App-data | Update | Verdict |
|---|---|---|---|---|---|---|---|
| 1 | ART runtime app image | `cache/oat_primary/arm64/base.art` | **yes** (ART image + Dalvik `<clinit>`) | **yes** (process start, before `Application.onCreate`) | **yes** | **no** (absolute install path; new `/data/app` after update) | **CANDIDATE, blocked** |
| 2 | Local native lib fallback | `files/lib/libtmessages.49loc.so` | **yes** (`System.load`) | conditional (`ks.g` catch only) | **yes** | file **yes**, trigger **no** | **CANDIDATE, blocked** |
| 3 | GMS Dynamite module loader | `y6/e`, `y6/a`, `y6/h` | **yes** (`DelegateLastClassLoader` / `PathClassLoader`) | on demand (MLKit/Firebase) | **no** (path from `com.google.android.gms.chimera`) | n/a | **NO-GO** |
| 4 | SQLite `load_extension` | `cache4.db` view/trigger | **yes if enabled** (native extension) | **yes** (startup DB open) | **yes** | DB **yes** | **LATENT NO-GO** (disabled) |
| 5 | WebView app-data HTML/JS | `WebInstantView`, `BotWebView`, `TelegramWebProxy` | JS only (not native) | **no** startup WebView | n/a | n/a | **NO-GO** |
| 6 | `Runtime.exec` / `app_process` | `o6` EmuDetector | `/system/bin/netcfg` only | after `native_setJava` | no attacker arg | n/a | **NO-GO** |
| 7 | ART AOT odex/vdex | `/data/app/.../oat/arm64/base.{odex,vdex}` | **yes** (AOT) | **yes** | **no** (`/data/app` read-only) | n/a | **NO-GO** |
| 8 | `code_cache` / profileinstaller | `code_cache`, `/data/misc/profiles/...` | no (profile metadata) | provider | partly | file yes | **NO-GO** |
| 9 | `androidx.startup` / Emoji / Font | `InitializationProvider` | no | **yes** (provider before app) | no | n/a | **NO-GO** |
| 10 | Firebase / MLKit / FileProvider | manifest providers | no | **yes** (provider before app) | no | n/a | **NO-GO** |
| 11 | twidget / TGS / tlottie | `WidgetSandboxNative`, assets | JS at widget view / parse | **no** | message data | n/a | **NO-GO** |
| 12 | tgnet | `files/tgnet.dat` | no (parser / C2) | **yes** (network init) | **yes** | **yes** | **NO-GO** |
| 13 | media decoders | FFmpeg/dav1d/opus/tlottie | no (parse) | playback | yes | n/a | **NO-GO** |
| 14 | update APK / AppCenter | `beta` prefs / downloaded APK | APK install (user) | user tap | yes | yes | **NO-GO** (user-gated) |
| 15 | WebRTC/MLKit `loadLibrary` | `jingle_peerconnection_so`, `language_id_l2c_jni` | fixed APK libs | on use | no | n/a | **NO-GO** |
| 16 | native `dlopen` | `libnetd_client.so`, `libandroid.so` | fixed system libs | on use | no | n/a | **NO-GO** |

The CSV/Markdown copy is in `lab/loader_startup_components/`.

---

## 2. Candidate 1 — ART runtime app image (`cache/oat_primary/arm64/base.art`)

### 2.1 What loads it, exactly

The target is a **runtime-generated app image**, not a file in the APK's
`oat/` directory.  ART derives the path from the process data directory and
the dex basename:

* `art17/runtime/runtime_image.cc:1846-1851`
  `RuntimeImage::GetRuntimeImageDir()` = `<app_data_dir>/cache/oat_primary/`.
* `art17/runtime/runtime_image.cc:1855-1861`
  `GetRuntimeImagePath()` = `<dir>/<isa>/<basename(dex_location)>.art`.
* `art17/runtime/oat/oat_file_manager.cc:353-367` loads the runtime image only
  when the oat file exists, `kEnableRuntimeAppImage` is on, the oat is not
  AOT-compiled (`!compilation_enabled`), and `!oat_file->RequiresImage()`.
* `art17/runtime/startup_completed_task.cc:53-61` writes the runtime image
  only if no app image is already loaded and the compiler filter is not AOT;
  a rejected image can therefore be replaced by a legitimate one.

Device evidence that this exact file is mapped at app start:

```
telegramandroidwidget/evidence/evidence_20261101/new_beta_72799/tombstone_20.txt:386
00000000'6a000000-00000000'6a4a3fff rw- 0 4a4000
  [anon:dalvik-/data/user/0/org.telegram.messenger.beta/cache/oat_primary/arm64/base.art]

same file:2926
0000007a'f2c05000-0000007a'f2c10fff r-- 150000 c000
  /data/data/org.telegram.messenger.beta/cache/oat_primary/arm64/base.art

startup_db/tombstone_07:593,2485 shows the same two mappings.
```

The image header of the pulled sample is:

```
magic=b'art\n' version=b'119\0' pointer_size=8
image_begin=0x72f58000 image_size=0x4a0978 reservation=0x4a4000
oat_checksum=0x0 boot_image_checksum=0x7c37c4a0
```

(`lab/persistence_nonquickjs/sample/base_72799_original.art`; host check
`lab/loader_startup_components/scripts/art_update_path_check.py`).

### 2.2 Why `ks.<clinit>` is the startup hook

`ApplicationLoaderImpl` extends `w0` and does **not** override `onCreate`
(`ApplicationLoaderImpl.smali:1-17`; jadx
`org/telegram/messenger/ApplicationLoaderImpl.java`).  `w0.onCreate` is final:

```
jadx w0.java:414  onCreate()
        :457  ks.g(f13920b)
        :459  ConnectionsManager.native_setJava(false)
smali w0.smali:2263 onCreate; :2734 ks.g; :2740 native_setJava
```

`ks` has a real synthetic class initializer
(`ks.smali:27 .method static synthetic constructor <clinit>`).  The JVM
initializes `ks` before the static `ks.g` call, so a forged `ks.<clinit>` runs
before the real `ks.g` body.  `InitializeClass` invokes a class initializer
directly (`art17/runtime/class_linker.cc:6197-6203`), not through the
interpreter's `IsInvokable()` check, which is why a forged/abstract clinit is
usable.  The real `ks.g` then loads `libtmessages.49`
(`ks.smali:1484`) and startup continues.

Any class that ART initializes at startup can be targeted the same way;
`ks` is chosen because it has a real `<clinit>` and is reached by
`w0.onCreate` before the native load.  `w0` itself has no real `<clinit>`, so
a forged one would need an added method and is a variant of the same
`base.art` surface, not a separate loader.

`AppStartReceiver` handles `android.intent.action.BOOT_COMPLETED`
(`AppStartReceiver.smali:25-50`; manifest receiver lines 799-806), so the app
process — and therefore the image load and `ks.g` — is started at boot as
well as on launch.

### 2.3 Device status: loaded, not executed

The current forged image is **accepted** by the Sony and reaches
`ClassLinker::InitializeClass` from `w0.onCreate`, but crashes before the
forged `<clinit>` runs:

```
#00 art::ClassLinker::InitializeClass(...)+980
    called from org.telegram.messenger.w0.onCreate+478
signal 11, fault addr 0x60, x0=0, x1=0x11d (dex_class_def_idx 285)
x2=0x6a00117c (fake Class)
```

(`notes/persistence_local_existing_rce.md` §7.3; no tombstone file was saved
for that run.)  The image was mapped at `0x6a000000-0x6a377fff`; the failure is
a fake-`Class` layout / class-def-substitution problem, not an image load
rejection.  **No payload marker and no RCE yet.**  This is the closest
startup+app-data surface, but it is not a working loader today.

### 2.4 Update survival — the decisive problem

The runtime image contains the **absolute install path** in its DexCache
location data.  In the pulled sample:

```
$ strings -a -t x sample/base_72799_original.art | grep /data/app
    15f )/data/app/~~r1vDzV8CpQVWKXLwu8aDPA==/org.telegram.messenger.beta-JVB3quhnKMMIKSJdj4fj2A==/base.apk
```

The `strings` hit starts one byte early at `0x15f`; the path itself starts at
`0x160` (`lab/loader_startup_components/scripts/art_update_path_check.py`
prints `path @0x160 len=98`).  ART's loader
uses that string:

* `art17/runtime/gc/space/image_space.cc:3100-3135`
  `ImageSpace::OpenAndSetDexFiles()` reads
  `dex_cache->GetLocation()` and calls
  `oat_file->OpenOatDexFile(dex_file_location)`.
* `art17/runtime/oat/oat_file.cc:2240-2290`
  `OatFile::GetOatDexFile()` first looks up the **exact** string in the oat
  dex table; only if that fails does it try
  `DexFileLoader::GetDexCanonicalLocation(location)`.
* A package update installs to a new `/data/app/~~<new-hash>/...` directory.
  The old absolute path is neither an exact key in the new oat table nor a
  resolvable symlink, so `OpenAndSetDexFiles()` fails; `OatFileManager` falls
  back to the APK dex and may regenerate a legitimate image
  (`startup_completed_task.cc:53-61`).

Therefore the file survives an update at the filesystem level (it is ordinary
`cache/` data), but the **image is not update-surviving as an executable
artifact**.  It is a same-install / reboot persistence, not an app-update
persistence.  This is consistent with the main report's update-survival
paragraph (`REPORT_20261102.md:775-781`); the new detail here is the exact
absolute path and the exact-key lookup.

**Caveat:** if the device's `pm install -r` reuses the old code path, or if
the image's DexCache location is rewritten to a stable key that the new oat
table also contains, the conclusion would change.  The device test in §10
(`T2`) is the authority.  Do not claim update survival without it.

An ART/Mainline update is a separate invalidation: `InitAppImage` checks the
boot-image checksum (`image_space.cc:1289-1332`), so a new boot image rejects
the forged runtime image even on the same app install.

### 2.5 What would make it work

1. Fix the fake-`Class` layout so `InitializeClass` does not crash; the device
   fault (`class+0x24` null, `dex_class_def_idx=285`) suggests the
   zero-static-field class-def substitution is inconsistent with the real
   `Class` layout.  Using the real `ks` class def (5862) and patching only the
   `<clinit>` code item is the obvious next experiment; the copied real
   fields/methods already exist in the image.
2. For update survival, solve the absolute path problem (e.g. a stable
   DexCache location that the new oat table also has).  This is not
   demonstrated; a data-dex image does not help because the dex still has to
   be a key in the app's oat table (`REPORT_20261102.md:778-781`).

---

## 3. Candidate 2 — local native lib fallback (`files/lib/libtmessages.49loc.so`)

### 3.1 The exact path

`org.telegram.messenger.ks.g(Context)` (`ks.smali:1439-1907`;
jadx `ks.java:138-232`):

| step | smali | action |
|---|---|---|
| 1 | `ks.smali:1484` | `System.loadLibrary("tmessages.49")` in `try` |
| 2 | `ks.smali:1489-1505` | success: `ks.a = true`, log `loaded normal lib`, return |
| 3 | `ks.smali:1611-1625` | on `Error`: `getFilesDir()/lib`, `mkdirs()`, `libtmessages.49loc.so` |
| 4 | `ks.smali:1655-1672` | if it exists: `System.load(absolutePath)` |
| 5 | `ks.smali:1769` | otherwise `ks.k(...)` extracts `lib/<Build.CPU_ABI>/libtmessages.49.so` from `sourceDir` to `files/lib/libtmessages.49loc.so` |
| 6 | `ks.smali:2803` | `System.load(absolutePath)` after extraction |
| 7 | `ks.smali:1831` | final `System.loadLibrary("tmessages.49")` retry |

`ks.k` uses `ZipFile(getApplicationInfo().sourceDir)` and a fixed entry name
(`ks.smali:2634-2692`); there is no attacker-controlled path component.

### 3.2 Is app data enough to trigger it?

**No.**  The primary `System.loadLibrary` resolves through the app's
`nativeLibraryDir` and the classloader namespace.  The 72799 startup log shows
the namespace:

```
nb_v2_run10.log:15290
nativeloader: Configuring clns-5 ... library_path=/data/app/~~r1vDz.../lib/arm64:/data/app/.../base.apk!/lib/arm64-v8a,
permitted_path=/data:/mnt/expand:/data/user/0/org.telegram.messenger.beta
nb_v2_run10.log:15318
tmessages: loaded normal lib
```

So the platform would allow `System.load()` from `/data/user/0/...` (the
`permitted_path` includes it), but `System.loadLibrary` does not search app
data, and the APK lib is install-owned/read-only.  The local file is consulted
only after the primary load throws.  There is no app-data-only way to make
`/data/app/.../lib/arm64/libtmessages.49.so` disappear or fail: the app UID
cannot write `/data/app`, and no pre-load app-data allocation exists to force
an `ENOMEM`/`dlopen` failure.

The prior root-assisted proof (move the APK lib to `.bak`, plant a
`JNI_OnLoad` `.so` in `files/lib`) is real and confirms the loader; it is not
a no-root path.  The full analysis is
`notes/native_appdata_audit.md`; the platform correction (SELinux permits
`dlopen`/`System.load` from `/data`; the gate is only the
`UnsatisfiedLinkError`) is in §4 of that note.

### 3.3 Update survival

The file survives a normal app update (`files/` is preserved) and a reboot.
But:

* It is only loaded after a primary-load failure, which the app data cannot
  cause.
* The filename is versioned: `libtmessages.49loc.so`.  A future Telegram
  update that bumps `tmessages.49` to `tmessages.50` makes the planted `.49`
  file inert; the new `ks` looks for `libtmessages.50loc.so`.
* `ks.k` first deletes every entry in `files/lib` (`ks.smali:2571-2575`) when
  it runs, so a later fallback/extraction path can remove the file.

Thus it is **not** an update-surviving startup loader in the normal case.

The exception is a **broken/partial install** that leaves the package without
its ABI lib (or a build whose `JNI_OnLoad` `RegisterNatives` fails).  That would
make the fallback reachable, but it is an install/build condition, not an
app-data-only trigger; the first exploit cannot cause it.

---

## 4. Java / Dex class loaders

### 4.1 No `DexClassLoader`, `InMemoryDexClassLoader`, `DexFile.loadDex`

Raw scan over all four smali trees (`lab/loader_startup_components/scripts/scan_loaders.sh`):

```
Ldalvik/system/DexClassLoader;                 0
Ldalvik/system/InMemoryDexClassLoader;         0
Ldalvik/system/BaseDexClassLoader;             0
Ldalvik/system/DexFile;                        0
loadDex                                        0
defineClass                                    0
MultiDex / ReLinker / SplitInstall             0
```

There is no app-data dex loader.  `y6/e` is the only `PathClassLoader` /
`DelegateLastClassLoader` site.

### 4.1.1 Split APK / `LoadedApk` / `SourceDir`

The app's own `PathClassLoader` is created by the Android framework from the
installed package metadata (`sourceDir`, `splitSourceDirs`), not by Telegram
code.  There is **no `LoadedApk`/`ApplicationLoaders` symbol in the dex** and
no app call that adds a dex path.  `ApplicationInfo.sourceDir` appears only
in `ks.k` (`ks.smali:2634`), where it is used as a `ZipFile` to extract
`lib/<Build.CPU_ABI>/libtmessages.49.so`; the entry name and destination are
fixed.  Split APKs are install-owned; app data cannot add or replace one.

### 4.2 GMS Dynamite (`y6/e`, `y6/a`, `y6/h`) — real loader, wrong owner

`y6/e` is Google Play services' `DynamiteModule` loader (strings
`"DynamiteModule"` at `y6/e.smali:136`, `"com.google.android.gms.dynamite.descriptors."`
at `:144`).  It builds a class loader from a module path:

```
y6/e.smali:2347  Ly6/a;->a(ClassLoader, String) -> DelegateLastClassLoader
y6/e.smali:2380  new PathClassLoader(path, parent)       # pre-API-29 fallback
y6/a.smali:11-15  new DelegateLastClassLoader(path, parent)
y6/h.smali:2,59  PathClassLoader subclass; findClass first
```

The path (`Ly6/e;->e`) is assigned from a GMS ContentProvider cursor:

```
y6/e.smali:3415  "com.google.android.gms.chimera"
y6/e.smali:3479  ContentResolver.acquireUnstableContentProviderClient(uri)
y6/e.smali:3522  ContentProviderClient.query(...)
y6/e.smali:3928  sput-object p0, Ly6/e;->e  # cursor.getString(...)
```

The module ID (`c(Context, Ly6/d, String)`) and the path come from GMS, not
from Telegram app data.  A Telegram UID 10357 process cannot write
`/data/user_de/0/com.google.android.gms/...`; this is not an app-data loader.
`y6/h` is **not** unused (the earlier note said it was); it is the pre-API-29
fallback, but its path is still the GMS path.

`j6/e` is a different custom `ClassLoader`: it maps
`com.google.android.gms.iid.MessengerCompat` to the built-in `j6/f`
(`j6/e.smali:45`); no file path, no dex load.

---

## 5. Native loading and execution

### 5.1 `System.load` / `System.loadLibrary` sites

| Site | Name | App-data? |
|---|---|---|
| `ks.smali:1484` | `System.loadLibrary("tmessages.49")` | no (APK lib) |
| `ks.smali:1672` | `System.load(files/lib/libtmessages.49loc.so)` | **yes**, gated by primary failure |
| `ks.smali:1831` | `System.loadLibrary("tmessages.49")` retry | no |
| `ks.smali:2803` | `System.load(extracted files/lib/libtmessages.49loc.so)` | **yes**, extraction from APK |
| `org/webrtc/NativeLibrary$DefaultLoader.smali:78` | `System.loadLibrary(p1)` | no; `PeerConnectionFactory` passes the literal `"jingle_peerconnection_so"` (`PeerConnectionFactory$InitializationOptions$Builder.smali:64`) |
| `ThickLanguageIdentifier.smali:230-234` | `System.loadLibrary("language_id_l2c_jni")` | no; APK lib |

`files/lib` is the only app-data native path, and it is the gated fallback in
§3.  The classloader namespace would permit `/data/user/0/...` (logcat
`nb_v2_run10.log:15290`), so the gate is the primary load, not SELinux.

### 5.2 `dlopen` / `android_dlopen_ext`

IDA on `libtmessages.49.so` (md5 `2c0caa68a07fc26f79d13519af6c3526`):

```
import dlopen  0x1cb8b58
only real call site: sub_A45BD0 (WebRTC NetworkMonitor)
  0xa45f5c  dlopen("libnetd_client.so", 6)
  0xa45fac  dlopen("libandroid.so", 2)
  dlsym(..., "setNetworkForSocket" / "android_setsocknetwork")
generic wrapper sub_181CA18(path) { return dlopen(path, 258); }
  xrefs: 0x19ca348, 0x19ca3f0, 0x19ca498, 0x19ca540 — DATA ONLY,
  no code xref; surrounding table has "Unix"/"UnixNone" strings.
android_dlopen_ext: not imported.
```

`liblanguage_id_l2c_jni.so` also imports `dlopen` (TensorFlow Lite delegate
loading) but its strings contain no `/data` path; it is loaded by a literal
`System.loadLibrary`.  No `dlopen` call takes an app-data path.

Full dump: `lab/loader_startup_components/outputs/native_dlopen_sites.txt`.

### 5.3 `Runtime.exec` / `app_process`

There is no `Runtime;->exec` call in the dex.  The only `ProcessBuilder` is
`org.telegram.messenger.o6` (EmuDetector):

```
o6.smali:1538  const-string "/system/bin/netcfg"
o6.smali:1544  filled-new-array {netcfg}
o6.smali:1564  new ProcessBuilder
o6.smali:1592  start()
```

It is called from `ConnectionsManager.getInitFlags`
(`ConnectionsManager.java:760`); the native init path is after `ks.g` in
`w0.onCreate:459`.  The command is fixed; no app-data path/argument.
`app_process` does not appear in the dex.

---

## 6. WebView / JavaScript at startup

### 6.1 No startup WebView

There are only eight `new WebView` sites in the whole APK:

```
ji/k.smali:595                         (TelegramWebProxy)
recaptcha/internal/zzma.smali:137      (reCAPTCHA)
org/telegram/ui/web/m1.smali:436       (WebInstantView)
org/telegram/ui/web/s0.smali:573       (WebInstantView)
org/telegram/ui/web/q1.smali:419       (WebInstantView)
org/telegram/ui/ue1.smali:1399         (article/web UI)
org/telegram/ui/fw0.smali:1764         (article/web UI)
org/telegram/ui/ru.smali:5690          (article/web UI)
```

`w0.smali`, `ApplicationLoaderImpl.smali`, `LaunchActivity.smali`,
`AppStartReceiver.smali`, `InitializationProvider.smali`,
`EmojiCompatInitializer.smali`, and `ProfileInstallerInitializer.smali`
contain **zero** `WebView`/`loadUrl`/`addJavascriptInterface` references
(`lab/loader_startup_components/outputs/startup_classes_webview_counts.txt`).  The 72799 cold-start log for
PID 14579 has no `chromium`/`WebViewFactory`/`loadUrl` line; only
`loaded normal lib` (`nb_v2_run10.log:15318`) and normal startup.

The first WebView is created by a user action: opening an Instant View, a bot
web app, an article, a video, or a reCAPTCHA.  The `TelegramWebProxy` local
server (`ji/k`) is not a startup WebView either; it loads `about:blank`
(`ji/k.smali:2570`) and serves proxy traffic, not app-data files.

### 6.2 Settings / bridges

* `WebInstantView` (`q1`): `setAllowContentAccess(false)` (`:436`),
  `setAllowFileAccess(false)` (`:446`), JS enabled (`:451`),
  `setAllowFileAccessFromFileURLs(false)` (`:471`),
  `setAllowUniversalAccessFromFileURLs(false)` (`:476`); JS interface added at
  `:550`.
* `BotWebViewContainer` (`z0`): JS enabled (`:11945`),
  file access false (`:11970`), content false (`:11975`), file-from-file false
  (`:11980`), universal false (`:11985`); JS interfaces at `:12740`, `:12757`.
* `ArticleViewer` (`r1`): `setAllowContentAccess(true)` only (`:169`); with
  `targetSdk 36` the platform default `setAllowFileAccess` is false.  No
  `file://` page is loaded by `r1`.
* `ji/k` (TelegramWebProxy): `setAllowFileAccess(false)` (`:662`),
  content false (`:667`).
* `WebViewAssetLoader`: **0 hits**.
* `javascript:` scheme: **0 hits**.
* The `file://` literals in `LaunchActivity`, `PhotoViewer`,
  `MediaController`, `pt`, `hf/d` are media/intent paths, not WebView page
  loads.  `PhotoViewer` uses `addJavascriptInterface` for its video player,
  only when a video is opened.

No WebView path reads app-data HTML/JS at startup.

---

## 7. Providers, startup initializers, fonts, profiles

### 7.1 `androidx.startup.InitializationProvider`

Manifest lines 1179-1189 declare the provider with three initializers:
`EmojiCompatInitializer`, `ProcessLifecycleInitializer`,
`ProfileInstallerInitializer`.

`InitializationProvider.onCreate` gets its own `ProviderInfo.metaData` from
the **installed APK manifest** and passes it to `v4/a.a(Bundle)`
(`InitializationProvider.smali:172-184`).  `v4/a` iterates the metadata keys,
`Class.forName(name)` (`v4/a.smali:257,277`) and instantiates them.  The names
are compile-time manifest strings; app data cannot add a class.  This is APK
code loading, not app-data loading.

### 7.2 EmojiCompat / FontRequest

`EmojiCompatInitializer.b` builds the default config and calls `c(context)`
(`EmojiCompatInitializer.smali:90-150`).  `v7/s.a` finds a font provider with
`Intent("androidx.content.action.LOAD_EMOJI_FONT")` and
`queryIntentContentProviders` (`v7/s.smali:69-85`).  The provider is a content provider that advertises the action (normally the
system/GMS font provider); the font is data parsed by the platform font stack,
not code.  `FontRequest` (`o0/d.smali:135`) carries a provider authority/query
from resources, not an app-data path.  No `System.load`/`DexClassLoader` is
reachable from this initializer.

### 7.3 ProfileInstaller / ArtManagerLocal

`ProfileInstallerInitializer.b` schedules a runnable (`:85-94`) that writes a
baseline profile from the APK asset `dexopt/baseline.prof`
(`r4/d.smali:6327`) to `/data/misc/profiles/cur/0/<pkg>/primary.prof`
(`r4/d.smali:6305,6314`).  `ProfileInstallReceiver` writes a sentinel under
`getCodeCacheDir()` (`ProfileInstallReceiver.smali:485`) and handles
`INSTALL_PROFILE`/`SKIP_FILE`/`SAVE_PROFILE`; it is exported with the `DUMP`
permission (manifest 1214), not an app-data loader.  There is **no
`ArtManagerLocal`/`Dexopt` API** in the dex (only the profile strings above).
Profiles are compilation metadata; they do not inject code.

### 7.4 Firebase / MLKit / FileProvider

* `FirebaseInitProvider` (manifest 1144) runs before `Application.onCreate`;
  logcat shows `FirebaseApp: Device unlocked: initializing all Firebase APIs`
  (`nb_v2_run10.log:15300`).  It initializes Firebase from APK resources/classes; no app-data code load.
* `MlKitInitProvider` (manifest 1113) initializes MLKit; no app-data code
  load.
* `FileProvider` (manifest 859) reads `res/xml/provider_paths` from the APK;
  it exposes app files, it does not load them.
* `NotificationImageProvider` and `CallNotificationSoundProvider` serve
  notification data; no code.

### 7.5 `Application` static initialization

`w0` and `ApplicationLoaderImpl` have **no static constructor** in smali
(`grep 'static constructor'` = 0).  `ks` does have a real `<clinit>`
(`ks.smali:27`) that initializes arrays/strings; that is the class used by the
forged ART image.  The `AppComponentFactory` is the stock
`androidx.core.app.CoreComponentFactory` (manifest 161); it instantiates
components named in the APK manifest, not app data.

---

## 8. ART files other than `base.art`

### 8.1 `base.vdex` / `base.odex`

The device maps them from `/data/app/.../oat/arm64/`:

```
tombstone_20.txt:1073  /data/app/~~r1vDz.../oat/arm64/base.vdex
tombstone_20.txt:1565  /data/app/~~r1vDz.../oat/arm64/base.odex
```

`/data/app` is install-owned (system:system, read-only to UID 10357); the app
cannot write/replace them.  They are AOT code, but not an app-data surface.

### 8.2 `code_cache`

`code_cache` is used by:
* `ProfileInstallReceiver` for the profile-written sentinel
  (`ProfileInstallReceiver.smali:485`);
* `r4/a` for the device-protected profile sentinel;
* `w7/n` for `gl-programs` (MLKit GL shader cache).

None of these is an ART app-image path.  `RuntimeImage::GetRuntimeImageDir`
uses `cache/oat_primary`, not `code_cache` (`runtime_image.cc:1846-1851`).
There is no `DexClassLoader`/`DexFile` that would load a dex from `code_cache`.

The `gl-programs` cache is executable **GPU** metadata (shader programs), not
CPU code; it is read when a GL context is created (MLKit vision/rendering),
not in the cold-start path audited here.  It is a driver/parser surface, not an
app-data CPU loader.

### 8.3 Profiles

Profiles in `/data/misc/profiles/cur/0/<pkg>/primary.prof` are read by
dexopt/ART to guide AOT compilation of existing methods; they are not
executable metadata that redirects a class/method.  A corrupted profile is a
parser/DoS surface at most; it cannot insert a new method or class.

---

## 9. Data parsers that are often mistaken for loaders

These are **not** code loaders; they are listed to close false leads.

### 9.1 twidget / TGS / tlottie

* `WidgetSandboxNative` is registered by `JNI_OnLoad` (the twidget
  `RegisterNatives` batch at `sub_987CAC`; see
  `lab/native_appdata_audit/jni_onload_registrations.txt`).  It is a JNI
  binding, not a dynamic library load.
* The JS bundle is the APK asset
  `assets/WidgetSandbox/WidgetJS/sandbox-bundle.js`; it is read from the APK,
  not app data.
* The engine is created only when a widget bubble is bound:
  `ChatMessageCell` → `wv` → `hl0` → `pb` → `p.o` → `k0.e` →
  `WidgetSandboxNative.create` (`notes/update_widget_cache.md` §4.2).  A cold
  start on the chat list does not render the widget; `AppStartReceiver` does
  not open a chat.
* TGS is gzip + tlottie/Rust parsing; `tlottie` is statically linked.  It
  parses animation data; no `dlopen`/`System.load`.  The known TGS UAF is a
  memory-corruption primitive, not a loader.
* Note that chat-list startup does parse custom-emoji TGS documents with
  `RLottieNative` (main report §6); that is a startup *parser* surface.  A TGS
  UAF can become memory corruption, but it does not load a `.so`/dex and is not
  a code loader.

### 9.2 SQLite / `cache4.db`

`cache4.db` is opened at startup (`is.java:2232`, `sqlite3_open` in
`SqliteWrapper.cpp:142-154`) and its `params` view/triggers run.  SQLite 3.39.3
is app-bundled and **compiles** `load_extension()`, but:

* `load_extension()` is disabled by default
  (`sqlite3.c:123886` checks `SQLITE_LoadExtFunc`; `sqlite3.c:130807` checks
  `SQLITE_LoadExtension`).
* Telegram never calls `sqlite3_enable_load_extension` or
  `sqlite3_db_config` (source scan; `SqliteWrapper.cpp` only
  `sqlite3_open`/`sqlite3_exec`).
* In a trigger/view, `load_extension()` is rejected as
  `unsafe use of load_extension()` (device evidence in
  `notes/sqlite_trigger_rce.md:89-94`).

The old `#define SQLITE_OMIT_LOAD_EXTENSION 1` at `sqlite3.c:158` is inside the
VxWorks branch (`#if defined(__RTP__) || defined(_WRS_KERNEL)`), not the
Android build.  The correct statement is “compiled but runtime-disabled”; the
trigger path is a SQL execution primitive/DoS, not native code execution.
See `notes/sqlite_trigger_rce.md` §7 for the full correction.

### 9.3 tgnet

`files/tgnet.dat` / `files/dc<id>conf.dat` are parsed by the native
`Config`/`Datacenter` code at network init.  The parser can redirect the app
to an attacker-chosen DC (persistent C2) and has a short-auth-key OOB read,
but it does not `dlopen`/`System.load` a file.  Details:
`notes/tgnet_parser_audit.md`, `notes/startup_appdata_full_audit_20261102.md`
§5.

### 9.4 Media decoders

FFmpeg 8.1.3, dav1d, libvpx, opus and tlottie are statically linked into
`libtmessages.49.so`; they parse/decode media data.  There is no `dlopen` of a
codec `.so` from app data.  The known media parser bugs are memory-safety
issues, not loaders (`notes/ida_media_parsers_72799.md`,
`notes/tlottie_gzip_audit.md`, `notes/tgs_uaf_weaponization.md`).

### 9.5 Update APK / AppCenter

`k1` reads the `beta` prefs (`version`, `versionCode`, `path`, `lastCheck`) in
its constructor (`k1.java:44-64`).  `ApplicationLoaderImpl.g()` returns the
file at `path`; `v()` starts an `ACTION_VIEW` install intent through
`FileProvider` (`ApplicationLoaderImpl.java:26-70`).  The install requires a
user tap and the APK must be signed by Telegram's key; `REQUEST_INSTALL_PACKAGES`
is not `INSTALL_PACKAGES` (manifest 155 vs 823), so there is no silent install.
Microsoft AppCenter Distribute is present (manifest 233, 250) and is likewise
user-gated.  This is an update-delivery/phishing surface, not automatic code
execution.

There is **no `MY_PACKAGE_REPLACED`/`PACKAGE_REPLACED` receiver** in 72799
(manifest scan), so an update does not start the app or re-run any app-data
loader by itself.  A reboot or a user launch is still needed to reach the
startup path after an update.

---

## 10. Device test plan (Sony XQ-BT52)

Host-only audit; these are the tests that would settle the two candidates and
the WebView negative.  Full commands and interpretation matrix:
`lab/loader_startup_components/device_testplan.md`.

Preconditions:

```
adb shell getprop ro.product.model                 # XQ-BT52
adb shell getprop ro.build.version.release         # 13
adb shell getprop ro.build.version.security_patch  # 2023-07-01 expected
adb shell dumpsys package org.telegram.messenger.beta | grep -E 'versionCode|userId|codePath|nativeLibraryDir'
```

Back up and pull `cache/oat_primary/arm64/base.art` and `files/cache4.db` with
the existing app-UID shell; keep copies off-device.  Do **not** `pm clear`.
A failed ART image load is fail-closed; always have the original image.

| # | Test | Action | Expected / diagnostic |
|---|---|---|---|
| T0 | preflight | record `pm path`, versionCode, UID, cgroup, `run-as` state | baseline; note codePath for T2 |
| T1 | ART same-install | generate fake image from the **current** pulled `base.art`; write `files/.p`; atomically replace `cache/oat_primary/arm64/base.art`; `am force-stop`; cold start | marker `files/.p_started` with `uid=10357`; `loaded normal lib`; if no marker, logcat `Invalid image header` / `Failed to open app image` / `Failed to find OatDexFile` / `InitializeClass` |
| T2 | ART after update | `pm path` before; `adb install -r base72799.apk` (or a newer beta); `pm path` after; cold start; check marker | if codePath changed and image rejected: **update survival = no**; logcat exact error.  If marker runs, record it; the claim changes only with this evidence |
| T3 | ART reboot | `adb reboot`; wait; let `AppStartReceiver` receive `BOOT_COMPLETED`; check marker | marker at boot if image still valid (same install, not stopped state) |
| T4 | native fallback negative | plant a test `files/lib/libtmessages.49loc.so` whose `JNI_OnLoad` writes `files/.loc_proof`; cold start | no `.loc_proof`; `loaded normal lib`; no `Load local lib` (primary load succeeded) |
| T5 | native fallback positive control (root only) | move `/data/app/.../lib/arm64/libtmessages.49.so` to `.bak`; cold start; restore | `.loc_proof` present; logcat `Load local lib`; proves the loader but is **not** a no-root path |
| T6 | WebView negative | `logcat -c`; cold start; `logcat -d | grep -E 'chromium|WebViewFactory|AwContents|TelegramWebProxy'` | no Telegram-PID WebView lines; control: open an Instant View and see the lines |
| T7 | SQLite trigger | copy DB; create a `params` view calling `load_extension('/data/user/0/.../files/lib.so')`; cold start; restore | `unsafe use of load_extension()` / `not authorized`; no marker; SQL only, no native load |
| T8 | update APK | set `beta` prefs `path` to a test APK; cold start; observe blocking update screen | user tap required; signature check; no automatic install |

Do not run T5 on a production phone without root and a full backup; it is a
positive control only.  T1/T2 are the decisive tests for the stated goal.

### 10.1 Test mapping for the table

| Table row | Device test |
|---|---|
| 1 ART image | T1 (same install), T2 (update), T3 (reboot) |
| 2 native fallback | T4 (negative), T5 (root positive control) |
| 3 GMS Dynamite | static only; path is GMS-owned |
| 4 SQLite extension | T7 (trigger/view `load_extension`) |
| 5 WebView | T6 (cold-start filter + Instant View control) |
| 6 `Runtime.exec` | static; logcat shows only `netcfg` on emulator |
| 7 AOT odex/vdex | static; no app write path |
| 8 `code_cache`/profile | static; profile write only |
| 9 startup/Emoji | static; cold-start logcat |
| 10 Firebase/MLKit/FileProvider | static; cold-start logcat |
| 11 twidget/TGS/tlottie | control: open a widget chat; no startup path |
| 12 tgnet | static; startup logcat shows DC traffic, no code |
| 13 media | playback control; no loader |
| 14 update APK | T8 (user-gated; do not install untrusted APK) |
| 15/16 fixed native loads | static; logcat `nativeloader` lines |

---

## 11. Proven vs not proven

**Proven on the host:**

* The 72799 dex has no `DexClassLoader`/`InMemoryDexClassLoader`/`DexFile`
  loader; the only dynamic class loader is GMS Dynamite (`y6/e`), whose path
  comes from GMS.
* The only app-data native load is `ks.g`'s `files/lib/libtmessages.49loc.so`
  fallback; it is gated by a primary `System.loadLibrary` failure.
* `libtmessages.49.so`'s `dlopen` call sites are fixed `libnetd_client.so` /
  `libandroid.so`; no `android_dlopen_ext`; no app-data path.
* `Runtime.exec` is only the fixed `/system/bin/netcfg` emulator check.
* No startup WebView; no `WebViewAssetLoader`; no `javascript:`; file access
  is off for BotWebView/InstantView/TelegramWebProxy.
* `androidx.startup` initializers, Emoji/Font, ProfileInstaller,
  Firebase/MLKit/FileProvider do not load app-data code.
* SQLite 3.39.3 compiles `load_extension()` but disables it by default;
  Telegram never enables it; triggers get `unsafe use`.
* ART runtime image path and loading; `ks.<clinit>` trigger; device image
  accepted and crash in `InitializeClass`.
* The runtime image embeds the absolute `/data/app/.../base.apk` path; an app
  update changes that path, so `OpenAndSetDexFiles()` is expected to reject
  the stale image.  This is the main update-survival blocker.

**Not proven / device-dependent:**

* Whether the Sony accepts a stale `base.art` after `pm install -r` if the
  code path happens to be stable; T2 settles it.
* Whether the fake-`Class` layout can be fixed to execute `ks.<clinit>`; the
  current device PoC crashes before the payload.
* Whether any future Telegram build calls `sqlite3_enable_load_extension` or
  introduces a real app-data `DexClassLoader`; re-audit after updates.
* The native fallback positive control on the exact Sony build (root-only).

---

## 12. Exact evidence index

Conventions: `smali72799/` = `/tmp/opencode/dbgbuild/smali72799`;
`jadx72799_c1/` = `/tmp/opencode/jadx72799_c1/sources`; `art17/` =
`/tmp/opencode/art17`; `evidence/` = `telegramandroidwidget/evidence/`.

### App / startup

* `jadx72799_c1/sources/org/telegram/messenger/w0.java:414,457,459`
* `smali72799/smali/org/telegram/messenger/w0.smali:2263,2734,2740`
* `smali72799/smali/org/telegram/messenger/ks.smali:27,1439,1484,1672,1831,2556,2571,2634,2803`
* `smali72799/smali/org/telegram/messenger/ApplicationLoaderImpl.smali:1-17`
* `smali72799/smali/org/telegram/messenger/AppStartReceiver.smali:25-50`
* `lab/loader_startup_components/outputs/manifest_startup_full.txt` (aapt2
  xmltree; application, providers, receiver lines)
* `evidence/evidence_20261101/new_beta_72799/nb_v2_run10.log:15290,15318,15300`

### ART

* `art17/runtime/runtime_image.cc:1846-1861`
* `art17/runtime/oat/oat_file_manager.cc:340-367`
* `art17/runtime/gc/space/image_space.cc:3100-3135`
* `art17/runtime/oat/oat_file.cc:2240-2290`
* `art17/runtime/oat/image.cc:145-171`
* `art17/runtime/startup_completed_task.cc:53-61`
* `art17/runtime/class_linker.cc:6197-6203`
* `lab/persistence_nonquickjs/sample/base_72799_original.art` (path @0x160)
* `lab/loader_startup_components/scripts/art_update_path_check.py`
* `notes/persistence_local_existing_rce.md` §7.1-7.4
* `evidence/evidence_20261101/new_beta_72799/tombstone_20.txt:386,1073,1565,2926`
* `evidence/evidence_20261101/startup_db/tombstone_07:593,2485`

### Native

* `lab/loader_startup_components/outputs/native_dlopen_sites.txt`
* `notes/native_appdata_audit.md` §1-5
* `notes/persistence_20261101.md` §1 (root-assisted fallback proof)
* `smali72799/smali/org/telegram/messenger/o6.smali:1538,1544,1592`
* `smali72799/smali_classes4/org/webrtc/NativeLibrary$DefaultLoader.smali:78`
* `smali72799/smali/com/google/mlkit/nl/languageid/bundled/internal/ThickLanguageIdentifier.smali:230-234`

### WebView

* `smali72799/smali_classes4/org/telegram/ui/web/q1.smali:436,446,451,471,476,550`
* `smali72799/smali_classes4/org/telegram/ui/web/z0.smali:11945,11970,11975,11980,11985,12740,12757`
* `smali72799/smali_classes3/org/telegram/ui/r1.smali:169,312`
* `smali72799/smali_classes4/ji/k.smali:662,667,2570`
* `lab/loader_startup_components/outputs/webview_construction_sites.txt`
* `lab/loader_startup_components/outputs/webview_settings.txt`
* `lab/loader_startup_components/outputs/webview_schemes.txt`

### Providers / startup / fonts / profiles

* `smali72799/smali/androidx/startup/InitializationProvider.smali:172-184`
* `smali72799/smali/v4/a.smali:257,277`
* `smali72799/smali/androidx/emoji2/text/EmojiCompatInitializer.smali:90-150`
* `smali72799/smali/v7/s.smali:69-85`
* `smali72799/smali/o0/d.smali:135`
* `smali72799/smali/androidx/profileinstaller/ProfileInstallerInitializer.smali:85-94`
* `smali72799/smali/r4/d.smali:6305,6314,6327`
* `smali72799/smali/androidx/profileinstaller/ProfileInstallReceiver.smali:485`
* manifest lines 1144 (Firebase), 1113 (MLKit), 859 (FileProvider),
  1179-1189 (startup), 1214 (ProfileInstallReceiver)

### SQLite

* `Android/TMessagesProj/jni/sqlite/sqlite3.c:123886,130807`
* `Android/TMessagesProj/jni/sqlite/sqlite3.c:158` (VxWorks branch)
* `notes/sqlite_trigger_rce.md:54,89-94,381-385`
* `lab/loader_startup_components/scripts/sqlite_extension_check.py`
* `lab/loader_startup_components/outputs/sqlite_extension_check.txt`

### GMS Dynamite

* `smali72799/smali/y6/e.smali:136,144,2347,2380,3415,3479,3522,3928`
* `smali72799/smali/y6/a.smali:7-27`
* `smali72799/smali/y6/h.smali:2,59`
* `smali72799/smali/j6/e.smali:45`

### Update flow

* `jadx72799_c1/sources/org/telegram/messenger/k1.java:44-64`
* `jadx72799_c1/sources/org/telegram/messenger/ApplicationLoaderImpl.java:26-70`
* manifest 155 (`REQUEST_INSTALL_PACKAGES`), 823 (`RefererReceiver`
  permission), 233/250 (AppCenter)
* `notes/android_update_daemon_survival.md` §6 (update kills the app cgroup;
  app data survives)

---

## 13. Residual risks / what would change the verdict

* **A stable ART image key.** If a forged image can use a DexCache location
  that survives a new `/data/app/~~<hash>` (or if the image is regenerated
  into a still-valid key), the ART candidate could become update-surviving.
  Not demonstrated; T2 decides.
  A theoretical variant is a stable `/proc/self/fd/<n>` alias that
  `GetDexCanonicalLocation()` resolves to the current APK; it needs a
  predictable fd and is not demonstrated, so it is a hypothesis only.
* **A fixed `ks.<clinit>` layout.** The device crash is a layout bug; fixing
  it would make the ART candidate a real same-install/reboot code exec, but
  not automatically update-surviving.
* **A future `System.loadLibrary` failure.** If a Telegram build/broken install
  leaves no ABI lib, the native fallback becomes a no-root app-data loader.
  That is an install/build condition, not app-data-only; re-audit each update.
* **A future `sqlite3_enable_load_extension` call or a new `DexClassLoader`.**
  Both are absent in 72799; a future build could reintroduce them.
* **A WebView startup path.** None in 72799; a future build that instantiates
  WebView in `Application.onCreate` or a startup provider with a `file://`/
  app-data URL would change the no-go.
* **A parser memory-corruption chain.** TGS/SQLite/media/WebP bugs are
  memory-corruption surfaces, not loaders; they still need a full exploit to
  become code execution.  This audit does not claim any.

No false loader is promoted: every row labelled **NO-GO** either does not
load code (parser/metadata) or does not read an app-data path (APK/GMS/system
path).  The only two true loaders are ranked 1 and 2, and both fail one of the
four requirements today.
