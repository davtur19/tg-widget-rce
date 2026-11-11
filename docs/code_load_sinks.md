# Code-load / code-execute sinks in Telegram 72799 — the exhaustive audit

Date: 2026-11-02. Host/static only; no device run in this pass.
Target: `org.telegram.messenger.beta` 13.2.0 beta, versionCode **72799**,
arm64 (`lib/arm64-v8a/libtmessages.49.so`, md5
`2c0caa68a07fc26f79d13519af6c3526`, 27,016,000 B, BuildId
`645cce3998197329915f6cbfcc9ffd7f124d9f86`; `liblanguage_id_l2c_jni.so`,
1,019,552 B, md5 `96bf0e71fe2033edfd0bc5b26fb8a8f1`), Sony XQ-BT52,
Android 13, UID 10357.

This note answers one question: **which sink in all Telegram code can consume
app data at startup (boot / process start / before `Application.onCreate`) and
execute it as code?** It enumerates every sink, accounts for every one, and
ranks the survivors. It does not modify the main report.

Companion lab: `lab/code_load_sinks/` — `sinks.csv` (36 rows x 12 columns),
`callgraphs.md`, `no_go.md`, `device_plan.md`, `scan_java.sh`, `evidence/`.

**Scope boundary.** The question is about code *the app itself* loads at
startup. Excluded by that definition (and confirmed absent from app code):
`app_process`/`linker64` helper processes (0 references in all four dex and in
`libtmessages.49.so`), the widget/QuickJS RCE, and any attacker-launched
process. The ART runtime image is kept in scope because ART loads it without
any app code running first; it is ranked but flagged as the generic ART
mechanism.

---

## 0. Verdict

**There is no Telegram-specific loader that the app itself loads from app data
at startup on a healthy install.** After accounting for every Java, native,
JNI and ART sink in this build:

| # | Sink | Telegram-specific | App data | Startup | Code | Status |
|---|---|---|---|---|---|---|
| 1 | `ks.g` fallback `files/lib/libtmessages.49loc.so` (`System.load`) | **yes** | **yes** | yes (once J1 throws) | **yes** | **real loader, dead gate** |
| 2 | ART runtime image `cache/oat_primary/arm64/base.art` | no (ART-generic, app file) | **yes** | **yes** (before app code) | **yes** | works only same-install; update-fragile; not a Telegram loader |
| 3 | WAMR AOT/JIT (`libtmessages`) | yes (tgcalls) | no (memory buffer) | no | **yes** | only `PROT_EXEC` producer; no file path |
| 4 | Breakpad `execve` (`libtmessages`) | yes (bundled) | no | no | yes | **dead code** (JNI never called) |
| 5 | everything else (Java loaders, dlopen, JNI_OnLoad, init_array, providers, WebView, GMS) | – | no | – | mostly no | no-go |

The one Telegram-specific app-data native loader (`ks.g`) is gated on
`System.loadLibrary("tmessages.49")` throwing, and **no app-data-only action
can make it throw**. The only app-writable file whose content ART executes is
the runtime app image, which is the generic ART mechanism the user has already
rejected (and which additionally embeds the absolute install path, so it does
not survive an update).

New in this pass, relative to `notes/loader_startup_components.md`:

1. The only executable-memory creation in Telegram's native code is the **WAMR
   AOT loader** (`mmap prot=7`, `mprotect prot=7`); its input is an in-memory
   module buffer, and there is **no `open`/`fopen` anywhere in the WAMR address
   range** (`0xFB0000-0xFF4000`). It is not a file loader.
2. The only `execve` instructions in the binary are **2 Breakpad syscalls in
   dead code**: `Java_...Utilities_setupNativeCrashesListener` is declared
   (`Utilities.smali:2684`) and never invoked by any dex.
3. `Runtime.exec` **does not exist** in the app at all (0 sites in all four
   dex). The only process spawn is `ProcessBuilder("/system/bin/netcfg")`.
4. `android_dlopen_ext` is absent from both native libraries **and** from every
   dex string, and there is no dex-class loader of any kind.
5. There are **two** `ks.g` call sites in `w0` (`w0.smali:1405` in `w0.w()`,
   `w0.smali:2734` in `onCreate`). `w0.w()` is the shared "ensure initialised"
   entry used by the widget providers (`ChatsWidgetProvider`,
   `ContactsWidgetProvider`), `PushListenerController` and the notification
   receivers; the boot receiver starts the process, which runs `onCreate`.
   Either way the startup trigger surface for J1/J2 is wider than
   `Application.onCreate` alone.
6. `liblanguage_id_l2c_jni.so` has exactly two `dlopen`s, both fixed literals
   (`libandroid.so`, `libdvm.so`), and 6 clean `INIT_ARRAY` constructors.
7. `System.loadLibrary("jingle_peerconnection_so")` targets a library that does
   not exist in the APK — it can only throw.

---

## 1. Method and accounting

Scanned:

* **Java/dex** — all four dex, via the apktool tree
  `/tmp/opencode/dbgbuild/smali72799` (`smali` 11,979 files, `smali_classes2`
  579, `smali_classes3` 8,526, `smali_classes4` 963). Script:
  `lab/code_load_sinks/scan_java.sh` (regenerates `evidence/10_java_api_sinks.tsv`).
  Raw dex string checks were also run on `classes.dex` … `classes4.dex` to
  catch names that never appear in smali syntax.
* **Native** — IDA 9.4 on `libtmessages.49.so` (IDB
  `<HOME>/ailocal/Telegram/.opencode/idbs/libtmessages_49_arm64_media_annotated.i64`),
  `readelf`/`llvm-objdump` on both `arm64-v8a` libraries. Every import xref was
  resolved to its caller; `INIT_ARRAY` entries were recovered from
  `R_AARCH64_RELATIVE` relocations (the file bytes are zero).
* **ART** — the existing 72799 tombstones and the ART 17 sources used in
  `notes/loader_startup_components.md`; no re-derivation here.

Accounting (every hit is attributed; counts are the actual scan results):

| Family | Sites | Where |
|---|---|---|
| `System.load` | 2 | `ks.smali:1672`, `:2803` |
| `System.loadLibrary` | 4 | `ks.smali:1484`, `:1831`, `NativeLibrary$DefaultLoader:78`, `ThickLanguageIdentifier:234` |
| `Runtime.exec` | **0** | – |
| `ProcessBuilder.start` | 1 | `o6.smali:1592` |
| `DexClassLoader` / `InMemoryDexClassLoader` / `BaseDexClassLoader` / `DexFile` / `loadDex` / `defineClass` | **0** | – |
| `PathClassLoader` / `DelegateLastClassLoader` | 8 refs, 1 owner | `y6/a`, `y6/e`, `y6/h` (GMS Dynamite) |
| `createPackageContext` | 5 | GMS/Firebase/core |
| WebView `addJavascriptInterface` | 10 calls (+1 interface declaration) | UI classes |
| WebView construction | 14 | UI classes |
| native `dlopen` (libtmessages) | 3 xrefs, 1 real caller | `0xa45f5c`, `0xa45fac`, wrapper `0x181ca18` |
| native `dlsym` (libtmessages) | 5 xrefs | `0xa45f74/c4`, `0x162b72c`, `0x16886a0`, `0x181ca90` |
| native `dlopen` (MLKit) | 2 | `0xb15a8`, `0xb97e4` |
| native `android_dlopen_ext` | **0** | not imported, not a dex string |
| native `execve` | 2 (raw `svc`) | Breakpad, dead |
| native `clone` / `wait4` / `ptrace` | 1 / 2 / 6 | Breakpad, dead |
| native `system`/`popen`/`posix_spawn`/`fork` | **0** | – |
| `mmap` | 13 call sites | 11 via PLT + 2 via GOT |
| `mprotect` | **1** | WAMR only |
| `JNI_OnLoad` | 1 | `0x16efa34` |
| `RegisterNatives` | 3 tables | `sub_7529D4`, `sub_755ABC`, `sub_A5801C` (+1 `GetMethodID` in `sub_74ECC0`) |
| `INIT_ARRAY` constructors | 18 + 6 | libtmessages + MLKit |
| `DT_INIT` | **0** | absent in both |
| ART app-data code files | 1 | `cache/oat_primary/arm64/base.art` |

---

## 2. Java / dex sinks

### 2.1 `System.load*` — six sites, one app-data path

| Ref | API | Argument | Startup? | App-data? |
|---|---|---|---|---|
| `ks.smali:1484` | `loadLibrary("tmessages.49")` | literal | **yes** (`w0.onCreate:2734`, `w0.w():1405`) | no — `/data/app/.../lib/arm64` |
| `ks.smali:1672` | `load(<files>/lib/libtmessages.49loc.so)` | `getFilesDir()` | only in `catch(Error)` of the above | **yes** |
| `ks.smali:1831` | `loadLibrary("tmessages.49")` retry | literal | same | no |
| `ks.smali:2803` | `load(<extracted>)` | `getFilesDir()` | only after `ks.k` extraction | path yes, content from APK |
| `NativeLibrary$DefaultLoader.smali:78` | `loadLibrary(p1)` | builder default `"jingle_peerconnection_so"` (`Builder:64`) | on WebRTC use | no; **lib absent from APK** |
| `ThickLanguageIdentifier.smali:234` | `loadLibrary("language_id_l2c_jni")` | literal | on MLKit use | no (APK lib) |

`ks.g` (`ks.smali:1439-1907`) in order: `if (ks.a) return;` → try J1 →
`catch (Error)` → `files/lib/libtmessages.49loc.so` exists? → `System.load`
(J2) → else `ks.k` extraction (`ks.smali:2556`, `ZipFile(sourceDir)` at 2634,
entry `lib/<ABI>/libtmessages.49.so`) → `System.load` (J4). Nothing else in the
app calls `ks.g`; `w0.w()` and `w0.onCreate` are the only two call sites
(`w0.smali:1405`, `:2734`), both with the same behaviour.

**Why J2 cannot be reached from app data.** `loadLibrary` resolves through
`ApplicationInfo.nativeLibraryDir` and `base.apk!/lib/arm64-v8a` (AOSP 13
`LoadedApk.makePaths`), both `system:system`. App data is in the linker
namespace *permitted* path (`/data:/mnt/expand:/data/user/0/<pkg>`) but not in
its search path; "permitted" is what makes J2 legal once reached, not what makes
J1 fail. The APK entry is deflated and install-owned, so `ks.k`'s source can be
neither replaced nor removed by UID 10357.

The only app-data way to make J1 throw is to make `JNI_OnLoad` (`0x16efa34`)
fail: it returns `-1` if any of the three gating helpers (`sub_74ECC0`,
`sub_7529D4`, `sub_755ABC`) fails. Those helpers need
`FindClass`/`GetMethodID`/`RegisterNatives` to succeed against class metadata
that lives in the APK or in the ART image. Changing that metadata from app data
means rewriting `cache/oat_primary/arm64/base.art` — the ART image — which is
itself a code-execution primitive. **The gate is circular with the ART image;
it is not an independent route.**

### 2.2 Process execution

* `Runtime.exec` — 0. `Runtime` is used only for `availableProcessors`,
  `freeMemory`, `totalMemory`, `maxMemory`, `gc`, `addShutdownHook`.
* `ProcessBuilder` — 1 site, `o6.smali:1592`, argv `{"/system/bin/netcfg"}`,
  `directory("/system/bin")`, `redirectErrorStream(true)`. It sits in
  `o6.b()Z` (`o6.smali:1244`, exec block 1538-1592). Chain:
  `ConnectionsManager.getInitFlags()` (`ConnectionsManager.smali:1710`) →
  `o6.h` (1718) → `o6.f` (1726) → `o6.b` (called at 2231). `getInitFlags` is a
  Java method whose ID is cached by `JNI_OnLoad`'s `sub_7529D4` (string
  `"getInitFlags"` at `0x20920e`) and called from native during network init —
  so this exec **does** happen at startup, but with a fixed system binary and
  no attacker-controlled argv.
* `PackageInstaller` / `application/vnd.android.package-archive`
  (`ApplicationLoaderImpl:274`, `i0:35900`, `sr:1333`, `bh/f:2691`,
  `k6/g:1259-1314`) — APK install, user-confirmed.

### 2.3 Class loaders

* `DexClassLoader`, `InMemoryDexClassLoader`, `BaseDexClassLoader`, `DexFile`,
  `DexFile.loadDex`, `defineClass`, `addDexPath`, `makeDexFile`,
  `ApplicationLoaders`, `LoadedApk`, `splitSourceDirs`, `nativeLibraryDir`,
  `SplitInstallHelper` — **0 in smali and 0 as raw dex strings**.
* `y6/e` is Google Play services `DynamiteModule`: the dex path is read from
  the `com.google.android.gms.chimera` provider (`y6/e.smali:3415/3479/3522`,
  stored at `:3928`), then `DelegateLastClassLoader` (`y6/a.smali:11/15/27`,
  called at `y6/e.smali:2347`) or `PathClassLoader` (`y6/e.smali:2380`);
  `y6/h` is the pre-API-29 fallback. GMS-owned path, not app data.
* `j6/e` is the only direct `java.lang.ClassLoader` subclass in the app (the
  only other loader class, `y6/h`, extends `PathClassLoader`): it maps
  `com.google.android.gms.iid.MessengerCompat` to the built-in `j6/f`; no path.

### 2.4 `createPackageContext`

5 sites: `FlagProviderImpl:619` (GMS flags), `y6/e:4719` (Dynamite),
`v7/z7:513/544` (Firebase options), `g0/f:3033` (shortcut icon resources).
They return a `Context`; none loads a class or a library from it.

### 2.5 WebView JS bridges

10 `addJavascriptInterface` calls (plus one boundary-interface declaration)
over 14 `WebView` constructions — all in UI classes (`org/telegram/ui/web/*`,
`Components/*`, `PhotoViewer`, the YouTube player, recaptcha). Bridges:
`TelegramWebviewProxy`, `Instant`, `YoutubeProxy`, `JavaScriptInterface`. No
WebView is created in `ApplicationLoaderImpl`, in `w0`, in any
`ContentProvider`, or in `AppStartReceiver`. JS in a WebView executes JS, not
native code; none of the bridge methods calls `System.load*`, `dlopen` or a
class loader.

### 2.6 Widget QuickJS

`WidgetSandboxNative.create([B[B[BFFI[B[B[B[BZL...)`
(`WidgetSandboxNative.smali:52`, called at `k0.smali:1263`) takes byte arrays,
not paths. The bytes come from string resources via `dd.L0(resId, null)` (APK),
and the asset bundles (`assets/WidgetSandbox/WidgetJS/*.js|*.qbc`) are listed
with SHA-256 in `assets/WidgetSandbox/manifest.txt`. No file-based module
loader exists in the QuickJS build (`js_module_loader` / `js_std_*` strings
are absent from the binary). This is the rejected widget route, and it is not
an app-data file loader either.

### 2.7 Startup containers

Manifest providers (created before `Application.onCreate`):
`androidx.car.app.connection.provider`, `androidx.core.content.FileProvider`,
`NotificationImageProvider`, `CallNotificationSoundProvider`,
`MlKitInitProvider`, `FirebaseInitProvider`, `androidx.startup.InitializationProvider`.
The startup provider's initializers are exactly
`androidx.emoji2.text.EmojiCompatInitializer`,
`androidx.lifecycle.ProcessLifecycleInitializer` and
`androidx.profileinstaller.ProfileInstallerInitializer` (manifest
`meta-data` lines 1183/1186/1189) — font/emoji metadata, lifecycle, profile
installation. None loads code. `AppStartReceiver` (BOOT_COMPLETED; manifest receiver line 811,
action line 820) starts the process, i.e. the J1 path, and schedules a
`Runnable`; it adds no new sink. It is the **only** BOOT_COMPLETED receiver.

---

## 3. Native sinks — `libtmessages.49.so`

### 3.1 Imports

`readelf -d`: `NEEDED libm, libandroid, liblog, libdl, libjnigraphics, libz,
libGLESv2, libEGL, libOpenSLES, libc`; `SYMBOLIC`, `BIND_NOW`, no
`RUNPATH`/`RPATH`, **no `DT_INIT`**. Undefined symbols: 434. Loader/exec
relevant: `dlopen`, `dlsym`, `dlerror`, `dl_iterate_phdr`, `mmap`, `mprotect`,
`syscall` (unused PLT stub). **Absent as imports**: `execve`, `execv`,
`execvp`, `execl`, `posix_spawn`, `posix_spawnp`, `system`, `popen`, `fork`,
`vfork`, `clone`, `android_dlopen_ext`, `dlmopen`, `memfd_create`
(`evidence/01_native_imports.txt`).

### 3.2 `dlopen` — three xrefs, one real caller

```
0xa45f5c  dlopen("libandroid.so", 2 = RTLD_NOW)                  } WebRTC NetworkMonitor
0xa45fac  dlopen("libnetd_client.so", 6 = RTLD_NOW|RTLD_NOLOAD)   } sub_A45BD0
0x181ca20 sub_181CA18 -> dlopen(path, 258)                        data-only xrefs
```

The two WebRTC strings are not rodata pointers: `libandroid.so` is assembled
byte-by-byte on the stack at `0xa45f40-0xa45f58`, and `libnetd_client.so` is
copied from rodata `0x26c585`. Both are compile-time constants.

`sub_181CA18` has **no code xref**; its four references are a
function-pointer table at `0x19ca348/3f0/498/540` (surrounded by `Unix`/
`UnixNone` strings — a library-internal vtable), and those table slots are
themselves unreferenced (no xref to any address in `0x19ca2f8-0x19ca330`).
The wrapper is dead even for indirect callers.

### 3.3 `dlsym` — five xrefs, all fixed or data-only

`0xa45f74/c4` (`setNetworkForSocket`, `android_setsocknetwork`), `0x162b72c`
(`dlsym(NULL, "getrandom")`), `0x16886a0` (`dlsym(NULL,
"android_set_abort_message")`), `0x181ca90` (data-only wrapper `0x181ca88`).

### 3.4 `JNI_OnLoad` and `RegisterNatives`

`JNI_OnLoad` at `0x16efa34` (228 bytes): `srand(time())`, then four helpers —
`sub_74ECC0` (`FindClass`+`GetMethodID` for `AnimatedFileDrawableStream`), `sub_7529D4`
(`NativeByteBuffer` 5 natives + `ConnectionsManager.getInitFlags`),
`sub_755ABC` (`FfmpegAudioDecoder` 6 natives), `sub_A5801C` (a static table at
`qword_19ECC60`) — then `ExceptionCheck`/`ExceptionClear`. All names and
signatures are compile-time literals in `.rodata` / `.data.rel.ro`; nothing is
read from a file, property or environment variable. JNI exports: 418 `Java_*`
symbols, none of which loads a library or dex (the closest is
`Utilities_readlink`/`readlinkFd`).

### 3.5 `INIT_ARRAY` / `DT_INIT`

`.init_array` at `0x19594c8`, 18 entries (144 bytes), all `R_AARCH64_RELATIVE`
(file bytes are zero). Entry points: `0x109a60c, 0x109a8bc, 0x16ae860,
0x742544, 0x7425e4, 0x742684, 0x74738c, 0x83d1f0, 0x86e4b8, 0x86f544, 0x8927dc,
0x8a920c, 0x8b68a0, 0x99a97c, 0xa6abd0, 0xa9bd54, 0xab9398, 0x147079c`.
Transitive callee scan (depth 2) for `dlopen/dlsym/mmap/mprotect/open/fopen/
openat/execve/system/popen/posix_spawn/android_dlopen_ext`: **empty for all 18**
(`evidence/04_init_array.txt`). `DT_INIT` is absent.

### 3.6 `execve` — two sites, both dead Breakpad

Two raw `svc` with `x8=59` (`execve`): `0x158aeb4`, `0x158b9b0`. Together with
`clone` (`0x158af60`), `wait4` (`0x158b05c`, `0x158ea60`) and 6 `ptrace` sites
they are the Google Breakpad `ExceptionHandler::GenerateDump` machinery
(strings `ExceptionHandler::GenerateDump sys_pipe failed:` /
`waitpid failed:` at `0x158aee0`/`0x158b0bc`; `google-breakpad` typeinfo;
`-----BEGIN BREAKPAD MICRODUMP-----`). Its only entry point is
`Java_org_telegram_messenger_Utilities_setupNativeCrashesListener` (`0x74cef8`),
which calls `sub_1589F90` (the ExceptionHandler constructor) with the single
`jstring` path (dump directory). **`Utilities.setupNativeCrashesListener` is
declared at `Utilities.smali:2684` and is never called from any dex** — the
whole exec path is dead in this build (`evidence/06_exec_sites.txt`).

`system`, `popen`, `posix_spawn`, `fork` do not exist at all.

### 3.7 Executable memory — WAMR only

`mprotect` has exactly one call site (`sub_FB2A70`, `prot = a3 & 7`); `mmap` has
13 sites, of which only the WAMR pair can request `PROT_EXEC`:

```
sub_FB2768  mmap(addr, len, prot = a3 & 7, flags, fd = -1)   a3 in {0,3,7}
sub_FB2A70  mprotect(addr, len, prot = a3 & 7)                a3 in {3,7}
sub_FED93C  AOT loader: mmap prot=3 then mprotect prot=7
sub_FF1F5C  AOT loader: mmap prot=7
```

All other `mmap`s are `PROT_READ|PROT_WRITE` anonymous (`prot=3`, `flags=34`) or
`PROT_READ` file-backed (`prot=1`, `flags=2`, e.g. the two GOT-based calls in
`sub_181DCC8`/`sub_181EF78`) — allocators, parsers and Rust panic messages, never
executable.

The WAMR (`wasm_runtime_*`) code is present in full: interpreter loader
(`sub_FCC7A0`), AOT loader (`sub_FED93C`), magic dispatch (`sub_FB3C90`), and
the C++ entry `sub_B761CC`, whose address is stored in a `.data.rel.ro` pointer
table at `0x18d49f0` (the surrounding slots `0x18d49e0/0x18d49e8/0x18d49f8`
are `0xb76110/0xb761a8/0xb76780`, i.e. a vtable-shaped run of functions).
But:

* there is **no `open`/`openat`/`fopen`/`stat`/`access` xref from any function
  in `0xFB0000-0xFF4000`** — the module is never read from a file;
* there is **no `.wasm`/`.aot` string** in the binary and no such asset in the
  APK;
* no Java/Kotlin code references wasm (0 case-insensitive hits in all four dex).

So the module bytes come from a `std::vector<uint8_t>` supplied by tgcalls (the
RTTI names show `...function<void(vector<unsigned char>)>` callbacks in
`tgcalls::v2wasm::ReferenceCallCore`). It is a real "map and execute" primitive,
but not a file loader and not a startup path.

### 3.8 Everything else in the binary

`dl_iterate_phdr` (2 sites) is used by the Rust backtrace and by the
module-base helper — data only. The statically linked components — `tgnet`,
FFmpeg/dav1d/opus/libvpx/libjpeg, rlottie, the widget JS engine, Telegram's
SQLite fork (version string `3.39.3`) and tgcalls/WebRTC/BoringSSL — contain
**no `dlopen`/`dlsym` xref outside the three sites above** and no exec import,
so none of them can load code. In particular SQLite's `load_extension` is not
reachable: the extension loader is the only SQLite code that would call
`dlopen`, and no such xref exists. (WebP/PNG decoding goes through the
platform's `BitmapFactory`, i.e. system libraries.)

---

## 4. Native sinks — `liblanguage_id_l2c_jni.so`

Google MLKit language-id (TFLite). Imports `dlopen`, `dlsym`, `mmap`,
`__system_property_get`; `DT_INIT` absent; `.init_array` 6 entries.

* `0xb15a8` — `dlopen("libandroid.so", RTLD_NOW)` in a lazily-run init routine
  (`0xb1584`), then `dlsym` of `ATrace_beginSection`/`ATrace_endSection`/
  `JNI_GetCreatedJavaVMs` (`0x170b3`, `0x16233`, `0x13c14`, `0x144ce`).
* `0xb97e4` — `dlopen(path, RTLD_LAZY)` inside helper `0xb97d0`, whose only
  caller (`0xb96f0`) passes the rodata pointer `0x180e8` = `"libdvm.so"`; then
  `dlsym("JNI_GetCreatedJavaVMs")`.
* 6 `INIT_ARRAY` constructors (`0xf3f40`, entries `0xe9fa4, 0xea5d8, 0xd53d4,
  0xa210c, 0xbcf54, 0xbd9bc`): `getauxval`, `__system_property_get`, internal
  init. The library has exactly two `dlopen` call sites and neither is inside
  one of the six constructors.

Not Telegram code and not app-data driven; listed for completeness.

---

## 5. ART / system sinks

| Surface | Path | App-writable | Executed | Verdict |
|---|---|---|---|---|
| runtime app image | `<data>/cache/oat_primary/arm64/base.art` | **yes** | **yes**, at process start, before `Application.onCreate` | the only app-data code ART maps |
| AOT odex/vdex | `/data/app/.../oat/arm64/base.{odex,vdex}` | no | yes | install-owned |
| boot image | `/data/misc/apexdata/com.android.art/dalvik-cache` | no | yes | system |
| JIT cache | `/memfd:jit-cache` | no | yes | runtime memory |

The runtime image is mapped in the 72799 tombstone at `0x6a000000-0x6a4a3fff`
(`rw-`, `[anon:dalvik-.../cache/oat_primary/arm64/base.art]`) and
`0x7af2c05000` (`r--`, the file). The class-init hook is `ks.<clinit>`
(`ks.smali:27`), reached from `w0.onCreate` → `ks.g` before the native load.
Its two blockers are unchanged: (a) the current forged image crashes in
`ClassLinker::InitializeClass` (fake `Class` layout), and (b) the image embeds
the absolute `/data/app/~~<hash>/.../base.apk` location in its DexCaches, so a
normal update (new install path) invalidates it.

---

## 6. Ranking (Telegram-specific first)

### 6.1 Rank 1 — `ks.g` local-library fallback (J2)

* Telegram-specific: **yes** — it is Telegram's own loader, not a framework
  mechanism.
* Executes **app-data native code** with `System.load` + `JNI_OnLoad`.
* The `ks.g` entry is reached at every process start — `Application.onCreate`
  (`w0.smali:2734`), BOOT_COMPLETED (`AppStartReceiver` → process start) and
  widget updates (`w0.w()` at `w0.smali:1405`); the app-data branch (J2) is
  taken only inside the `catch (Error)`.
* Survives reboot and update **as a file** (`files/` is preserved); the name is
  version-pinned (`libtmessages.49loc.so`), and `ks.k` deletes every entry in
  `files/lib` with `listFiles()`+`delete()` before extracting
  (`ks.smali:2560-2580`).
* **Fails because the trigger is not app-data-reachable.** The gate is J1
  throwing; the platform resolves J1 in install-owned paths; the only app-data
  lever on `JNI_OnLoad` is ART class metadata, i.e. the image (rank 2).
* Therefore: **not a no-root startup loader**. It is the correct answer to
  "which Telegram code *would* load an app-data library at startup" and the
  wrong answer to "which one *does*".

### 6.2 Rank 2 — ART runtime app image (S1)

* App-data file, executed at process start before any Telegram code.
* Not Telegram-specific in mechanism (ART), which is the user's objection; and
  update-fragile by construction (absolute install path).
* Still the **only** app-data startup execution that is reachable without
  touching install-owned files.

### 6.3 Rank 3 — WAMR AOT (N7)

* Telegram-specific native code path with `PROT_EXEC`; would run attacker
  native code if the module buffer were attacker-controlled.
* Not file-driven, not startup, and the buffer is supplied by tgcalls. Not a
  persistence route in this build.

### 6.4 Rank 4 — Breakpad (N6)

* Real `execve` in the binary, but the JNI entry is never called. Dead.

### 6.5 Nothing else loads code

All remaining sinks are accounted for in `lab/code_load_sinks/sinks.csv` and
rejected in `lab/code_load_sinks/no_go.md`.

---

## 7. What would change the answer

Watch these in any later build (each would create a **new** sink, not a variant
of an existing one):

1. a `DexClassLoader`/`InMemoryDexClassLoader`/`DexFile` call anywhere in the
   dex (today: zero);
2. a `System.load`/`loadLibrary` whose argument is not a compile-time literal
   or a fixed `getFilesDir()` name;
3. a `dlopen` whose path comes from a `std::string`/`jstring` rather than
   `.rodata`;
4. a wasm/AOT module read from a file (an `open` in the WAMR range), or a
   `.wasm`/`.aot` asset plus a cache in `files/`;
5. a call to `Utilities.setupNativeCrashesListener` (would arm the Breakpad
   exec path);
6. a new `ks`-style fallback that runs **before** the primary load, or that is
   keyed on a file's existence rather than on an exception;
7. an `android_dlopen_ext` import (today: absent).

---

## 8. Deliverables

| File | Content |
|---|---|
| `lab/code_load_sinks/sinks.csv` | 36 sinks x 12 columns (layer, exact ref, caller chain, argument source, code/startup/app-data/update flags, verdict) |
| `lab/code_load_sinks/callgraphs.md` | the six call graphs (cold start, ART, WAMR, Breakpad, Dynamite, WebView) |
| `lab/code_load_sinks/no_go.md` | false positives + no-go by mechanism |
| `lab/code_load_sinks/device_plan.md` | P1–P6 device plan (baseline, planted-lib negative, gate-forcing attempts, root positive control, ART image, optional checks) |
| `lab/code_load_sinks/scan_java.sh` | regenerates the Java inventory |
| `lab/code_load_sinks/evidence/01_native_imports.txt` | every loader/exec import + all xrefs |
| `lab/code_load_sinks/evidence/02_direct_syscalls.txt` | all `svc` sites with their `x8` numbers |
| `lab/code_load_sinks/evidence/03_dlopen_sites.txt` | dlopen/dlsym xrefs, wrapper decompilation |
| `lab/code_load_sinks/evidence/04_init_array.txt` | 18 constructors + callee scan |
| `lab/code_load_sinks/evidence/05_jni_onload.txt` | `JNI_OnLoad` + the four registration helpers |
| `lab/code_load_sinks/evidence/06_exec_sites.txt` | the two `execve`s, their function, the Breakpad JNI entry |
| `lab/code_load_sinks/evidence/07_mmap_mprotect.txt` | every `mmap`/`mprotect` prot value |
| `lab/code_load_sinks/evidence/08_mlkit_lib.txt` | `liblanguage_id_l2c_jni.so`: dynamic section, imports, dlopen sites, init_array, JNI exports |
| `lab/code_load_sinks/evidence/09_assets_and_dex_strings.txt` | APK `.so` inventory, code-like assets, raw dex string checks per dex |
| `lab/code_load_sinks/evidence/10_java_api_sinks.tsv` | all Java API hits with file:line |
