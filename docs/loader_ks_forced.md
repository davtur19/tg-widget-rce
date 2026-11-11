# Forcing `ks.g`'s app-data fallback — 72799, no-root re-audit

Date: 2026-11-02. Target: `org.telegram.messenger.beta` 13.2.0 beta,
versionCode **72799**, arm64, Sony **XQ-BT52**, Android 13 (SDK 33), app UID
**10357**, SELinux `u:r:untrusted_app:s0:c101,c257,c512,c768`.
Scope: **host/source/smali/native plus a device run** on the debuggable Sony
package `org.telegram.messenger.beta.dbg` (UID **10362**, same 72799 code,
separate debug key) with the release package `org.telegram.messenger.beta`
(UID 10357) as the read-only control. The debug package was removed after the
tests; the release data was not modified. The device plan is in §6.

This note does not modify the main report. Lab: `lab/loader_ks_forced/`.

**Threat model.** The first stage is assumed to be an app-UID write (the prior
widget/C2 first exploit or any equivalent). The question is what happens at the
**next process start** with no first-stage process running: can the app itself
be made to load `files/lib/libtmessages.49loc.so`? If no app-UID write is
allowed at all, no route exists: an outsider cannot write Telegram's private
data. The widget is therefore not required **at boot**; it is only one possible
way to perform the initial write. This follow-up tests **plain app-data
resource conditions only**; no executable-metadata/ART route is used.

---

## 0. Verdict

**No data-only trigger. The gate is closed.** The follow-up tested the one
remaining class — deterministic resource exhaustion — on a healthy 72799
install, using the debuggable Sony package `org.telegram.messenger.beta.dbg`
(UID 10362, same dex/native code, debug key) with the release package as the
restore control. Every test kept the planted
`files/lib/libtmessages.49loc.so` **inert**:

| test | condition | result | marker |
|---|---|---|---|
| disk full | 100 GiB sparse file (0 blocks), then actual filler to 5 GB / 1 GB / 100 MB / 10 MB / 1 MB / **0 KB** free | `nativeloader: Load …/lib/arm64/libtmessages.49.so … ok` at **0 KB free**; the app later dies on Firebase `ENOSPC` (process kill) | **absent** |
| EMFILE | 20,000 files in `files/bulk` + 20,000 in `files/logs`, app UID | fd count rises 85 → **235**; limit **32768**; loader `ok`; files untouched | **absent** |
| OOM (prefs) | 300 MB `shared_prefs/systemConfig.xml` | loader `ok`; RSS 467 MB; no `OutOfMemoryError` at the load | **absent** |
| OOM (Firebase) | 300 MB `files/PersistedInstallation.<appId>.json` | Firebase **background thread** `OutOfMemoryError`; in one run the process survived and the loader still `ok`; in the combined 300 MB + 300 MB run the process was **killed before `ks.g`** (no loader line) | **absent** |
| OOM (post-load) | 300 MB `tgnet.dat` and 300 MB `cache4.db` (both read after `ks.g`) | loader `ok`; no FATAL; no effect | **absent** |
| T1 | probe `.so` loaded **by the app's own `ks.g` fallback** in `u:r:untrusted_app` | all writes `EACCES`; `symlink`/`statx` allowed | n/a (probe log) |
| update | debug APK `install -r` over the same package (same key); `files/lib/libtmessages.49loc.so` survives | new `/data/app/~~…` path; loader `ok`; loc lib inert | **absent** |

The critical distinction the follow-up asked for holds: **a process kill or an
LMK is not a caught `Error`.** At 0 KB free the loader itself still succeeds;
the later `ENOSPC` is a `FATAL EXCEPTION: Firebase Background Thread` that kills
the process, not a `catch (Error)` in `ks.g`. The Firebase OOM is likewise on a
background thread; the combined run dies before the main thread reaches
`ks.g`. No test produced the loc marker.

**The only remaining paths are root/installer** (move/replace the install-owned
lib, `pm install`, `setprop wrap.*`, `settings put global GPU_DEBUG_APP`), which
are outside the app-UID premise and are reference controls only. **ART is
rejected by the user and is not part of this deliverable**; the prior ART lab is
kept under `lab/loader_ks_forced/rejected_art/` for traceability only.

| question | answer |
|---|---|
| Can the installed `.so` be modified by UID 10362/10357? | **No** — `system:system` `r-x`/`apk_data_file`; T1 probe: `open_wronly/open_rdwr/truncate/mmap PROT_WRITE/rename/unlink/link` all `EACCES`; only `symlink`/`statx` succeed. |
| Does disk full make `dlopen` fail? | **No** — the lib is extracted to `/data/app/.../lib/arm64`; at **0 KB free** `nativeloader` still loads it `ok`; no extraction/tmpfs is used. |
| Can app data exhaust fds before `ks.g`? | **No** — 40k app-data files do not cause a scan; fd count 235/32768; no pre-`ks.g` directory open loop. |
| Can app data OOM `JNI_OnLoad`/`dlopen`? | **No** — 300 MB prefs loads the lib `ok` (RSS 467 MB); 300 MB Firebase JSON OOMs a **background thread** or kills the process **before** `ks.g`; post-`ks.g` `tgnet.dat`/`cache4.db` have no effect. |
| Does the loc lib survive an update? | **Yes**, `files/lib/libtmessages.49loc.so` survives `install -r`; it is **inert** because no resource condition makes the primary load throw. |
| Is there any data-only route left? | **No.** Root/installer only; ART rejected. |

The `w0.b`/provider correction from the first pass remains: `w0.w()` returns
while `w0.b == null`; the first `ks.g` is the `onCreate` call at `:2734`, after
`v2` (`:2312`) and `f8` (`:2331`), so no class-initialiser trick can throw
inside the `try`. The in-try surface is still `System.loadLibrary` + `v2.a` +
`f8.b`.

---

## 1. The loader path, exactly

### 1.1 `ks.g` (`org/telegram/messenger/ks.smali:1439-1907`)

```
1439  .method public static declared-synchronized g(Landroid/content/Context;)V
1459  sget-boolean v3, ks.a; if true return
1480  const-string v4, "tmessages.49"
1484  invoke-static {v4}, System->loadLibrary(String)V     # try_start_1
1489  sput-boolean v3, ks.a
1496  sget-boolean v4, v2.a
1501  const-string v4, "loaded normal lib"
1505  invoke-static {v4}, f8->b(String)V
1506  :try_end_1
1507  .catch Ljava/lang/Error; -> catch_0
1508  .catchall -> catchall_0
...
1611  const-string v7, "libtmessages.49loc.so"
1643  const-string v7, "Load local lib"
1672  invoke-static {v7}, System->load(String)V             # pre-existing loc file
1677  sput-boolean v3, ks.a
...
1769  invoke-static {p0,v5,v6,v4}, ks->k(Context,File,File,String)Z
1786  if k()==true: return
1827  const-string p0, "tmessages.49"
1831  invoke-static {p0}, System->loadLibrary(String)V       # retry
```

The two `catch` arms are semantically different:

* `catch (Error)` (`:1507`) goes to `:goto_1` and reaches the loc-file branch
  (`:1611-1677`) and then `ks.k` (`:1769`);
* `.catchall` (`:1508`) catches any other `Throwable`, prints it and goes to
  the retry at `:1831`; it **does not** load the loc file.

So only an `Error` from the `try_start_1` block switches the loader. This is the exact gate.

`ks.k` (`:2556-3076`) is called **only** from `:1769` (verified: one call
site); it deletes `files/lib` entries (`:2571-2575`) and extracts
`lib/<Build.CPU_ABI>/libtmessages.49.so` from
`getApplicationInfo().sourceDir` (`:2634-2692`) into
`files/lib/libtmessages.49loc.so`, then `System.load`s it (`:2803`). It is
post-failure by construction.

### 1.2 `w0.onCreate` order — correction to the prior note

`w0.onCreate` is `w0.smali:2263`. The exact order is:

| line | action |
|---|---|
| 2296 | `w0.b = getApplicationContext()` |
| 2312 | `sget-boolean v4, v2.a` — **first use of `v2`; `<clinit>` runs here** |
| 2318-2331 | `f8.b("Hello World!")` — **first use of `f8`; singleton is created here** |
| 2350-... | `getPackageInfo`, `Typeface`, `Build.*`, log writes |
| 2734 | `ks.g(w0.b)` |
| 2740 | `ConnectionsManager.native_setJava(false)` (inside `try/catch UnsatisfiedLinkError`) |

`w0.w()` (`:1365`) begins with `sget-boolean w0.f; if true return;
sget-object w0.b; if null return` (`:1369-1371`). `w0.b` is written only at
`:2296` and `:2725`, both inside `onCreate`. **Therefore no ContentProvider can
call `ks.g` before `w0.b` is set**: the prior note's "the first `ks.g` can be
on a provider Binder thread" is wrong for the pre-`onCreate` window. A
provider thread can only call `w0.w` **after** the main thread has passed
`:2296`; that is a real but tiny race window (`2296..2331`) and is analysed in
§3.3.

---

## 2. Why the primary load cannot fail from app data

### 2.1 `LoadedApk.makePaths` — the search path

`LoadedApk.java` (AOSP 13) builds the classloader's native path in this order:

```java
// LoadedApk.java:545-546
if (outLibPaths.isEmpty()) {
    outLibPaths.add(libDir);              // ApplicationInfo.nativeLibraryDir
}
// LoadedApk.java:555-559
for (String apk : outZipPaths) {
    outLibPaths.add(apk + "!/lib/" + aInfo.primaryCpuAbi);
}
// LoadedApk.java:563-568
if (isBundledApp) {
    outLibPaths.add(System.getProperty("java.library.path"));
}
// LoadedApk.java:574-599
appendSharedLibrariesLibPathsIfNeeded(aInfo.sharedLibraryInfos, ...);
if (aInfo.sharedLibraryFiles != null) { ... appendApkLibPathIfNeeded(lib, ...); }
```

`libDir` is first. `outZipPaths` starts with `sourceDir` and adds
`splitSourceDirs` (`LoadedApk.java:474-489`); every element is an installed
APK path. `java.library.path` is added only for **bundled** apps; Telegram is
installed in `/data/app` and is not bundled. Shared-library APKs
(`uses-library`) are appended **after** `libDir` (see §4.2). `legacyNativeLibraryDir`
is not an `ApplicationInfo` field on Android 13 and is never added to
`libPaths` (the only `/data/data/<pkg>/lib` creator is the 32-bit
`Installer.linkNativeLibraryDirectory`, §2.5). There is no app-data element.

### 2.2 `DexPathList.findLibrary`

`DexPathList.java:590-605` iterates the `NativeLibraryElement`s in order.
A directory element returns `dir/name` only if `IoUtils.canOpenReadOnly` can
`open()` it (`:878-885`); a zip element returns `apk!/lib/.../name` only if
the entry is **stored** (`:891`). For 72799:

* the extracted file exists at
  `/data/app/~~…/lib/arm64/libtmessages.49.so` (`system:system`, mode `0755`/`0644`; no write for the app);
* the APK's `lib/arm64-v8a/libtmessages.49.so` is `Defl:N` (compress_type 8,
  27,016,000 B, md5 `2c0caa68a07fc26f79d13519af6c3526`), so the zip element is
  never a candidate.

Host check: `lab/loader_ks_forced/host/verify_forced.py` asserts both.

### 2.3 The by-name fallback

`Runtime.java:1041-1088`: if `findLibrary` returns null and the loader is a
`PathClassLoader`/`DelegateLastClassLoader`, `Runtime.loadLibrary0` retries
`System.mapLibraryName(libraryName)` = `"libtmessages.49.so"` through
`nativeLoad(filename, loader)`. That `dlopen` runs in the **classloader
namespace**, whose search path is `library_path` (`library_namespaces.cpp:184-186`,
`:300-302`), i.e. the same install-owned `libDir` + APK elements. The namespace
also has `permitted_path = "/data:/mnt/expand" + java_permitted_path`
(`:81`, `:219-226`); "permitted" means an absolute `System.load()` under
`/data` is allowed, not that `dlopen` searches it. The device log shows both
strings verbatim:

```
D nativeloader: Configuring clns-5 for other apk /data/app/~~…/base.apk.
  target_sdk_version=36, uses_libraries=,
  library_path=/data/app/~~…/lib/arm64:/data/app/~~…/base.apk!/lib/arm64-v8a,
  permitted_path=/data:/mnt/expand:/data/user/0/org.telegram.messenger.beta
```

(`evidence/device_namespace.txt`, copied from
`evidence/evidence_20261101/logcat_survB.txt:13680`).

`OpenNativeLibrary` selects the namespace by `class_loader`
(`native_loader.cpp:259-279`) and calls `android_dlopen_ext` with
`ANDROID_DLEXT_USE_NAMESPACE`; if the classloader has no namespace it creates
an **isolated** namespace with the same `library_path` and
`permitted_path = /data:/mnt/expand` (`:263-269`). Neither branch adds app
data to the search path. `ld.config.txt` is read from `/system/etc` (and the
APEX `/linkerconfig`) at linker initialisation; `LD_LIBRARY_PATH` and
`LD_CONFIG_FILE` are inherited from zygote/init, not from app data
(`linker.cpp:3401-3403`; §4.4). The namespace is created once per classloader
under `g_namespaces_mutex` and the app cannot race or replace it from app
data.

### 2.4 DAC and SELinux

AOSP `NativeLibraryHelper.removeNativeBinariesFromDirLI` states the intent:

```java
/*
 * Just remove any file in the directory. Since the directory is owned
 * by the 'system' UID, the application is not supposed to have written
 * anything there.
 */
```

The installer creates `lib/<abi>` with `mkdir()` + `chmod(0755)` from
`system_server`. The 2026-11-01 device measurement agrees:
`lib/arm64` and the `.so` are `system:system 755`
(`notes/persistence_20261101.md:36`,
`evidence/evidence_20261101/persistence/db_state.txt:12`). SELinux grants only
`allow appdomain apk_data_file:file rx_file_perms` (read/execute; no write),
while app data grants `allow untrusted_app_all app_data_file:file
{ r_file_perms execute }`. `execve` from app data is removed by
`execute_no_trans` for targetSdk ≥ 29, but `dlopen`/`System.load` is allowed.

UID 10357 therefore gets `EACCES`/`EPERM` for `open(O_WRONLY)`, `truncate`,
`chmod`, `chown`, `rename`, `unlink`, `link` (protected_hardlinks),
`mmap(MAP_SHARED, PROT_WRITE)` and `setxattr` on
`/data/app/…/lib/arm64/libtmessages.49.so`. The lab's `tamper_probe.so`
measures each one in `u:r:untrusted_app` (§6 T1); `fs.protected_hardlinks`
additionally refuses a hardlink to a file the UID neither owns nor may write.

### 2.5 `/data/user/0/<pkg>/lib` (the "legacy" path)

`Installer.java:783-785` documents the symlink as
"Links the **32 bit** native library directory … Note that no such symlink is
created for 64 bit shared libraries." `LoadedApk` never adds
`dataDir/lib` to `libPaths`; it is an ASEC-era path. On the arm64 target it is
absent (T0). It is not a search path.

### 2.6 Same-soname preload

`System.loadLibrary` passes the **full path** returned by `findLibrary`;
bionic's `find_loaded_library_by_soname` ignores names containing `/`, and
`load_library` dedupes by inode/realpath. A library in app data with
`SONAME libtmessages.49.so` is a second library, not a replacement. The
by-name fallback would use the soname, but it is only reached when
`findLibrary` returns null (install-owned file missing) and it searches
`library_path`, not app data.

### 2.7 The APK and the installer

`ks.k` reads `context.getApplicationInfo().sourceDir` (the installed base
APK) and extracts `lib/<ABI>/libtmessages.49.so`. `sourceDir` is a
PackageManager value backed by a system-owned APK. The app cannot replace it,
and `ApplicationInfo` is created by PMS and delivered over Binder; the app's
in-process copy cannot change the system's copy. A **ContentProvider** cannot
inject a `sourceDir`, and a **backup restore** writes app data, not PM state.
An app update / ABI split change is an **installer** action (root, shell, Play
or the user), outside the app-UID premise.

### 2.8 No other Telegram startup loader

A full smali scan finds exactly **six** `System.load`/`System.loadLibrary`
call sites: four in `ks` (`ks.smali:1484`, `:1672`, `:1831`, `:2803`), one in
ML Kit `ThickLanguageIdentifier` (`"language_id_l2c_jni"`, fixed), and one in
WebRTC `NativeLibrary$DefaultLoader` (`p1` is the fixed
`"jingle_peerconnection_so"`, `PeerConnectionFactory$InitializationOptions$Builder.smali:64`). There is no other variable library name.
`Runtime.exec` is only `o6`'s `ProcessBuilder` for
`/system/bin/netcfg` with `directory("/system/bin")` (`o6.smali:1538-1592`);
`libtmessages.49.so`'s native `dlopen` sites are the fixed
`libnetd_client.so`/`libandroid.so` (IDA `dlopen` xrefs), with no
`android_dlopen_ext`; no Telegram component calls `app_process` or
`linker64`. The prior `notes/loader_startup_components.md` ranked the same
surface; this note re-checks the loader-specific subset.

---

## 3. The `catch (Error)` surface — new proof

### 3.1 The exact `try` body

The `try_start_1` block (`ks.smali:1480-1506`) contains only:

| line | instruction | can it throw an `Error` from app data? |
|---|---|---|
| 1484 | `System.loadLibrary("tmessages.49")` | only via the native loader (§2) or a pending exception (§3.4) |
| 1489 | `sput-boolean ks.a` | no (class already initialised at `sget` `:1459`) |
| 1496 | `sget-boolean v2.a` | **no**: `v2` was initialised at `w0.smali:2312` |
| 1505 | `f8.b("loaded normal lib")` | **no deterministic Error**: `f8` was initialised at `w0.smali:2331`; `b()` only checks `v2.a`, calls `f8.h()` (a no-op after init), `Log.d` and `r5.c` (a `Handler.post`). |

`f8.b` is at `f8.smali:246-283`; `f8.j()` at `:1179`; `f8.k()` at `:1381` catches
`Exception` (not `Error`) around the log-file setup. The only `Error`
reachable from `f8.b` is an allocation failure in `Log`/`Message`/`o4`
(`OutOfMemoryError`), not an app-data condition.

### 3.2 Why the class-initialiser trick is dead

`v2.<clinit>` reads `getSharedPreferences("systemConfig", 0)`
(`v2.smali:129`, `:39-61`), which is app-writable (`shared_prefs/systemConfig.xml`),
and `f8.<clinit>` allocates an `AtomicInteger`. It is tempting to make one of
them throw inside the `try`. It cannot happen on the normal path: `w0.onCreate`
touches `v2` at `:2312` and `f8` at `:2331`, both **before** `ks.g` at `:2734`.
If `v2.<clinit>` throws there, the process dies before `ks.g`; if it is already
erroneous, `ks.g` is never reached. `getSharedPreferences` is asynchronous
(`SharedPreferencesImpl.startLoadFromDisk`), so a malicious
`systemConfig.xml` does not throw inside `<clinit>` anyway.

### 3.3 The provider race window

The only way to get `v2`/`f8` initialisation **inside** the `try` is a
provider Binder thread that calls `w0.w()` after `w0.b` is set at `:2296` but
before the main thread's `:2312`/`:2331`. That window is a few instructions
wide. Even if won:

* if `v2.<clinit>` throws an `Error`, the `catch (Error)` handler calls
  `f8.g`, which reads `v2.a`; the erroneous class throws
  `NoClassDefFoundError`, which goes to `.catchall` → retry (`:1831`), **not**
  the loc file;
* if `f8.j()`/`f8.k()` throws an `Error`, it must be an allocation/thread
  failure (the file errors are `Exception`s caught in `k()`), not app data.

There is no deterministic app-data `Error` in this window.

### 3.4 Runtime `LoadNativeLibrary` pending-exception semantics (new)

`Runtime.loadLibrary0` → ART `JavaVMExt::LoadNativeLibrary`
(`art17/runtime/jni/java_vm_ext.cc:952-1160`; excerpt `evidence/art_loadnative_a17.txt`) has two relevant checks:

* **after `dlopen` and before `JNI_OnLoad`** it clears a pending exception
  (`:1089-1094`), so a constructor that leaves a JNI exception does not abort
  the load;
* **after `JNI_OnLoad`** there is **no `ExceptionCheck`**: if `JNI_OnLoad`
  returns a valid version while a `Throwable` is pending, `was_successful =
  true` and the pending exception propagates into `ks.g`'s `try`. If it is an
  `Error` (`OutOfMemoryError`/`NoClassDefFoundError`), the `catch (Error)`
  fires **even though the library loaded**.

This is a real second way into the fallback, but the trigger must still be an
`Error` from `JNI_OnLoad`. `JNI_OnLoad` (`0x16EFA34`, IDA) calls
`GetEnv`, `0x74ECC0`, `0x7529D4`, `0x755ABC` (`FindClass`/`RegisterNatives`
with compile-time literals), `0xA5801C` (`GetJavaVM`) and tolerates the
widget batch. No file/property/environment input reaches it; the only
app-data-sensitive failure is heap exhaustion during `FindClass`/registration,
which is non-deterministic and would also threaten the fallback's own
`System.load` (see §4.8). This note does **not** claim an OOM trigger.

---

## 4. Candidate mechanisms — new audit

### 4.1 Same-soname preload — rejected

See §2.6. Path lookup ignores the soname; inode dedupe does not replace the
path.

### 4.2 Shared-library APK — rejected

Telegram declares three optional `<uses-library>` entries: `com.google.android.maps`
(`aapt2` release manifest line 194), `com.sec.android.app.multiwindow`
(`:927`) and `org.apache.http.legacy` (`:1010`). `LoadedApk.makePaths` adds
`libDir` first, then the base/split APK elements, then
`appendSharedLibrariesLibPathsIfNeeded` paths and `aInfo.sharedLibraryFiles`
(`LoadedApk.java:444-463`, `:574-599`; `appendApkLibPathIfNeeded` at `:615`).
A malicious or installed shared-library APK can therefore only be consulted
**after** the real `nativeLibraryDir`; it cannot override
`libtmessages.49.so`. Installing such an APK is an installer action anyway.
The manifest's `com.sec.android.app.multiwindow` is an optional Samsung-only
entry; its absence on the Sony is normal and has no effect.

### 4.3 `Settings.Global.GPU_DEBUG_APP` / debug layers — rejected

`LoadedApk.java:938-955`: if `Settings.Global.GPU_DEBUG_APP` equals the
package, `GraphicsEnvironment.getDebugLayerPathsFromSettings` adds the layer
path to **`libraryPermittedPath`**, not to `librarySearchPath`. Permitted paths
only allow `System.load(absolute)`; they do not make `dlopen` search them.
`Settings.Global` writes require `WRITE_SECURE_SETTINGS` (signature/privileged);
UID 10357 cannot set it (T5). ADB shell can, which is the boundary, not the
bug.

### 4.4 `LD_CONFIG_FILE` — rejected

`bionic/linker/linker.cpp:3401-3403` reads `LD_CONFIG_FILE` **once at linker
initialisation** (`__linker_init`), before `main`; the app inherits the
zygote's environment and cannot change it for its next process. A `setenv` in
the app after init does not re-read the config, and a new `app_process` child
that sets it is the known `app_process` route (a separate process), not the
app's own startup.

### 4.5 `wrap.<pkg>` / `wrap.sh` — rejected

`ProcessList.java:1822-1828` uses `nativeLibraryDir + "/wrap.sh"` only when
`debuggableFlag` is set; Telegram 72799 is not debuggable. The `wrap.<pkg>`
system property is read by zygote; setting it requires root/shell. Both are
outside the app-UID premise (T5).

### 4.6 `ApplicationInfo` / `sourceDir` injection — rejected

`ApplicationInfo` is a Parcelable produced by PMS and delivered in
`ActivityThread.AppBindData`; the app's in-process copy is not the system's
copy. `LoadedApk.makePaths` runs at classloader creation, **before** any app
code (`Application` is loaded after `getClassLoader()`); a later
`LoadedApk.updateApplicationInfo` only consumes a new `ApplicationInfo` from
PMS (`ActivityThread.handleUpdateApplicationInfo`). `sharedLibraryFiles` is a
public mutable field, but mutating it from app code would be code execution,
not data, and it is appended after `libDir` anyway.

### 4.7 `RegisterNatives` / `JNI_OnLoad` — executable metadata only (rejected route)

Every class/method/signature in `0x74ECC0`/`0x7529D4`/`0x755ABC` is a
compile-time literal (prior audit `notes/native_appdata_audit.md` §4; IDA
re-check in `lab/loader_ks_forced/evidence/`). The only app-writable input that
can change a class's metadata is the ART app image, which the user **rejected**
(§4.11); it is not a proposed route. Breaking a registration is a
code-metadata edit and would still not be plain data.

### 4.8 OOM / EMFILE / disk — measured, rejected

The first pass dismissed this class as non-deterministic. This follow-up
measured it on the debuggable package; the details are in §5. Summary:

* **Disk full** — the installed lib is extracted to
  `/data/app/.../lib/arm64/libtmessages.49.so`; `dlopen` `open`s and `mmap`s
  that existing file. At **0 KB free** `nativeloader` still logs
  `Load ... ok`; the deflated APK entry is irrelevant because the
  extracted file exists. The app later dies on `Firebase ... ENOSPC`, a
  process kill, not a caught `Error` (§5.2).
* **EMFILE** — 20,000 files in `files/bulk` and 20,000 in `files/logs` do not
  cause a pre-`ks.g` scan; the app's fd count rises 85 → 235 against a
  32768 limit, and the loader succeeds (§5.3). The startup order (§1.2)
  shows only a fixed set of pre-`ks.g` opens: `systemConfig` (async), the
  Typeface/resources, `getPackageInfo`, and the `f8` log.
* **OOM** — a 300 MB `systemConfig.xml` is parsed on the
  `SharedPreferences` loader thread; the main thread's load still happens
  first (`ok`, RSS 467 MB). A 300 MB `PersistedInstallation` JSON OOMs the
  **Firebase background thread**; in one run the process survived and the
  loader still succeeded, in the combined 300 MB + 300 MB run the process
  was killed **before** `ks.g` (no loader line). Post-`ks.g` `tgnet.dat` /
  `cache4.db` have no effect (§5.4). None of these is a `catch (Error)` in
  `ks.g`.

The class is therefore **closed for data-only**.

### 4.9 `ks.k` cleanup — rejected

`ks.k` is called only at `ks.smali:1769` (post-failure). Its
`listFiles()+delete()` (`:2571-2575`) follows a symlinked `files/lib`, but
`delete()` needs write permission on the target directory. If the target is
the native dir (`system:system 0755`), every delete is `EACCES`; if it is
another app-private dir, the app can delete its own files (not the install).
The subsequent `FileOutputStream` to the loc path is also `EACCES` on the
native dir. It cannot remove or replace `libtmessages.49.so`. T4 tests this
with a system-owned decoy and checks the decoy survives.

### 4.10 Installer/ABI/update — rejected

A missing native dir, an ABI split change, a staged install, `pm install -r`
or `--abi` all change PMS state and are installer actions (root, shell, Play
or the user). A **split APK with a colliding
`lib/arm64-v8a/libtmessages.49.so`** is also install-owned: it would be
appended to `outLibPaths` **after** `libDir`, and only PackageInstaller/Play
can add a split. They are outside the app-UID premise; T5's
`setprop`/`settings` tests show the same boundary for the runtime knobs.

### 4.11 App image (ART) — rejected by the user

The ART runtime app image (`cache/oat_primary/arm64/base.art`) is a genuine
startup code-load surface, but the user **rejected** it for this deliverable.
It is not proposed or relied on here; the prior artifacts are retained under
`lab/loader_ks_forced/rejected_art/` for traceability only. The data-only
resource class in §5 is the remaining question, and it is negative.

## 5. Resource-exhaustion tests (data-only) — measured

All tests below were run on the **debuggable Sony package**
`org.telegram.messenger.beta.dbg` (UID **10362**, same 72799 dex and native
code, signed with a debug key) with the proof loc lib planted at
`/data/user/0/org.telegram.messenger.beta.dbg/files/lib/libtmessages.49loc.so`.
The release package (`org.telegram.messenger.beta`, UID 10357) was used only
for read-only state checks and the final restore. The debug package was
uninstalled afterwards; the release data was not modified.

The proof loc lib is `payload/libtmessages.49loc.dbg.so` (md5
`d3eb51b1d648f2c0f1c533cac33170dd`), built by `payload/build_proof.sh
org.telegram.messenger.beta.dbg`. Its `.init_array` writes
`files/.loader_forced_proof` (`FORCED_LOADED`); `JNI_OnLoad` returns 1.6.
The healthy control is T3: with the real lib intact, the marker is **absent**
and `nativeloader` logs the real lib `ok`.

### 5.1 Disk full

Commands (as root only for the filler; the app runs as its normal UID):

```sh
PKG=org.telegram.messenger.beta.dbg
# sparse: 100 GiB apparent, 0 blocks
adb shell run-as $PKG truncate -s 100G files/fill.sparse     # ls -ls -> 0 blocks
# actual blocks: fill /data until df reports the target, then cold start
A=$(adb shell df -k /data | awk 'NR==2{print $4}' | tr -d '\r')
adb shell su -c "fallocate -l ${A}K /data/local/tmp/loader_fill.bin"  # target 0
adb shell am force-stop $PKG; adb logcat -c
adb shell monkey -p $PKG -c android.intent.category.LAUNCHER 1
sleep 4; adb shell df -k /data; adb logcat -d -s nativeloader
adb shell run-as $PKG ls -l files/.loader_forced_proof
adb shell su -c 'rm -f /data/local/tmp/loader_fill.bin'
```

Observed (evidence `evidence/device_disk_full_0.txt`, fresh; the staged
5 GB/1 GB/100 MB/10 MB/1 MB runs are in `evidence/device_disk_full_stages.txt`):

```
df before/after:
/dev/block/dm-45 109481716 109440816         0 100% /data/user/0
D nativeloader: Load /data/app/~~vxt…/lib/arm64/libtmessages.49.so …: ok
E AndroidRuntime: FATAL EXCEPTION: Firebase Background Thread #3
E AndroidRuntime: java.io.FileNotFoundException: …/datastore/…preferences_pb.tmp:
  open failed: ENOSPC (No space left on device)
marker: ls: files/.loader_forced_proof: No such file or directory
```

**Interpretation.** The loader opens the **already extracted**
`/data/app/.../lib/arm64/libtmessages.49.so` and mmaps it; it does not extract
the deflated APK entry, does not use a memfd/tmpfs, and does not need free
blocks. The app's later Firebase write fails `ENOSPC` and the process dies —
a process kill, **not** a caught `Error` in `ks.g`. No marker. The sparse
100 GiB file uses 0 blocks and has no effect (`evidence/device_disk_sparse.txt`).

### 5.2 EMFILE

Commands:

```sh
# 20k empty files in files/bulk and 20k in files/logs (host tar, app-UID extract)
adb push bulk_files.tar bulk_logs.tar /data/local/tmp/
adb shell run-as $PKG mkdir -p bulk logs
adb shell run-as $PKG tar xf /data/local/tmp/bulk_files.tar
adb shell run-as $PKG tar xf /data/local/tmp/bulk_logs.tar
# cold start; sample fd counts from the host
adb shell am force-stop $PKG; adb logcat -c
( for i in $(seq 1 20); do P=$(adb shell pidof $PKG); ...; done ) &
adb shell monkey -p $PKG -c android.intent.category.LAUNCHER 1
```

Observed (`evidence/device_emfile_40k.txt`):

```
fd samples (pid 12249): 85, 86, 128, 148, 148, 147, 181, 191, 215, 231, 235...
Max open files 32768
D nativeloader: Load .../lib/arm64/libtmessages.49.so ...: ok
bulk/logs counts after: 20000 / 20000   (untouched)
marker: NO MARKER
```

**Interpretation.** There is no pre-`ks.g` path that opens app-data files in a
loop. The only pre-`ks.g` app-data opens are `systemConfig.xml` (async
`SharedPreferences` load), the Firebase `PersistedInstallation` JSON (one
file), the app's own `f8` log (one file), and the fixed APK/dex/DB descriptors.
`w0.w()` returns while `w0.b == null`; the first `ks.g` is the `onCreate` call
at `w0.smali:2734`, after `v2`/`f8` init. The fd table cannot be driven to
32768 by app data.

### 5.3 OOM

| file | size | observed |
|---|---|---|
| `shared_prefs/systemConfig.xml` | 300 MB (one value) | loader `ok`; RSS 467 MB; no `OutOfMemoryError` at the load; no marker (`device_oom_systemconfig.txt`) |
| `files/PersistedInstallation.<appId>.json` | 300 MB | Firebase **background thread** `OutOfMemoryError: Failed to allocate 536870928 byte`; in the single-file run the process survived and the loader was `ok`; in the combined 300 MB + 300 MB run the process was **killed before** `ks.g` (no loader line); no marker (`device_oom_persisted.txt`, `device_oom_combined.txt`) |
| `tgnet.dat` / `cache4.db` | 300 MB each | loader `ok`; no FATAL; no marker (`device_oom_tgnet_cache4.txt`; the app resets `tgnet.dat` to 1,580 B before the saved run, so the file shown there is `cache4.db` 300 MB; the first 300 MB `tgnet.dat` run also loaded `ok`) |

**Interpretation.** The pre-`ks.g` app-data reads are either asynchronous
(`systemConfig`) or in a provider (`PersistedInstallation`), and both OOM paths
are **background-thread** or **pre-`ks.g` process kills**, not an `Error`
raised on the main thread inside `ks.g`. `tgnet.dat`/`cache4.db` are opened
**after** `ks.g` (`w0.onCreate` → `ks.g` at 2734 → `native_setJava` at 2740 →
later DB/config init), so they cannot affect the load. The combined run is the
critical control: the app never reaches `ks.g`, so there is no `catch (Error)`;
the marker is absent.

### 5.4 T1 — app-UID tamper in the app process (probe)

The probe (`device/tamper_probe.c`, rebuilt for the debug package) was loaded
**as the loc lib** by the app's own `ks.g` fallback: root moved the real
`libtmessages.49.so` to `.moved`, the app started, `ks.g` caught the
`UnsatisfiedLinkError` and `System.load`ed
`files/lib/libtmessages.49loc.so` — the probe. The probe ran in the Telegram app process (a zygote fork; its
`/proc/self/exe` is `/system/bin/app_process64`), not in a separate
`app_process` helper or a `run-as` shell.

Observed (`evidence/device_debug_probe.txt`):

```
uid=10362 euid=10362
selinux=0 u:r:untrusted_app:s0:c106,c257,c512,c768
open_rdonly=102
open_wronly=13 errno=EACCES
open_rdwr=13 errno=EACCES
mmap_shared_write=13 errno=EACCES
truncate=13 errno=EACCES
fchmod=13 errno=EACCES
fchown=13 errno=EACCES
access_w=13 errno=EACCES
setxattr=13 errno=EACCES
rename_same_dir=13 errno=EACCES
unlink=13 errno=EACCES
link_same_dir=13 errno=EACCES
symlink_to_target=0
statx=0
```

The target was the install-owned `.../libtmessages.49.so.moved`
(`system:system`, `apk_data_file`). Every write/rename/link/chmod/chown/truncate
fails; only read (`statx`) and an app-data symlink (`symlink_to_target`) are
allowed. This is the decisive falsification test for any "replace the lib"
data-only idea. The release package's native dir was re-checked read-only:
`system:system r-x`, `u:object_r:apk_data_file:s0`.

### 5.5 Update survival control

The debug APK was installed **over itself** (`adb install -r -g`, same debug
key) with the proof loc lib planted. App data survives:

```
files/lib/libtmessages.49loc.so  (2704 B, u0_a362, 0400)  -> still present
new install path /data/app/~~vxt…/…/lib/arm64/libtmessages.49.so
nativeloader: Load .../lib/arm64/libtmessages.49.so ...: ok
tmessages: loaded normal lib
marker: NO MARKER
```

(`evidence/device_update_inert.txt`). The loc lib **does** survive the update,
which is the persistence property the user asked about, but it is **inert**:
no resource condition made the primary load throw. A real trigger would have
produced the marker here; none did.

### 5.6 Verdict of the resource class

**No deterministic data-only trigger.** The primary load is robust to disk
fullness, app-data file count, and heap pressure; the only failures observed
are process kills (Firebase `ENOSPC`, background `OutOfMemoryError`,
combined-run pre-`ks.g` death), which are not caught by `ks.g`. The gate is
closed for data-only; root/installer remains out of scope, and ART is rejected.

## 6. Device test plan and executed controls

Target: Sony XQ-BT52, Android 13, build 62.2.A.0.533. The **debuggable Sony
package** `org.telegram.messenger.beta.dbg` (UID 10362, same 72799 code,
debug key) was used for the destructive/resource tests; the release
`org.telegram.messenger.beta` (UID 10357) was kept read-only and used for the
final restore check. The debug package was uninstalled after the tests; the
release data was not modified.

Scripts:

* `device/forced_fallback_test.sh` — T0–T6 (`info`, `probe_app`, `probe`,
  `inert`, `rootctl`, `symlink`, `boundary`, `update`, `restore`).
* `device/resource_tests.sh` — T7–T9 (`disk`, `sparse`, `emfile`,
  `oom_systemconfig`, `oom_persisted`, `oom_combined`, `oom_post`).

**Domain fidelity.** The T1 probe is loaded by the app's own `ks.g` fallback
in the **Telegram app process** (`u:r:untrusted_app`, UID 10362); root only
moves the install-owned `.so` aside to force the fallback. `su 10357` and
`run-as` are **not** the app domain (`run-as` is `runas_app`, which has
`app_data_file:file execute_no_trans`) and are used only for DAC/setup.

### T0 — install state (read-only)

`./forced_fallback_test.sh info`

Expected: `codePath`/`primaryCpuAbi=arm64-v8a`; native dir
`/data/app/~~…/lib/arm64`, `system:system`, `.so` `r-x`/`apk_data_file`;
`/data/user/0/<pkg>/lib` absent; `/data` mount `rw,nosuid,nodev`; running app
maps `/data/app/.../lib/arm64/libtmessages.49.so`; `nativeloader` shows
`library_path=...` and `permitted_path=/data:/mnt/expand:/data/user/0/<pkg>`.
If the native dir is app-owned/writable, stop: the premise is wrong.

### T1 — app-UID tamper in the app process (executed)

`./forced_fallback_test.sh probe_app` (debug package). It plants
`tamper_probe.dbg.so` as `files/lib/libtmessages.49loc.so`, moves the real
`.so` to `.moved`, starts the app, and reads `files/.tamper_probe`.
Expected/observed: `uid=10362`, `selinux=0 u:r:untrusted_app:...`;
`open_wronly/open_rdwr/mmap_shared_write/truncate/fchmod/fchown/access_w/
setxattr/rename_same_dir/unlink/link_same_dir` all `EACCES`; `symlink`/`statx`
allowed. Evidence `evidence/device_debug_probe.txt`.

Alternative for the **release** package (no debuggable): `probe` stages the
probe + `loader.dex` and prints the `app_process` command to run from the
widget/C2; `run-as` is forbidden for the SELinux result.

### T2 — root positive control (reference only)

`./forced_fallback_test.sh rootctl` on the release. The prior 2026-11-01 run
(`evidence/device_fallback.txt`) already proves the fallback: move
`libtmessages.49.so` aside, plant the loc lib, cold start → `Load local lib`,
`Load .../files/lib/libtmessages.49loc.so ...: ok`, marker, then the expected
`FATAL` because the proof lib has no Telegram natives. Root is used **only**
to create the failure; the loc lib load itself is app-UID.

### T3 — healthy inert control (executed)

`./forced_fallback_test.sh inert` (release) and the debug-package proof
(`evidence/device_t3_inert.txt`, `device_update_inert.txt`).

Expected/observed: `loaded normal lib`; no `Load local lib`; **no marker**.
This is the control that invalidates any claimed resource trigger that also
fires on a healthy start.

### T4 — `ks.k` cleanup through a symlinked `files/lib` (plan)

`./forced_fallback_test.sh symlink`: app UID creates `files/lib` → native dir;
root creates a `system`-owned decoy and moves the real `.so` aside; `ks.k`'s
`listFiles()` enumerates and every `delete()` fails `EACCES`; the decoy and
the moved `.so` must survive. If the decoy is gone, the app UID can delete
install-owned files — the premise is false.

### T5 — runtime-knob boundary (plan)

`./forced_fallback_test.sh boundary`: as app UID `setprop wrap.<pkg>` and
`settings put global GPU_DEBUG_APP` fail; `/proc/self/environ` has no
app-controlled `LD_*`. As shell they succeed (restore immediately). This is
the root/shell boundary, not app data.

### T6 — update survival control (executed)

`./forced_fallback_test.sh update` (debug package, same debug key). Plant
`files/lib/libtmessages.49loc.so`, `adb install -r -g` the same debug APK,
cold start. Expected/observed: `files/lib` still present; new
`/data/app/~~…` path; `nativeloader` loads the real `.so` `ok`; no `Load local
lib`; **no marker** (`evidence/device_update_inert.txt`). The loc lib survives
the update but is inert — a deterministic trigger would show the marker here.

### T7 — disk full (executed)

`./resource_tests.sh disk 0` (actual blocks) and `sparse` (100 GiB, 0 blocks).

At 0 KB free the `nativeloader` line is still
`Load .../lib/arm64/libtmessages.49.so ...: ok`; the app later dies on
`Firebase ... ENOSPC` (process kill). The extracted lib needs no free blocks;
the deflated APK entry is not used. Sparse 100 GiB uses 0 blocks and is
inert. Evidence `device_disk_full_0.txt`, `device_disk_sparse.txt`,
`device_disk_full_stages.txt`.

### T8 — EMFILE (executed)

`./resource_tests.sh emfile`: 20,000 files in `files/bulk` + 20,000 in
`files/logs`; cold start; fd samples 85 → 235 (limit 32768); loader `ok`;
files untouched; no marker (`device_emfile_40k.txt`). No pre-`ks.g` app-data
directory/open loop exists; `w0.w()` returns while `w0.b == null`, and the
first `ks.g` is `w0.onCreate:2734`.

### T9 — OOM (executed)

`./resource_tests.sh oom_systemconfig` (300 MB prefs) → loader `ok`, RSS
467 MB, no marker; `oom_persisted` (300 MB Firebase JSON) → background
`OutOfMemoryError`, in the single run the process survives and the loader is
`ok`, in `oom_combined` the process is killed **before** `ks.g` (no loader
line), no marker; `oom_post` (300 MB `tgnet.dat`/`cache4.db`, read after
`ks.g`) → loader `ok`, no marker. A background-thread OOM or a pre-`ks.g`
kill is **not** a caught `Error`. Evidence `device_oom_systemconfig.txt`,
`device_oom_persisted.txt`, `device_oom_combined.txt`,
`device_oom_tgnet_cache4.txt`.

### Cleanup

`./forced_fallback_test.sh restore` restores the release `.so` from the
backup, removes `files/lib`/markers/tamper files, force-stops and starts the
release (`loaded normal lib`, no marker). The debug package is uninstalled
(`adb uninstall org.telegram.messenger.beta.dbg`); the release data was not
modified. The disk filler is removed and `df /data` returns to ~15% used.

## 7. Lab index

| file | contents |
|---|---|
| `payload/libtmessages.49loc.so` | release proof loc lib: `.init_array` writes `files/.loader_forced_proof`, `JNI_OnLoad` 1.6, SONAME `libtmessages.49loc.so` |
| `payload/libtmessages.49loc.dbg.so` | debug-package variant (marker under `.dbg`, md5 `d3eb51b1d648f2c0f1c533cac33170dd`) |
| `payload/proof_ctor.S`, `payload/build_proof.sh` | raw-syscall aarch64 source/build |
| `device/tamper_probe.c`, `tamper_probe.so`, `tamper_probe.dbg.so` | untrusted_app DAC/SELinux probe: read of `attr/current`, `open`/`mmap`/`truncate`/`chmod`/`chown`/`rename`/`unlink`/`link`/`setxattr`, same-dir rename/link, app-data control |
| `device/forced_fallback_test.sh` | T0–T6: info, probe_app, probe, inert, rootctl, symlink, boundary, update, restore |
| `device/resource_tests.sh` | T7–T9: disk 0/sparse, EMFILE 40k files, 300 MB prefs/Firebase/post-load, update |
| `rejected_art/` | prior ART app-image generator/images/validator; **rejected by the user, not used** |
| `host/verify_forced.py` | re-checks APK/smali/AOSP/lab claims (PASS) |
| `evidence/device_debug_probe.txt` | T1 probe log (`u:r:untrusted_app`, all writes `EACCES`) |
| `evidence/device_t3_inert.txt`, `device_update_inert.txt` | healthy/inert and update-survival controls (no marker) |
| `evidence/device_disk_full_0.txt`, `device_disk_sparse.txt`, `device_disk_full_stages.txt` | disk-full tests (0 KB free / 100 GiB sparse / staged fills) |
| `evidence/device_emfile_40k.txt` | 20k+20k files, fd 85→235/32768, loader `ok` |
| `evidence/device_oom_systemconfig.txt`, `device_oom_persisted.txt`, `device_oom_combined.txt`, `device_oom_tgnet_cache4.txt` | OOM tests (prefs / Firebase / combined / post-load) |
| `evidence/ks_g.txt`, `ks_k.txt`, `w0_oncreate.txt`, `w0_w.txt`, `v2.txt`, `f8_b.txt`, `f8_k.txt` | exact smali with line numbers |
| `evidence/runtime_loadlibrary0.txt`, `loadedapk_makepaths.txt`, `loadedapk_classloader.txt`, `dexpathlist_findlibrary.txt`, `dexpathlist_element.txt` | AOSP 13 loader source |
| `evidence/nativeloader_permitted.txt`, `nativeloader_create.txt`, `native_loader_open.txt` | ART 13 nativeloader source |
| `evidence/art_loadnative.txt`, `art_loadnative_a17.txt` | ART 13/17 `LoadNativeLibrary` |
| `evidence/processlist_wrapsh.txt`, `installer_legacy.txt`, `linker_ldconfig.txt` | `wrap.sh`, 32-bit `lib` symlink, `LD_CONFIG_FILE` |
| `evidence/loadedapk_gpu.txt`, `manifest_*_lib.txt` | GPU debug layers, optional `uses-library` |
| `evidence/device_fallback.txt`, `device_appimage.txt`, `device_namespace.txt` | prior device fallback, namespace; ART mapping (rejected route) |
| `evidence/ida_jni_onload.txt`, `verify_forced.txt`, `route_b_primary_validation.txt`, `route_b_variant_validation.txt` | IDA JNI_OnLoad; host checks; rejected-ART validation |

Reproduce the host checks:

```sh
python3 lab/loader_ks_forced/host/verify_forced.py
```

The `rejected_art/validate_loc_clinit.py` invocation is kept only to document
the rejected ART artifact; it is not part of the recommended work.

---

## 8. Negative results and open questions

* **No data-only trigger.** Disk full (0 KB free), 40k app-data files
  (fd 235/32768), 300 MB prefs/Firebase JSON, and 300 MB
  `tgnet.dat`/`cache4.db` all left the loc lib inert. The only failures are
  process kills (Firebase `ENOSPC`, background `OutOfMemoryError`,
  pre-`ks.g` combined OOM), which are **not** `catch (Error)` in `ks.g`.
* **The update-survival premise is confirmed but inert.** The loc lib survives
  `adb install -r` (same debug key, app data survives) and still does not
  load on a healthy start. The missing piece is a deterministic trigger;
  none was found.
* **The native dir is not app-writable.** The app-process probe
  (`u:r:untrusted_app`, UID 10362) fails every write/rename/link/chmod/chown/
  truncate on the install-owned `.so` with `EACCES`; only `statx` and an
  app-data symlink succeed. Root is used only for the reference/control.
* **The prior provider-first `ks.g` correction stands.** `w0.b` is null until
  `onCreate:2296`; `w0.w()` returns; the first `ks.g` is `:2734`, after
  `v2`:2312 and `f8`:2331. The in-try surface is `System.loadLibrary` +
  `v2.a` + `f8.b`.
* **ART is rejected by the user.** The app-image artifacts are retained under
  `rejected_art/` for traceability only; no ART route is proposed or relied
  on.
* **Root/installer remains the only way** to force the fallback: move/
  replace the install-owned `.so`, `pm install`, `setprop wrap.*`,
  `settings put global GPU_DEBUG_APP`. These are outside the app-UID premise
  and are reference controls.
* **Not executed in this pass:** the release T1 via widget/C2 (the debug
  app-process probe is the faithful substitute), T4 symlink and T5 boundary
  on the release (planned), and the release T2 (prior 2026-11-01 evidence
  `device_fallback.txt`). The debug package was uninstalled after the tests.
* **If a future OEM/Android build makes `nativeLibraryDir` app-owned or
  places it under app data**, the direct replacement path opens. T0/T1 in
  `forced_fallback_test.sh` are designed to detect exactly that case before
  any exploit work.
