# `ks.g` / `libtmessages.49loc.so` — can app-UID code execution force the fallback?

Date: 2026-11-02. Target: `org.telegram.messenger.beta` 13.2.0 beta, versionCode
**72799**, arm64, Sony **XQ-BT52** (Xperia 10 III), Android 13 (SDK 33), app UID
**10357**. Host/static only: no device run in this task; the device plan in §6 is
for the operator.

This note re-audits the surface of `notes/native_appdata_audit.md` from a
different premise: **the attacker already has app-UID code execution** (the
widget/QuickJS RCE) and can create files, symlinks and chmod bits as UID 10357.
Question: can that pre-existing code execution make the next process start take
the `files/lib/libtmessages.49loc.so` path, or otherwise get that file loaded at
startup?

The main report is not edited. The lab is `lab/loader_ks_fallback/`.

---

## 0. Verdict

**Without executable metadata (plain files/symlinks/chmod in app data): no.**
The first `System.loadLibrary("tmessages.49")` is resolved from install-owned
paths only, and a failure cannot be produced from app data:

* `DexPathList.findLibrary` searches `ApplicationInfo.nativeLibraryDir`
  (`/data/app/~~…/lib/arm64`) and then `base.apk!/lib/arm64-v8a`
  (`LoadedApk.makePaths`, AOSP 13 `LoadedApk.java:546,558`). Both are
  `system:system`, `0755`/`0644`; the APK entry is **deflated**, so the zip
  element cannot serve the library either.
* If `findLibrary` returns null, `Runtime.loadLibrary0` retries
  `dlopen("libtmessages.49.so")` **by name** (`Runtime.java:1051-1075`). That
  lookup runs in the app classloader namespace whose **search** path is the same
  `library_path` — the two install-owned entries. App data is on the namespace's
  **permitted** path (`/data:/mnt/expand` + the app data dir), not its search
  path (`library_namespaces.cpp:81,219,301`). "Permitted" means an absolute
  `System.load("/data/user/0/…")` is allowed; it does not make `dlopen` search
  app data.
* `ks.k`'s `listFiles()+delete()` cleanup and its `FileOutputStream` run **only
  after** the first load has already failed (`ks.g:1769`). The cleanup follows a
  symlinked `files/lib`, but `delete()`/`write` need write permission on the
  target, which UID 10357 does not have on `/data/app/.../lib/arm64`.
* `JNI_OnLoad` reads no file, property or environment value; class/method names
  and signatures are compile-time literals. The only way to make a
  `RegisterNatives`/`GetMethodID` batch fail from app data is to change **Java
  class metadata**, and the only app-writable file in that path is the ART app
  image (`cache/oat_primary/arm64/base.art`). That is the counterfeit-ART
  vector, already a **startup code-execution** primitive
  (`notes/persistence_local_existing_rce.md`): if you can forge the image you can
  run code in `ks.<clinit>` and load any library directly. Using the same
  primitive to break a JNI registration and then rely on `ks.g` is strictly more
  work for the same precondition; it is recorded below only as an in-principle
  variant, not as a tested trigger.

**With the app image (executable metadata the first RCE can write): yes, in
principle** — the image is processed at every process start before `w0.onCreate`
and its classes shadow the dex (host-validated in
`notes/persistence_local_existing_rce.md`; device-untested there). The image is therefore the actual app-data
startup code-execution surface; the loader fallback adds no capability that the
image does not already give. The honest summary is: *the loader is not a
data-only persistence path; the app image is.*

The gate is still the `UnsatisfiedLinkError`, not SELinux/DAC: loading a valid
ELF from `/data` is permitted on Android 13 (prior audit §4; confirmed by
`/data:/mnt/expand` in the device namespace line, §2.6).

| question | short answer |
|---|---|
| Q1 — `nativeLibraryDir` / legacy / `findLibrary` / `dlopen` | The lookup is `[nativeLibraryDir, base.apk!/lib/arm64-v8a]`, both install-owned; `/data` is **permitted** but not **searched**; the legacy `/data/user/0/<pkg>/lib` is ASEC-era and not consulted. App-data symlinks/dirs/files cannot influence it (§2). |
| Q2 — `ks.k` `loadFromZip` bugs | `listFiles()+delete()` and the extraction are **post-failure only**; a symlinked `files/lib` is followed but cannot write the install-owned target; `k()`'s `return true` after a failed `System.load` skips the retry and leaves `ks.a=false` (§3). |
| Q3 — `JNI_OnLoad` failure | Literal-only class/method names; no file/env/property input; `GetEnv` cannot fail; `RegisterNatives` fails only on a class/APK mismatch. The app image is the one app-data executable-metadata surface; breaking a registration with it is a hypothesis and is strictly dominated by its `ks.<clinit>` code execution. OOM/EMFILE is not deterministic (§4). |
| Q4 — device plan | `device_test_plan.sh` T0–T5: info/owner/mode/SELinux, plant a constructor proof `.so`, app-UID tamper negative, root-assisted fallback positive control, `files/lib` symlink test, writable-file test, restore (§6). |

---

## 1. The loader path, exactly

### 1.1 `ks.g` (smali `org/telegram/messenger/ks.smali:1439-1907`)

```
1439  .method public static declared-synchronized g(Landroid/content/Context;)V
1459  sget-boolean ks.a ; if true return
1480-1484  System.loadLibrary("tmessages.49")            # try_start_1
1489  ks.a = true ; log "loaded normal lib" ; return
1507  .catch Ljava/lang/Error; -> catch_0               # Error, not Exception/Throwable
...
1580-1625  on Error: new File(getFilesDir(), "lib"); mkdirs();
           new File(libDir, "libtmessages.49loc.so"); exists()
1630  if exists:
1672     System.load(localLib.getAbsolutePath())          # try_start_3
1679     .catch Ljava/lang/Error; -> catch_1
1682-1690     on Error: log + localLib.delete()
1769  ks.k(context, files/lib, locFile, arch)             # loadFromZip
1786  if k()==true: return                               # note: ks.a may still be false
1831  else: retry System.loadLibrary("tmessages.49")      # only if k()==false
```

Consequences:

* The normal library is attempted **once** at 1484; `files/lib` is not touched
  on a successful start.
* The pre-existing loc file is attempted at 1672 **before** `k()`'s cleanup, so
  planting it is enough if a failure ever happens; `k()` is not needed.
* The catch is `java.lang.Error` (`ks.smali:1507`): `UnsatisfiedLinkError`,
  `ExceptionInInitializerError`, `OutOfMemoryError`, `StackOverflowError` are all
  caught; a checked exception during the load is not expected.
* `k()` returning `true` after its **own** `System.load` failed skips the retry at
  1831 and leaves `ks.a == false` (`ks.smali:2803-2875`). That is a real logic
  bug, but it is downstream of the failure we cannot create.

### 1.2 Call sites and startup order

* `w0.onCreate` calls `ks.g` at `w0.smali:2734`, immediately before
  `ConnectionsManager.native_setJava(false)` at `w0.smali:2740`.
* `w0.w()` calls `ks.g` at `w0.smali:1405`. `w0.w()` is reachable from
  providers/receivers (`NotificationImageProvider.openFile`, widget providers,
  `PushListenerController`, …), and **ContentProviders are installed before
  `Application.onCreate`** (`ActivityThread.handleBindApplication`:
  `installContentProviders` at `ActivityThread.java:6770`,
  `callApplicationOnCreate` at `:6785`). So the *first* `ks.g` call can be on a
  provider Binder thread rather than on the main thread. `ks.g` is
  `synchronized`, so the behavior is the same; this only moves the load earlier.
* The prior audit's "pre-load path = `w0.onCreate`" is therefore incomplete as a
  statement about *all* first calls, but the loader path is identical. The
  provider code is APK code, not app data (see §4.4 for the one app-data read it
  performs).

### 1.3 `ks.k` / "loadFromZip" (smali `ks.smali:2556-3076`)

| line | action |
|---|---|
| 2571-2575 | `files/lib.listFiles()`; `delete()` every entry (inside `try/catch Exception`) |
| 2634 | `new ZipFile(context.getApplicationInfo().sourceDir)` — the installed base APK |
| 2656-2692 | `getEntry("lib/" + Build.CPU_ABI + "/libtmessages.49.so")` |
| 2770-2786 | `FileOutputStream(locFile)`; copy 4 KiB chunks; `setReadable(true,false)`, `setExecutable(true,false)`, `setWritable(true)` |
| 2803-2818 | `System.load(locFile.getAbsolutePath())`; `ks.a = true` on success |
| 2819-2875 | `catch Error`: log; fall through to `:goto_4` → `return true` |

The path components are fixed: `getFilesDir()` (system-provided data dir), literal
`lib`, literal `libtmessages.49loc.so`; `arch` is `Build.CPU_ABI` from
`ks.e()` (`ks.smali:1174`, a `ro.product.cpu.abi` value). There is no
attacker-controlled string and no traversal.

### 1.4 Corrections to the prior audit

* **Providers run before `Application.onCreate`.** The prior audit treated
  `w0.onCreate` as the pre-load path; `ActivityThread.handleBindApplication`
  installs providers first (`ActivityThread.java:6770` vs `:6785`), and
  `w0.w()` can call `ks.g` from a provider Binder thread. The loader path does
  not change, but "before `ks.g`" includes provider code.
* **A bundled SDK reads app data before `ks.g`.** `FirebaseInitProvider` runs
  before `onCreate` and Firebase `PersistedInstallation` reads
  `files/PersistedInstallation.<appId>.json` (`m4/c.smali`). The prior "no
  app-data parse before `ks.g`" is correct for Telegram's own data
  (`tgnet.dat`, `cache4.db`) but not for Firebase/ML Kit/AndroidX providers.
  This does not create a load trigger (§4.4).
* **`legacyNativeLibraryDir` is not a thing on Android 13.** `ApplicationInfo`
  has `nativeLibraryDir`/`secondaryNativeLibraryDir`; `/data/data/<pkg>/lib` is
  an ASEC-era path and is not in the classloader library path (§2.4).
* **`k()`'s `return true` after a failed `System.load`** is confirmed
  (`ks.smali:2819-2875`); it skips the retry and leaves `ks.a == false`, but it
  is downstream of the failure we cannot create (§3.2).

---

## 2. Q1 — `nativeLibraryDir`, legacy dir, `findLibrary`, `dlopen` namespace

### 2.1 `findLibrary` order (source)

`LoadedApk.makePaths` (AOSP 13) builds the classloader library path:

```java
// LoadedApk.java:545-558
if (outLibPaths.isEmpty()) {
    outLibPaths.add(libDir);                 // ApplicationInfo.nativeLibraryDir
}
...
for (String apk : outZipPaths) {
    outLibPaths.add(apk + "!/lib/" + aInfo.primaryCpuAbi);   // base.apk!/lib/arm64-v8a
}
```

`librarySearchPath` is that list (`LoadedApk.java:936`). `PathClassLoader`
inherits `BaseDexClassLoader.findLibrary`, which delegates to
`DexPathList.findLibrary`; that method iterates the elements in order
(`DexPathList.java:590`); a directory element
returns `dir/name` only if `IoUtils.canOpenReadOnly(path)` succeeds
(`DexPathList.java:883`); a zip element returns `apk!/lib/.../name` only if the
entry is **stored**, not deflated (`isEntryStored`, `DexPathList.java:891`).

Shared libraries and `java.library.path` do not add app data either. A `uses-library`
APK contributes only its own `!/lib/<abi>` path (system APK), and
`java.library.path` is added only for **bundled** apps (`LoadedApk.java:561-567`);
the device's `clns-4` line for `org.apache.http.legacy.jar` shows the same two
install-owned entries (`evidence/device_namespace.txt`).

For 72799: `extractNativeLibs=true` (release manifest, verified with `aapt2`), so
the loader sees the extracted file at
`/data/app/~~…/lib/arm64/libtmessages.49.so`. The APK's
`lib/arm64-v8a/libtmessages.49.so` entry is **deflated** (`compress_type 8`;
`unzip -lv`: `Defl:N`), so the zip element is not usable when the extracted file
is missing. That is exactly the prior root test: after moving the extracted file
aside, the log says `dlopen failed: library "libtmessages.49.so" not found`, not
"loaded from APK" (`evidence/device_fallback.txt`).

### 2.2 The by-name fallback

If `findLibrary` returns null and the loader is a `PathClassLoader`,
`Runtime.loadLibrary0` does **not** give up:

```java
// Runtime.java:1051-1075
String filename = loader.findLibrary(libraryName);
if (filename == null && (loader.getClass() == PathClassLoader.class || ...)) {
    // "proceed to load the library with its soname"
    filename = System.mapLibraryName(libraryName);      // "libtmessages.49.so"
}
...
String error = nativeLoad(filename, loader);
```

`nativeLoad` → ART `JavaVMExt::LoadNativeLibrary` → `android::OpenNativeLibrary`
with the classloader namespace. The namespace was created with:

* **search** paths = `library_path` = the classloader `librarySearchPath`
  (`library_namespaces.cpp:301`, `NativeLoaderNamespace::Create(namespace_name,
  library_path, permitted_path, ...)`);
* **permitted** paths = `"/data:/mnt/expand"` plus `java_permitted_path`
  (`library_namespaces.cpp:81,219`), where `java_permitted_path` is the app's
  data dir (`LoadedApk.java:919`: `canAccessDataDir() ? mDataDir : ""`).

The device log shows both strings verbatim:

```
D nativeloader: Configuring clns-5 for other apk /data/app/~~…/base.apk.
  target_sdk_version=36, uses_libraries=,
  library_path=/data/app/~~…/lib/arm64:/data/app/~~…/base.apk!/lib/arm64-v8a,
  permitted_path=/data:/mnt/expand:/data/user/0/org.telegram.messenger.beta
```

(`lab/loader_ks_fallback/evidence/device_namespace.txt`, from
`evidence/evidence_20261101/logcat_survB.txt:13680`.)

So: **`/data` is permitted, not searched.** A file in app data is reachable only
by an explicit `System.load(absolutePath)` (which is what `ks.g` does after the
failure), never by `System.loadLibrary("tmessages.49")`.

### 2.3 Who owns the native dir? (DAC + SELinux)

AOSP states the intent directly in `NativeLibraryHelper.removeNativeBinariesFromDirLI`:

```java
/*
 * Just remove any file in the directory. Since the directory is owned
 * by the 'system' UID, the application is not supposed to have written
 * anything there.
 */
```

(`NativeLibraryHelper.java:257-261`). The installer creates the dir with
`createNativeLibrarySubdir` → `mkdir()` + `chmod(0755)`
(`NativeLibraryHelper.java:291-300`), from `system_server` (`uid 1000`); the
session stage dir itself is created with `0775` by system_server
(`PackageInstallerService.java:1029`). The final `/data/app/~~…/pkg-…` tree is
therefore `system:system`.

The device measurement from 2026-11-01 agrees: `lib/arm64` and the `.so` are
`system:system 755` (`notes/persistence_20261101.md:36`,
`evidence/evidence_20261101/persistence/db_state.txt:12`). The test plan in §6
re-checks this with `ls -ldZ` and `md5sum`.

SELinux is consistent:

* `allow appdomain apk_data_file:file rx_file_perms;` — read/execute only
  (`app.te:410-411`); no write rule exists for `apk_data_file` in the untrusted
  app domain.
* `allow untrusted_app_all app_data_file:file { r_file_perms execute };` — app
  data is readable and `dlopen`-able, but `execute_no_trans` (execve) is a
  neverallow (`untrusted_app_all.te:26-27`, `app_neverallows.te:67`). This is
  the correct distinction: **`dlopen` from app data is allowed; writing the
  installed lib is not.**

DAC consequences for UID 10357: `open(O_WRONLY)`, `truncate`, `chmod`, `chown`,
`rename`, `unlink`, `link` and `mmap(MAP_SHARED, PROT_WRITE)` on
`/data/app/.../lib/arm64/libtmessages.49.so` all fail with `EACCES`/`EPERM`.
`fs.protected_hardlinks` also refuses a hardlink to a file the UID does not own
and cannot write. §6 T2 is the empirical check.

### 2.4 `/data/user/0/<pkg>/lib` (the "legacy" path)

On Android 13, `ApplicationInfo` has `nativeLibraryDir` and
`secondaryNativeLibraryDir` only; `legacyNativeLibraryDir` is **not** a field in
`android13-release` `ApplicationInfo.java`, and `LoadedApk` never adds
`dataDir/lib` to `libPaths`. The only platform code that creates
`/data/data/<pkg>/lib` is `Installer.linkNativeLibraryDirectory`, used for
**ASEC** (forward-locked/SD-card) apps (`InstalldNativeService.cpp`,
`linkNativeLibraryDirectory`). For this install the path is absent or a stale
leftover; either way it is not consulted by `System.loadLibrary` or by `ks.g`.
§6 T0 prints it.

### 2.5 The APK itself

`ks.k` opens `getApplicationInfo().sourceDir` (the installed base APK) and
extracts `lib/<Build.CPU_ABI>/libtmessages.49.so`. `sourceDir` is a
PackageManager value (system-owned APK); the app cannot modify the APK, replace
it, or change `ApplicationInfo` for the next process. The only attacker-relevant
fact about this code is that it is **post-failure**: it runs from the `catch`
branch.

### 2.6 Why the platform is not the gate (confirmed)

The prior audit corrected the old "root-gated fallback" wording: Android 13's
`kAlwaysPermittedDirectories = "/data:/mnt/expand"`
(`library_namespaces.cpp:81`) plus `untrusted_app_all.te`'s
`app_data_file:file { r_file_perms execute }` means a valid ELF at
`files/lib/libtmessages.49loc.so` **does** load as UID 10357. The device proof
is in `evidence/device_fallback.txt`: `Load …/files/lib/libtmessages.49loc.so
using class loader ns clns-5 … ok`, marker written. The gate is the
`UnsatisfiedLinkError`, not the linker or SELinux.

### 2.7 Can a symlink/dir/file at `files` change the lookup?

* `files/lib` is created by `ks.g` only *after* the failure (`mkdirs()` at
  `ks.smali:1602`). It is not on any classloader path.
* A symlink at `files` (the `getFilesDir()` root) would redirect `ks.g`'s
  `new File(files, "lib")` and `ks.k`'s writes/deletes, but only after the
  failure; it cannot influence the first `loadLibrary`.
* A symlink at `files/lib` is followed by `File.listFiles()` in `k()`
  (`ks.smali:2571`), so `k()` would enumerate (and attempt to delete) entries in
  the target. If the target is `/data/app/.../lib/arm64`, the `delete()` calls
  fail with `EACCES`; if it is another app-private dir, the app can delete
  entries there. Either way this is post-failure and does not touch the APK lib.
* A symlink at `files/lib/libtmessages.49loc.so`: the pre-existing branch
  `System.load`s it (post-failure); `k()`'s cleanup would normally delete it
  first, and `FileOutputStream` follows it only if it survives cleanup (e.g.
  `listFiles()` returned null). Again post-failure.

No symlink, directory or file in app data participates in
`BaseDexClassLoader.findLibrary` or in the by-name `dlopen` search.

---

## 3. Q2 — `ks.k` (`loadFromZip`): can the two bugs skip/redirect the load?

**No, because `k()` is called only from `ks.g`'s `catch (Error)` branch**
(`ks.smali:1769`; the only caller of `ks.k` in the APK — verified by grepping all
smali). The two real issues are:

### 3.1 `listFiles()+delete()` follows a symlinked `files/lib`

`ks.smali:2571-2575`:

```smali
invoke-virtual {p1}, Ljava/io/File;->listFiles()[Ljava/io/File;
array-length v3, p1
...
invoke-virtual {v5}, Ljava/io/File;->delete()Z
```

If `files/lib` is a symlink to a directory, `listFiles()` returns that
directory's entries and `delete()` operates through the symlink. Reachable only
after the failure; and it needs write permission on the target directory. The
native dir is not writable (§2.3), so the worst case is a failed `delete()` and
an `EACCES` on the subsequent `FileOutputStream`; `k()` then returns `false`
(catch_5 path) and `ks.g` retries `loadLibrary`, which fails again. It cannot
delete `libtmessages.49.so`.

### 3.2 `k()` returns `true` after its own `System.load` fails

`ks.smali:2803-2875`: the `System.load` is wrapped in `catch Error`; `catch_2`
only logs and falls through to `:goto_4` → `return v2` where `v2 == 1`
(`ks.smali:2819-2875`). `ks.g` treats `true` as success and skips the retry at
1831. `ks.a` remains `false`. The process then reaches
`ConnectionsManager.native_setJava(false)` with no registered natives and throws
`UnsatisfiedLinkError` (the prior root test's `FATAL EXCEPTION` is this, because
the proof .so implemented only `JNI_OnLoad`). A **functional** loc lib (one that
implements the natives, or `dlopen`s the real lib and calls its `JNI_OnLoad`)
would keep the app alive; the bug is still only post-failure. Setting
`ks.a = true` by reflection to skip the load is likewise useless: it leaves
`native_setJava` without registered natives, so the process crashes instead of
loading the loc lib.

### 3.3 `k()` sets the extracted file writable

`ks.smali:2776-2786` sets `setReadable(true,false)`,
`setExecutable(true,false)`, `setWritable(true)`. The device loader warns:

```
W System: Attempt to load writable file: /data/user/0/…/files/lib/libtmessages.49loc.so.
  This will throw on a future Android version. Current sdk version: 33
```

(`evidence/device_fallback.txt:20`). On this Android 13 it is a warning; a future
platform that enforces it would make `k()`'s load fail. A **pre-existing**
read-only loc file (the branch at `ks.smali:1672`) is the safer shape and is
what the test plan plants (`chmod 0400`).

---

## 4. Q3 — can `JNI_OnLoad` fail from app data?

### 4.1 The registration path is literal-only

`JNI_OnLoad` @`0x16efa34` (prior audit, `lab/native_appdata_audit/jni_onload.txt`):

```
GetEnv(vm,&env,0x10006)             -> non-zero => W19 = -1
sub_74ECC0(env,vm) must return 1    AnimatedFileDrawableStream: FindClass + 5 GetMethodID
sub_7529D4(env,vm) must return 1    NativeByteBuffer(5) + ConnectionsManager(37) RegisterNatives
sub_755ABC(env,vm) must return 1    FfmpegAudioDecoder(6) + FfmpegLibrary(4) RegisterNatives
sub_A5801C(env,vm)                  GetJavaVM (always returns 1)
sub_987CAC(env)                     WidgetSandboxNative(23); failure tolerated
return W19                          # 0x00010006
```

Every class name, method name and signature is a `.rodata`/`.data.rel.ro`
literal (`lab/native_appdata_audit/jni_onload_registrations.txt`). No file,
SharedPreferences, system property or Java field is read. The transitive
file-API closure of `JNI_OnLoad` and all 18 `.init_array` constructors is empty
(depth 5; only `getenv("LH_SVG_LATE_CACHE")` in a litehtml constructor, not
app-controlled). `GetEnv` cannot fail on the Java loading thread. The JNI version
is hard-coded `0x10006`; ART maps `JNI_ERR` (`-1`) or a bad version to
`was_successful=false` → `UnsatisfiedLinkError` (`java_vm_ext.cc:1092-1136`).

`RegisterNatives`/`GetMethodID` can fail only if the **class metadata** does not
match the literals: a broken/partial APK, a renamed class in a new build, or a
class loader that returns a different class. App data cannot change the APK or
the classloader.

### 4.2 Pending JNI exception before `ks.g`

`ClassLinker::FindClass` starts with `self->AssertNoPendingException()` (a
DCHECK) and, when the class is not already loaded, goes through
`FindClassInBaseDexClassLoader`; a pre-existing exception is preserved and
returned rather than cleared (`class_linker.cc:2877-3012`). A pending JNI
exception at `ks.g` could therefore make `FindClass` fail. But nothing on the
pre-`ks.g` path leaves one: `w0.onCreate`'s code is `getPackageInfo`,
`Typeface` (`i0.<clinit>`), `Build.*`, the `f8` log write, and `ks.g`; all
Java-level exceptions are caught and cleared by their handlers. The providers
that run before `onCreate` (§1.2) are APK code; the one app-data read they do
(Firebase, §4.4) catches its own `IOException`/`JSONException`. There is no
app-data-driven native call that leaves a pending exception.

### 4.3 App-image class shadowing (theoretical, different vector)

The only app-writable file that ART treats as **executable metadata** at process
start is the app image:

```
/data/user/0/<pkg>/cache/oat_primary/arm64/base.art
```

(`art17/runtime/runtime_image.cc:1851`; the device mapping is in
`evidence/device_appimage.txt` and `notes/persistence_local_existing_rce.md`).
ART maps and relocates it at every start, before `w0.onCreate`, and its classes
are the classes the class linker resolves. A forged image can change a class's
`ArtMethod`/code item; the prior note proves this with a forged `ks.<clinit>`
that executes bytecode.

In principle, the same edit could remove a method that a `JNI_OnLoad` batch
registers (e.g. one of `NativeByteBuffer`'s five natives or one of
`ConnectionsManager`'s 37), so `RegisterNatives` fails, `JNI_OnLoad` returns
`-1`, and `ks.g` takes the fallback. **This is not tested, and it is not a
"data-only" trigger**: it requires the app-image forgery (the counterfeit-ART
primitive), and if you can forge the image you can execute code at
`ks.<clinit>` and load the loc lib directly. It is recorded as a variant to
test only if a future task specifically needs the fallback code path rather than
startup code execution. The image is also regenerated by ART/app updates, so it
has its own persistence caveats.

### 4.4 Resource exhaustion (not a reliable trigger)

* **OOM/EMFILE in `dlopen`/`JNI_OnLoad`**: the loader needs native memory and
  (for `JNI_OnLoad`) Java heap for `FindClass`/`RegisterNatives`. The app is
  `android:largeHeap="true"`; the pre-`ks.g` allocations are transient. The
  prior audit's "no pre-load app-data allocation" is **not quite complete**:
  `FirebaseInitProvider` runs before `ks.g` (device log: `FirebaseApp
  initialization successful` at 33.463, `Load …libtmessages.49.so` at 33.491)
  and Firebase `PersistedInstallation` reads
  `files/PersistedInstallation.<appId>.json` (`m4/c.smali:2059,2112,2369`; the
  2026-11-01 startup trace lists this file among the app-data opens,
  `notes/persistence_20261101.md`).
  A huge/malformed JSON is parsed before the load. But:
  * Firebase's own persistence reader handles its expected I/O/JSON errors
    (the obfuscated reader is `m4/c`/`sa/a`; the path is
    `getFilesDir()/PersistedInstallation.<appId>.json`, see
    `evidence/firebase_persisted.txt`), so a malformed file normally does not
    escape `FirebaseInitProvider.onCreate`;
  * an uncaught `Exception` escaping a provider `onCreate` is rethrown as a
    `RuntimeException` by `ActivityThread.installProvider`
    (`catch (java.lang.Exception)` at `ActivityThread.java:7489`), and an
    `Error` (OOM/SOE) is not caught at all (`evidence/activitythread_provider_catch.txt`);
    either kills the process before `ks.g`, so it cannot produce the fallback;
  * a successful parse leaves only a small `PersistedInstallationEntry`; the
    `JSONObject` is collected, so the pressure is transient.
  A carefully sized retained allocation could in principle leave the heap near
  the limit and make `JNI_OnLoad`'s `FindClass` throw OOM, but it is a race, it
  is device/heap-state dependent, and the 27 MB extraction in `ks.k` would face
  the same pressure. Not a persistence mechanism.
* **System-wide resource exhaustion** (file-max, memory) from an app-UID daemon
  is a DoS, not a deterministic loader switch; it also risks killing the app
  before the fallback. Not recommended.

### 4.5 The writable-file warning is a shelf-life limit

The device emits `Attempt to load writable file: … This will throw on a future
Android version. Current sdk version: 33` for the `ks.k`-extracted loc file
(§3.3). Two consequences:

1. On this Android 13 the fallback works (proven).
2. A future platform that enforces the check would break `ks.k`'s branch even if
   a trigger existed. A pre-existing read-only file (planted by an attacker, not
   extracted by `k()`) should avoid the warning today; T5 checks the exact
   condition (writable vs `0400`) on the device.

---

## 5. What would change the answer

The verdict is "no data-only trigger". It would be falsified by any one of:

1. **A writable native dir.** If `ls -ldZ /data/app/.../lib/arm64` shows the app
   UID (or a group the app is in) with write permission, or if the app can write
   the `.so`, then replacing/removing it forces the fallback. The AOSP source
   and the 2026-11-01 device measurement say `system:system 755`; §6 T0/T2
   re-check.
2. **A missing/partial ABI install.** A split set without the ABI split, an
   aborted `installd` extraction, or a `primaryCpuAbi` mismatch would leave the
   package without the lib; `ks.k` extracts from `sourceDir` (base APK) and
   would fail too on an ABI-split install. This is an installer/user action, not
   app data.
3. **An APK/class mismatch** (a Telegram build whose class/method names differ
   from the native registration literals) — a build bug, not attacker data.
4. **A future platform that enforces the writable-file rule** — it would break
   the fallback rather than enable it.
5. **In-process code execution before `ks.g`** (the app image, or any other
   pre-`ks.g` code path). With code in the process you do not need the loader:
   call `System.load` on the loc file directly. A "preload a fake lib with the
   same soname" trick does **not** work: bionic ignores soname lookups for names
   containing `/` and dedupes only by inode/realpath (§5.1).
6. **Root/installer/system write** to the native lib or the APK — out of the
   app-UID premise.

### 5.1 Why a "fake same-soname lib" does not force the fallback

It is tempting to think that a library with `SONAME libtmessages.49.so`, loaded
early from app data, would make the later
`dlopen("/data/app/.../lib/arm64/libtmessages.49.so")` return the fake handle.
Bionic does not do that on Android 13:

* `find_loaded_library_by_soname` **ignores names containing `/`**
  (`linker.cpp:1362-1364`), and `System.loadLibrary` passes the full path
  returned by `findLibrary`; and
* `load_library` dedupes by **inode** (and realpath), not by soname
  (`linker.cpp:1162-1173`).

So a different file with the same soname is simply a second library; the
`/data/app` file is opened and loaded normally. The only ways to make
`findLibrary` return the fake path are to write the install-owned directory or
to change the classloader (`DexPathList.addNativePath`/reflection), both of which
need code or write access, not app data. This is a correction to the earlier
idea of a "same-soname preload" (it was considered but is refuted by the
linker source).

---

## 6. Device test plan (Sony XQ-BT52, Android 13, 72799)

Script: `lab/loader_ks_fallback/device_test_plan.sh` (root is used only for the
positive control and for reading install-owned paths; the negative tests run as
UID 10357). The proof payload is `lab/loader_ks_fallback/libtmessages.49loc.so`
built by `build_proof.sh`: a raw-syscall aarch64 `.so` with a `.init_array`
constructor that writes `files/.loader_fallback_proof`, and `JNI_OnLoad`
returning `JNI_VERSION_1_6`. It has **no** Telegram natives, so the app will
crash at `native_setJava` after the marker (expected; the marker is the proof).

Preconditions:

* `adb` device online; root (`su`) available; package
  `org.telegram.messenger.beta` installed; app not in the middle of an update.
* Back up the native lib and record its md5:
  `adb shell su -c 'cp -a <lib> <lib>.bak && md5sum <lib>'`.
* Have the app-UID command channel (the existing widget-RCE shell) or use
  Magisk `su 10357 sh <script>`.

### T0 — paths, owner/mode, SELinux label

```
./device_test_plan.sh info
```

Expected:

* `nativeLibraryDir=/data/app/~~…/lib/arm64`;
* `ls -ldZ` → `system:system 755` for the dir, `system:system 644` (or 755) for
  the `.so`, SELinux `u:object_r:apk_data_file:s0`;
* `/data/user/0/<pkg>/lib` absent (or not a symlink used by the loader);
* `/proc/<pid>/maps` shows the lib at `/data/app/~~…/lib/arm64/libtmessages.49.so`.

If the owner is the app UID or the dir is group-writable by the app's group,
**stop**: the premise of this note is wrong and the direct replacement path is
open.

### T1 — baseline: planted loc file is inert on a normal start

```
./device_test_plan.sh plant
adb shell am force-stop org.telegram.messenger.beta
adb shell logcat -c && adb shell monkey -p org.telegram.messenger.beta -c android.intent.category.LAUNCHER 1
# after ~8 s:
adb shell logcat -d | grep -E 'Load local lib|libtmessages|loaded normal lib'
adb shell su -c 'ls -l /data/user/0/org.telegram.messenger.beta/files/.loader_fallback_proof'
```

Expected: `Load /data/app/.../lib/arm64/libtmessages.49.so ... ok`,
`loaded normal lib`; **no** `Load local lib`; **no** marker. This is the key
control: a planted `files/lib/libtmessages.49loc.so` is inert when the APK lib
loads.

### T2 — negative: app-UID tamper attempts

```
./device_test_plan.sh negative
```

The script runs `touch`, `rm`, `mv`, `chmod`, `chown`, `ln` (hardlink) and
`dd`/append against `/data/app/.../lib/arm64/libtmessages.49.so` as UID 10357.
Expected: every operation fails with `Permission denied` (or the hardlink with
`Operation not permitted`), and the root-side `md5sum` is unchanged. If any
operation succeeds, the app can force the fallback by removing/replacing the
lib; the note's verdict does not apply to that install.

### T3 — positive control (root): force the fallback

```
./device_test_plan.sh control
```

The script force-stops the app, copies the lib to a timestamped backup, moves it
to `libtmessages.49.so.moved`, cold-starts the app, and greps logcat. Expected:

```
D nativeloader: Load libtmessages.49.so using class loader ns clns-5 ...:
  dlopen failed: library "libtmessages.49.so" not found
W System.err: java.lang.UnsatisfiedLinkError: ...
D tmessages: Load local lib
D nativeloader: Load /data/user/0/…/files/lib/libtmessages.49loc.so ...: ok
E AndroidRuntime: FATAL EXCEPTION: main        # expected: proof .so has no natives
```

and the marker `FALLBACK_LOADED` at
`/data/user/0/<pkg>/files/.loader_fallback_proof`. The trap restores the lib and
removes the marker; then start the app once and confirm `loaded normal lib`.
This is a controlled reproduction of the prior 2026-11-01 result
(`evidence/device_fallback.txt`), now with a **constructor** proof and a
read-only planted file.

### T4 — `ks.k` cleanup through a symlinked `files/lib`

After T2, as the app UID:

```
rm -rf /data/user/0/<pkg>/files/lib
ln -s /data/app/~~…/lib/arm64 /data/user/0/<pkg>/files/lib
```

Then run `./device_test_plan.sh control` again. Expected: `ks.g` catches the
failure, `ks.k`'s `listFiles()` enumerates the native dir, every `delete()`
fails with `EACCES`, the `FileOutputStream` to
`files/lib/libtmessages.49loc.so` fails, `k()` returns `false`, `ks.g` retries
`loadLibrary` (which fails), and the app crashes at `native_setJava`. Crucially,
`libtmessages.49.so` is **still present** (the app could not delete it) and its
md5 is unchanged. Restore `files/lib`/the lib and re-run T1.

### T5 — writable-file warning / read-only payload

Compare a planted `0400` loc file (T3) with a `0666` one. With the writable file
the device logs `Attempt to load writable file: … This will throw on a future
Android version`; with `0400` it should not. This does not change the trigger,
but it documents the shelf life of the `k()` branch and the safer shape of a
pre-existing payload.

### Abort / restore

If anything fails: restore the backup (`cp -a <lib>.bak <lib>`), verify the md5
against the APK's `lib/arm64-v8a/libtmessages.49.so`
(`2c0caa68a07fc26f79d13519af6c3526`), remove
`files/lib/libtmessages.49loc.so` and the marker, `am force-stop`, start, and
confirm `loaded normal lib`. The script's `restore` action does this
idempotently.

### What a failure of T3 means

If T3 does **not** produce `Load local lib`, the fallback path changed (a new
`ks` version, a different class name, or the app's classloader no longer
permits `/data`). If T2 shows the lib is writable, the data-only trigger exists
and the direct replacement test is the next step. If T0 shows
`extractNativeLibs=false`/a missing lib dir, the APK-zip element must be checked
instead.

---

## 7. Evidence and lab index

`notes/loader_ks_fallback.md` (this file) and `lab/loader_ks_fallback/`:

| file | contents |
|---|---|
| `libtmessages.49loc.so` | proof payload: `.init_array` constructor writes `files/.loader_fallback_proof`; `JNI_OnLoad` returns 1.6 |
| `proof_ctor.S` | assembly source (raw aarch64 syscalls; no libc) |
| `build_proof.sh` | `clang --target=aarch64-linux-android -nostdlib -shared` build, SONAME `libtmessages.49loc.so` |
| `device_test_plan.sh` | T0–T5, with root control and restore trap |
| `make_host_evidence.sh` | regenerates the excerpts below from the local smali/AOSP/ART trees |
| `verify_host_evidence.sh` | re-checks the key claims against the excerpts and the `.so` |
| `evidence/ks_g_flow.txt`, `ks_g_local.txt`, `ks_g_k_retry.txt` | `ks.g` smali with line numbers |
| `evidence/ks_k_cleanup.txt`, `ks_k_extract_load.txt`, `ks_k_chmod.txt`, `ks_k_load_return.txt` | `ks.k` smali |
| `evidence/ks_e_arch.txt` | `Build.CPU_ABI` use |
| `evidence/w0_oncreate.txt`, `w0_w.txt` | call sites |
| `evidence/loadedapk_makepaths.txt`, `loadedapk_permitted.txt` | `makePaths`, `libraryPermittedPath`, `librarySearchPath` |
| `evidence/dexpathlist_findlibrary.txt`, `dexpathlist_element.txt` | `findLibrary` / directory vs stored zip element |
| `evidence/runtime_loadlibrary0.txt` | by-name `dlopen` fallback |
| `evidence/nativeloader_namespace*.txt` | `kAlwaysPermittedDirectories`, permitted vs search paths |
| `evidence/art_loadnative*.txt` | ART `LoadNativeLibrary` / `JNI_OnLoad` semantics |
| `evidence/nativelibraryhelper*.txt`, `stage_dir.txt` | install ownership / 0755 / 0775 |
| `evidence/selinux_*.txt` | `apk_data_file rx`, `app_data_file` write/execute, `execute_no_trans` |
| `evidence/art_appimage_path.txt` | ART app-image path (`cache/oat_primary`) |
| `evidence/bionic_soname.txt`, `bionic_inode.txt` | soname-by-path ignored; inode/realpath dedup |
| `evidence/device_namespace.txt` | device `library_path`/`permitted_path` log line |
| `evidence/device_fallback.txt` | prior root-assisted fallback proof |
| `evidence/device_appimage.txt` | tombstone mapping of `base.art` |
| `evidence/activitythread_providers.txt`, `activitythread_provider_catch.txt`, `firebase_persisted.txt` | provider ordering / exception handling / Firebase path |

Related prior work (not modified): `notes/native_appdata_audit.md` (the
`JNI_OnLoad`/constructor and registration audit),
`notes/persistence_local_existing_rce.md` (the app-image startup code-exec
vector), `evidence/evidence_20261101/persistence/` (the 2026-11-01 fallback
run), `lab/native_appdata_audit/verify_loader.sh` (passes).

---

## 8. Negative results and open questions

* **No data-only trigger found.** The native dir is install-owned by AOSP design
  and by the 2026-11-01 device measurement; app data is permitted but not
  searched; the APK entry is deflated; `ks.k` is post-failure.
* **The app-image variant is not a loader finding.** It is the counterfeit-ART
  code-exec primitive; a "break `RegisterNatives`" image is a hypothesis, not a
  tested PoC. It is strictly dominated by the image's direct `ks.<clinit>`
  code execution for persistence purposes.
* **Provider-time app-data reads are a correction** to the prior audit's
  "no app data before `ks.g`": Firebase (and possibly ML Kit/AndroidX) providers
  run before `Application.onCreate` and Firebase `PersistedInstallation` reads
  `files/PersistedInstallation.*.json`. This does not give a load trigger:
  parse errors are caught, OOM/SOE in a provider kills the process before
  `ks.g`, and the parsed object is small/transient. It is a candidate for a
  future resource-exhaustion experiment only.
* **The writable-file warning** (`Current sdk version: 33`) is a shelf-life
  limit for `ks.k`'s extracted loc file. A pre-existing read-only payload avoids
  it today; a future platform may reject it.
* **Untested on device in this task:** T0–T5. The device is rooted, so T3 is a
  controlled reproduction; T2 is the decisive falsification test for the
  "not writable" claim.

If T2 ever succeeds on a different OEM/Android build, the whole conclusion
changes: `ks.k`'s `listFiles()+delete()` (or a direct `rm`) removes the lib, and
the next start loads `files/lib/libtmessages.49loc.so` with no root. The test
plan is designed to detect exactly that case before any exploit work.
