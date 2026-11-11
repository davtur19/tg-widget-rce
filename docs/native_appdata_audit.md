# `ks` / NativeLoader + `libtmessages` `JNI_OnLoad` — 72799

Date: 2026-11-02. Scope: **surface 1 only** — the `ks` local-lib loader and
everything that runs during `System.loadLibrary("tmessages.49")`.
`tgnet`, `twidget` and `tlottie` are handled by the parallel agents and are not
audited here.

Target: `lib/arm64-v8a/libtmessages.49.so` of APK **72799** (Telegram 13.2.0
beta), md5 `2c0caa68a07fc26f79d13519af6c3526`.
IDB `/tmp/opencode/tg49_72799.so.i64` — verified in-session with
`ida_nalt.retrieve_input_file_md5() == 2c0caa68…`; 80,520 functions.
Java: `/tmp/opencode/dbgbuild/smali72799/smali` and
`/tmp/opencode/jadx72799_c1`. Host-only: no device/emulator.

Lab: `lab/native_appdata_audit/` (`jni_onload.txt`,
`jni_onload_registrations.txt`, `file_api_xrefs.txt`, `loader_evidence.md`).

---

## 0. Answers

**Q1 — can any app-data-driven Telegram-specific condition make
`System.loadLibrary("tmessages.49")` fail (or `JNI_OnLoad` return an error/throw)
so `ks` takes the `files/lib/libtmessages.49loc.so` fallback?**

**No.** `JNI_OnLoad` (@`0x16EFA34`) returns `0x00010006` unless either
`JavaVM->GetEnv` fails (impossible on the Java loading thread) or one of three
`RegisterNatives`/`GetMethodID` batches fails (`0x74ECC0`, `0x7529D4`,
`0x755ABC`). Every class name, method name and signature in those batches is a
compile-time literal in `.rodata`/`.data.rel.ro`; none comes from app data. The
twidget batch (`0x987CAC`) is explicitly tolerated on failure, and
`0xA5801C` is `GetJavaVM` (always returns 1). The ELF `.init_array` constructors
and `JNI_OnLoad` reach **no file API at depth 5** (verified over the call graph;
only `getenv` in one litehtml constructor, which is not app-controlled). The
`w0.onCreate` code before `ks.g` reads no app-writable file (only
`getPackageInfo`, system `Typeface`, `Build.*`, and a *write-only* log file).

**Q2 — is there a Telegram-specific bug in `ks`/`loadFromZip`/path handling
that loads a file from app data (or a wrong path) directly?**

**No.** `ks.g` loads exactly `new File(getFilesDir(), "lib/libtmessages.49loc.so")`
and `ks.k` extracts exactly `lib/<Build.CPU_ABI>/libtmessages.49.so` from
`getApplicationInfo().sourceDir` into that same fixed path. There is no
attacker-controlled component in the path, no traversal, no dynamic class or
library name. Two real but **latent** logic issues are recorded below
(`k()` returns true after a failed `System.load`; the `listFiles()`+`delete()`
cleanup would follow a symlink at `files/lib`) — neither can be reached or
armed from app data alone.

**Q3 — what would be needed for the local-lib loader to be reachable after an
app update?**

Any one of: (a) a primitive that deletes/corrupts
`/data/app/.../lib/arm64/libtmessages.49.so` or the base APK (system/root/
installer, not app data); (b) a partial/broken install/update that leaves the package
installed **without** the ABI native lib (missing/partial ABI split, aborted
extraction); (c) a Telegram build/APK mismatch that makes one of the
`RegisterNatives` batches fail (a build bug, not attacker data); or (d) a
resource exhaustion at load severe enough to fail `dlopen`/`JNI_OnLoad` but not
the subsequent 27 MB extraction — no pre-load app-data allocation exists to
cause it. §5.

---

## 1. The loader path, exactly

### 1.1 Call order

`ApplicationLoaderImpl` (jadx) overrides only `b/g/q/v`; it has **no
`onCreate`** and no static fields. `w0.attachBaseContext` only calls
`super.attachBaseContext`. So the pre-load path is `w0.onCreate`:

```
jadx w0.java:414  onCreate()
        :440  getPackageInfo(...)        # APK manifest, system
        :452  Typeface i0.f11120a        # i0.<clinit>: regex/ThreadLocal + i0.v(display metrics); no files
        :457  ks.g(f13920b)              # smali w0.smali:2734
        :459  ConnectionsManager.native_setJava(false)   # smali:2740
```

`w0.w()` (receiver entry) calls `ks.g` at `w0.smali:1405`, also before
`native_setJava`. `w0` has **no `<clinit>`**; `ApplicationLoaderImpl` has none.
`f8.b` (beta-only log line before `ks.g`) calls `f8.h()` → `f8.k()`, which
**creates** a new `dd_MM_yyyy_HH_mm_ss.txt` under `i0.P0()` and writes; it does
not read or parse attacker files (smali `f8.k`).

### 1.2 `ks.g` (smali `ks.smali:1439-1907`)

| line | action |
|---|---|
| 1480-1484 | `System.loadLibrary("tmessages.49")` in `try`, `catch Error` |
| 1493-1498 | success: `ks.a = true`, log `loaded normal lib`, return |
| 1611-1625 | on `Error`: `files/lib/libtmessages.49loc.so`, `mkdirs()`, `exists()` |
| 1655-1672 | if it exists: `System.load(absolutePath)`; on `Error` log + `delete()` |
| 1769 | `ks.k(context, files/lib, libtmessages.49loc.so, arch)` |
| 1831 | if `k()` returned false: retry `System.loadLibrary("tmessages.49")` |

The pre-existing local file is therefore consulted **before** `ks.k` does any
cleanup. On a normal start (load succeeds) nothing under `files/lib` is touched.

### 1.3 `ks.k` / “loadFromZip” (smali `ks.smali:2556-3075`)

| line | action |
|---|---|
| 2571-2575 | `files/lib.listFiles()` and `delete()` **every** entry |
| 2634 | `new ZipFile(getApplicationInfo().sourceDir)` — the installed **base APK** |
| 2666-2692 | `getEntry("lib/" + Build.CPU_ABI + "/libtmessages.49.so")` |
| 2770-2786 | `new FileOutputStream(files/lib/libtmessages.49loc.so)`, copy 4 KiB chunks, `setReadable/setExecutable/setWritable(true,false)` |
| 2803 | `System.load(absolutePath)` |
| 2819-2875 | `catch Error`: log, then **`return true`** |

`arch` is `Build.CPU_ABI` from `ks.e()` (system property). Every path component
is fixed. `k()` returns `false` only for exceptions in the ZipFile/extraction
path; a failure of its own `System.load` is swallowed and still returns `true`.

### 1.4 Two Telegram-specific logic bugs (latent, not triggers)

1. **`k()` returns `true` after a failed `System.load`.** `ks.g` then skips the
   normal `loadLibrary` retry (`:1769-1786`), `ks.a` stays false, and the
   process runs with no native methods. `k()` also does **not** delete the bad
   local lib in this path. A broken planted lib therefore yields a silent
   degraded app rather than a retry. Severity low: it happens after the failure
   we cannot create, and writing `files/lib` already implies app-UID file write.
2. **Cleanup follows a symlinked `files/lib`.** `File.listFiles()` follows a
   symlink; if `files/lib` were a symlink to another app-private directory,
   `k()` would `delete()` entries in the target. `k()` also writes
   `libtmessages.49loc.so` with `FileOutputStream`, which follows a symlink at
   that name if it survives cleanup. Both require a separate **symlink
   primitive** (and the load-failure trigger), so they are not app-data-only.

---

## 2. What runs during `System.loadLibrary`

Order: `Runtime.loadLibrary0` → `BaseDexClassLoader.findLibrary`
(`nativeLibraryDir`, read-only `/data/app/.../lib/arm64`) →
`nativeLoad` → `OpenNativeLibrary` (`dlopen`, RTLD_NOW, classloader namespace)
→ ELF `.init_array` constructors → `JNI_OnLoad`.

### 2.1 ELF constructors

`.init_array` @`0x19594C8`, 18 entries (dump in `jni_onload.txt`). Transitive
call-graph closure (depth 5, PLT-resolved) of every constructor touches **no**
file API (`open/openat/fopen/fread/fstat/stat/lstat/access/mmap/gzopen/gzread/
AAsset*/inflate/dlopen/readlink/realpath`); only constructor `0x83D1F0`
(litehtml `LH_SVG_LATE_CACHE`) calls `getenv`. `getenv` is not app-writable.
No constructor reads a path.

### 2.2 `JNI_OnLoad` @`0x16EFA34`

Disassembly in `jni_onload.txt`. Summary:

```
GetEnv(vm,&env,JNI_VERSION_1_6)            # JavaVM index 6
  -> non-zero => W19 = -1 @0x16EFB00        # only GetEnv failure
sub_74ECC0(env, vm)  must return 1
sub_7529D4(env, vm)  must return 1
sub_755ABC(env, vm)  must return 1
sub_A5801C(env, vm)  (GetJavaVM; always returns 1)
sub_987CAC(env)      failure tolerated (ExceptionCheck/Clear at 0x16EFAE0/AF8)
return W19                                  # 0x00010006
```

| batch | what it does | can fail? | input |
|---|---|---|---|
| `0x74ECC0` | FindClass `AnimatedFileDrawableStream`, 5× GetMethodID (`read (II)I`, `cancel ()V`, `isFinishedLoadingFile ()Z`, `isCanceled ()Z`, `getFinishedFilePath ()String`) | yes → returns 0 | literals only |
| `0x7529D4` | FindClass `NativeByteBuffer` + RegisterNatives(5); FindClass `ConnectionsManager` + RegisterNatives(37); GetMethodID `RequestTimeDelegate.run (J)V`; 20+ `ConnectionsManager` callbacks | yes → returns 0 | literals only |
| `0x755ABC` | FindClass `FfmpegAudioDecoder`, GetMethodID `growOutputBuffer`, RegisterNatives(6); FindClass `FfmpegLibrary`, RegisterNatives(4) | yes → returns `-1` | literals only |
| `0x987CAC` | FindClass `WidgetSandboxNative`; copy 23 `JNINativeMethod` entries from `.data.rel.ro` `off_18C7090` to stack; RegisterNatives | **no** (tolerated) | literals/`.data.rel.ro` |
| `0xA5801C` | `GetJavaVM(env, &qword_19ECC60)` (JNIEnv index 219) | **no** (returns 1) | — |

All method tables are immutable after relocation (`.data.rel.ro` for the
FFmpeg/twidget tables; the tgnet table at `.data 0x1969970` is relocated at
load time). No table entry or name comes from a file or a Java string.

The only realistic `RegisterNatives` failure is an **APK/Java-class mismatch**
(missing/renamed class or method, e.g. a broken build/split install). `OOM`
inside `FindClass`/`RegisterNatives` could also fail it, but there is no
app-data-controlled allocation before this point (§1.1) — the app-data parses
(`tgnet.dat`, DB) start later, after `native_setJava`.

### 2.3 `JNI_OnLoad` return semantics (ART 13)

`art/runtime/jni/java_vm_ext.cc` (`android13-release`): `version == JNI_ERR`
(-1) or a bad version sets `was_successful = false`; `Runtime.nativeLoad`
then throws `UnsatisfiedLinkError`, which `ks.g` catches. There is no path from
a Java field, file, property or environment value into `version`.

---

## 3. Why app data cannot force the failure (exhaustive matrix)

| failure mode | app-data controlled? | reason |
|---|---|---|
| lib missing in `nativeLibraryDir` | no | `/data/app/.../lib/arm64` is install-owned; the app cannot write it |
| bad ELF / wrong ABI / missing `DT_NEEDED` | no | APK/install content |
| `dlopen` `ENOMEM`/`EMFILE` | no (not deterministically) | would also break `k()`'s 27 MB extraction + `System.load`; no pre-load app-data allocation exists |
| linker namespace denial | no | APK lib dir is in the namespace; app data is permitted anyway (§4) |
| SELinux denial | no | APK lib dir is allowed |
| `GetEnv` failure | no | Java loading thread is attached |
| `RegisterNatives`/`GetMethodID` failure | no | literal names/signatures; only an APK mismatch breaks them |
| bad JNI version | no | hard-coded `0x10006` |
| `OutOfMemoryError` from `loadLibrary` | no | pre-load code reads no app data; `mainconfig.xml` OOM is *after* `ks.g` (prior note) |
| `SecurityException` | no | no SecurityManager on Android |

The startup parser that does read app data (`ConnectionsManager.native_init` →
`loadConfig`) runs **after** `ks.g` has already succeeded
(`w0.java:457` vs `:459`). Its crash/OOM cannot retroactively fail the load.

---

## 4. The platform is *not* the gate (correction)

The prior note calls `files/lib/libtmessages.49loc.so` a “root-gated fallback”
(`notes/persistence_local_existing_rce.md:151`). For Android 13 that is wrong:

* `art/libnativeloader/library_namespaces.cpp` (android13-release) line 81:
  `kAlwaysPermittedDirectories = "/data:/mnt/expand"`, used at line 219 with the
  comment “effectively allows such a classloader to access anything under /data
  and /mnt/expand”.
* `system/sepolicy/private/untrusted_app_all.te:27`:
  `allow untrusted_app_all app_data_file:file { r_file_perms execute };`
  The only neverallow is `execute_no_trans` (`app_neverallows.te:61-67`), i.e.
  `execve` of a binary (the Android-10 W^X change). `dlopen`/`mmap(PROT_EXEC)`
  uses `file execute`, which is allowed.
* `ks.k` sets the executable bit itself (`setExecutable(true,false)`).

So a valid ELF at that path **would** load as UID 10357. The gate is only the
`UnsatisfiedLinkError`, not SELinux/the linker.

---

## 5. What would make it reachable after an update

The local file is app-writable, unverified, and survives app updates and
reboots (`files/` is preserved). It does **not** survive uninstall/“clear data”,
and it does **not** survive a library-name bump (`tmessages.49` → `.50`): the
new `ks` looks for `libtmessages.50`/`libtmessages.50loc.so`, so the payload
would have to be re-planted.

To actually reach `System.load(files/lib/libtmessages.49loc.so)` one of these is
required:

1. **System/root/installer write** to `/data/app/~~…/lib/arm64/libtmessages.49.so`
   or to `base.apk` (delete/corrupt it). Not app data.
2. **An install/update that leaves the package without the ABI native lib**:
   installing a split set without the ABI split, an aborted
   `installd` extraction, or a `primaryCpuAbi`/`nativeLibraryDir` mismatch.
   User/installer action, not app data. Note `ks.k` extracts from `sourceDir`
   (base APK only), so on ABI-split installs the fallback itself cannot restore
   the lib.
3. **A Telegram build/APK mismatch** that makes `FindClass`/`RegisterNatives`
   fail (renamed class/method, stripped method, wrong signature). This is a
   build bug, not attacker data; but if such a version ships, the fallback
   becomes an immediate app-data code-exec primitive.
4. **Resource exhaustion at load** (ENOMEM/EMFILE) severe enough to fail
   `dlopen`/`JNI_OnLoad` but not the 27 MB extraction — not realistically
   controllable from app data, and no pre-load app-data allocation exists.
5. The separate **ART app-image** vector (`cache/oat_primary/arm64/base.art`,
   `notes/persistence_local_existing_rce.md`) — app-data code exec in
   `ks.<clinit>` *before* `ks.g`; it does not use and does not need this
   fallback.

Without one of (1)–(4), `files/lib/libtmessages.49loc.so` is inert data: on
every start the APK's own lib loads successfully and `ks.g` returns at
`ks.smali:1493-1498` before touching it.

---

## 6. Negative results / evidence

* `JNI_OnLoad` + all 18 `.init_array` constructors: transitive file-API closure
  (depth 5) = **none** (`file_api_xrefs.txt`, `jni_onload.txt`).
* Pre-`ks.g` Java: no app-data read; `f8` log is write-only; `w0` has no
  `<clinit>`; `ApplicationLoaderImpl` has no `onCreate`; `attachBaseContext` is
  a `super` call.
* `ks`/`k`: fixed paths only; no attacker component; `sourceDir` + `Build.CPU_ABI`
  + literal entry name.
* `k()` success return after failed `System.load` (logic bug); cleanup/symlink
  caveat (needs a symlink primitive). Neither is a load trigger.
* Platform: loading from `/data` is permitted on Android 13 (§4); the prior
  “root-gated” wording is corrected.

Artifacts:

```
lab/native_appdata_audit/
  jni_onload.txt                 # JNI_OnLoad disasm + 5 callees + .init_array
  jni_onload_registrations.txt   # every literal per registration batch
  load_path_closure.txt          # transitive file-API closure of JNI_OnLoad + ctors
  file_api_xrefs.txt             # file-API callers in the real lib
  loader_evidence.md             # smali/policy excerpts, trigger matrix
  verify_loader.sh               # read-only re-check of every claim above
  README.md
```
