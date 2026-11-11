# Local loader from app data: `app_process` + dex + `System.load` (2026-11-02)

Target: Telegram Android beta 72799, Sony XQ-BT52, Android 13, app UID 10357
(`u:r:untrusted_app`). The only execution primitive is the existing widget
RCE (#1827/#1865), which reaches libc `system()` as the app UID. No root, no
device in this pass: the Android-specific conclusions are from the
`android13-release` sources; the device plan is in
`lab/loader_app_process/device/test_plan.md`.

**Question.** Can the app UID run a *native* payload stored in its own data
directory, given that the widget RCE only gives a shell?

**Short answer.** Yes, but not by `execve` of a payload ELF: that is blocked by
SELinux (`app_data_file:file execute_no_trans`, neverallow for targetSdk >= 29).
The working shape is:

```
widget system("sh .../run_loader.sh")
  -> /system/bin/sh (already proven to run as untrusted_app)
  -> /system/bin/app_process  (zygote_exec, allowed by app.te:204; no domain transition)
       CLASSPATH=/data/user/0/<pkg>/files/loader/loader.dex
       main: System.load("/data/user/0/<pkg>/files/loader/libloader.so")
  -> dlopen of app_data_file (file:execute allowed; linker namespace /data)
  -> libloader.so constructor + JNI_OnLoad run as UID 10357
```

This is **not** a privilege escalation: the helper is the same UID and the same
`untrusted_app` domain, and it dies with the app cgroup. It is a native-code
host, not persistence. The update/re-trigger design is in §5.

The prior note `notes/native_appdata_audit.md` §5 is correct that
`System.load()` from `/data` is permitted and that the `ks` fallback is gated
by the `UnsatisfiedLinkError`. This note adds the missing distinction:
**`dlopen` of app data is allowed (`file:execute`), `execve` of app data is
not (`execute_no_trans`)**. That is why the loader must be a *dex/native
library* loaded by a system binary, not an ELF executed from `/data`.

| question | verdict | evidence |
|---|---|---|
| `execve("/system/bin/app_process")` as the app UID | **allowed** (AOSP); same UID/domain, no transition | `app.te:204`, `global_macros:24-27`, `file_contexts:250-251`; T1 |
| `execve()` a payload ELF from app data | **denied** (`execute_no_trans`) | `app_neverallows.te:58-67`; T2 |
| `dlopen()`/`System.load()` a `.so` from app data | **allowed** (`file:execute`; `/data` namespace) | `untrusted_app_all.te:27`; `library_namespaces.cpp:81,219`; T4 |
| read a dex from app data | **allowed** (`r_file_perms`) | `untrusted_app_all.te:27`; T3 |
| helper survives app update / force-stop | **no** (app cgroup kill) | `local_ace_daemon.md` §4; T5/T6 |

**This is not the `ks` fallback.** Telegram's own `ks.g` tries
`System.loadLibrary("tmessages.49")` and only falls back to
`System.load(files/lib/libtmessages.49loc.so)` after that throws
(`notes/native_appdata_audit.md` §2, §6). The throw is not app-data-triggerable,
so that path is root-gated. Our loader does not try to make the primary load
fail: it starts a **new** VM with `app_process` and calls `System.load`
directly, in a process where no earlier `loadLibrary` has to fail. The
`/data` permission is the same in both cases; the difference is who calls it
and when.

---

## 1. SELinux: the exact rules

All citations are `system/sepolicy` at `android13-release`; the excerpts are
collected in `lab/loader_app_process/evidence/aosp_excerpts.txt`.

### 1.1 `app_process` is executable by apps

`/system/bin/app_process32` and `app_process64` are `zygote_exec`
(`private/file_contexts:250-251`). `/system/bin/app_process` is a symlink to
`app_process64`; SELinux checks the resolved inode, so the `zygote_exec`
label applies to the exec. The app domain gets:

```
# private/app.te:204
allow appdomain zygote_exec:file rx_file_perms;
```

`rx_file_perms = r_file_perms + x_file_perms`, and
`x_file_perms = { getattr execute execute_no_trans map }`
(`public/global_macros:24-27`). So the app gets **both** `execute` (the mmap
check used by `dlopen`/exec mapping) and `execute_no_trans` (the execve check
when no domain transition happens).

There is no `type_transition` from any app domain to `zygote` on
`zygote_exec`; the only transition is `init_daemon_domain(zygote)` in
`private/zygote.te:5`, i.e. init → zygote. A child launched by an app therefore
stays `untrusted_app` (same categories) and same UID. In that no-transition
case the bprm hook checks `FILE__EXECUTE_NO_TRANS`
(`kernel/common android13-5.10 security/selinux/hooks.c:2364-2369`); the
separate `file:execute` mapping check on the binary is also granted here by
`rx_file_perms`:

```c
if (new_tsec->sid == old_tsec->sid) {
    rc = avc_has_perm(..., SECCLASS_FILE, FILE__EXECUTE_NO_TRANS, &ad);
    if (rc) return rc;
}
```

This is the AOSP baseline. The device test T1 is the only way to know whether
Sony kept it. If it is denied, the exact denial is:

```
avc: denied { execute_no_trans } for path="/system/bin/app_process64" ...
  scontext=u:r:untrusted_app:s0:c101,c257,c512,c768
  tcontext=u:object_r:zygote_exec:s0 tclass=file permissive=0
```

(or `{ execute }` if the mapping check is the one denied). The shell symptom
is `Permission denied` / rc 126. Do not claim the loader works on the Sony
until T1 passes.

`/system/bin/dalvikvm` has no specific `file_contexts` entry; it falls under
the generic `/system(/.*)? -> system_file` and `private/app.te:273`
(`allow appdomain system_file:file x_file_perms`) also permits execve without
transition. It is the fallback if `app_process` is OEM-blocked (§4.2).

### 1.2 App-data ELF: `execve` is blocked, `dlopen` is not

`private/untrusted_app_all.te:27` grants only the mapping permission:

```
allow untrusted_app_all app_data_file:file { r_file_perms execute };
auditallow untrusted_app_all app_data_file:file execute;   # :28
```

`private/app_neverallows.te:58-67` removes `execute_no_trans` for every app
targeting API 29+:

```
# Block calling execve() on files in an apps home directory.
neverallow {
  all_untrusted_apps
  -untrusted_app_25
  -untrusted_app_27
  -runas_app
} { app_data_file privapp_data_file }:file execute_no_trans;
```

Telegram 72799 has `targetSdkVersion=36` and `compileSdkVersion=36`
(`lab/post_update_retrigger/manifest_72799_full.txt:6,13`), so
`seapp_contexts:171`
maps it to `untrusted_app`, not the legacy `untrusted_app_25/27` domains that
still have `app_data_file:file execute_no_trans`
(`private/untrusted_app_25.te:36`, `private/untrusted_app_27.te:24`).
Consequences:

| operation on an app-data file | permission checked | result |
|---|---|---|
| `dlopen(path)` / `System.load(path)` (mmap `PROT_EXEC`) | `file:execute` | **allowed** (untrusted_app_all.te:27) |
| `execve(path)` (no transition) | `file:execute_no_trans` | **denied** (app_neverallows.te:58-67) |

The exact denial for a payload ELF is:

```
avc: denied { execute_no_trans } for path="/data/user/0/org.telegram.messenger.beta/files/loader/exec_probe" ...
  scontext=u:r:untrusted_app:s0:c101,c257,c512,c768
  tcontext=u:object_r:app_data_file:s0:c101,c257,c512,c768 tclass=file permissive=0
```

This is why the loader is a dex + shared library, not a helper binary.

**Trap: `run-as` is not the app domain.** `adb shell run-as
org.telegram.messenger.beta` switches to `runas_app`, and
`private/runas_app.te:11` has
`allow runas_app app_data_file:file execute_no_trans;`. A `run-as` test would
run the payload ELF and falsely refute the W^X analysis. All SELinux tests
must run from a child of the Telegram process (the widget `system()` or the
C2 `exec`).

### 1.3 The already-proven part

The widget RCE calls libc `system()` inside the Telegram process; the proof
file from the device is

```
uid=10357(u0_a357) ... context=u:r:untrusted_app:s0:c101,c257,c512,c768
```

(`notes/aes_tiny_loader_72799.md`, `notes/widget_loader.md`). The C2 implant is
an mksh script (`c2/README.md`), so the app UID already execs
`/system/bin/sh` and toybox (`app.te:128-129` grants `shell_exec`/`toolbox_exec`
`rx_file_perms`). `app_process` is the same kind of exec, just a different
system file and a JVM instead of a shell.

---

## 2. Linker and ART: why `System.load` from `/data` works

### 2.1 The `/data` namespace allowance

`art/libnativeloader/library_namespaces.cpp:78-81`:

```cpp
// (http://b/27588281) This is a workaround for apps using custom classloaders and calling
// System.load() with an absolute path which is outside of the classloader library search path.
// This list includes all directories app is allowed to access this way.
constexpr const char* kAlwaysPermittedDirectories = "/data:/mnt/expand";
```

`LibraryNamespaces::Create` starts every classloader namespace with

```cpp
std::string permitted_path = kAlwaysPermittedDirectories;   // :219
```

(`:211-226`), then adds the APK's permitted path if any. For a classloader not
created by `ApplicationLoaders` — which is the case for the CLASSPATH loader
of `app_process` — `OpenNativeLibrary` creates an isolated namespace with
`dex_path = nullptr`, `permitted_path = nullptr`
(`art/libnativeloader/native_loader.cpp:259-279`), which still starts at
`/data:/mnt/expand`. `System.load("/data/user/0/...")` therefore passes the
namespace check; if it ever fails, bionic reports:

```
library "/data/.../libloader.so" needed or dlopened by "..." is not accessible for the namespace "classloader-namespace"
```

(`bionic/linker/linker.cpp:1214-1219`). That string is the refutation
signature for this section.

The one condition that matters: the `main` class must be loaded by the
**CLASSPATH classloader**, not the boot classloader. It is: `app_process`
passes the class name to `AppRuntime`, which does an early `FindClass` from
native code before boot Java runs (`app_main.cpp:50-76`), so the class is
defined by the `PathClassLoader` over `CLASSPATH`. `System.load` then uses
that class's loader, not `null`, so the `/data` namespace path applies.

### 2.2 `app_process` in non-zygote mode

`frameworks/base/cmds/app_process/app_main.cpp:285-338`: with a class name
(no `--zygote`), it calls
`runtime.start("com.android.internal.os.RuntimeInit", args, zygote=false)`.
`AppRuntime::onStarted()` calls `callMain()`, which invokes
`public static void main(String[])` on the class. No `maybeCreateDalvikCache()`
runs in this branch; that is zygote-only (`app_main.cpp:307`). This matters
because `untrusted_app` cannot write `/data/dalvik-cache`, but the non-zygote
path does not need to.

`AndroidRuntime::start` has hard environment requirements
(`frameworks/base/core/jni/AndroidRuntime.cpp:1209-1245`):

* `ANDROID_ART_ROOT` — `LOG_FATAL` if unset;
* `ANDROID_I18N_ROOT` — `LOG_FATAL` if unset;
* `ANDROID_TZDATA_ROOT` — `LOG_FATAL` if unset;
* `ANDROID_ROOT` — defaults to `/system`;
* `BOOTCLASSPATH` — read by ART (`art/runtime/parsed_options.cc:664-668`);
  without it the runtime has no boot class path;
* `CLASSPATH` — read by ART (`parsed_options.cc:670-671`) into
  `class_path_string_`; libcore exposes it as `java.class.path` via
  `VMRuntime.classPath()` (`libcore System.java:977`), and
  `ClassLoader.createSystemClassLoader()` builds the `PathClassLoader` from it
  (`ClassLoader.java:206-224`). That loader defines `LoaderMain` and is the
  loader `System.load` uses.

These are exported by `init` (`system/core/rootdir/init.environ.rc.in:4-10`
for `ANDROID_*`) and by `derive_classpath` via
`load_exports /data/system/environ/classpath` (`init.rc:981-984`), and are
inherited through zygote by every app process. The device test T0.1 checks
them in the app's own `/proc/self/environ`; `run_loader.sh` refuses to start
if they are missing. Do not guess `BOOTCLASSPATH`: the APEX/framework jar list
is device-specific.

`app_process` also calls `ProcessState::self()->startThreadPool()` in
`onStarted`; apps already have `/dev/binder` access, so this is not a gate.
The process is `untrusted_app`, UID 10357, and inherits the app's seccomp
filter (the same one under which the app already runs ART).

### 2.3 The load sequence

`System.load(path)` → `Runtime.load0` → `nativeLoad` → ART
`JavaVMExt::LoadNativeLibrary` → `OpenNativeLibrary` with the caller's
classloader → `android_dlopen_ext` in the `/data`-permitted namespace. The
linker runs `DT_INIT_ARRAY` (our constructor), then ART resolves `JNI_OnLoad`
and calls it with the `JavaVM*`. Both are independent proofs:

* constructor: the `.so` was mapped and executed;
* `JNI_OnLoad`: a real JavaVM called into the library.

`libloader.c` implements both with raw aarch64 syscalls and **no
`DT_NEEDED`** (`-nostdlib`), so a missing dependency cannot be the failure.
The host build is 16 KiB LOAD-aligned and has `DT_INIT_ARRAY` (see
`lab/loader_app_process/evidence/host_tests.txt`).

---

## 3. What the loader is

| piece | path | role |
|---|---|---|
| shell glue | `files/loader/run_loader.sh` | reads the env, checks the files, starts `app_process` in the background |
| Java entry | `files/loader/loader.dex` | `org.telegram.loader.LoaderMain`; calls `System.load` |
| native payload | `files/loader/libloader.so` | constructor + `JNI_OnLoad`; the actual native stage |
| host process | `tgloader` (`/system/bin/app_process64`) | ephemeral; same UID/domain/cgroup as Telegram |

The exact command (after the `app_process` argument parser):

```sh
CLASSPATH=/data/user/0/org.telegram.messenger.beta/files/loader/loader.dex \
  /system/bin/app_process /system/bin --nice-name=tgloader \
  org.telegram.loader.LoaderMain \
  /data/user/0/org.telegram.messenger.beta/files/loader/libloader.so \
  /data/user/0/org.telegram.messenger.beta/files/loader 0
```

`--nice-name=tgloader` must come **after** `/system/bin` (it is parsed in the
second loop); putting it before would make it a VM option. It only sets
`argv[0]`, so `ps`/`pidof` can find the helper.

**The helper must be backgrounded.** The widget's `system()` call is
synchronous; if `app_process` runs in the foreground, the QuickJS native call
blocks until the VM exits. `run_loader.sh` uses `nohup ... &` and returns
after a 1 s liveness check. The helper is reparented to init but stays in the
Telegram cgroup.

The `.so` constructor can start threads, but the `main` must keep the process
alive: `LoaderMain` sleeps for the `hold-seconds` argument. If `main`
returns, ART shuts the VM down and the threads die with the process.

The helper is a **separate VM and process**: it does not share the Telegram
app's Java objects, its already-loaded `libtmessages.49.so` state, or its
`JNIEnv`. It runs with the same UID and can use files/binder, but anything
that must touch the app's live objects needs the in-process `dlopen` variant
(§4.5), not this loader.

---

## 4. Alternatives, and why they are not better

### 4.1 `DexClassLoader` / `InMemoryDexClassLoader`

Both require an existing ART VM and a Java caller. The widget shell is a
native process (a `system()` child); it has no JNIEnv and no Java frame. The
app process does have a VM, but the exploit's one-shot native call primitive
would need a multi-call JNI chain (`JNI_GetCreatedJavaVMs` →
`AttachCurrentThread` → `FindClass` → `CallStaticVoidMethod`) to use it;
`app_process`/`dalvikvm` is the practical way to get a VM we control. Once
`app_process` runs, `System.load` is simpler than a class loader and gives
the same native code. They add nothing here.

### 4.2 `dalvikvm`

`/system/bin/dalvikvm` is the bare-VM tool. It has no specific
`file_contexts` label (generic `system_file`) and `app.te:273` grants
`appdomain system_file:file x_file_perms`, so AOSP permits it. It calls
`JNI_CreateJavaVM` directly, without `startReg`, so `android.*` JNI natives
are unavailable — `LoaderMain` deliberately uses only `java.*`. It still needs
`BOOTCLASSPATH` (`parsed_options.cc:664`). Use it only as T7 if
`app_process` is OEM-blocked; it is a different file type (`system_file`), so
an OEM rule that removes `zygote_exec` might not remove it.

### 4.3 A helper ELF in app data

Blocked: see §1.2. It is a useful negative control (`exec_probe`), not a
loader.

### 4.4 `Runtime.exec` of a helper

`Runtime.exec`/`system()` can exec `/system/bin/*` (sh, toybox,
`app_process`), but not an app-data ELF. If the helper were written as a
`/system/bin` binary it would have to be installed by the system; that is not
available without root.

### 4.5 In-process `dlopen` (the only remaining fallback)

The widget exploit already has a native call primitive
(`mf.js_free(opaque, ptr-8)` → `system(opaque, ptr-8)`, see
`notes/regexp1827_arena_report.md` §5.6). Calling `dlopen(path, RTLD_NOW)` in
the Telegram process would need `rdi=path`, `rsi=1` — a different call shape
or a re-targeted function pointer. It is not implemented; if `app_process`
and `dalvikvm` are both blocked, this is the only no-root native-loader route
left. It would load the `.so` into the app process itself (same lifetime as
the app), not into a separate helper.

---

## 5. Process lifetime and the update

The helper is forked by the app's `system()`/shell and inherits the app
cgroup: `uid_10357/pid_<app_pid>` (`notes/local_ace_daemon.md` §4,
`lab/local_ace_daemon/analysis/cgroup_and_freezer.md:23-45`). Reparenting to
init (`PPID=1`), `setsid`, `nohup`, a new session or a closed stdio do not
change the cgroup. Therefore:

| event | helper |
|---|---|
| app Java crash / process death without cgroup kill | may survive (same cgroup, reparented) |
| `am force-stop` | killed (`Process.killProcessGroup` walks the app cgroup) |
| `adb install -r` / Play update | killed (the installer force-stops the package first) |
| reboot | killed |
| `adb uninstall` / clear data | killed; loader files deleted |

The loader files survive an update (same package/signer): `files/loader/`
stays, `cache4.db` and the widget message 79415 stay. The **process** does
not. This is the same conclusion as `notes/post_update_retrigger.md` and
`notes/local_ace_daemon.md` §5.3: no app-UID daemon survives the update
without an external trigger.

### 5.1 Re-running the loader after an update

1. **Widget chat (primary).** Message 79415 is in `cache4.db`; opening the
   chat re-binds the widget, runs #1827/#1865, and the payload's endgame calls
   `system()`. Set the endgame to
   `sh /data/user/0/<pkg>/files/loader/run_loader.sh 0 bg` with
   `c2/tools/patch_payload.py` (it only rewrites `var cmd="..."`); the widget
   then re-creates the helper itself. Without a user/automation opening the
   chat, this does not happen.
2. **Alarm → activity PendingIntent (autonomous, needs overlay).** The
   existing `lab/post_update_retrigger/helper/Retrigger.java` runs under
   `app_process` and schedules a Telegram-owned alarm. The alarm survives the
   update, but `AlarmManager` sets BAL=false; `ActivityStarter` only allows the
   activity start with `SYSTEM_ALERT_WINDOW` (or another exemption). With the
   overlay special access, the alarm opens the chat at 79415; the widget runs
   and re-creates the helper. Without overlay, it aborts
   (`notes/post_update_retrigger.md` §6.1, §8). Note that `Retrigger` is itself
   app_process-based: if T1 fails, this alarm path is unavailable too.
3. **Alarm → broadcast (process start only).** `AppStartReceiver` +
   `BOOT_COMPLETED` starts the app process, but does not render the widget, so
   it does not re-run the widget endgame. It is only useful for a
   *startup-stage* payload (the forged ART app image is not working:
   `notes/persistence_local_existing_rce.md` §7). Do not present it as a
   loader re-trigger.
4. **User-assisted.** A notification tap or the launcher opens the chat; the
   same as 1.

`Retrigger` and the loader can be the same dex (a `LoaderMain` that optionally
schedules the alarm), but keep the two mechanisms separate for the test: the
alarm is not what loads the `.so`; it only opens the chat/process that lets the
widget exploit run again.

---

## 6. Device test plan (summary)

Full commands, expected outputs and refutation criteria:
`lab/loader_app_process/device/test_plan.md`.

* **T0** — check UID/domain/context and the `ANDROID_*`/`BOOTCLASSPATH`
  environment from the app's own child shell; stage `loader.dex`,
  `libloader.so`, `exec_probe`, `run_loader.sh` under `files/loader/`.
* **T1** — `/system/bin/app_process` with no arguments as the app UID: printing
  `Error: no class name or --zygote supplied.` proves the `zygote_exec` exec;
  `CLASSPATH=.../am.jar app_process ... Am help` then proves ART starts. If
  `Permission denied`, capture the `avc` and stop; T7/T8 only.
* **T2** — run `exec_probe` from app data: must fail with `execute_no_trans`
  (negative control).
* **T3** — run the dex with a nonexistent `.so` path: the dex proof appears,
  the load fails with `UnsatisfiedLinkError`.
* **T4** — with the `.so` present: `lib_proof` (ctor) and `lib_proof.jni`
  (`JNI_OnLoad`) appear, same pid, UID 10357.
* **T5** — `hold=600`, then `pidof tgloader`, `/proc/<pid>/cgroup` =
  `uid_10357/pid_<app>`, `attr/current` = `untrusted_app`, `exe` =
  `app_process64`.
* **T6** — `am force-stop` and `adb install -r -d` of the same-key APK:
  helper gone, files and widget message intact; open the widget with the
  loader endgame → new ctor line with a new pid.
* **T7/T8** — `dalvikvm` fallback; in-process `dlopen` is not implemented.

Do not use `run-as` for T1/T2 (see §1.2). Keep app data; do not uninstall.

---

## 7. Confidence, open risks, refutation

**High confidence (AOSP android13-release):**

* `app_process` (`zygote_exec`) is executable by `appdomain` with
  `execute_no_trans`; it does not transition to `zygote` (app.te:204,
  global_macros:24-27, zygote.te:5, hooks.c:2364-2369);
* app-data `execve` is denied for targetSdk >= 29
  (app_neverallows.te:58-67, untrusted_app_all.te:27);
* app-data `dlopen` is allowed (untrusted_app_all.te:27) and `/data` is in
  every classloader namespace (library_namespaces.cpp:81,219;
  native_loader.cpp:259-279);
* `app_process` non-zygote runs `RuntimeInit` → `callMain`, needs
  `ANDROID_ART_ROOT`/`I18N_ROOT`/`TZDATA_ROOT`/`BOOTCLASSPATH`, and does not
  create `/data/dalvik-cache` (app_main.cpp:285-338, AndroidRuntime.cpp:1209-1245,
  parsed_options.cc:664-671);
* the helper is in the app cgroup and is killed by force-stop/update
  (`notes/local_ace_daemon.md` §4-5).

**Not device-proven yet (the plan closes these):**

* Sony's policy keeps `allow appdomain zygote_exec:file rx_file_perms`
  (T1);
* the app environment actually carries `ANDROID_ART_ROOT`/`BOOTCLASSPATH`
  (T0.1);
* the `untrusted_app` `System.load` of the app-data `.so` passes the linker
  namespace and SELinux on this ROM (T4);
* ART starts cleanly from `app_process` as UID 10357 with a CLASSPATH dex in
  app data (T3/T4; possible OEM/ART differences: hidden-API policy, profile
  writes, dex oat creation — all expected to be soft failures, but not
  measured);
* the update kill and the widget re-trigger (T6).

**What would refute the design:**

* T1 `avc: denied { execute_no_trans }` on `zygote_exec` → `app_process` is
  OEM-blocked; use T7 `dalvikvm`, or T8 only;
* T4 `is not accessible for the namespace "classloader-namespace"` → the
  `/data` allowance is not in effect; the `System.load` path is dead;
* T4 `avc: denied { execute }` on `app_data_file` → `dlopen` from app data is
  blocked; no native loader via this route;
* T2 `EXEC-PROBE-RAN` → app-data `execve` is allowed on this ROM; a plain
  helper ELF is simpler and the `app_process` machinery is unnecessary (but
  the rest of the design still works);
* T5 cgroup not `uid_10357/...` → the update-kill premise is wrong; redo the
  lifetime analysis before claiming anything;
* T6 helper survives force-stop/update → the cgroup analysis is wrong; record
  the actual cgroup and kill path.

**Cost/visibility.** `app_process` starts a full ART VM: tens of MB RSS, a
visible `tgloader` process, and ART/logcat noise. It is a lab/loader
mechanism, not a stealthy implant. The `Retrigger` and C2 tooling already
accept that visibility.

---

## 8. Files and evidence

| path | content |
|---|---|
| `lab/loader_app_process/src/org/telegram/loader/LoaderMain.java` | dex entry; `System.load`, proofs, optional hold |
| `lab/loader_app_process/src/libloader.c` | `.so` constructor + `JNI_OnLoad`, raw aarch64 syscalls, no `DT_NEEDED` |
| `lab/loader_app_process/src/exec_probe.c` | negative-control ELF (`execve` from app data) |
| `lab/loader_app_process/build.sh` | javac + d8 + clang (Android .so, host .so, qemu test) |
| `lab/loader_app_process/out/` | built `loader.dex`, `libloader.so`, `exec_probe`, host test binaries |
| `lab/loader_app_process/host/test_dlopen.c` | host `dlopen` harness |
| `lab/loader_app_process/host/test_run_loader.sh` | host test of the launcher shell glue (mock `app_process`) |
| `lab/loader_app_process/device/run_loader.sh` | app-UID launcher (background, env checks, logs) |
| `lab/loader_app_process/device/test_plan.md` | T0-T8 with exact commands and refutations |
| `lab/loader_app_process/evidence/aosp_excerpts.txt` | the cited AOSP/kernel excerpts |
| `lab/loader_app_process/evidence/host_tests.txt` | build, `readelf`, `dexdump`, host `dlopen`, qemu logs |

Host-side results (2026-11-02):

* `loader.dex` contains `Lorg/telegram/loader/LoaderMain;` with
  `main([Ljava/lang/String;)V` (dexdump);
* `libloader.so` is aarch64, no `DT_NEEDED`, `SONAME libloader.so`,
  `DT_INIT_ARRAY` present, 16 KiB LOAD alignment;
* host `dlopen` runs the constructor and `JNI_OnLoad` returns `0x00010006`,
  both proofs written;
* the same constructor built as a static aarch64 Linux binary runs under
  `qemu-aarch64`, proving the raw syscall numbers and the proof formatting;
* `exec_probe` is a static PIE with no interpreter and runs under
  `qemu-aarch64`;
* `device/run_loader.sh` passes 10/10 host checks with a mock `app_process`
  (argument order, `CLASSPATH`, background liveness, `BOOTCLASSPATH` and
  missing-file refusals).

The Android-specific steps (app_process exec, `System.load` from app data,
cgroup/update) are **not** measured in this pass; T1-T6 are the device gate.
