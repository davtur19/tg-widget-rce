# App update vs an app-UID `setsid` daemon — Android 13 (72799)

Scope: `org.telegram.messenger.beta` 13.2.0 (72799), Sony XQ-BT52, Android 13,
UID 10357.  The daemon is a process started by the #1827/#1865 widget RCE via
`Runtime.exec`/`system()` as the app UID, detached with `setsid` (optionally
`nohup`, double-fork, stdio to `/dev/null`).

Question: can that daemon survive `pm install -r` / a package replace?

**Verdict: no, not genuinely.**  The update path kills every live
`ProcessRecord` of the package and then kills the **process cgroup** of each
one.  A `setsid` child of the app lives in that same cgroup: `setsid` changes
the session and pgid, not cgroup membership.  The update kill is the same
process kill as `am force-stop`; the difference is only what happens to the
package afterwards (stopped state, alarms/jobs, broadcasts).  Apart from an
escape from the cgroup or a device where the cgroup kill is a no-op, the only
branch in which an update leaves the daemon alive is when the daemon is no
longer in the cgroup of **any live `ProcessRecord`** at update time (its
owning app process is gone, or a restarted service is in a new cgroup) — and
that requires the daemon to have already survived the death of the process
that owned its cgroup, which is itself a cgroup kill
(`ActivityManagerService.appDiedLocked` → `ProcessList.killProcessGroup`), i.e.
a narrow fork-vs-`cgroup.procs`-read race or a cgroup escape that an app UID
does not have.

Two honesty notes up front:

1. The source chain is AOSP 13 and is complete; the device-specific premise —
   that the Sony actually mounts the `cgroup2` controller and the daemon is in
   `uid_10357/pid_<app>` — is **not yet directly captured**.  The test plan in
   `lab/update_daemon_survival/` starts by proving exactly that.  If the
   premise fails, the AOSP `killProcessGroup` call is a no-op and the
   mechanism needs a different explanation.
2. The prior observation "the app-UID watcher died on `am force-stop`" is real,
   but it did not record whether a `ProcessRecord` existed at that moment or
   which cgroup the watcher was in.  It is consistent with the cgroup model
   but is not, by itself, proof of it.  The new plan closes that gap.

---

## 1. What `pm install -r` does — the exact chain

Source files and line numbers: `lab/update_daemon_survival/SOURCE_REFS.md`.
Summary:

```
pm install / adb install / in-app PackageInstaller
  → PackageInstallerSession
  → InstallPackageHelper.installPackageLI
      InstallPackageHelper.java:1515  freezePackageForInstall(pkg, flags, "installPackageLI")
      InstallPackageHelper.java:1881  if INSTALL_DONT_KILL_APP → stub; else freezePackage()
  → PackageManagerService.freezePackage
  → new PackageFreezer(...)
      PackageFreezer.java:65          mPm.killApplication(pkg, appId, userId, killReason)
  → PackageManagerService.killApplication
      PackageManagerService.java:2940 IActivityManager.killApplication(...)
  → ActivityManagerService.killApplication
      ActivityManagerService.java:4073 post KILL_APPLICATION_MSG
  → ActivityManagerService:1748      forceStopPackageLocked(pkg, appId,
                                         callerWillRestart=false, purgeCache=false,
                                         doit=true, evenPersistent=false,
                                         uninstalling=false, userId, reason)
  → ProcessList.killPackageProcessesLSP (ActivityManagerService.java:4492)
      ProcessList.java:2702           iterate mProcessNames (ProcessRecords only)
      ProcessList.java:2853           app.killLocked(...)
  → ProcessRecord.killLocked
      ProcessRecord.java:1087         Process.killProcessQuiet(mPid)
      ProcessRecord.java:1088         ProcessList.killProcessGroup(uid, mPid)
  → ProcessList.KillHandler → Process.killProcessGroup (JNI)
  → libprocessgroup: killProcessGroup(uid, pid, SIGKILL)
      processgroup.cpp:346            open .../uid_<uid>/pid_<pid>/cgroup.procs
      processgroup.cpp:380-409        kill every pid/pgid listed in that cgroup
```

The kill reason passed through is `"installPackageLI"`.  On the Sony this is
visible as:

```
11-01 19:05:04.042  1728  2025 I am_kill : [0,6157,org.telegram.messenger.beta,0,
    stop org.telegram.messenger.beta due to installPackageLI]
```

(`evidence/evidence_20261101/new_beta_72799/nb_v2_run10.log:11990`, an in-app
APK update at 19:05:04 on 2026-11-01).  That is device proof that the update
path kills a running 72799 process; it is not yet proof that a child in the
same cgroup is included, but that follows from the native code below.  The
freezer also adds the package to `mFrozenPackages` before the kill
(`PackageFreezer.java:59-63`), so the app cannot be restarted while the install
is in progress.

### 1.1 Why the daemon is included

`Runtime.exec` / `system()` forks a child of the app process.  The child
inherits the app's cgroup (`uid_<uid>/pid_<app_pid>`), and `setsid` does not
change cgroups — it only creates a new session/process group.  The
`libprocessgroup` kill does not depend on the POSIX process group: it reads
**every pid in the cgroup** (`cgroup.procs`), computes each pid's pgid, and
kills both the pgids and the remaining pids:

```cpp
// system/core/libprocessgroup/processgroup.cpp:346-409 (compressed)
auto path = ConvertUidPidToPath(cgroup, uid, initialPid) + "/cgroup.procs";
...
pid_t pgid = getpgid(pid);
if (pgid == pid) pgids.emplace(pid); else pids.emplace(pid);
...
for (const auto pgid : pgids) kill(-pgid, signal);
for (const auto pid : pids)   kill(pid, signal);
```

Despite its name, `Process.killProcessGroup` is a **cgroup** kill, not a POSIX
`kill(-pgid)`; the pgid grouping is only an optimization inside the cgroup
read.  A process that leaves the pgid but stays in the cgroup is still killed.

So all of these are irrelevant to survival:

| Technique | Effect on the app cgroup | Survives `killProcessGroup`? |
|---|---|---|
| `setsid` | none (new session/pgid only) | no |
| `nohup` | ignores SIGHUP; not sent anyway | no |
| double-fork | reparents to init; cgroup unchanged | no |
| `</dev/null >/dev/null 2>&1` | closes stdio; no cgroup change | no |
| `chdir`, `umask`, `setpgid` | none | no |
| write `/sys/fs/cgroup/.../cgroup.procs` | would move it | **not permitted to the app UID** |

(`Process.setProcessGroup` in the Android API is the scheduler group —
`SP_FOREGROUND` etc. — not a cgroup; it does not move the process either.)

The cgroup directories are created by `createProcessGroupInternal` and are
owned by system (`processgroup.cpp:500-540`); an `untrusted_app` cannot write
`cgroup.procs`.  An unprivileged cgroup namespace does not change membership,
and `CLONE_INTO_CGROUP` requires a writable cgroup fd, which the app UID does
not have.

### 1.2 `killUid` and `killall` are not shortcuts around this

* The install path never calls `killUid`; it calls `killApplication` (above).
* `ActivityManagerService.killUid` (used by permission changes) calls
  `killPackageProcessesLSP(null, appId, userId, ...)` — again a walk of
  `mProcessNames`, not a `/proc` scan (`ActivityManagerService.java:7720-7735`).
  It kills the cgroups of live ProcessRecords of that appId; an orphaned child
  is not reached by a UID scan.
* `killall` is not used by the update path.  `am kill-all` /
  `killAllBackgroundProcesses` also walk ProcessRecords.

So if the app has a live process, its cgroup is killed regardless of
`setsid`.  If it has none, the update does not scan `/proc` for the UID and
does not kill an orphan by UID either.

---

## 2. `pm install -r` vs `am force-stop`

Both go through `forceStopPackageLocked` and the same
`killPackageProcessesLSP`; the process/daemon kill is identical.  The
differences are post-kill:

| | `pm install -r` | `am force-stop` |
|---|---|---|
| kill process + cgroup | yes | yes |
| set package stopped state | **no** | **yes** (`ActivityManagerService.java:4015`) |
| `ACTION_PACKAGE_RESTARTED` | no | yes |
| alarms | preserved (exact-alarm permission recheck on `PACKAGE_ADDED`) | removed |
| jobs | preserved | cancelled |
| `PACKAGE_REPLACED` / `MY_PACKAGE_REPLACED` | yes | no |
| app can auto-restart later | yes (user launch, later broadcast, alarm/job) | no, until user launch |

Consequences for the daemon:

* The update does not need the stopped state to kill the daemon; it kills the
  cgroup through `killApplication`.
* `MY_PACKAGE_REPLACED` cannot revive the daemon.  At most it starts the app
  again (a new process, a new cgroup).  Telegram 72799 has no
  `PACKAGE_REPLACED`/`MY_PACKAGE_REPLACED` receiver (`aapt dump xmltree
  base72799.apk AndroidManifest.xml`: `AppStartReceiver` handles
  `org.telegram.start` and `BOOT_COMPLETED` only), so the update does not start
  the app by itself.
* Alarms and jobs also only start the app; they do not re-create the daemon.

`pm install -r --dont-kill` is **not** an escape for a base APK:
`PackageInstallerSession` clears `INSTALL_DONT_KILL_APP` when a base APK is
installed (`PackageInstallerSession.java:2840-2844`, `2887-2891`, comment
"Installing base.apk. Make sure the app is restarted").  The flag is for
feature splits only.

### 2.1 Common misconceptions

| Belief | Reality |
|---|---|
| "`setsid` detaches the daemon from the app, so the update cannot see it." | `setsid` changes session/pgid only.  The update kills the app's **cgroup**, which still contains the daemon. |
| "The daemon is not a `ProcessRecord`, so `killPackageProcesses` ignores it." | True — but the app's `ProcessRecord.killLocked` calls `Process.killProcessGroup` on the app's cgroup, which includes every child in it. |
| "An update is gentler than force-stop." | The process kill is the same `forceStopPackageLocked` core; only the post-kill package state, alarms/jobs and broadcasts differ. |
| "`MY_PACKAGE_REPLACED` restarts the daemon." | It can start the **app** (a new process, new cgroup).  It does not re-run the old child, and 72799 has no receiver for it. |
| "`--dont-kill` protects a base-APK update." | The session clears the flag when a base APK is installed; it only helps feature splits. |

---

## 3. The daemon's actual cgroup (the only thing that matters)

Android 13 places each zygote-forked app process in
`/sys/fs/cgroup/uid_<uid>/pid_<pid>` (cgroup v2; v1 controllers carry the same
`uid_*/pid_*` suffix).  `Runtime.exec` children are plain forks: same cgroup.
`setsid` does not move them.

Therefore a daemon is reachable by the `Process.killProcessGroup(uid, app_pid)`
call targeted at the app's `ProcessRecord` for as long as the daemon remains in
`uid_<uid>/pid_<app_pid>` — whether the app process is still alive or the call
comes from `appDiedLocked` after it died.  The kernel-side kill covers every
pid in that `cgroup.procs`, including the daemon.

The only ways out are:

1. **Move the process to another cgroup** (or create a child cgroup under the
   app's `pid_` dir and move it there) — both require write access to a
   cgroup directory/`cgroup.procs` file; the app UID does not have it on stock
   Android, and SELinux denies it too.
2. **Be forked by a process that is not in the app cgroup** — e.g. an `adb
   shell`/root process, or a second app UID.  That is not "a process started
   by the app-UID exploit".
3. **Win the fork race**: `killProcessGroup` reads `cgroup.procs`, kills the
   listed pids, and repeats while `processes > 0` (40 retries, 5 ms apart).  A
   fork that lands after the last read that returns 0 survives, and the
   subsequent `rmdir` fails with `EBUSY`; the group is left with the new child.
   This is a microsecond-to-millisecond race, not a stable property, and it
   applies to any app death, not specifically to updates.

The device plan measures escape (1) directly: `hb.sh` makes one attempt to
write its pid to `uid_<uid>/cgroup.procs` and logs `CGROUP_MOVE_OK` or
`CGROUP_MOVE_DENIED`; the T0 `cg` vs `appcg` comparison catches a move even if
the log cannot be read.

The prior "reverse shell survived the app crash" observation is consistent
with (3) — or with the daemon being in a different cgroup — but not with a
guarantee.  `ActivityManagerService.appDiedLocked` calls
`ProcessList.killProcessGroup` for an unexpected death too
(`ActivityManagerService.java:3312-3319`), and a controlled `kill -9` test in
this project killed the detached C2 (`REPORT_20261102.md` §5).  So "survives
an app crash" is a race, not a property.

---

## 4. Device evidence on the Sony — what is and is not proven

The analysis above is AOSP 13; the Sony ships a vendor build, so the
`libprocessgroup`/`cgroup.rc` capture is part of the proof, not an optional
extra.

**Proven on the device:**

* The update path kills the running 72799 app with reason `installPackageLI`:
  `am_kill : [0,6157,...,stop ... due to installPackageLI]`
  (`nb_v2_run10.log:11990`, 2026-11-01 19:05:04).
* `libprocessgroup` runs its process-cgroup kill path on this phone:
  `Successfully killed process cgroup uid 10357 pid 31275 in 0ms`
  (`.../sony_sweep/runs/b5_idle60/logcat.txt:1777`) and many sibling lines.
  Caveat: that log line is printed when the loop ends with `processes == 0`.
  The elapsed time is diagnostic: a **non-empty** cgroup is killed, slept on
  for 5 ms and re-read, so a non-empty cgroup logs `in 5ms` or more; `in 0ms`
  means the first `cgroup.procs` read was already empty.  The app itself can
  be the member, so the time is a weak signal, but `in 0ms` rules out the
  daemon being in that cgroup at the kill.  The line alone does not prove the
  `cgroup2` controller exists; the M0/T0 steps in the test plan check
  `/dev/cgroup_info/cgroup.rc` and `/proc/<pid>/cgroup` directly.
* An app-UID `setsid` watcher (UID 10357) stopped and its PIDs disappeared
  during `am force-stop`, while the root run of the same script survived
  (`evidence/evidence_20261101/persistence/`).  This is consistent with a
  cgroup kill, but the run did not record whether a `ProcessRecord` existed or
  the watcher's cgroup at that moment; the watcher logged `app=none`, which
  could mean no app process or a transient `pidof` failure during the crash.
  The new plan records `/proc/<pid>/cgroup` and `dumpsys activity processes`
  at that moment.

**Not yet proven on the device:**

* that the daemon's `/proc/<pid>/cgroup` equals the app's
  `uid_10357/pid_<app_pid>`;
* that `cgroup2` is mounted and the `cgroup.procs` kill covers the daemon;
* that a single `adb install -r` run kills the daemon (the 19:05 log shows the
  app kill, not a daemon in the same run).

Those are exactly the three things the device plan measures.  Until they are
measured, the source-level verdict is strong but the device-level mechanism is
"expected, not yet instrumented".

---

## 5. The branch where an update does not kill the daemon: an orphaned cgroup

If the daemon is no longer in the cgroup of any live `ProcessRecord` when
`pm install -r` runs, the update cannot reach it:

* `killApplication` still posts `KILL_APPLICATION_MSG`;
* `forceStopPackageLocked` → `killPackageProcessesLSP` iterates
  `mProcessNames`; if there is no ProcessRecord for the package at all it
  finds nothing and returns `N == 0`; if the app has restarted in a **new**
  process/cgroup, it kills that new process, but the daemon is in the old
  cgroup, which is not targeted;
* `killAppZygotesLocked` finds no app zygote;
* no `Process.killProcessGroup` is called for the daemon's cgroup.

This is the branch the task asks about, but note what it requires: the daemon
must have **already** outlived the process that owned its cgroup, and that
process's death runs the same cgroup kill (`appDiedLocked`).  Getting there
needs the race in §3(3) or a cgroup escape that an app UID does not have.  It
is not "the update preserved the daemon"; it is "the update had nothing to
kill in the daemon's cgroup because the daemon had already detached from a
dead process".  A sticky service restarting the app in a new cgroup does not
change this: the new process is killed, the orphan is not.

A corollary worth testing: with the daemon in an orphaned cgroup, AOSP 13
`am force-stop` also walks the current ProcessRecords only, so it should
**not** kill the orphan either.  If the Sony does kill it in that state, there
is a vendor/UID-wide mechanism outside AOSP 13, and the mechanism section must
be revised.  The prior watcher had `app=none` at force-stop time, so this is a
real open question, not a formality.

---

## 6. What an update actually kills — checklist

Killed by `pm install -r` (with the app running):

- every live `ProcessRecord` of the package (and of the same appId with the
  package in its `pkgList`), including the main process;
- the **process cgroup** of each such process, i.e. all descendants that did
  not leave the cgroup: `setsid`, `nohup`, double-fork, reparented-to-init
  children, `sh`/`nc` pipelines, the C2 supervisor and its workers;
- the app's activities/tasks (the force-stop core removes the task), and the
  process's pending broadcasts/providers cleanup.

Not killed:

- app data (`files/`, `shared_prefs/`, databases); the update keeps them;
- alarms (except exact alarms if the permission is lost on update);
- jobs (cancelled only on full removal or force-stop);
- a process in a different cgroup/UID (second app, root, init service);
- a daemon whose cgroup is no longer owned by a live ProcessRecord (its app
  process is gone, or the app restarted in a new cgroup) — the update simply
  does not reach it.

Not achieved by the update:

- restarting the daemon: `PACKAGE_REPLACED`/`MY_PACKAGE_REPLACED` can start
  the **app**, not the old child; the app has no `MY_PACKAGE_REPLACED`
  receiver in 72799;
- restoring the daemon after a reboot; reboot kills every process.

---

## 7. Device test plan (summary)

Full commands, expected outcomes and the interpretation matrix:
`lab/update_daemon_survival/device_testplan.md`.  Files:

* `hb.sh` — heartbeat daemon; each beat carries `uid`, `pid`, `ppid`, `app`,
  `appcg`, `sidpg`, `cg`; writes `files/.hb.log` and sends the line to the host.
* `hb_listener.py` — timestamped TCP listener (`CONNECT`/`HB`/`CLOSE`), keep it
  running across the install.
* `deploy_cmd.sh` — prints the exact `system()` string (base64 of `hb.sh`, no
  single quotes, so it fits the payload's JS literal).
* `capture.sh` — records `/dev/cgroup_info/cgroup.rc`, mountinfo,
  `/proc/<app>/cgroup`, `ps`, `dumpsys package`.
* `SOURCE_REFS.md` — the AOSP citations.

Cases:

| Case | Action | Expected |
|---|---|---|
| M0 | `cgroup.rc`, mountinfo, app `/proc/<pid>/cgroup` | `cgroup2` present; `uid_10357/pid_<app>` |
| T0 | start daemon; compare `cg` and `appcg`; `sidpg` | same cgroup; pgid/sid changed by `setsid` |
| T1 | app alive, `adb install -r <pulled apk>` | daemon dies; `am_kill ... installPackageLI`; `Successfully killed process cgroup uid 10357 pid <app>`; HB stops |
| T2 | `am force-stop` | daemon dies the same way; `stopped=true`; alarms/jobs cancelled |
| T3 | `pm install -r --dont-kill` on the base APK | still kills (session clears the flag for base APKs) |
| T4 | daemon in an orphaned cgroup (old app pid), then `adb install -r` | update does not kill the orphan (it may kill a restarted app process in a new cgroup); this is the race branch, not update survival |
| T5 | `pm clear` (destructive) | daemon and its files gone |
| T6 | reboot | daemon gone; nothing restarts it |

The plan's interpretation matrix distinguishes "daemon died with the app" from
"daemon died because of the update" and from "daemon was never in the app
cgroup".  Do not collapse them.

---

## 8. What would change the verdict

* M0 fails (no `cgroup2`): the AOSP `Process.killProcessGroup` call is a no-op
  on the device.  The update then kills only the app process, and a `setsid`
  child may survive the update.  It would also be expected to survive
  `am force-stop` unless the vendor force-stop adds a UID-wide kill; the T2
  control distinguishes those two.  In either case the real killer (if any)
  must be identified (vendor code, a different cgroup path, or a process-group
  kill).
* T0 shows `cg != appcg`: the daemon left the app cgroup.  That is the only
  genuine escape; find the mechanism (cgroup write or privileged move).  If it
  is reproducible without root, the verdict changes for that mechanism, not
  for plain `setsid`.
* T1 shows the app killed, the daemon alive, and no
  `Successfully killed process cgroup` line: the cgroup kill did not reach it.
  Capture the daemon cgroup and full log; this is a direct refutation.
* T4 shows `am force-stop` killing a daemon in an orphaned cgroup: AOSP 13's
  ProcessRecord-only model is incomplete on this build; document the
  vendor/UID-wide mechanism.

Until one of those is observed, the correct statement is: **the update is
designed to kill the app's process cgroup and there is no app-UID escape from
it; a `setsid` daemon is not update-surviving, and its only observed
cross-death survival is the app-death fork race.**

Implication for persistence: the daemon is a session extender while the app is
alive (useful for a C2 during a session) or, at best, a race-based orphan.  It
is not an update/reboot persistence layer.  Durable persistence has to come
from code that re-runs on app start (the bundle hook / native loader path in
`REPORT_20261102.md` §6), not from the process.

---

## 9. Relationship to the main report

`REPORT_20261102.md` §6 already says the detached supervisor "stays in the
Telegram UID cgroup" and that "`am force-stop`, recents/`am kill` when actually
killed, package update and reboot reach `Process.killProcessGroup`, so the
supervisor dies; crash survival is the `appDiedLocked`/ENOENT race."  This note
supplies the source-level call chain and the device plan behind that sentence,
and refines two points:

* the kill is per-`ProcessRecord` cgroup, not a `/proc` UID sweep; with no live
  ProcessRecord, AOSP 13 force-stop/update has nothing to kill;
* `--dont-kill` does not protect a base-APK update (the session clears it);
  only a feature-split install can use it.

No change to the main report is made here.

---

## 10. Artifacts

* `lab/update_daemon_survival/README.md` — index and quick start.
* `lab/update_daemon_survival/SOURCE_REFS.md` — AOSP file:line citations.
* `lab/update_daemon_survival/device_testplan.md` — full device plan.
* `lab/update_daemon_survival/hb.sh`, `hb_listener.py`, `deploy_cmd.sh`,
  `capture.sh`.
* Device evidence referenced above:
  `evidence/evidence_20261101/new_beta_72799/nb_v2_run10.log`,
  `lab/qjs_postsnapshot/loaders/size_variants/sony_sweep/runs/b5_idle60/logcat.txt`,
  `evidence/evidence_20261101/persistence/`.
