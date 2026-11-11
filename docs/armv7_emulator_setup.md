# armv7 emulator environment — working (2026-11-01)

Status: **working, benign only.** Phone 72799 app data loads on the emulator's
72789 app; chats, message 79415 (`<div id="t">restored</div>`) and the armv7
widget engine are verified on `emulator-5554`.

## Devices / versions

| | Phone | Emulator |
|---|---|---|
| Serial | `<SERIAL>` (XQ-BT52) | `emulator-5554` (`sdk_google_phone_armv7`) |
| Android | 13 | **7.1.1 / SDK 25** |
| ABI | arm64-v8a | **armeabi-v7a, armeabi** |
| Package | `org.telegram.messenger.beta` 13.2.0 (**72799**) | `org.telegram.messenger.beta` 13.2.0 (**72789**) |
| App UID | 10357 (`u0_a357`) | **10084 (`u0_a84`)** |
| Native lib | `lib/arm64-v8a/libtmessages.49.so` | `lib/armeabi-v7a/libtmessages.49.so` (installed as `lib/arm/`, see below) |

`/data/data` was copied from the phone at 2026-11-01 22:12 (live tar,
`tgdata.tgz` md5 `2deb53b23ee95d2c605dd555ed312e64`, 9,887,679 B). The phone was
not force-stopped; the app was still running at the end (pid 6503).

## Copy / deploy procedure used

1. Phone: `su -c 'tar -czf /sdcard/tgdata.tgz -C /data/data org.telegram.messenger.beta'`
   (whole dir incl. `files/cache4.db` + `-wal`/`-shm`); pulled, tar removed from
   `/sdcard` afterwards.
2. Host: extracted, `PRAGMA wal_checkpoint(TRUNCATE)` on the main DB (and the
   empty `files/account{1,2,3}/cache4.db` stubs), `PRAGMA integrity_check` = `ok`.
3. Emulator: `am force-stop`, wiped the old partial copy, pushed the snapshot,
   `chown -R 10084:10084`, dirs `771` / files `600` (top-level dir `700`),
   `restorecon -RF` → `u:object_r:app_data_file:s0:c512,c768`.
4. **`files/widget-sandbox` was excluded** from the deploy; the armv7 app
   re-extracted its own bundle from the APK on first launch
   (`eb66a43ba04d4a7d1ded44d8`, 1.8 MB, `.qbc` + JS) — confirmed present again.
5. `strace`-free live snapshot caveat: DB is checkpointed, `-wal`/`-shm` were
   not deployed; the app recreated a fresh WAL.

Message 79415 needed no patch: the phone snapshot already contained the benign
`<div id="t">restored</div>` (zlib 34 → 27 B, blob 129 B, media at offset 72).

## Verification

- **Account/chat loads:** cold start shows the full dialog list and the chat
  `User` (`users.uid <CHAT_ID>`, `users.name = "user"`, usernames
  `<TG_USERNAME>`), last message “Widget” 9:40 PM. 862 messages / 407 dialogs,
  `PRAGMA user_version = 181`, `integrity_check = ok`.
- **Benign widget renders:** the 79415 bubble paints `restored`
  (`evidence/.../widget_79415_restored.png`); surrounding widgets also render
  (`turi` `<b>turi</b>`, “Welcome to Turi's website”, Box Breathing, DOOM, World
  Clock) — `widgets_rendered.png`.
- **armv7 native lib mapped** (pid 8104):
  ```
  8a8c0000-8bdd0000 r-xp /data/app/org.telegram.messenger.beta-1/lib/arm/libtmessages.49.so
  8bdd3000-8be38000 r--p .../lib/arm/libtmessages.49.so
  8be3b000-8be99000 rw-p .../lib/arm/libtmessages.49.so
  ```
  Android 7.1 installs the APK's `lib/armeabi-v7a/libtmessages.49.so` into the
  `lib/arm` native dir; the file is identical
  (md5 `e950232092fba8452eddb36349bc25ef`, ELF32 ARM EABI5, BuildID
  `406a1befe8f723798888235a759969174c13f95e`, NDK r27c, minSdk 23).
- **widget sandbox engine runs:** threads `widget.sandbox` (4–7),
  `widget.validato` (4–7), `widget-control` (4–7), `widget-sandbox-io`;
  `WidgetSandboxBackend.signal/canvas` native calls in logcat;
  per-message `widget height … on screen, loaded, 50 (cache) -> 58 (frame)`
  for 79415 and `… 50 -> 278` for 79449.

## Anomalies / caveats

- **First-render race (fixed):** on the very first launch after the data copy,
  79415's bubble painted blank while the sandbox bundle was still being
  extracted (12 s `AssetManager.openAsset` contention). Other widgets loaded.
  After a cold restart (bundle already extracted) 79415 renders correctly.
  No corruption — DB unchanged (same md5 at rest: `666d23222bfd40986909f01cd711c0be`).
- **One ANR** during rapid scrolling in that first session (slow ARM emulation,
  not a crash); dismissed with “Wait”, app continued.
- Non-fatal `ClassNotFoundException: android.graphics.ImageDecoder$OnHeaderDecodedListener`
  (API 28 class referenced under guard on Android 7.1) — caught, harmless.
- No FATAL/`AndroidRuntime` crash, no DB migration error, no missing data
  between 72799 and 72789.
- Emulator is offline (airplane mode on, `wlan0` down). The account and chats
  load purely from the copied DB; no server contact and no new login/session
  side effects on the phone.
- Phone state: only read (safe live tar); the temp tar was deleted. Phone
  cache4.db was compacted by Telegram itself (4.3 MB at 22:20) — no action taken.

## Evidence

`evidence/evidence_20261101/armv7_emulator/`

| File | Content |
|---|---|
| `chatlist_loaded.png` | cold start, dialogs from copied DB |
| `widget_79415_restored.png` | 79415 “restored” rendered in chat <TG_USERNAME> |
| `widgets_rendered.png` | `turi`, “Welcome to Turi's website” widgets |
| `maps_libtmessages.txt` | `/proc/<pid>/maps` lines for libtmessages.49.so |
| `threads.txt` | thread-name census (`widget.sandbox`, `widget.validato`, …) |
| `logcat_widget.txt` | widget payload/height/sandbox log lines |
| `db_info.txt` | device/version, DB path+md5, row counts, integrity, 79415 dump |

## Repro (short)

```bash
# phone snapshot
adb -s <SERIAL> shell "su -c 'tar -czf /sdcard/tgdata.tgz -C /data/data org.telegram.messenger.beta'"
adb -s <SERIAL> pull /sdcard/tgdata.tgz .
# host: extract, sqlite3 cache4.db 'PRAGMA wal_checkpoint(TRUNCATE);'
# emulator: force-stop, replace /data/data/<pkg>, chown 10084:10084,
#           chmod 700 top / 771 dirs / 600 files, restorecon -RF,
#           delete files/widget-sandbox
adb -s emulator-5554 shell am start -n org.telegram.messenger.beta/org.telegram.ui.LaunchActivity
# wait for cold start, open chat <CHAT_ID>, allow storage if prompted
```
