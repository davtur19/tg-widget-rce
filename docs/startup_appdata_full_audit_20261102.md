# Startup app-data persistence: full launch-read audit, the S2 correction, and the cached-avatar libwebp candidate

Date: 2026-11-02
Target: `org.telegram.messenger.beta` 13.2.0 beta, versionCode **72799**, arm64,
Sony **XQ-BT52** (Xperia 10 III), Android 13, build **62.2.A.0.533**, UID 10357.
Scope: **host/static only**; the phone was not touched. The widget bundle / QuickJS
re-arm is excluded by instruction.

Artifacts added by this note:

* `notes/poc/make_s2_group_poc.py` — GROUP BY variant of the `params`-view PoC
  (the previous no-GROUP-BY PoC did not actually read `iMem`; see §2).
* `notes/poc/find_avatar_cache.py` — parses a real `cache4.db` and prints the
  startup-visible dialogs and their small-avatar cache file names.
* `notes/poc/webp/{oob,bad,poc}.webp` + the ASan logs — copied public
  CVE-2023-4863 triggers, with attribution in `notes/poc/webp/README.md`.
* Host traces: `notes/poc/webp/s2_groupby_*`, `oob_asan_libwebp124.txt`,
  `bad_asan_libwebp{124,131}.txt`.

The main report (`telegramandroidwidget/REPORT_20261102.md`) is **not** modified.

---

## 0. Verdict (honest)

1. **The previous S2 description is wrong in an important detail.** The no-GROUP-BY
   `params` view never dereferences the out-of-bounds `AggInfo_col`: the 32,769
   negative `iAgg` values are only used for pointer arithmetic while
   `directMode == 1`. `pCol->iMem` is read only when `directMode == 0`. I
   instrumented the exact 3.39.3 code and the exact startup query:
   `TRACE IMEM` count = **0**, `TRACE PERSIST` count = **0**, query `exec ok`.
   The previous "32,769 wild iMem reads" were `iAgg` prints, not `iMem` reads.
2. **The reachable S2 fault is a different one.** With a `GROUP BY` in the view,
   `useSortingIdx` is set and the `directMode == 1` branch does
   `pTab->aCol[pCol->iColumn]` on the OOB `pCol`. On a real 72799 DB copy this
   is a host **SIGSEGV at `sqlite3.c:107738`** (OOB `Table*` read). It is a
   launch crash/DoS, **not a write** and not code execution. The only write
   site, `agginfoPersistExprCb`, requires the OOB `pCExpr` to equal the current
   `Expr*` (an 8-byte pointer equality) and writes a duplicate Expr pointer; it
   was not reached, and app data cannot supply the pointer equality.
3. **Native-lib fallback remains the only by-design app-data code loader, and
   it is root-gated.** `NativeLoader.initNativeLibs` tries
   `System.loadLibrary("tmessages.49")` first; on the phone the logcat says
   `loaded normal lib`. `files/lib/libtmessages.49loc.so` is loaded only in the
   `catch (Error)` block. The prior root-assisted proof (move the APK lib,
   place a `.so` in `files/lib`, app loads it) is real but not no-root.
4. **No Dex/exec/WebView-at-startup path was found.** No `DexClassLoader` /
   `InMemoryDexClassLoader` / `loadDex` in 72799; `Runtime.exec` only for
   `/system/bin/netcfg` with a hard-coded argument; WebView file access is off
   and no startup WebView load exists.
5. **`shared_prefs` + the update flow is user-gated.** The `beta` prefs carry an
   update APK `path`/`versionCode`; `BlockingUpdateView` shows a blocking update
   screen and `ACTION_VIEW` starts the system installer. A crafted
   `pendingAppUpdate` TL blob is deserialized at startup and can force the
   blocking screen, but the install still requires a user tap.
6. **Top remaining code-exec candidate: CVE-2023-4863 through a cached avatar
   decoded at chat-list startup.** XQ-BT52 build `62.2.A.0.533` is the
   **July 1, 2023** security patch (Sony's own Xperia 10 III page), before the
   September/October 2023 libwebp fix. The app decodes the avatar with
   `BitmapFactory` (system Skia/libwebp), no app-native decoder. `oob.webp`
   gives a **216-byte OOB write** past a 12,072-byte libwebp Huffman table on
   host libwebp 1.2.4/1.3.1 (ASan); the primitive is documented by DARKNAVY as
   partially-controlled 4-byte writes at offsets that are multiples of 8, and
   a public full Chromium exploit exists. **But no Android/Scudo full exploit
   was built or found; a device crash is a launch DoS, not code execution.**
   The exact device test is in §6.
7. **Secondary persistent C2 without code exec:** `files/tgnet.dat` /
   `dc<id>conf.dat` redirection. The app connects to an attacker-chosen
   `ip:port` with a known auth key at every start (prior note §6.2). This keeps
   an app-initiated C2 channel across restarts/reboot but executes no code; it
   needs a content bug (e.g., the WebP path) to become code execution.

Bottom line: **no proven no-root startup code-exec persistence was found in the
app's own parsers.** The strongest concrete lead is the known, actively
exploited libwebp CVE, reachable at chat-list startup from one app-data cache
file; the missing piece is the Android-specific weaponization, not reachability.
The S2 claim is corrected to a crash/DoS.

Version caveat: the only decompiled APK in the workspace is **72789**
(`.scratch_beta1320/jadx_out`); the 72799 binary is
`/tmp/opencode/tg49_72799.so` (27,016,000 B, md5
`2c0caa68a07fc26f79d13519af6c3526`), and the device evidence is 72799. Code
references below are from the 72789 jadx unless marked; the DB schema,
`user_version=181`, `params` startup SELECT, native loader and image paths are
confirmed for 72799 by the binary/logcat/DB.

---

## 1. Exact launch reads (or first-UI reads with no user action)

The table is the answer to the "enumerate every file" request. "App-writable"
means UID 10357 can write it; "Automatic" means the app reads it on a cold
start / first chat-list render without a tap. "Sink" is what the bytes reach.

| # | File / pattern | When | Parser | App-writable | Automatic | Sink / verdict |
|---|---|---|---|---|---|---|
| 1 | `files/cache4.db`, `files/account{1..N}/cache4.db` (+`-wal`,`-shm`) | startup, before UI (`hs.java:2219-2241`) | SQLite **3.39.3** (stock amalgamation, `jni/sqlite/sqlite3.c`, md5 `4039d3d3…`) | yes | yes | schema SQL + `params` SELECT; S1 stack overflow, S2 OOB read/crash (§2); no code exec |
| 2 | `files/file_to_path.db`, `file_to_path_backup.db` | ~1 s after start | SQLite 3.39.3 (`FilePathDatabase.java:35-124,165-231`) | yes | yes | views on `paths` are compiled by `SELECT path FROM paths WHERE document_id=…`; path injection for a document id; DoS; no code exec |
| 3 | `files/tgnet.dat`, `files/dc<id>conf.dat`, `files/accountN/tgnet.dat` | startup network init | native `tgnet` (`Config.cpp`, `Datacenter.cpp`) | yes | yes | DC address + auth key; persistent traffic redirection / server impersonation (C2), short-auth-key OOB read; no code exec |
| 4 | `files/remote_<code>.xml`, `files/malformed_locales/*` | startup language init | framework `Xml.newPullParser` (`cd.java:1525`) | yes | yes | strings → `String.format`; width OOM (DoS); `langconfig` descriptor `d` is an arbitrary path read; no code exec |
| 5 | `files/*.attheme`, `files/<theme>_*.jpg`, theme wallpapers | startup / selected-theme load | Java `t6.T0` + platform `BitmapFactory` (`t6.n1`, `o6.b`) | yes | yes for selected theme | colors/keys in Java; wallpaper reaches system Skia/libwebp; theme path traversal at most; no app-native code exec |
| 6 | `shared_prefs/*.xml` (`mainconfig`, `userconfing`, `beta`, `langconfig`, `systemConfig`, `Notifications`, `background_activity`, …) | startup | Android `SharedPreferencesImpl` / framework XML | yes | yes | selects theme/language/cache dir/proxy/passcode; `beta` update path + `pendingAppUpdate` TL blob (Java `TLRPC.help_AppUpdate.TLdeserialize`, `SharedConfig.java:559-590`); update install is user-gated; OOM/DoS only |
| 7 | `files/PersistedInstallation*.json`, `files/.com.google.firebase…json` | startup | Firebase SDK / `JSONObject` | yes | yes | Java JSON; no native sink found |
| 8 | `files/lib/libtmessages.49loc.so` | startup, **only if** `System.loadLibrary` throws | `NativeLoader.initNativeLibs` → `System.load(path)` | yes | conditional | **real code execution** (app-data `.so`), but only after the primary APK lib load fails; root-gated on this install |
| 9 | avatar/photo cache: `<cacheDir>/<volume_id>_<local_id>.jpg`, `files/Telegram/Telegram Images/…` | first chat-list render, no tap | platform `BitmapFactory.decodeFile` / `decodeStream` (`ImageLoader.CacheOutTask`) | yes | **yes** (visible dialogs) | system Skia/libwebp/libjpeg/libpng/libgif/libheif; **CVE-2023-4863** candidate (§6) |
| 10 | `files/Telegram/Telegram Images`, `Telegram Video`, `Telegram Audio`, `Telegram Documents`, `Telegram Stories` | render/playback | FFmpeg 8.1.3 / libvpx 1.17.0 / dav1d 1.5.4 / opus 1.6.1 / tlottie (Rust) | yes | only when the media is rendered/played | current versions; known reachable bugs are DoS; no known RCE; chat-list itself shows static thumbs only |
| 11 | `files/voip_persistent_state.json`, `cache/voip_logs`, `cache/logs`, `files/logs` | VoIP/startup logging | JSON/text | yes | partially | data only; no code loader |
| 12 | `cache/` WebView / ExoPlayer caches | only when WebView/player is opened | Chromium/ExoPlayer | yes | no | not read on cold start; WebView is not started at launch |
| 13 | `files/datastore`, `files/recover*` | — | — | — | — | no separate parser with these names in the 72799 source/jadx; the actual DB/config files are rows 1–3. If a future version adds one, it must be re-audited. |
| 14 | APK `assets/`, `lib/arm64-v8a/libtmessages.49.so` | startup | loader / assets | no | yes | trusted APK, not app data |

Notes:
- The app opens `cache4.db` with `sqlite3_open` (read-write-create) via
  `SqliteWrapper.cpp`, runs `PRAGMA secure_delete/temp_store/journal_mode/
  journal_size_limit`, `PRAGMA user_version`, then
  `SELECT seq, pts, date, qts, lsv, sg, pbytes FROM params WHERE id = 1`
  (`hs.java:2226-2241`). `params` is `CREATE TABLE IF NOT EXISTS` only in the
  new-DB branch, so an existing DB with `user_version=181` accepts a
  `VIEW params` as attacker SQL.
- The avatar path is derived from the TL `photo_id`: `TL_userProfilePhoto` and
  `TL_chatPhoto` set `photo_small.volume_id = -photo_id`, `local_id = 'a'`
  (97), `photo_big.local_id = 'c'` (99); the cache file is
  `<cacheDir>/<-photo_id>_97.jpg`. The device logcat confirms
  `cache path = /storage/emulated/0/Android/data/org.telegram.messenger.beta/cache`
  and `image path = …/files/Telegram/Telegram Images`
  (`logcat_survB.txt:13717-13721`).
- The phone is logged in and cold-starts to the chat list; the top dialogs are
  bound without a tap, so their avatars are decoded at startup.

---

## 2. S2 (CVE-2025-6965): correction — the wild `iMem` is not read

### 2.1 The exact 3.39.3 code

`sqlite3ExprCodeTarget`, `TK_AGG_COLUMN` (3.39.3, `sqlite3.c:107716-107740`):

```c
case TK_AGG_COLUMN: {
  AggInfo *pAggInfo = pExpr->pAggInfo;
  struct AggInfo_col *pCol;
  assert( pAggInfo!=0 );
  assert( pExpr->iAgg>=0 && pExpr->iAgg<pAggInfo->nColumn );
  pCol = &pAggInfo->aCol[pExpr->iAgg];       /* pointer arithmetic only */
  if( !pAggInfo->directMode ){
    assert( pCol->iMem>0 );
    return pCol->iMem;                       /* the only iMem read */
  }else if( pAggInfo->useSortingIdx ){
    Table *pTab = pCol->pTab;                /* OOB read of Table* */
    sqlite3VdbeAddOp3(v, OP_Column, pAggInfo->sortingIdxPTab,
                      pCol->iSorterColumn, target);
    if( pCol->iColumn<0 ){
      VdbeComment((v,"%s.rowid",pTab->zName));
    }else{
      VdbeComment((v,"%s.%s", pTab->zName, pTab->aCol[pCol->iColumn].zCnName));
      if( pTab->aCol[pCol->iColumn].affinity==SQLITE_AFF_REAL ){  /* line 107738 */
        sqlite3VdbeAddOp1(v, OP_RealAffinity, target);
      }
    }
    return target;
  }
  /* otherwise fall through to TK_COLUMN, using pExpr->iTable/iColumn */
```

Two facts matter:

1. `pCol = &aCol[iAgg]` is computed in **both** modes, but is only dereferenced
   in the `!directMode` branch (`pCol->iMem`) or the `useSortingIdx` branch
   (`pCol->pTab`, `pCol->iColumn`). The `assert` is gone under `NDEBUG`.
2. `iMem` is a **source register index**, not a destination. Even if read, it
   would only select a VDBE register to copy *from*; it does not write.

### 2.2 Why the old no-GROUP-BY PoC never reached it

The old `poc_agg.db` view is
`SELECT 1 AS id, CASE WHEN random()&1 THEN count(max(a0.c0,…,a0.c126)) … END AS seq, … FROM t AS a0,…`
with no `GROUP BY`. `updateAccumulator()` sets `pAggInfo->directMode = 1` and
codes the aggregate argument list. The negative-`iAgg` columns are exactly the
aggregate arguments, so they are coded with `directMode=1`; without GROUP BY,
`useSortingIdx==0`, so the code falls through to `TK_COLUMN` and never touches
`pCol`. The result expression `count(max(...))` is a `TK_AGG_FUNCTION` and
returns the count accumulator's `iMem`; it does not descend into the `max`
arguments. Host trace on the exact startup query:

```
$ ./sqlrun_trace3 poc_agg.db query.sql
TRACE CODEGEN OOB iAgg=-32768 nColumn=32893 direct=1
... (125 codegen hits, all direct=1)
TRACE IMEM count = 0
TRACE PERSIST count = 0
exec ok
```

The 125 `TRACE CODEGEN OOB` lines are **not** memory accesses; they print
`iAgg` before the `directMode` check. The query succeeds.

### 2.3 The GROUP BY variant: the real reachable fault is an OOB `Table*` read

Adding `GROUP BY` sets `pAggInfo->useSortingIdx` and makes the `directMode=1`
branch take `pTab->aCol[pCol->iColumn]`. `pCol` is at `aCol[-32768]`; `pTab`
and `iColumn` are read from uncontrolled heap. On a copy of the real 72799 DB:

```
$ python3 notes/poc/make_s2_group_poc.py \
    --base telegramandroidwidget/evidence/evidence_20261101/new_beta_72799/v4.db \
    --out /tmp/opencode/sq339/poc_s2_group_72799.db \
    --sqlrun /tmp/opencode/sq339/sqlrun_plain --v 1 --blob-bytes 1258291
wrote … (7155712 bytes), V=1, blob=1258291 bytes, view SQL ~2.8 MB

$ ./sqlrun_dbg poc_s2_group_72799.db query_s2.sql
sqlrun_dbg: sqlite3.c:107722: sqlite3ExprCodeTarget: Assertion
  `pExpr->iAgg>=0 && pExpr->iAgg<pAggInfo->nColumn' failed.   (abort)

$ ./sqlrun_trace3 poc_s2_group_72799.db query_s2.sql
TRACE CODEGEN OOB iAgg=-32768 nColumn=32769 direct=1
Segmentation fault   (SIGSEGV)
```

The generator's 1.2 MB blob first argument was added to test the
`pCol->iMem` control hypothesis: `sqlite3HexToBlob()` allocates its binary
form during codegen, after `aCol`, and fills it with the chosen register index
`V`. The instrumentation shows the `iMem` read never happens
(`TRACE IMEM=0`), so the blob does not affect the reachable fault; the crash is
the `pTab->aCol` read. This is a useful negative: even a large,
attacker-controlled codegen allocation does not make the wild register index
reachable.

Release gdb backtrace:

```
Program received signal SIGSEGV
0x… in sqlite3ExprCodeTarget … at sqlite3_trace4.c:107738
107738  if( pTab->aCol[pCol->iColumn].affinity==SQLITE_AFF_REAL ){
#4 updateAccumulator … sqlite3_trace4.c:141917
#5 sqlite3Select … sqlite3_trace4.c:143226
```

`TRACE IMEM` count is still **0**; the crash happens before any `iMem` read.
The `aCol` order explains why: `sqlite3Select` analyzes `pEList` first, then
ORDER BY, then the aggregate argument lists; the GROUP BY columns appear in
`pEList` and therefore get the **low** aCol indices. The negative indices are
the **aggregate argument columns**, which are only coded in `directMode=1`.
There is no way for a negative-`iAgg` TK_AGG_COLUMN to reach the
`!directMode` branch in this query shape: the low-index group columns are
valid, and the high-index aggregate columns are directMode=1.

The same `useSortingIdx` branch also emits `OP_Column` with the OOB
`pCol->iSorterColumn` as the column number. That is not a write primitive
either: the sorter record is built from the GROUP BY terms and has exactly
`nSortingColumn` header fields, so `OP_Column`'s header loop is bounded by the
record header, not by `p2`; a wild `p2` returns NULL or `SQLITE_CORRUPT`.
A controlled OOB `pCol` (if the 1 MB region below `aCol` were groomed) could at
most choose a wild `pTab`/`iColumn` read and a sorter column index; neither
writes attacker data.

### 2.4 The only write site

`agginfoPersistExprCb` (`sqlite3.c:109744-109773`) is the only place that can
write through `iAgg`:

```c
int iAgg = pExpr->iAgg;
if( pExpr->op==TK_AGG_COLUMN ){
  assert( iAgg>=0 && iAgg<pAggInfo->nColumn );
  if( pAggInfo->aCol[iAgg].pCExpr==pExpr ){     /* 8-byte pointer equality */
    pExpr = sqlite3ExprDup(db, pExpr, 0);
    if( pExpr ) pAggInfo->aCol[iAgg].pCExpr = pExpr;  /* write */
  }
}
```

The guard requires the OOB 8-byte field to equal the address of the current
`Expr` node. The app cannot supply that pointer: the attacker controls file
bytes, not the parse-tree address (ASLR), and the OOB region is not a live
copy of the current aCol array. The walker was not reached on the startup
query (`TRACE PERSIST=0`). The CVE's "memory corruption" is real, but in this
startup delivery it is the **OOB Table read / crash**, not an attacker-chosen
register or a controllable write.

**Result:** CVE-2025-6965 through `VIEW params` is a launch **DoS** (GROUP BY
variant) or a benign no-op (no GROUP BY), not a code-exec primitive. The prior
"wild iMem" statement is retracted in this note.

---

## 3. Native-lib fallback: real app-data code exec, but root-gated

`NativeLoader.initNativeLibs` (source `NativeLoader.java:113-186`, jadx
`js.g`/`ks.g`) order:

1. `System.loadLibrary("tmessages.49")`; on success `nativeLoaded = true` and
   return (`loaded normal lib` in the phone logcat).
2. On `Error`: `dir = getFilesDir()/lib`; if `libtmessages.49loc.so` exists,
   `System.load(dir/libtmessages.49loc.so)` and return.
3. Otherwise `loadFromZip()` extracts `lib/<abi>/libtmessages.49.so` from the
   **APK** into `files/lib/libtmessages.49loc.so` and `System.load`s it.
4. Final `System.loadLibrary` retry.

The fallback is live and executes app-data native code; the prior proof
(`telegramandroidwidget/notes/persistence_20261101.md:41-53`) moved the APK
lib, placed a raw-syscall `JNI_OnLoad` `.so` at
`files/lib/libtmessages.49loc.so`, and the app logged `Load local lib` and ran
the `.so` (then threw because the proof `.so` did not implement the full JNI).
This is **not** reachable from app data alone on the install: `extractNativeLibs=true`,
the APK lib is `system:system 755` in `/data/app/.../lib/arm64`, `files/lib`
did not exist normally, and no preference switches the loader. No new
no-root way to make step 1 fail was found. A root-assisted one-time move of
the APK lib gives a persistent startup code-exec (patch the stock lib with a
payload and place it in `files/lib`), but it is not the no-root goal.

Boot note: the manifest registers `org.telegram.messenger.AppStartReceiver`
for `BOOT_COMPLETED` (`manifest.xml:384-388`); the receiver starts the process,
so `ApplicationLoader.onCreate` → `NativeLoader.initNativeLibs` runs at boot.
With the APK lib moved and a patched stock lib in `files/lib`, the payload
would run at boot, not only when the UI is opened. The avatar/WebP path in §6
does not run at boot (no chat-list render), only on app launch.

No `DexClassLoader` / `InMemoryDexClassLoader` / `DexFile.loadDex` exists in
72799; `y6.h` is an unused `PathClassLoader` subclass. `Runtime.exec` /
`ProcessBuilder` is only `EmuDetector`'s hard-coded `/system/bin/netcfg`.
No `System.load` site other than `NativeLoader` and `org.webrtc.NativeLibrary`
(static names) was found.

---

## 4. `shared_prefs` and the update flow: user-gated

The `beta` SharedPreferences are read at startup by `k1` (`k1.java:44-64`):
`version`, `versionCode`, `changelog`, `path`, `lastCheck`. `ApplicationLoaderImpl.g()`
returns the update file at `path`; `BlockingUpdateView` shows it and
`ApplicationLoaderImpl.v()` starts an `ACTION_VIEW` install intent with
`application/vnd.android.package-archive`. `SharedConfig.loadConfig()` also
deserializes a Base64 `appUpdate` TL blob at startup
(`SharedConfig.java:559-590`), and a crafted `TL_help_appUpdate` with
`can_not_skip=true` forces the blocking update screen at every launch.

This is a persistent, app-data-controlled **blocking screen / phishing / DoS**
and a delivery of an APK that the user must install. It is not automatic code
execution. The TL blob is a Java `SerializedData` parser; malformed lengths can
throw or OOM (DoS), not native code exec.

`SharedConfig.storageCacheDir` is a pref-controlled cache path; it selects
where the app reads/writes media. It does not select a code loader. Theme
names are sanitized by `fixFileName`; the wallpaper path is derived from the
theme slug, so a path traversal is at most an image read/write, not a `.so`
load (the native loader does not consult the theme path).

Language pack `remote_<code>.xml` is parsed by framework XML; values are used
as format strings (`String.format`), giving the known width OOM; the
`langconfig` descriptor `d` can point at an arbitrary readable file, which is
parsed/copied as XML (arbitrary read, no code). `.attheme` is parsed by Java
`t6.T0`; wallpapers go to platform `BitmapFactory`. Fonts come from APK assets
(`Typeface.createFromAsset`); no app-data font path was found.

---

## 5. `tgnet.dat`: a persistent C2 channel without code exec

`files/tgnet.dat` (5716 B on the phone) and `files/dc<id>conf.dat` are
app-writable and read at startup (`Config::readConfig`, `Datacenter`). A crafted
entry supplies the DC `ip:port` and auth key; the app connects at every start
and rewrites the file with the parsed values. The prior note already found a
short-auth-key OOB read in `generateMessageKey()/aesIgeEncryption()` and the
redirection primitive. This is the only **app-initiated, restart-surviving C2
channel** found: with a mock MTProto server and the known key, the app talks to
the attacker at startup. It does not execute code; it is useful as the delivery
and control channel for a separate content bug (e.g. the WebP cache file) and
for server-side updates (`help.getAppUpdate` → user-gated APK prompt).

The exact `tgnet.dat` field format is in
`notes/startup_appdata_persistence.md` §6.2 and the source
`jni/tgnet/Config.cpp`/`Datacenter.cpp`; this audit did not re-implement the
mock server. A device test is a separate, low-volume step (backup
`tgnet.dat`, craft one DC entry, cold start, observe the connection; restore).

---

## 6. Top remaining code-exec candidate: CVE-2023-4863 via a cached avatar

### 6.1 Why the device is in range

* Device fingerprint from the tombstones/logcat:
  `Sony/XQ-BT52_EEA/XQ-BT52:13/62.2.A.0.533/062002A000053303716344522:user/release-keys`.
  XQ-BT52 is the **Xperia 10 III**.
* Sony's Xperia 10 III support page for build **62.2.A.0.533** lists
  **Android security patch level: July 1st, 2023**
  (`https://www.sony.com/electronics/support/articles/00288866`).
* CVE-2023-4863 (`BuildHuffmanTable`/`ReplicateValue` heap OOB write in
  libwebp < 1.3.2) was fixed in the Android September/October 2023 bulletin
  and is in CISA KEV; a July 2023 SPL predates the fix.
* The app does **not** bundle libwebp (`libtmessages.49.so` has no
  `RIFF`/`WEBP`/`VP8L`/VP8L code tables, no libjpeg/libpng/FreeType; the
  media-parser note is correct on this). Avatar/photo decoding is
  `android.graphics.BitmapFactory` in the app process, i.e. **system**
  Skia/libwebp. `ImageLoader.CacheOutTask` uses
  `BitmapFactory.decodeFile`/`decodeStream`; the chat-list
  `ImageReceiver` binds `photo_small` for visible dialogs at startup.

### 6.2 The exact app-data input

No DB edit is required: the real 72799 DB already has a visible dialog whose
`TL_user`/`TL_chat` photo id maps to a cache file. `notes/poc/find_avatar_cache.py`
parses `users.data`/`chats.data` and prints the names. On the 72799 backup
`new_beta_72799/v4.db`:

```
$ python3 notes/poc/find_avatar_cache.py .../v4.db --limit 40
did=-1665872459 date=1793536507 peer=chat photo_id=5413632455442823479 dc=134742288
    small=-5413632455442823479_97.jpg big=-5413632455442823479_99.jpg
did=<CHAT_ID> date=<CHAT_ID> peer=user photo_id=108965549847546626 dc=134742288
    small=-108965549847546626_97.jpg big=-108965549847546626_99.jpg
...
```

The **first dialog** (chat) and the **third dialog** (user) are at the top of
the chat list and are visible on a cold start. Place the crafted WebP at:

```
/storage/emulated/0/Android/data/org.telegram.messenger.beta/cache/-5413632455442823479_97.jpg
/storage/emulated/0/Android/data/org.telegram.messenger.beta/cache/-108965549847546626_97.jpg
/storage/emulated/0/Android/data/org.telegram.messenger.beta/files/Telegram/Telegram Images/-5413632455442823479_97.jpg
/storage/emulated/0/Android/data/org.telegram.messenger.beta/files/Telegram/Telegram Images/-108965549847546626_97.jpg
```

(The cache dir is confirmed by `logcat_survB.txt:13717`; the image dir by
`:13721`; `ImageLoader` chooses `MEDIA_DIR_CACHE` for `cacheType==1` and
`MEDIA_DIR_IMAGE` otherwise, so cover both. The internal
`/data/user/0/org.telegram.messenger.beta/cache/<name>` is the fallback if the
external cache is unavailable.)

The file content: `notes/poc/webp/oob.webp` (656 B, md5
`cf0715f8611ebf6044562d67b2376b2e`) is the strongest public trigger;
`bad.webp` (236 B, md5 `de6dbd42df4535633b452aa14c915696`) and `poc.webp`
(642 B) are alternates. `oob.webp` is a valid lossless WebP that
`BitmapFactory` will decode; the `.jpg` extension is irrelevant because the
decoder sniffs RIFF/WEBP.

### 6.3 Host proof of the OOB write (libwebp 1.2.4 / 1.3.1, ASan)

Build the vulnerable library and run `dwebp`; the exact commands are in
`notes/poc/webp/README.md`. On host libwebp **1.2.4** (the Android-13-era
version):

```
$ ASAN_OPTIONS=detect_leaks=0 ./dwebp notes/poc/webp/oob.webp -o /tmp/oob.png
==…==ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 1 at 0x527000003100
    #0 ReplicateValue src/utils/huffman_utils.c:59
    #1 BuildHuffmanTable src/utils/huffman_utils.c:194
    #2 VP8LBuildHuffmanTable src/utils/huffman_utils.c:224
0x527000003100 is located 216 bytes after 12072-byte region
    [0x527000000100,0x527000003028)
SUMMARY: AddressSanitizer: heap-buffer-overflow … in ReplicateValue
```

`bad.webp` gives a 1-byte write at 11,816 B; `poc.webp` gives 152 bytes past
12,072. `oob.webp`'s 216 bytes are exactly `0x3000 - 0x2F28`: if the allocator
size class is 0x3000, the last write is the **first byte of the next slot**.
DARKNAVY's analysis (`https://www.darknavy.org/blog/exploiting_the_libwebp_vulnerability_part_1/`)
shows the written unit is a 4-byte `HuffmanCode` (`bits` 1 byte, padding,
`value` 2 bytes, value 0..39 for the distance alphabet) at offsets that are
multiples of 8; the public Part 2 and the `DarkNavySecurity/PoC/CVE-2023-4863`
repository contain a full **Chromium/PartitionAlloc** exploit. That is a known
RCE primitive; it is not an Android/Scudo exploit.

### 6.4 Device test plan (Sony only; not executed here)

Preconditions: the phone is logged in and cold-starts to the chat list; back up
`files/cache4.db` and pull it; keep the off-device backup; do not touch the
widget payload. A crash is **not** code exec; it is a launch DoS, so restore
after each test.

0. On the phone, read `getprop ro.build.version.security_patch` and
   `getprop ro.build.version.release`. The expected values for build
   `62.2.A.0.533` are Android 13 and **2023-07-01**; if the ROM was updated,
   the libwebp fix may be present and this candidate is out of range.
1. Pull the live DB and run
   `python3 notes/poc/find_avatar_cache.py cache4.db --limit 40` to confirm the
   current top-dialog photo ids and file names. If the live DB differs from the
   backup, use the names it prints (the parser is the authority).
2. `adb shell` (UID 10357 or root to chown): place `oob.webp` as the exact
   `<name>_97.jpg` under **both** the external cache dir and
   `.../files/Telegram/Telegram Images/`; `chown 10357:10357`, `chmod 600`.
   Keep a copy of the original cache file for restore.
3. Airplane mode on; `am force-stop org.telegram.messenger.beta`; `adb logcat -c`;
   cold start; stay on the chat list (do not tap). Capture logcat and
   `/data/tombstones` (or `dumpsys dropbox --print`).
4. Expected if the vulnerable libwebp path is hit: a SIGSEGV/SIGABRT in
   `libwebp`/`libhwui`/`libskia` with `BuildHuffmanTable`/`ReplicateValue` or a
   heap-buffer-overflow tombstone in the app process. That is the reachability
   proof; it also confirms the July 2023 SPL is unpatched for this decoder.
   If the app survives, the 216 bytes stayed inside the Scudo slot or the
   avatar was not bound: try `poc.webp`, `bad.webp`, both cache dirs, and scroll
   the top dialogs once (still no tap), then stop.
5. Restore the original cache file(s); cold start; confirm the chat list.

What this does **not** prove: code execution. The Android/Scudo chain needs a
controlled next-slot object; Scudo keeps per-chunk metadata between user
allocations, so a 216-byte overflow from a 12,072-byte user slot may hit the
next chunk's header/checksum rather than a usable object. The DARKNAVY Chrome
chain (a `CSSVariableData` refcount plus a cross-bucket allocation) is a
PartitionAlloc layout and does not transfer directly. No public Android full
exploit was found; building one is the next research step, not a result of
this audit. If a device test only crashes, the
result is a **persistent launch DoS** (the cache file survives restart), not
the requested code-exec persistence.

### 6.5 Is there a simpler file than the avatar?

The selected theme's wallpaper (`files/<theme>_…_v5.jpg`) is also decoded at
startup by `BitmapFactory`, and a `.attheme`/theme path is app data. It is an
alternate delivery for the same libwebp CVE, but it depends on the current
theme/pattern slug and the wallpaper path; the avatar cache is guaranteed by
the DB and the visible chat list. The avatar path is used in the device plan.

---

## 7. Ranked remaining candidates

| Rank | Candidate | Why | Status |
|---|---|---|---|
| 1 | **CVE-2023-4863, cached avatar at chat-list startup** | Known actively-exploited RCE in libwebp <1.3.2; device SPL July 2023; app decodes avatar with system libwebp, no tap; one app-data file survives restart | Host OOB write proven; device reachability test in §6.4; **no Android full chain** |
| 2 | `tgnet.dat` fake DC | App-initiated persistent C2 at every start; no code exec by itself; can deliver content/updates | Prior static primitive; mock server/device test not done |
| 3 | Root-assisted `files/lib/libtmessages.49loc.so` | Real app-data native code exec; only if the APK lib is moved | Prior proof, root-gated |
| 4 | Theme wallpaper libwebp | Same CVE via a theme file; depends on selected theme | Alternate to rank 1 |
| 5 | SQLite S2 GROUP BY | Host-proven OOB `Table*` read / launch crash | DoS only; no write/RCE |
| 6 | SQLite S1 view chain | Host/device-proven launch stack overflow | DoS only |
| 7 | FFmpeg / tlottie 0-day | Current versions; no known RCE | Research only; chat-open/playback, not chat list |

---

## 8. Proven vs untested

**Proven on the host:**
- The exact 72799 DB schema and startup `params` SELECT; `VIEW params` is
  compiled at launch.
- S2 correction: no `iMem` read in the no-GROUP-BY view; GROUP BY variant
  asserts/SIGSEGVs at `pTab->aCol[pCol->iColumn]` (OOB `Table*` read); no
  `agginfoPersistExprCb` call; no controllable write.
- `oob.webp`/`bad.webp`/`poc.webp` trigger libwebp 1.2.4/1.3.1 ASan OOB writes
  (216/1/152 bytes past the Huffman table).
- The real DB has visible top dialogs with photo ids; the avatar cache names
  are `<-photo_id>_97.jpg`; the device cache/image paths are in the logcat.
- Native loader fallback is app-data code exec only after the primary lib load
  fails; no no-root way to force that was found.
- No Dex/exec/startup-WebView path; prefs/update install is user-gated;
  language/theme/font parsers are Java/framework; FFmpeg/tlottie are current.

**Untested (device):**
- Whether `oob.webp` (or the alternates) reaches a crash/OOB on the phone's
  system libwebp/Scudo, and whether the 0x3000 slot assumption holds.
- Whether the avatar cache file is used at the first chat-list render for the
  chosen dialog (logcat/behavior), and whether the app re-downloads it.
- A full Android code-exec chain for CVE-2023-4863 (not built).
- The `tgnet.dat` mock-server connection and the root-assisted lib fallback.

**Novelty:**
- The S2 correction is new: the prior "wild iMem" is a misread of the
  `iAgg` trace; the reachable bug is an OOB `Table*` read in the GROUP BY
  directMode path. This is a negative result for code execution, useful to
  prevent a false lead.
- The launch-read map is a complete enumeration for 72799.
- The cached-avatar CVE-2023-4863 delivery (one app-data cache file + existing
  DB photo id, chat-list startup, no widget/QuickJS) is new for this target.
  The CVE itself is known and actively exploited; the novelty is the
  app-data/startup delivery and the exact device patch-level match.
- No new no-root code-exec path was found.

---

## 9. References / commands

* `notes/poc/make_s2_group_poc.py` — GROUP BY view generator; uses a 3.39.3
  `sqlrun`/`sqlite3` binary (the host Python 3.46 rejects >2,000 aggregate
  terms, which is the fixed behavior).
* `notes/poc/find_avatar_cache.py` — DB → visible dialog → `<photo_id>_97.jpg`.
* `notes/poc/webp/README.md` — WebP files, hashes, source attribution, and the
  exact libwebp 1.2.4/1.3.1 ASan build/run commands.
* 3.39.3 source: `Android/TMessagesProj/jni/sqlite/sqlite3.c` (md5
  `4039d3d3d015d3092dda140c0bb27f7d`), `sqlite3ExprCodeTarget` lines
  107716-107740, `agginfoPersistExprCb` 109744-109773,
  `updateAccumulator` 141864-141960, `sqlite3Select` 142900-143050.
* App code: `hs.java:2219-2241`, `MessagesStorage.java:330-380`,
  `SharedConfig.java:513-594`, `NativeLoader.java:113-186`,
  `ImageLoader.java:2417-2495, 3200-3260`, `FilePathDatabase.java:35-231`,
  `Theme.java`/`t6.java` (theme), `k1.java`/`BlockingUpdateView.java` (update).
* Device evidence: `logcat_survB.txt:13717-13721` (cache/image paths, DB version),
  `new_beta_72799/v4.db` (real 72799 DB with visible photo dialogs),
  `tombstone_07` (build fingerprint).
* Sony build page: `https://www.sony.com/electronics/support/articles/00288866`
  (Xperia 10 III 62.2.A.0.533, July 1 2023 security patch).
* CVE-2023-4863: CISA KEV, Android October 2023 bulletin; libwebp
  `BuildHuffmanTable`/`ReplicateValue`, fixed 1.3.2.
* DARKNAVY: `https://www.darknavy.org/blog/exploiting_the_libwebp_vulnerability_part_1/`
  and Part 2; public PoC `https://github.com/DarkNavySecurity/PoC/tree/main/CVE-2023-4863`.
* Public triggers: `https://github.com/mistymntncop/CVE-2023-4863`
  (`bad.webp`, `nso.webp`, `craft.c`), Ben Hawkes,
  `https://blog.isosceles.com/the-webp-0day`.
