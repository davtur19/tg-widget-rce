# SQLite 3.39.3 in Telegram 72799 — SQL-reachable memory safety in `cache4.db`

Date: 2026-11-02. Target: `org.telegram.messenger.beta` 13.2.0 (72799), arm64,
`lib/arm64-v8a/libtmessages.49.so`. Host-only lab (no device, no emulator).
Question: can attacker-controlled `cache4.db` schema (views, triggers,
`sqlite_master`) reach memory corruption / RCE in the **bundled** SQLite
3.39.3, and would it survive an app update?

---

## 0. Verdict

- **No SQL-reachable RCE and no write primitive was found.** Three memory-safety
  issues are reachable from attacker-controlled schema:
  1. **CVE-2025-7458** — `SELECT DISTINCT` with more result terms than ORDER BY
     terms: negative `nExpr-iStart`, `KeyInfo.nKeyField` becomes 65535, and
     `sqlite3VdbeSorterInit()` `memcpy`s **524312 bytes** from a ~0.6 KB
     allocation. Host x86-64 release: SIGSEGV at every launch.
  2. **CVE-2025-6965** — more than 32767 distinct aggregate columns:
     `Expr.iAgg` (i16) becomes negative and `pCol = &aCol[-32768]` reads
     **1 MiB before** the `AggInfo.aCol` array. Host x86-64 and aarch64 release:
     SIGSEGV.
  3. **json_each UAF** (fixed 2024-03-05, no CVE): the `json` column is returned
     as `SQLITE_STATIC`; a correlated `json_each` frees the JSON text on cursor
     reset while `max()` still holds it. ASan-only in our release runs.
- All three are **reads / use-after-free reads**. No heap write, double free, or
  controlled indirect call was demonstrated.
- **The premise "system SQLite" does not hold for `cache4.db`.** Telegram opens
  `cache4.db` through its own JNI wrapper
  (`SqliteWrapper.cpp:142-154`, `sqlite3_open`) against the amalgamation compiled
  into `libtmessages.49.so` (`jni/sqlite/sqlite3.c`, 3.39.3, source id
  2022-09-05). AOSP Android 13's framework SQLite is **3.32.2** and is not in this
  path. An **app update** replaces the engine; an OS update does not.
- **The DB schema is update-surviving; code execution is not.** `cache4.db` and
  its views/triggers live in app data and survive updates. The app contains no
  `DROP TRIGGER`/`DROP VIEW`, and migrations can be skipped by pinning
  `PRAGMA user_version` high (`is.java:2289`). But the vulnerable engine is
  app-bundled: Telegram 72789 and 72799 both ship 3.39.3, so near-term app
  updates likely keep it; a build that bumps SQLite to ≥ 3.50.2 fixes all three
  (verified). The result is a **persistent launch-DoS in the tested builds**
  (F2 on both x86-64 and aarch64; F1 allocator-dependent), not persistent code
  execution.

---

## 1. Target facts (measured)

| Item | Value |
|---|---|
| App | Telegram Android 13.2.0 beta 72799 (and 72789) |
| Engine | SQLite **3.39.3**, source id `2022-09-05 11:02:23 4635f4a69c8c2a8df242b384a992aea71224e39a2ccab42d8c0b0602f1e826e8` |
| Amalgamation | `Android/TMessagesProj/jni/sqlite/sqlite3.c`, md5 `4039d3d3d015d3092dda140c0bb27f7d` — byte-identical to the official `sqlite-amalgamation-3390300.zip` |
| Compile flags | `-fno-strict-aliasing -Oz`; no `SQLITE_*` feature defines (`jni/CMakeLists.txt:168-176`) |
| Features | no FTS3/4/5, no RTREE, no STAT4, no SESSION; `SQLITE_OMIT_LOAD_EXTENSION` **not** defined; JSON1 built in; `load_extension` compiled but disabled at runtime |
| Open path | `is.java:2232` `new SQLiteDatabase(".../cache4.db")` → `SqliteWrapper.cpp:142-154` `sqlite3_open` |
| Framework SQLite | AOSP `android13-release` `external/sqlite` = **3.32.2** (not used for `cache4.db`) |
| DB version | 181; `user_version == 0` is "malformed", `< 181` runs migrations (`is.java:2289`) |

Evidence: `lab/sqlite_trigger_rce/logs/target_facts.txt`,
`logs/host_compile_options.txt`, `src/sqlite3.c` md5 above.

The compile-option strings in `libtmessages.49.so` are exactly those of a
default 3.39.3 build (all 35 non-compiler options of our default build are
present; no `ENABLE_*`/`OMIT_*` string exists). This is why FTS5/RTree CVEs do
not apply, and why `load_extension()` is present but cannot be enabled by SQL.

### 1.1 What runs at startup

`is.java#V0` (2232-2296) does, in order:

```sql
PRAGMA secure_delete = ON;
PRAGMA temp_store = MEMORY;
PRAGMA journal_mode = WAL;
PRAGMA journal_size_limit = 10485760;
PRAGMA user_version;
SELECT seq, pts, date, qts, lsv, sg, pbytes FROM params WHERE id = 1;
-- if user_version < 181: P1(user_version)   (migrations)
```

A **view named `params`** replaces the table and executes attacker SQL on that
first SELECT. A **trigger on `params`** fires on the app's periodic
`UPDATE params SET seq = ?, pts = ?, date = ?, qts = ? WHERE id = 1`
(`is.java:879-895`). Both are reachable with only DB-content control (the
existing RCE gives the required file write).

Why not just call a dangerous function? In this build:

- `SELECT load_extension(...)` → `not authorized` (extension loading disabled;
  Telegram never calls `sqlite3_enable_load_extension`).
- In a trigger/view: `unsafe use of load_extension()`.
- `writefile()`/`readfile()` → no such function.
- `ATTACH` / `VACUUM INTO` in a trigger body → syntax error.
- `PRAGMA trusted_schema` = 1, but does not help: `load_extension` is rejected
  in schema, and ATTACH/VACUUM are not trigger statements.

So the SQL-only route to code execution must be a **memory-safety bug in the
engine**, not a SQL API.

---

## 2. Method

- Built the exact amalgamation three ways: ASan+UBSan, ASan-only (`-O1`), and
  release (`-O2 -fno-strict-aliasing`), plus an aarch64 cross-build under
  `qemu-aarch64` (glibc) as an architecture proxy. Harness
  `harness/tgdb.c` mirrors `V0` plus representative chat-list reads.
- Compared against upstream 3.41.2, 3.50.2 and AOSP 3.32.2.
- Reviewed `https://www.sqlite.org/cves.html` and the upstream git history,
  including the actual regression tests added with the fixes.
- Bounded fuzzing: 20,000 mutated DB files and 5,000 generated SQL/DDL shapes
  under ASan — zero ASan findings (`fuzz/db_mutate.py`, `fuzz/sql_gen.py`,
  `logs/db_fuzz_A.txt`, `logs/sql_fuzz_B.txt`). This is negative evidence, not
  a proof of absence.

Surface coverage:

| Surface | Result |
|---|---|
| FTS3/4/5, RTree, STAT4, session, zipfile | **not compiled** (compile-option strings and binary strings); their CVEs do not apply |
| JSON functions and `json_each`/`json_tree` | present; F3 UAF read found; JSONB CVEs (3.43+) not applicable |
| window functions, aggregates, compound SELECT, CTEs, DISTINCT/ORDER BY | 5,000 generated shapes + targeted regression tests; F1/F2 found; no write |
| `printf`/format strings | exercised; the 2020 printf stack-overflow CVE is fixed before 3.39.3 |
| `load_extension`, `ATTACH`, `VACUUM INTO`, `writefile` | unreachable from schema (disabled/unsafe/not a trigger statement) |
| malformed DB file / `sqlite_master` bytes | 20,000 mutations of a valid 1 MB schema, startup sequence; no ASan finding. Ten hand-crafted `sqlite_master` type-confusion cases (table/view/index/trigger type and SQL prefix mismatches, wrong `tbl_name`/`rootpage`) all fail closed with “malformed database schema”; a shared rootpage is accepted but yields only data-level reinterpretation (`fuzz/schema_probe.py`, `logs/schema_probe.txt`) |
| app-defined SQL functions/vtabs | none registered by `SqliteWrapper.cpp` |

---

## 3. Findings

### F1 — CVE-2025-7458: 512 KB out-of-bounds read at startup (SIGSEGV)

**Reachability.** `CREATE VIEW params AS SELECT ... FROM (SELECT DISTINCT
<65 constant terms> ORDER BY <64 constant terms>);` — the view exposes the eight
columns the app asks for. The app's startup SELECT compiles and runs the inner
DISTINCT (the over-read happens when `OP_OpenSorter` executes).

**Root cause (3.39.3).** With all result terms constant and
`nResult > nOrderBy`, the DISTINCT optimisation sets
`pWInfo->nOBSat = nResult` (65) while `pSort->pOrderBy->nExpr = 64`. In
`pushOntoSorter()`:

```c
sqlite3KeyInfoFromExprList(pParse, pSort->pOrderBy, nOBSat, ...)  /* N = 64-65 = -1 */
```

`sqlite3KeyInfoAlloc()` computes a negative `nExtra`, allocates a ~0.6 KB
`KeyInfo`, and stores `p->nKeyField = (u16)N = 65535`. When `OP_OpenSorter`
runs:

```c
szKeyInfo = sizeof(KeyInfo) + (pKeyInfo->nKeyField-1)*sizeof(CollSeq*);
memcpy(pKeyInfo, pCsr->pKeyInfo, szKeyInfo);   /* 524312-byte READ */
```

Debug trace (exact): `nExpr=64 iStart=65 -> N=-1`, `nKeyField=65535`,
`szKeyInfo=524312`, `nField=0`.

**Host result.**

- ASan: `heap-buffer-overflow READ of size 524312` in `__asan_memcpy` ←
  `sqlite3VdbeSorterInit` (`sqlite3.c:98590`).
- Release x86-64: SIGSEGV, 5/5 runs, ~2 ms.
- Release aarch64 (qemu/glibc): **survives** 3/3 — the 512 KB over-read stays
  inside mapped heap. This makes F1 an allocator-dependent crash; on Android
  Scudo it is likely but not proven.
- Fixed by upstream check-in `b816ca9994e0` (2023-03-16; `distinct.test` 10.1),
  first release 3.41.2. CVE-2025-7458 lists 3.39.2–3.41.1 affected. Note the CVE
  text says “a large number of expressions in the ORDER BY clause”; the actual
  upstream regression test is the 65-result/64-ORDER-BY case above, and the
  root cause is the missing `nOBSat > nOrderBy` clamp.

**PoCs.** `poc/s1_params_view.sql` (view) and `poc/s1_trigger.sql`
(`CREATE TRIGGER ... INSERT INTO zz_m SELECT DISTINCT ...`). A bare discard
SELECT in a trigger did **not** build the sorter in our test (SQLite optimises
discarded results); the `INSERT ... SELECT` form does, and crashes.

**Impact.** Launch crash (view) or crash on the first params save (trigger).
Read-only: the over-read feeds the sorter's `KeyInfo`, but only the first
`nKeyField` entries are used, and no query output exposes them.

---

### F2 — CVE-2025-6965: aggregate-column index wraps, 1 MiB OOB read (SIGSEGV)

**Reachability.** > 32767 distinct aggregate column terms in one query. In
3.39.3 `SQLITE_LIMIT_COLUMN` is **not** applied to aggregate terms, so a
769-column table (`zz_poc_t`) joined 17 ways, with the columns referenced
inside aggregate expressions, reaches 32769 `AggInfo.aCol` entries. The payload
is a `params` view (2.8 MB SQL) or a trigger on `params`.

**Root cause.** `Expr.iAgg` is `i16` (`sqlite3Int.h`/`sqlite3.c`). In
`sqlite3ExprAnalyzeAggregates()`:

```c
pExpr->iAgg = (i16)k;          /* k = 32768 -> -32768 */
...
pCol = &pAggInfo->aCol[pExpr->iAgg];   /* aCol - 32768*32 = aCol - 1 MiB */
```

Debug trace: `DBG AGGADD k=32768 iAgg=-32768 nColumn=32769`;
`DBG AGGCOL iAgg=-32768 nColumn=32769 aCol=0x...81ec8
pCol=0x...a81ec8` (difference exactly `-0x100000`). The code then reads
`pCol->pTab`, `pCol->iSorterColumn`, `pCol->iMem` from 1 MiB before the array.

**Host result.**

- ASan: `heap-use-after-free READ of size 8` at
  `sqlite3ExprCodeTarget` (`sqlite3.c:107728`) — the OOB pointer lands in a
  freed VDBE op array (`growOpArray` realloc).
- Release x86-64: SIGSEGV, 5/5, ~210 ms.
- Release aarch64 (qemu/glibc): SIGSEGV, 3/3.
- AOSP 3.32.2: the same query also produces the ASan UAF (the bug is older than
  3.39.3), but the system engine is not the opener.
- Fixed by upstream check-in `c52e9d97d` / fossil `5508b56fd2` (2025-06-27),
  release 3.50.2: the fix caps aggregate terms at `SQLITE_LIMIT_COLUMN` and
  widens `iColumn`/`iSorterColumn`.

**PoCs.** `poc/s2_setup.sql` (view + `zz_poc_t`, 2.8 MB) and
`poc/s2_trigger_full.sql` (same SELECT in a trigger; fires on the app's
`UPDATE params`). The trigger form is the stealthy one: `params` stays a normal
table, so the app's startup SELECT succeeds (measured rc 0) and the crash
happens when the app saves its update state (`UPDATE ... seq/pts/date/qts`,
measured SIGSEGV).

**Impact.** Reliable crash at startup/near-startup on both tested
architectures. Read-only: the OOB `AggInfo_col` may yield a wild `pTab`/
`iSorterColumn` read, but no write or output primitive was found. A theoretical
escalation (placing a fake `AggInfo_col` in the stale 1 MiB region) needs a
controlled heap at a known address; we found no leak and no write.

---

### F3 — json_each `json` column UAF (fixed 2024-03-05, no CVE)

**Reachability.** A correlated `json_each` inside an aggregate over a table/CTE:

```sql
WITH src(j) AS (VALUES('[1,2,3,4,5,6,7,8]'),('[9,10,11]'))
SELECT max(x.json) FROM src, json_each(src.j) AS x;
```

**Root cause.** `jsonEachColumn()` returns the raw JSON text with
`SQLITE_STATIC`. When the next outer row resets the vtab cursor,
`jsonEachCursorReset()` frees `zJson`; `minmaxStep()` still holds the text in
its accumulator and compares it with `memcmp` → heap-use-after-free read.
Fixed by commit `28001204f` / fossil `952ed71b9b` (2024-03-05): return the
value with `SQLITE_TRANSIENT`.

**Host result.** ASan: `heap-use-after-free READ of size 9` in `memcmp` ←
`binCollFunc` ← `minmaxStep` (`sqlite3.c:124086`); freed in
`jsonEachCursorReset` (`:197622`). The release build **survives** in our tests
(the freed small chunk stays mapped); a 1 MB JSON text also survived. 3.50.2 is
clean. No CVE is listed for this fix in sqlite.org's table.

**Impact.** ASan-visible memory corruption; in a release build it is a stale
read that can return freed heap bytes as the aggregate value (potential info
exposure), but we found no path that returns those bytes to an attacker or
crashes reliably. Not counted as a DoS primitive.

---

## 4. Why this is not RCE

- Every reproducible primitive is a **read**: F1 a 512 KB `memcpy` source
  over-read; F2 an OOB/UAF read of `AggInfo_col`; F3 a UAF read of JSON text.
  None writes attacker data to attacker-chosen memory.
- The only potentially interesting escalation, F2's `pCol->pTab` /
  `pCol->iSorterColumn`, is used for a column lookup and an affinity test; the
  aggregate register `iMem` is returned as a **source** register in the paths we
  inspected. We found no destination pointer derived from it, but we did not
  exhaustively prove that for every codegen path.
- No SQL route to `load_extension`, file I/O, or a custom vtab/function:
  Telegram registers no SQL functions or modules, extension loading is off,
  and `load_extension` is rejected in schema. `ATTACH`/`VACUUM` are not trigger
  statements.
- FTS3/4/5, RTree, STAT4 and the session extension are not compiled, so the
  FTS5 heap-overflow CVEs (2025-7709, 2026-11822/11824) and the rtree UAF do
  not apply.
- CVE-2024-0232 (JSON `jsonParseAddNodeArray` UAF) is **not** in 3.39.3: the
  JSON cache that caused it was introduced in 3.43 (`json_remove`/`json_set`
  cache). The upstream forum replies confirm “≤ 3.42 not affected”.
- `concat_ws()` (CVE-2025-29087/3277) was added in 3.44 and is absent.

CVE review (3.39.3 vs the fixes listed on `sqlite.org/cves.html`):

| CVE | Fix | In 3.39.3? | Reachable from schema? | Outcome |
|---|---|---|---|---|
| CVE-2025-7458 | 3.41.2 / 3.42.0 | yes | **yes** | OOB read, SIGSEGV (F1) |
| CVE-2025-6965 | 3.50.2 | yes | **yes** | OOB/UAF read, SIGSEGV (F2) |
| (json_each UAF, no CVE) | 2024-03-05 | yes | **yes** (JSON built in) | UAF read, ASan-only (F3) |
| CVE-2024-0232 | 3.43.2 | no (JSON cache is 3.43+) | — | — |
| CVE-2025-7709, CVE-2026-11822/11824 | 3.50.3/3.53.2 | no FTS5 | no | — |
| CVE-2025-29087/3277 | 3.49.1 | no `concat_ws` (3.44+) | no | — |
| CVE-2025-70873 | 3.52.0 | no zipfile extension | no | — |
| CVE-2025-29088/52099 | 3.49.1 | C API only | no | — |
| CVE-2023-7104 | 3.43.1 | no session extension | no | — |
| CVE-2022-35737 | 3.39.2 | fixed before 3.39.3 | no | — |

**Conclusion: no SQL-reachable RCE in SQLite 3.39.3 as bundled in 72799; the
realistic outcome is launch denial-of-service (and, for F3, a potential
info leak).**

---

## 5. Update survival

| Layer | Survives app update? | Survives OS update? | Notes |
|---|---|---|---|
| `cache4.db` file + `sqlite_master` rows | yes (app data) | yes | views/triggers/text are ordinary DB content |
| Triggers on `params`/`dialogs`/... | yes, while the check holds | yes | app has **no** `DROP TRIGGER`/`DROP VIEW` anywhere in the dex; migrations are skipped if `user_version >= 181` (`is.java:2289`), so 999999 skips the current check (a future build could add an upper bound and then run migrations, which can drop/recreate tables) |
| The **engine bug** | **only if the new APK still bundles 3.39.3** | no effect | `libtmessages.49.so` is replaced by every app update; system SQLite is not in this path |
| Native RCE / code execution | no (unless a new engine bug) | no | this SQL layer cannot write files, load extensions, or execute native code |

Telegram has shipped the same 2022-09-05 SQLite 3.39.3 in both available builds
(72789 and 72799), so an app update in the near term will likely preserve the
crash. But that is a property of Telegram's build, not of Android: the correct
statement is **“app-bundled engine, replaced by app updates, currently frozen
at 3.39.3”**, not “system SQLite, only OS updates”.

A malicious `params` **view** is the strongest persistence form: it executes on
the very first startup SELECT, so the app crashes before any UI. Recovery
normally requires clearing app data (safe mode / reinstall); the app's
`catch` only handles Java exceptions and deletes `cache4.db` (plus `-wal`/`-shm`)
for messages containing `"malformed"` (`is.java:4035-4063`), and a SIGSEGV is
not catchable in Java. A trigger form is stealthier (the table survives) but
fires when the app next saves `params`.

If the goal is durable **code execution**, this vector does not provide it. If
the goal is durable **denial of service** of the app across updates and reboots,
the view/trigger survives as long as the bundled engine remains 3.39.3; F2 is
the architecture-robust crash (x86-64 and aarch64 glibc), F1 the
allocator-dependent one.

---

## 6. Reproduction

```sh
cd lab/sqlite_trigger_rce
./build.sh

# F1 view (startup SELECT)
cp poc/telegram72799_schema.db /tmp/s1.db
{ echo 'DROP TABLE params;'; cat poc/s1_params_view.sql; } > /tmp/s1.sql
./build/tgdb_rel /tmp/s1.db exec /tmp/s1.sql
./build/tgdb_rel /tmp/s1.db startup                 # SIGSEGV

# F2 trigger (app's UPDATE params)
cp poc/telegram72799_schema.db /tmp/s2.db
./build/tgdb_rel /tmp/s2.db exec poc/s2_trigger_full.sql
./build/tgdb_rel /tmp/s2.db query 'UPDATE params SET seq=seq WHERE id=1'  # SIGSEGV

# F3 ASan-only
cp poc/telegram72799_schema.db /tmp/j.db
./build/tgdb_rel /tmp/j.db exec poc/json_uaf_params_view.sql
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 ./build/tgdb_asan_only /tmp/j.db startup

python3 matrix.py        # full matrix, writes logs/matrix.txt
```

Measured matrix (`logs/matrix.txt`; `-11` = SIGSEGV, `-6` = SIGABRT/ASan):

| engine | baseline | s1_view | s2_view | s1_trigger | s2_trigger | json_view |
|---|---|---|---|---|---|---|
| 3.39.3 release x86-64 | 0 | **-11** | **-11** | **-11** | **-11** | 0 |
| 3.39.3 ASan | 0 | ASan read | ASan UAF | ASan read | ASan UAF | ASan UAF |
| 3.50.2 ASan | 0 | 0 | 0 | 0 | 0 | 0 |
| 3.32.2 ASan | 0 | 0 | ASan UAF | 0 | ASan UAF | 0 (stock build has no JSON1) |
| 3.39.3 release aarch64 (qemu) | 0 | 0 | **-11** | 0 | **-11** | 0 |

Exact ASan/debug logs: `logs/s1_view_asan.txt`, `logs/s2_view_asan.txt`,
`logs/json_view_asan.txt`, `logs/s1_trigger_asan.txt`,
`logs/s2_trigger_asan.txt`, `logs/s1_debug.txt`, `logs/s2_debug.txt`.

---

## 7. Corrections to earlier notes (not editing the main report)

- `notes/db_native_parsers.md` says `#define SQLITE_OMIT_LOAD_EXTENSION 1`
  (`sqlite3.c:158`). That line is inside the **VxWorks** `#if` block; the
  Android build does not define it (no `OMIT_LOAD_EXTENSION` compile-option
  string in `libtmessages.49.so`). Extension loading is still unusable because
  the C API is never enabled, and `load_extension()` is rejected as unsafe in
  triggers/views.
- The same note lists **CVE-2024-0232** as in range. It is not: the JSON cache
  was introduced in 3.43; 3.39.3 cannot reproduce it.
- `cache4.db` is not opened by Android's system SQLite. Android 13's AOSP
  SQLite is 3.32.2; the 3.39.3 engine lives in `libtmessages.49.so`, so the
  update-survival argument must be made against the app's build, not the OS.
  The only `android.database.sqlite` reference in the 72799 dex is
  `org/telegram/messenger/voip/d0.java` (call audio), not the message store.

---

## 8. Limitations

- Host-only: the target arm64 Android/Scudo runtime was not executed. The
  aarch64 glibc cross-build under qemu is a proxy; F2 crashes there, F1 does
  not. F1's on-device crash probability therefore remains unquantified.
- Fuzzing was bounded and not coverage-guided; the negative result is not proof
  that no other bug exists in 3.39.3.
- The trigger vector depends on the app reaching `UPDATE params`; a fully
  offline first launch may not. The view vector is immediate.
- No attempt was made to weaponise F2's stale 1 MiB region with heap grooming
  beyond confirming there is no leak/write in the normal path.
- The app's `P1` migration SQL (ALTER TABLE/DROP TABLE on attacker-shaped
  tables) was not fuzzed. It is a separate ALTER TABLE surface and is avoidable
  by setting `user_version >= 181`; it is not needed for the PoCs above.

---

## 9. References

- `https://www.sqlite.org/cves.html` — CVE-2025-7458 (fixed 3.41.2/3.42.0),
  CVE-2025-6965 (fixed 3.50.2); “reads not writes” note in 3.41.2 release notes.
- Upstream check-in `b816ca9994e0` (2023-03-16), fossil
  `12ad822d9b827777526ca5ed5bf3e678d600294fc9b5c25482dfff2a021328a4`;
  test `test/distinct.test` 10.1.
- Upstream check-in `c52e9d97d` (2025-06-27), fossil
  `5508b56fd24016c13981ec280ecdd833007c9d8dd595edb295b984c2b487b5c8`.
- Upstream check-in `28001204f` (2024-03-05), fossil
  `952ed71b9b61e79fe807ac3134bdfa7c94a415e02f13f94440a34d6d548d171e`.
- SQLite forum `b25edc1d4662` — CVE-2024-0232 only affects the 3.43 JSON cache.
- Telegram 72799: `org/telegram/messenger/is.java:2232-2296`, `:879-895`;
  `jni/SqliteWrapper.cpp:142-154`; `jni/CMakeLists.txt:168-176`;
  `jni/sqlite/sqlite3.c` (md5 above).
- AOSP `android13-release` `external/sqlite/dist/orig/sqlite3.h` = 3.32.2.

---

## 10. Follow-up 2026-11-03 — `lab/sqlite_db_ace/` (libFuzzer + OSS-Fuzz corpus + device)

A second, bounded effort re-tested the same threat model with a coverage-guided
libFuzzer harness, a grammar-aware mutator, a 225-seed structured corpus, and a
replay of the OSS-Fuzz corpus (35,146 SQL scripts + 749 fuzz DB images) against
the exact 3.39.3 amalgamation.

**Result: still no write primitive and no RCE.**  New results:

- **Recursive VIEW chain (new, 3.39.3; fixed in 3.54.0 by check-in
  `9fb22519`, 2026-06-16).**  2,000+ chained views (`CREATE VIEW params AS
  SELECT * FROM v1`, `v1 → v2 → …`) exhaust the thread stack in
  `sqlite3ResultSetOfSelect` / `sqlite3ViewGetColumnNames` when the startup
  SELECT expands them.  Host release SIGSEGV; **the real beta device crashes
  at startup** (`storageQueue_0`, 512 frames in `libtmessages.49.so`,
  "likely stack overflow").  DoS only, no controlled write.
- **CVE-2025-7458 is device-confirmed** as a launch crash: under Scudo the
  512 KiB sorter over-read hits a protected page (SIGSEGV `SEGV_ACCERR`),
  unlike the earlier qemu/glibc run that survived.
- Campaigns: 1,548,163 libFuzzer executions (ASan+UBSan, value profile,
  including a 2-hour run over a 7,209-unit accumulated + structured corpus)
  produced **0 sanitizer artifacts**; the OSS-Fuzz replay produced 0 crashes.
- F2 (aggregate OOB) and the `json_each` UAF were re-reviewed: still reads /
  info exposure, no store through corrupt state.

Details, harness, tombstones and reproduction:
`lab/sqlite_db_ace/`, `notes/sqlite_db_ace.md`, and
`lab/sqlite_db_ace/runs/device/tombstone_summary.md`.
