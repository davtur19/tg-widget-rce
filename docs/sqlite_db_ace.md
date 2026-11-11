# SQLite 3.39.3 in Telegram 72799 — DB-schema ACE attempt with libFuzzer

Date: 2026-11-03. Target: `org.telegram.messenger.beta` 13.2.0 (72799),
arm64, `lib/arm64-v8a/libtmessages.49.so`.
Lab: `lab/sqlite_db_ace/` (new; builds on `lab/sqlite_trigger_rce/`).
Question: **the first RCE can write `cache4.db` (app-private, app uid 10357).
Can a crafted schema — a VIEW named `params`, triggers, `sqlite_master`
content — produce a memory *write* / controlled write / code execution at the
next app start, with no user tap, in the bundled SQLite 3.39.3?**

---

## 0. Verdict

**No write primitive, no UAF-with-write, and no ACE were found.**  Every
reproducible memory-safety effect reachable from a crafted `cache4.db` in
3.39.3 is a **read** or **stack exhaustion**:

1. **CVE-2025-7458** (`DISTINCT` 65 results / 64 ORDER BY terms): 512 KiB
   heap over-read in `sqlite3VdbeSorterInit`.  Now **device-confirmed**: the
   shipped `libtmessages.49.so` dies with SIGSEGV/`SEGV_ACCERR` at startup
   (tombstone T2 below).  Read-only.
2. **Recursive VIEW chain** (new, fixed upstream 2026-06-16 by
   `9fb22519`, first release 3.54.0, 2026-10-09): a long chain of views
   (2,000 levels crash a 1 MiB stack; the 20,000-level PoC crashes the
   device) makes `sqlite3ResultSetOfSelect`/`sqlite3ViewGetColumnNames`
   recurse until the thread stack is exhausted.  **Device-confirmed** on the beta:
   `storageQueue_0`, 512 frames in `libtmessages.49.so`, "stack pointer is
   close to top of stack; likely stack overflow".  DoS, not a write.
3. CVE-2025-6965 (>32767 aggregate columns) and the `json_each` UAF were
   re-checked; both remain OOB/UAF **reads** with no destination pointer
   derived from the corrupt data (analysis in §5).

The campaign found **zero new sanitizer reports**:
35,146 OSS-Fuzz SQL scripts + 749 fuzz database images replayed clean;
**1,548,163 libFuzzer executions** over four coverage-guided campaigns
(ASan+UBSan, value profile, grammar-aware mutator), including a 2-hour run
with 7,209 accumulated + structured corpus units, with **0 artifacts**.
This is negative evidence, not a proof of absence, but it is consistent with
the upstream history: between 3.39.3 and 3.54.1 the only SQL-reachable
*write* CVEs are in components Telegram does not compile (FTS3/4/5, session,
RBU, concat_ws) or require multi-database super-journals.

The 2-hour extended campaign (D) specifically added write-path seeds
(REPLACE/UPSERT over overflow blobs, DELETE, WITHOUT ROWID upserts, generated
columns, INSTEAD OF triggers) plus recursive views/CTEs/window/JSON1 and
non-crashing N1/F1 boundary shapes; it added 539,751 executions and 6,107
coverage edges over C and remained clean.

The DB-schema attack is real and survives app updates as long as the app
keeps bundling 3.39.3, but it yields **launch denial of service**, not code
execution.

---

## 1. Reachability (unchanged, re-verified)

`hs.java` (72789/72799 beta dump) mirrors the earlier `is.java` analysis:

```
2219  this.f15942c = new File(h, "cache4.db");
2228  PRAGMA secure_delete = ON
2229  PRAGMA temp_store = MEMORY
2230  PRAGMA journal_mode = WAL
2231  PRAGMA journal_size_limit = 10485760
2233  PRAGMA user_version            -- 0 -> "malformed"
2241  SELECT seq, pts, date, qts, lsv, sg, pbytes FROM params WHERE id = 1
2242-2259  read the 8 columns (pbytes -> byte[])
2261  if (user_version < 181) P1(user_version)   -- migrations
```

- The SELECT runs **before** the migration check and **before any UI**.
  A `CREATE VIEW params(id,seq,pts,date,qts,lsv,sg,pbytes) AS …` executes at
  this point.  The view must expose `id` for the `WHERE id=1`.
- The app opens the DB on the **`storageQueue_0`** thread with the app uid
  (10357).  On this device that thread has a small stack: 20,000 view levels
  crash it.  The local 1 MiB-stack proxy crashes at 2,000 (1,000 survives);
  the device's `storageQueue_0` limit lies between 1,000 and 20,000 levels.
- A trigger on `params` fires on the app's periodic
  `UPDATE params SET seq=?,pts=?,date=?,qts=? WHERE id=1`; a `params` **view**
  with an `INSTEAD OF UPDATE` trigger fires on the same statement.  The
  error fallback also runs `CREATE TABLE IF NOT EXISTS params …` and
  `INSERT INTO params VALUES(1,0,…)` (`hs.java:2266-2267`), so an INSERT
  trigger is reachable too.
- `user_version >= 181` skips migrations; the app never drops views or
  triggers.  The schema is ordinary DB content, so it survives app updates
  and reboots.  The vulnerable engine is **app-bundled**, replaced only by an
  app update (Telegram has shipped 3.39.3 in every available build).

Device: Sony XQ-BT52, Android 13 (SDK 33), arm64, beta installed, `su`
(Magisk) available for the test harness only.  App uid 10357.

---

## 2. Harness

`lab/sqlite_db_ace/harness/tgfuzz.c` — libFuzzer target, exact 3.39.3
amalgamation (md5 `4039d3d3d015d3092dda140c0bb27f7d`), ASan+UBSan
(`-fsanitize=function` excluded: SQLite's intentional generic destructor
calls trip it on every statement), `-O1 -fno-strict-aliasing`.

Input: a SQL script (≤64 KiB).  Per input:

1. fresh `:memory:` connection + `sqlite3_deserialize()` of the stock
   `cache4.db` schema image (`base/tg_schema.db`, 239 sqlite_master objects,
   `user_version=181`);
2. `DROP TABLE IF EXISTS params` — the attacker replaced the stock table;
3. execute the input script statement-by-statement, continuing after
   ordinary SQL errors;
4. run the exact startup sequence (§1);
5. run the app's `UPDATE params …` and representative chat-list reads
   (`dialogs`, `messages_v2`, `users`, `chats`, `media_v4`,
   `user_settings`).

Top-level `ATTACH`/`DETACH` and `VACUUM` are denied/rejected by the harness:
a view or trigger cannot contain them, and an early campaign run showed they
only created stray files in the harness working directory (cleaned).  A
300 s confirmation campaign (C) over the accumulated corpus with the
hardened binary produced 0 artifacts (44,296 executions, cov 38,714); the policy does not change the
app-reachable surface.

Modes: `TGF_MODE=deser` (default; fresh schema per input) and `reuse`
(savepoint/rollback for speed; findings must be replayed before belief).
`TGF_BASE_DB` selects the full schema, a 512-byte-page copy, or a minimal
7-table schema for throughput.

`harness/tgfuzz_mut.c` adds a grammar-aware mutator (55 % default byte
mutations, 45 % token replace/insert, token-span duplication, and complete
clause splicing — ORDER BY / GROUP BY / HAVING / LIMIT / UNION ALL before the
terminating semicolon).  `seeds/sql.dict` has ~170 SQL keywords/functions.
`seeds/make_corpus.py` generates 225 valid seeds: Telegram-schema views,
DISTINCT boundary shapes, windows/frames, CTE/recursive CTE, JSON1,
`json_each`/`json_tree`, printf/CAST/COLLATE, RIGHT/FULL JOIN, compound
selects, generated columns, partial indexes, views-on-views, UPDATE/INSERT/
INSTEAD OF triggers, recursive triggers, and three `writable_schema` seeds.

For D, `seeds/make_corpus_long.py` adds 93 structured seeds: recursive VIEW
chains (50-700 levels, linear, explicit/expression variants), non-crashing
F1 boundary shapes (63/64, 64/64, 65/65, 66/65, 65/66, COLLATE variants),
recursive CTEs (linear/union/window/JSON/distinct), every window function with
named windows/FILTER/frames, JSON1 mutators and aggregates, generated-column
tables with indexes/UPSERT/CHECK, INSTEAD OF INSERT/UPDATE/DELETE and RAISE
triggers, REPLACE/UPSERT/DELETE write paths over 8-50 KB overflow blobs,
WITHOUT ROWID composite keys, and `writable_schema` type/rootpage probes.
The 7,209-unit D corpus is the deduplicated union of these 93, the 225 base
seeds, and the A/B/C accumulated corpora (60 MB, 3,804 merged inputs after
libFuzzer's own reduction).

`harness/tgreplay.c` is a fork-per-input replay driver (one process per input,
10 s alarm, ASan).  Two manifests from the **3.53.2** source tree's
`test/fuzzdata{1..8}.db` (which contains the OSS-Fuzz corpus up to 2026-06):
35,146 unique SQL scripts (`xsql` TEXT) and 749 database images (`xsql` BLOB).
SQL scripts run through the same schema+startup sequence; DB images are opened
with plain `sqlite3_open` (the app's path) and their whole schema is scanned.

Two main campaigns (A/B), a 312 s hardened confirmation (C), and an
extended 2-hour campaign (D) over an accumulated + structured corpus:

| campaign | base | mutator | forks | seconds | max_len | value profile |
|---|---|---|---|---|---|---|
| A | full Telegram schema (1 MB) | libFuzzer default + dict | 4 | 1800 | 65536 | yes |
| B | minimal schema (8.7 KB) | grammar-aware (`tgfuzz_gm`) | 2 | 1800 | 65536 | yes |
| C | full schema, hardened source | libFuzzer default + dict | 2 | 312 | 65536 | yes |
| D | full schema, hardened source | default + dict, 7,209-unit corpus | 4 | 7200 | 65536 | yes |

ASan options: `detect_leaks=0`, `allocator_may_return_null=1`,
`quarantine_size_mb=64`; UBSan recoverable in the campaign binary, a separate
`tgfuzz_ubsan` (`-fno-sanitize-recover`) for replay.

---

## 3. Campaign results

| campaign | executions | final cov (edges) | features | corpus units | artifacts |
|---|---|---|---|---|---|
| A (full schema, default+dict, 4 forks) | 670,760 | 38,473 | 136,732 | 3,045 | 0 |
| B (min schema, grammar mutator, 2 forks) | 293,356 | 38,442 | 179,325 | 3,971 | 0 |
| C (hardened, A's corpus, 2 forks, 312 s) | 44,296 | 38,714 | 137,689 | 2,427 | 0 |
| D (2 h, 7,209-unit accumulated+structured corpus, 4 forks) | 539,751 | 44,821 | 268,067 | 6,630 | 0 |
| **total** | **1,548,163** | | | | **0** |

A and B completed 1,800 s, C 312 s and D 7,231 s (`INFO: exiting: 0`);
none produced a sanitizer report, OOM, timeout or crash artifact, and the
hardened C/D working directories stayed empty (no stray ATTACH/VACUUM files).
D started at 43,704 edges (vs 38,714 at the end of C) and reached 44,821
(+6,107 over C) with a 6,630-unit final corpus.  UBSan was recoverable in
the campaign binary; a scan of all four logs finds zero `runtime error` lines.


Replay:

| corpus | inputs | crashes | timeouts |
|---|---|---|---|
| OSS-Fuzz SQL scripts (`fuzzdata1..8`, 3.53.2) | 35,146 | **0** | 9 (recursive/CPU-bound scripts) |
| OSS-Fuzz database images (`fuzzdata8` BLOBs) | 749 | **0** | 0 |

The two known-crash seeds (F1 `view_distinct_65`, F3 `json_each`) were kept
out of the corpus in `seeds/known/`; the harness reproduces both on demand
(§4), which validates that the startup path and sanitizer are live.

---

## 4. Findings

### N1 — Recursive VIEW chain: startup stack exhaustion (new, 3.39.3; fixed 3.54.0)

**PoC:** `poc/recursive_view_2000.db` (2 k levels),
`poc/recursive_view_20000.db` (20 k levels, device PoC).  Both are the stock
`cache4.db` schema with `params` replaced by:

```sql
CREATE VIEW v<N> AS SELECT 1 AS id,2 AS seq,3 AS pts,4 AS date,
       5 AS qts,6 AS lsv,7 AS sg,x'00' AS pbytes;
CREATE VIEW v<N-1> AS SELECT * FROM v<N>;
...
CREATE VIEW v1 AS SELECT * FROM v2;
CREATE VIEW params AS SELECT * FROM v1;
```

`SELECT … FROM params WHERE id=1` expands the chain in
`sqlite3ResultSetOfSelect` → `sqlite3ViewGetColumnNames` → `selectExpander` →
`sqlite3SelectPrep` with no nesting limit in 3.39.3.  Host release (8 MiB
stack): 20 k views → SIGSEGV; 2 k views → SIGSEGV at `ulimit -s 1024`
(1 k survives at 1 MiB).
Device: the real beta crashes in `storageQueue_0` with 512 repeated frames in
`libtmessages.49.so` and "Cause: stack pointer is close to top of stack;
likely stack overflow" (T1 in `runs/device/tombstone_summary.md`).

Upstream fix: check-in `9fb22519` (2026-06-16), first release **3.54.0** (2026-10-09),
adds `pParse->nNestSel` and rejects at `SQLITE_LIMIT_EXPR_DEPTH` (1000):
`VIEWs and/or subqueries nested too deep`.  Verified: the same 20 k-view DB
is rejected cleanly by a 3.54.1 ASan build (the fix first shipped in 3.54.0); 3.39.3 and 3.50.2 crash.

**Impact:** launch DoS from DB content alone, no SQL injection and no user
tap; survives updates while the app bundles 3.39.3.  **Not a write**: the
fault is a stack-limit fault (`SEGV_MAPERR` at the guard page); no attacker
value is written anywhere.

### N2 — CVE-2025-7458 is a launch crash on the real device

`poc/f1_view.db` is the 65-result/64-ORDER-BY `DISTINCT` view from the prior
lab.  Host ASan: `heap-buffer-overflow READ of size 524312` in
`sqlite3VdbeSorterInit` (source allocation 632 bytes).  On the beta:
SIGSEGV `SEGV_ACCERR` in `storageQueue_0`, process uptime 1 s (T2 in the
tombstone summary).  Scudo places the 512 KiB over-read across a protected
page, so the prior qemu/glibc "survives" result does not carry over to the
device: on this beta it is a device-confirmed launch crash (one run; the
exact Scudo placement can vary, but a 512 KiB over-read from a 632-byte
allocation has very little mapped headroom).

### N3 — Re-checked read primitives (no write)

- **CVE-2025-6965** (`AggInfo.aCol[negative iAgg]`, 1 MiB before the array):
  every use of the OOB `AggInfo_col` we inspected (`pTab`, `iColumn`,
  `iSorterColumn`, `iMem`) feeds a *source* in codegen or an affinity lookup;
  the aggregate register is consumed by `OP_Copy`/`OP_MakeRecord` as input.
  No path stores through a pointer derived from `pCol`.
- **json_each UAF** (`max(json)`): the stale text pointer is read by
  `memcmp` and may be returned as the aggregate result (info exposure), but
  the freed chunk is never written through.
- **F1's over-read KeyInfo**: the 524 KiB read lands in a 524 KiB
  destination, so the destination allocation is large enough; the copied
  `aColl` pointers could in principle reach `pColl->xCmp`, but the values are
  unrelated heap bytes, no address leak exists, and on the target the read
  faults before the sorter runs.  Not a demonstrated controlled call.

---

## 5. Why this is not a write primitive / ACE

- SQLite's SQL surface in this build cannot call `load_extension` (disabled
  and unsafe-in-schema), `writefile`/`readfile` (absent), ATTACH/VACUUM
  (not trigger statements), or any app-registered function (Telegram
  registers none through `SqliteWrapper.cpp`).
- Every reachable memory-safety bug in 3.39.3 that we can construct is a
  read, an OOB read fed into a source operand, or stack exhaustion.  A write
  needs either (a) an OOB *store* whose destination is derived from corrupt
  state, or (b) a UAF where the freed object is written through.  The
  campaign and the manual review found neither.
- Upstream fixes after 3.39.3 that *are* writes are out of reach: FTS3/4/5
  (not compiled), session/RBU/recover (not compiled), `concat_ws` (added
  3.44), super-journal (needs multiple attached DBs), CLI/recover extensions
  (not part of the app).
- DoS is not counted as ACE.  A launch crash from `cache4.db` is a real
  persistence primitive (the DB survives updates and reboots), but it does
  not run attacker code and cannot be upgraded to one from the primitives we
  found.

---

## 6. Device test

Performed with root `su` **only as a test harness** (the runtime premise
remains "no root/ADB at runtime"): the crafted DB is copied over the existing
`cache4.db` inode (owner/mode/SELinux context preserved), `-wal`/`-shm`
removed, `am force-stop`, `monkey … LAUNCHER 1`, tombstone captured, original
DB+WAL+SHM restored and the app restarted (pid alive, main-file md5
`1c2c45a720f53e97da28bbce6d171eea`).  Script: `device_test.sh`.

| test | DB | result |
|---|---|---|
| T1 | `poc/recursive_view_20000.db` | SIGSEGV SEGV_MAPERR, `storageQueue_0`, stack-overflow cause, 512 frames in `libtmessages.49.so`, 2 s uptime |
| T2 | `poc/f1_view.db` | SIGSEGV SEGV_ACCERR, `storageQueue_0`, 1 s uptime |

No user interaction was needed in either case.  Both are DoS, not ACE.  The
device logs are in `lab/sqlite_db_ace/runs/device/`.

---

## 7. Reproduction

```sh
cd lab/sqlite_db_ace
./build.sh
python3 seeds/make_corpus.py

# known read (host ASan) - validates the harness reaches the view
ASAN_OPTIONS=detect_leaks=0 ./build/tgfuzz_asan -runs=1 \
  seeds/known/known_f1_cve2025_7458.sql

# recursive-view DoS (host release; 3.39.3 SIGSEGV, 3.54.1 clean)
cd ../sqlite_trigger_rce
./build/tgdb_rel ../sqlite_db_ace/poc/recursive_view_20000.db startup

# device (destructive; restores automatically)
cd ../sqlite_db_ace
./device_test.sh poc/recursive_view_20000.db recview
```

---

## 8. Limitations

- Host fuzzing used the exact amalgamation but a host allocator; the device
  results cover the Scudo behaviour for the two concrete PoCs, not the whole
  fuzz corpus.
- The deserialized base image is converted to rollback-journal mode, because a
  WAL-mode (2/2) image cannot be deserialized into a `:memory:` database.
  The startup `PRAGMA journal_mode = WAL` is executed but returns "memory" on
  the memdb, so WAL recovery/checkpoint code is not fuzzed.  The attacker can
  also write `cache4.db-wal`/`-shm`; that surface was not structure-fuzzed,
  and the post-3.39.3 pager write fixes (super-journal, 2026-05) need multiple
  attached databases or an SMB/URI setup that this app does not use.
- The libFuzzer input cap is 64 KiB and inputs are SQL text.  A malicious DB
  file is not limited to 64 KiB (the 20 k-view PoC is 2.5 MB) and can also
  carry corrupt b-tree pages; the 749-image replay exercises that surface,
  but it is not a structure-aware DB-file fuzzer.  The prior lab's 20 k DB
  mutations plus this replay found no b-tree memory error.
- The migration path (`P1`) is skipped with `user_version >= 181`; it was not
  fuzzed.  It runs after the startup SELECT, so it cannot rescue a malicious
  view anyway, and its DDL is fixed by the app.
- The engine is app-bundled: an app update that bumps SQLite to ≥ 3.54.0
  would fix N1 and the two CVEs, but the DB schema itself would still
  survive.

---

## 9. References

- Lab: `lab/sqlite_db_ace/` (harness, corpus, manifests, campaign/replay
  logs, device tombstones).
- Prior lab and F1/F2/F3 details: `lab/sqlite_trigger_rce/`,
  `notes/sqlite_trigger_rce.md`.
- Upstream view-recursion fix: check-in `9fb22519` (2026-06-16), first
  release 3.54.0; verified with `sqlite-amalgamation-3540100` (3.54.1).
- CVE-2025-7458 fix: check-in `b816ca9994e0` (2023-03-16), release 3.41.2;
  CVE-2025-6965 fix: `c52e9d97d` (2025-06-27), release 3.50.2.
- OSS-Fuzz corpus: `sqlite-src-3530200/test/fuzzdata{1..8}.db`.
- Target: `lib/arm64-v8a/libtmessages.49.so`, BuildId
  `645cce3998197329915f6cbfcc9ffd7f124d9f86`, SQLite 3.39.3 source id
  `2022-09-05 11:02:23 4635f4a69c8c2a8df242b384a992aea71224e39a2ccab42d8c0b0602f1e826e8`.
