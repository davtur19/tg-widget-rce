# Widget bot limits — measured through <BOT_USERNAME>

> **Status (2026-11-09):** the values below are **lab measurements** and match
> the official limits. Official (`sendWidget` / Telegram Widgets guide):
> `html` is 1-32,768 bytes and at most 4,096 bytes after zlib at the maximum
> compression level; a NUL byte is refused with
> `INPUT_MEDIA_WIDGET_HTML_INVALID`; anything over the limits is refused with
> `INPUT_MEDIA_WIDGET_TOO_LARGE`. Related official limits not probed here:
> `public_data`/`chat_data` 0-1,024 bytes each, caption 0-1,024 characters,
> request `data` 1-64 bytes, answer `data` 0-1,024 bytes, 15 s answer window,
> 5 requests / 5 s per user and bot.

Date: 2026-11-05. Client: Telegram Android beta 13.2.0 (72879), Sony XQ-BT52.
Bot: `<BOT_ID>` (`<BOT_USERNAME>`, "Widget Bot").
All probes were generic demo HTML (colored box / single letter); no exploit
code, payload strings, PIN, C2 or project identifiers were sent to the bot.

## Result

The bot enforced **two independent limits** on a `.html`/`.txt` upload (lab):

| limit | lab value | accept | reject | official |
|---|---:|---|---|---|
| raw file size | **32,768 B (32 KiB)** | 32,768 B | 32,769 B | 1-32,768 bytes |
| compressed widget payload | **4,096 B zlib-9** | 4,096 B | 4,097 B | ≤ 4,096 bytes zlib, maximum compression level |

Both are byte limits. The compressed value is `len(zlib.compress(file, 9))`,
not gzip and not raw size. The accept/reject boundaries are lab measurements;
the official limits agree with them (the server compresses and checks).

## Probe matrix

| file | raw | zlib-9 | result |
|---|---:|---:|---|
| demo_a.html | 339 | 233 | accepted |
| demo_b.html | 65,732 | 261 | rejected: `the file must be text (.html/.txt) up to 32 KB` |
| demo_raw32768.html | 32,768 | 234 | **accepted** (widget rendered) |
| demo_raw32769.html | 32,769 | 234 | rejected: `up to 32 KB` |
| demo_z4096.html | 5,371 | 4,096 | **accepted** |
| demo_z4097.html | 5,372 | 4,097 | rejected: `INPUT_MEDIA_WIDGET_TOO_LARGE` |
| demo_js4096.html | 5,369 | 4,096 | **accepted** (JS-heavy, no separate JS gate) |
| demo_js32768.html | 32,768 | 233 | **accepted** (JS-heavy at raw boundary) |

The 64 KiB file proves the raw check is independent of compression: its zlib
payload was only 261 B and it was still rejected.

## Error strings

- raw overflow: `Could not build a widget: the file must be text (.html/.txt) up to 32 KB` (lab; widget-builder path)
- compressed overflow: `Could not build a widget: INPUT_MEDIA_WIDGET_TOO_LARGE` (lab)

Official Bot API errors: over either limit → `INPUT_MEDIA_WIDGET_TOO_LARGE`;
a NUL byte in the HTML → `INPUT_MEDIA_WIDGET_HTML_INVALID`.

## Practical ceiling

For one widget message, the payload must satisfy **both**:

```
raw  <= 32768
zlib9(raw) <= 4096
```

Official: "at most 32768 bytes of UTF-8 HTML and at most 4096 bytes after the
server compresses it with zlib at level 9." A file can use the full 32 KiB raw
budget only if it compresses to <= 4 KiB.
There is no separate HTML-vs-JS size gate: an HTML file that is mostly
`<script>` behaves exactly like markup. The text-message route is additionally
bounded by Telegram's own 4,096-character message limit.

For a multi-message split, the budgets are per message: N messages give at most
N * 32 KiB raw and N * 4 KiB zlib, and every part must independently pass both
checks.
