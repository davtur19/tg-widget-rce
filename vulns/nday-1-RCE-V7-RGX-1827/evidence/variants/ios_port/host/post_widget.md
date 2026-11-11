# Posting a `tgwidget` rich message on iOS 13.2

The widget source is a **code block with language `tgwidget` inside a rich
message**.  A plain message with a `pre` entity stays a code block.

## A. Markdown paste (quickest)

Paste this into the composer (Saved Messages / your own test chat), with the
HTML from `probe_min.html` between the fences:

````text
# Probe

```tgwidget
<!doctype html>
... the whole HTML document ...
```
````

The iOS rich-text composer should turn the fenced block into a code block whose
language is `tgwidget`.  Send it, open the chat; the widget boots during the
bubble layout.

## B. Formatting UI

1. Compose a rich message (formatting button).
2. Insert a code block.
3. Set its language to `tgwidget` (if the UI exposes a language field).
4. Paste the complete HTML document.
5. Send.

If the composer does not let you set the language, the block will be syntax
highlighted as text and the widget will not run.

## C. Built-in widget test tool

Public reporting says the 13.2 beta shipped in-app widget testing tools.  Check
Debug Settings (tap the version/build row in Settings repeatedly if the Debug
menu is hidden) for "Message Widgets (tgwidget)" and a widget test screen.
This avoids the composer/language path entirely.

## D. DB patch (only if A/B/C fail or the payload is too large)

The message is stored in the Postbox `db_sqlite` (see
`ios_sideload/IOS_PROCEDURE.md §7` for the 13.1.2 layout).  On the jailbroken
6s with root SSH:

1. Dump the schema and find the table/column that stores the rich text block
   (`RichTextMessageAttribute`) and the message text.
2. Insert a test message with a small `tgwidget` block, then inspect the row.
3. Replace the block text with the payload; keep the serialized structure
   valid (lengths/checksums).
4. Restart Telegram and open the chat.

Do not guess the 13.2 schema: dump it first and keep a backup of `db_sqlite`.

## Size

`probe_min.html` is ~1 KB.  `probe_ctx.html` is ~2 KB.
`device_widget_ios_v1.html` is ~21 KB readable; `--minify` produces ~8.6 KB.
If the composer refuses it, test the limit with 4/8/16/32 KB blocks before
using the DB path.
