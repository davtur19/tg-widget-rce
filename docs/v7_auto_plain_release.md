# v7 auto-run plaintext release (target after Telegram stable)

Date: 2026-11-05. Status: artifact saved locally; **not sent to any bot**.
This is the post-release target: universal Android payload, no UI, auto-run
when the widget is rendered, plaintext.

## Size

| component | raw | zlib-9 |
|---|---:|---:|
| payload (release, minified) | 6,824 | 3,147 |
| minimal `<script>` wrapper | 6,856 | **3,170** |
| bot limit | — | 4,096 |
| **margin** | — | **926** |

Raw limit: 32,768; used 6,856; raw is not binding.

## What it contains

- class-64 primitive, nonce/magic guards
- arena O(1) runtime selection + list-walk fallback
- **ELF libc resolver** (`free -> system`), no fixed delta, no libc table
- writer/reader, PLT/GOT `js_free` path, command/hook
- C2 one-line connect command; the full C2 stays server-side

Removed vs v7: comments/DBG/RESULT, prototype-chain context fallback.
The prototype fallback is the less reliable method and is not needed for the
arena path.

## Caveats

- **Plaintext**: the bot/anyone with the widget reads the payload. Do not send
  it to the third-party bot until the code is public (post-stable release).
- No PIN/UI: it runs as soon as the widget is rendered. The widget body is
  otherwise empty; the message bubble may still be visible.
- 926 B zlib of headroom, ~2 KB raw at the payload's compression ratio.
  Not enough for an iOS endgame; iOS needs a separate payload.
- Not device-tested in this exact form. The encrypted exact v7 is the tested
  reference (proof 5457, DB patch).

## Files

- `lab/regexp1827_class64/device_payload_v7_release_auto.js` (source)
- `lab/regexp1827_class64/device_payload_v7_release_auto.min.js`
- `poc/loader_v7_auto_plain.html` (minimal wrapper, auto-run)
