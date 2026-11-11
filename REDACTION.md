# Redaction notice

This repository was scrubbed of account-identifying data before publication
to the private remote. The following placeholders replace values that were
present in earlier history:

| placeholder | meaning |
|---|---|
| `<BOT_USERNAME>` | Telegram bot handle used for widget delivery |
| `<TG_USERNAME>` | Telegram user handle used in a few runbooks |
| `<BOT_TOKEN>` | Bot API token (never committed; env `BOT_TOKEN`) |
| `<CHAT_ID>` | Telegram user/chat id used in tests |
| `<ACCOUNT_NAME>` | account display name shown in evidence notes |
| `<APP_UUID>` | iOS application data-container UUID |
| `<APPGROUP>` | iOS AppGroup UUID |
| `<UDID>` | device UDID / vendor identifier |
| `<SERIAL>` | device hardware serial |
| `<MAC>` | device Wi-Fi MAC address |
| `<ECID>` | Apple ECID |
| `<ACCOUNT_ID>` | Telegram account directory id |
| `<HOME>` | absolute path under the operator's home directory |
| `<LAN_IP>` | RFC1918 address of the lab host |
| `<TG_API_ID>` / `<TG_API_HASH>` | MTProto app credentials (env only) |

Consequences:

* Payload files were edited in place. Full-UUID replacements preserve byte
  length (zero UUID), so geometry/size calibrations remain valid, but **any
  SHA-256 or zlib9 value recorded in older notes refers to the pre-redaction
  artifact**. The current names, sizes and hashes are in
  [`docs/PAYLOAD_HASHES.json`](docs/PAYLOAD_HASHES.json), checked by
  `python3 scripts/verify_payloads.py`.
* Repository history was rewritten; the previous commits are not reachable
  from any ref in the rewritten repository. This does not prove that the
  remote server has garbage-collected the old packs. See
  [`docs/CRITIQUE_20261108.md`](docs/CRITIQUE_20261108.md) P0-08.
* Bot/MTProto scripts read credentials from the environment or from
  `bot/config.example.json`; no credential is stored in the tree.
* Two account labels were still present after the first scrub (`@...` in two
  dated reports and a chat display name in one instrumentation note). They are
  replaced by `<TG_USERNAME>` / `<ACCOUNT_NAME>`; the literal values must not
  be reintroduced.

The machine-readable evidence in `vulns/**/evidence/` keeps technical message
ids, offsets and crash data, with chat ids and device identifiers removed.
