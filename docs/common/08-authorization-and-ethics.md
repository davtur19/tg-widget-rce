# Authorization and ethics

This is security research on software the researcher uses. The rules below are
not decoration; they are what makes the work legitimate.

## Scope

- All device tests were performed on devices **owned by the researcher** and
  on accounts **controlled by the researcher**.
- The devices were physically present, unlocked, and connected over USB or the
  researcher's own Wi-Fi.
- No third-party phone, account, chat, or service was targeted.
- No payload was sent to a person who did not ask for it. Bot delivery went to
  the researcher's own test chat.
- The C2 servers bind to loopback or the researcher's private LAN and accept
  only local peers. No public tunnel, no relay, no cloud service.
- The iPhone 17e is a stock device. Its n-day fallback was run with the
  researcher's own account. The 0day work on it is local instrumentation and
  delivery only.

## What not to do

- Do not run these payloads against someone else's device, account, or bot.
- Do not publish a working exploit for the unreported parser bug before the
  vendor has had a chance to fix it.
- Do not include bot tokens, session files, private keys, or account databases
  in a repository, a chat, or a bug report.
- Do not use a public tunnel to expose the C2. The project explicitly rejects
  localhost.run, ngrok, cloudflared quick tunnels, serveo, pinggy, and similar
  services.
- Do not turn a proof-of-concept into a persistence tool. The Android implants
  in the reference logs survive an app crash but not `am force-stop` or a
  reboot. That limit is intentional and documented.

## Disclosure

The parser bug (`ARG_SCOPE_END`) is unreported at the time of writing. The
responsible path is:

1. Confirm the bug against the current upstream source and the shipped app.
2. Write a minimal reproducer and a clear impact statement.
3. Contact the vendor's security channel (Telegram) and, if appropriate, the
   QuickJS-ng maintainers.
4. Agree on a disclosure date.
5. Publish the technical details only after the fix or the agreed date.

Do not open a public issue with a working exploit. Do not attach the device
payloads. A minimal reproducer and a stack trace are enough for a first
contact.

The n-day (`#1827`) is already public. It can be discussed, but it should still
not be used against third parties.

## Data handling

- The repository contains no bot token. The senders read `BOT_TOKEN` from the
  environment or take `--token` on the command line.
- The repository contains no Telegram session database, no `token.env`, no
  `cache4.db`, no APK, and no native library.
- The C2 logs are trimmed to the proof lines. They do not contain message
  contents, contact lists, or account credentials.
- Device identifiers in the logs are the lab devices. They are not secrets, but
  they are not needed to reproduce the work; replace them with placeholders if
  you republish.

## Legal

Computer misuse law differs by country. Running an exploit against a device you
do not own can be a crime even if the payload is harmless. If you are unsure,
stop and ask. The authors of this repository do not authorize any use against
systems they do not own.

## Reporting a mistake

If you find a claim in this repository that does not match its evidence, open an
issue with the marker, the log, and the payload hash. Correct the record; do not
quietly delete the failed run. The negative results are part of the value of the
repository.
