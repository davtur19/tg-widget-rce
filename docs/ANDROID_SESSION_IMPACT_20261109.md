# Android session impact — package (2026-11-09)

Status: **live-proven on 72929 (app-level)**; 72989 still requires the
app-process escape. No 72989 session claim yet.

## What it does

After app-process code execution as UID 10346, the package reads the Telegram
session/account files and exfiltrates them over a LAN socket:

| file | role |
|---|---|
| `files/tgnet.dat` (+`.bak`) | MTProto session: v5 record, per-DC 256-byte `authKeyPerm` + id, temp keys, DC address, salts. |
| `files/cache4.db` (+WAL/journal) | plain SQLite; users/chats/dialogs/messages and `enc_chats.authkey`/`fauthkey`. |
| `shared_prefs/userconfing.xml` | account identity TL blob, passcode hash/salt/type, push auth key, tmp password. |
| `shared_prefs/userconfig<N>.xml`, `mainconfig<N>.xml`, `saved_tokens*.xml` | per-account identity/settings/auth blobs. |
| `files/account<N>/tgnet.dat`, `cache4.db`, `file_to_path.db`, `stats2.dat` | per-account session/DBs. |

The app-lock is `md5(pass)` or `sha256(salt‖pass‖salt)`; it does not encrypt
the DB or the MTProto credential. The isolated process (UID 99xxx,
per-generation; `isolated_app`) cannot read these files; the package
requires the app process.

## Artifacts

Canonical package: `telegramandroidwidget/lab/android_session_impact/`
(symlinked as `lab/android_session_impact/`). Hashes in `MANIFEST.json` /
`SHA256SUMS`; `host/verify_artifacts.py` rebuilds/verifies.

| artifact | bytes | sha256 |
|---|---:|---|
| `c2560s_session_lan_72929.html` | 9,946 | `93049271065070a0a44880106156bfcc06a185293c87403f686a1be252b1f273` |
| `session_s1.sh` | 4,292 | `59a9b569de78a401061f245d4bd3fbb52ea3233a11528de4c528c53da1008303` |
| `session_s1_all.sh` | 4,288 | `4f70a374dc832b5ee48916271958f6f6d0bbbc35d80ca3af1f74240368fd803a` |
| `session.dex` | 8,976 | `0a0446bba27a05e0c504374e99694a800f5a226f3bdcd9206d52be91d941e974` |
| `session_java_s1.sh` | 13,405 | `820dae853ae23524fdf3ae99a3937bc4b1d1c5006f235b2bdb1f2f13bf0131fe` |

Routes: shell stealer (app-UID `sh`, HELLO/F-size/bytes/H-sha256/END),
Java `app_process` stealer (`session.dex`), or the existing C2 loader for an
interactive `get`. The widget is the same parser 0day + c2560s stage B; only
the 50-byte `system()` literal changed to the LAN bootstrap. A/C bytes are
identical to the device-proven c2560s source.

## Precondition

- **72929/72889**: parser RCE in the app process is device-proven; Phase A
  live test can read the session directly.
- **72989**: the widget runs in UID 99024 (`isolated_app`); app data is not
  readable. The package is a **post-escape** payload. The isolated process
  itself cannot read the session; the W2 app-process escape is still the
  missing step.
- **iOS**: a separate session-impact stream is in progress.

## Live test

`LIVE_TEST_session_impact.md`:
- Phase A on 72929/72889: install the lab baseline, send
  `c2560s_session_lan_72929.html`, run `session_s1.sh`; expect
  `HELLO uid=10346` + the three files with verified hashes; LAN only.
- Phase B on 72989: isolated negative control; no session read expected.
- Phase C: post-escape, conditional.
- Rotate the test session after the proof; no third-party tunnels.

## Live Phase A — 72929 (2026-11-09)

The 72929 app-level baseline was live-tested on the Sony (versionCode 72929,
UID 10346, data/login preserved across the `-r -d` downgrade — the final
downgrade-based run; the campaign rule now forbids `-d` installs, see
OBJECTIVE_20261109.md).

**Environment:** the lab Sony is rooted and has Frida installed. The payload
does not call root or Frida; adb is used only for the lab install. This is a
lab baseline; a stock-device run is still required for the final claim.

Delivery: beta `sendWidget` from the <BOT_USERNAME> token to the confirmed
account chat; `c2560s_session_lan_72929.html` (9,946 B raw, zlib9
4,028); LAN receiver `<LAN_IP>:5555/5556`; `session_s1_all.sh` (4,288 B).

```
HELLO tgsess uid=10346 ctx=u:r:untrusted_app:s0:c90,c257,c512,c768 mode=all
END
```

| file | bytes | SHA-256 |
|---|---:|---|
| `files/tgnet.dat` | 5,176 | `a5aa8871231fcae15bdb8707931c6ca2de035efca84202f1164b8df93404bbc9` |
| `shared_prefs/userconfing.xml` | 5,550 | `04719231b75407da25770bfd9e1c194738287f83185315965a3b6417d4df5f4a` |
| `files/cache4.db` | 10,199,040 | `9b87711ac5dbef761b70c1060e733f1003b06b42228056ba876ec0b7a3c487e5` |
| `files/cache4.db-wal` | 4,231,272 | `b5c3ea7eec21e1cb62824ee5244aa1f325e8234cf2c23c06b2be725918805acf` |

Also collected: `mainconfig.xml`, `saved_tokens_login.xml`, per-account
`tgnet.dat`/`userconfigN`/`mainconfigN`/`cache4` DBs, `file_to_path.db`.
Parsed: `tgnet.dat` v5; **DC1/DC2/DC5 authorized with 256-byte
`authKeyPerm`**, DC4 unauthorized; `userconfing` self id present,
`passcodeType 0`; `cache4.db` SQLite/WAL, 97 tables, 1,876 users / 385 chats
/ 446 dialogs / 2,616 messages. App alive.

Acceptance: `HELLO uid=10346` PASS; auth keys PASS; userconfing PASS; DB
header/counts PASS; all received SHA-256 PASS; app alive PASS.

**Rotation:** waived by the owner — these are test accounts. The 72929 UI
has no Log out row; the raw files stay in the lab at mode 600 (not committed)
for evidence, and the exfiltrated key is not used further.

This is the **72929 app-level** proof. On 72989/73029 the widget runs in the
isolated process (UID 99xxx, per-generation; `isolated_app`) and the session
still requires the app-process escape. The current-build APK is
`lab/artifacts_20261108/escape_host/tg73029.apk` (updated 2026-11-09 16:27;
the 72989 APK remains in the canonical
`telegramandroidwidget/lab/artifacts_20261108/escape_host/` tree). No
downgrade reinstall is planned; the APK serves the harness-verification run.

## Host validation

`host/self_test.py`: **26/26 PASS** on a synthetic 12-file fixture — shell
and Java modes, `app_process` delivery, dex hash, widget through the real
QuickJS sibling harness (`HF OK` → `system()` → loader → script), exact
48-character LAN command. Every received file matched its fixture SHA-256.

## Bot-return stealth variant (documented 2026-11-10)

The 72929 package returns over a LAN socket (`HELLO/F/H/END`,
5555/5556). Android has no iOS-style Local Network permission prompt, but
the LAN receiver is a distinct observable (and may be blocked); a stealthier
variant returns through the same bot that delivers the widget.

- The app-side Java `app_process` stealer (`session_java_s1.sh`/
  `session.dex`) runs as UID 10346 and can POST `files/tgnet.dat`,
  `shared_prefs/userconfing.xml`, `files/cache4.db` (+WAL) to the Bot API
  `sendDocument`/`sendMessage` with `HttpsURLConnection`/OkHttp, using the
  attacker’s bot token; the attacker reads the documents in the bot chat.
  No LAN socket; the traffic is the app’s normal HTTPS.
- The shell mode can use `toybox wget`/`curl` if the build’s HTTPS support
  permits; the Java mode is the reliable path. The bot delivery is already
  the `sendWidget`; the same bot can receive.
- Limits: the Bot API document limit is 50 MB; the session files
  (`tgnet.dat` 5,176 B, `userconfing.xml` 5,550 B, `cache4.db` 10,199,040 B)
  fit; the bot token must be in the app-side script; the bot chat is the
  attacker’s. The app UID 10346 reads the files; the app’s network is normal.
- Status: the 72929 LAN proof is device-proven; the **bot-return is a
  variant/idea, not yet device-proven**. It needs the same app-process code
  exec; on 73029 that escape is still missing. It improves stealth and
  portability but does not change the escape.
- iOS equivalent: `IOS27_SESSION_IMPACT_20261109.md` “Bot-return
  exfiltration” — the widget request/answer channel is small/paced; direct
  Bot API `sendDocument` needs return-to-JS/CFNetwork; the Android Java path
  is more direct.

## Claim boundary

No live session read on 72989, no 72989 escape, no new 0day/CVE, and no
reliability/speed number are claimed here. The 72929/72889 session proof is a
lab baseline on a rooted/Frida-installed device: the payload did not use
root/Frida and adb was only the install path, but a stock-device run is still
required. It is not the 72989 isolated escape.
