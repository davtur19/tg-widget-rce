# Audit: parser RCE: no root / no Frida / no debugger cheat

Date: 2026-11-07
Device: Sony XQ-BT52 (<SERIAL>), Android 13, Telegram beta 13.2.1 (72889), uid 10346
Artifact: `device/widget/c2560_final_c2560q_72889.html`; 8,120 B raw / 3,289 B zlib9
Payload SHA-256: `3f5f0474640fdc596de8283102d747b2be9d8afe78f4d61762ed965ab321d80a`
Proof: `/data/user/0/org.telegram.messenger.beta/files/n1`, 185 B,
`uid=10346(u0_a346) ... context=u:r:untrusted_app:s0:c90,c257,c512,c768`

## Verdict

> User note: the `frida-server` finding was a **false alarm**: it was the
> N1 server installed on the rooted Sony, not attached to the app. The audit
> keeps the clean re-runs as evidence, but there is no cheating finding.

The parser chain executes inside the Telegram app as **uid 10346
(untrusted_app)**, not as root. The app process has **CapEff=0**,
**TracerPid=0**, **Seccomp=2**, and no `su` policy in Magisk. The proof file
is owned by `u0_a346` with mode 600 in the app-private directory. The widget
contains no root/privilege/network API and the only libc call is `system`,
which runs in the app's uid.

A `frida-server` was running on the rooted Sony during the original 5/5
(it was installed for the N1 hook-assisted work). The app had no Frida maps,
no tracer, and no su policy, but to remove any doubt the server was stopped,
the magisk-frida module was disabled, and the final was re-run:

- **5/5 clean runs without Frida**: proof 185 B, md5
  `52258bc776f2f378542d1b2c736840e3`, app alive, `TracerPid=0`, `CapEff=0`,
  no `su`/`frida` process before or after execution;
- **1/1 no-root bot delivery**: the final was sent with the beta
  `sendWidget` API to the Sony account (chat <CHAT_ID>, mid <CHAT_ID>), the
  widget engine logged `zlib, 3289 -> 8120`, and the app (not root) wrote
  `n1` 185 B with the same md5.

The original root DB injection is a **harness/delivery** step only. The
no-root bot delivery proves the exploit does not need it.

## 1. What was audited

- The final widget HTML and its zlib payload.
- The Telegram app process during/after execution.
- The Magisk root policy and modules.
- Frida/debugger/injection artifacts.
- The proof file ownership, SELinux context and content.
- The exact root commands used by the certification harness.

## 2. Root usage inventory (exact)

### 2.1 Original 5/5 and clean 5/5 (DB harness)

Root (`su -c`) was used only for:

1. deploy: copy `cache4.db` into the app-private dir, remove `-wal`/`-shm`,
   `chown 10346:10346`, `chmod 600`,
   `chcon u:object_r:app_data_file:s0:c90,c257,c512,c768`;
2. cleanup: `rm -f .../files/n1` before a run;
3. evidence read: `cat .../files/n1`, `ls -la`, `stat`.

None of these commands contains the exploit command (`id>.../n1`), none
writes `n1`, and none is executed while the widget runs. The app is started
and stopped with `adb shell am ...` as uid 2000 (shell), not root.

### 2.2 No-root bot run

Root was used only to delete the previous `n1` before the run and to read
the new `n1` after it. The widget was delivered by the Telegram Bot API
(`sendWidget`, chat <CHAT_ID>, `is_shared=false`), not by adb or a root
shell. During the run:

- `ps -A | grep -E 'frida|(^| )su( |$)'` -> `NO_SU_NO_FRIDA`;
- app pid 29370, `Uid: 10346`, `Gid: 10346`, `CapEff: 0000000000000000`,
  `TracerPid: 0`, `Seccomp: 2`;
- logcat: `widget payload: zlib, 3289 -> 8120 bytes`;
- proof: 185 B, owner `u0_a346:u0_a346`, mode 600, md5
  `52258bc776f2f378542d1b2c736840e3`.

The `sendWidget` response was `ok=true`, `message_id=16679`; the prior
benign widget was `message_id=16678` (`zlib, 132 -> 140`).

## 3. Privilege evidence

App `/proc/<pid>/status` (clean runs and no-root run):

```
Name:   .messenger.beta
TracerPid: 0
Uid:    10346 10346 10346 10346
Gid:    10346 10346 10346 10346
CapEff: 0000000000000000
Seccomp: 2
```

Proof file:

```
-rw------- 1 u0_a346 u0_a346 u:object_r:app_data_file:s0:c90,c257,c512,c768 185 ... n1
10346 10346 600 185 2026-11-07 18:07:31.507995155 +0100
```

Magisk policy (`magisk --sqlite "SELECT * FROM policies"`):

```
uid=2000|policy=2|until=0|logging=1|notification=1
```

Only shell uid 2000 is allowed; **uid 10346 has no policy**, so the app
cannot invoke `su` successfully.

Platform:

```
SELinux: Enforcing
ro.debuggable=0
ro.secure=1
ro.build.type=user
package flags: no DEBUGGABLE
```

Magisk: `31100` / `31.1:MAGISK:R`. Modules:
`crashblock` (hosts only, no Zygisk), `magisk-frida` (Zygisk=no; disabled
after the audit). No Xposed/LSPosed/Riru/Zygisk injection module.

## 4. Frida / debugger audit

Finding: `frida-server` PID 3999 was running as root and listening on
`127.0.0.1:27042`; starttime tick 2497 vs uptime 12517, i.e. it started at
boot + ~25 s (14:35), before the original 5/5 at 17:57-18:00. The module
`magisk-frida` 17.26.1-1 (`service.sh`) starts it on boot.

However, during/after the certified execution:

- app `/proc/<pid>/maps`: no `frida`, `gadget`, `magisk`, `xposed`,
  `substrate`, `lspd` or `riru` mapping;
- `TracerPid=0` (no debugger/ptrace attach);
- `CapEff=0`;
- no `su` policy for uid 10346;
- `frida-server` service log contains only startup, no attach/session;
- libtmessages is loaded from `/data/app/.../lib/arm64/libtmessages.49.so`;
  libc is the stock APEX `bionic/libc.so`, not a Magisk overlay.

Remediation and re-run:

1. `kill 3999` + `pkill -f frida-server`; verified
   `NO_FRIDA_PROCESS` and `NO_FRIDA_LISTENER` (no 27042).
2. `touch /data/adb/modules/magisk-frida/disable` (module disabled for the
   next boot; no respawn in the session).
3. Clean 5/5: runs 18:04:58, 18:05:27, 18:05:56, 18:10:56, 18:11:24;
   each `NO_SU_NO_FRIDA` before/after, `TracerPid=0`, `CapEff=0`, proof
   185 B same md5.
4. No-root bot run 18:07:30: same checks, proof 185 B same md5.

Conclusion: the original 5/5 had a Frida **server** present, but the app had
no Frida **attachment**. The clean 5/5 and the no-root run are the
authoritative no-Frida evidence. The parser chain does not depend on Frida.

## 5. Static widget audit

Checks on the exact final HTML:

- sizes: raw 8,120 (limit 32,768), zlib9 3,289 (limit 4,096);
- DB blob 3,364 B; the engine log shows `zlib, 3289 -> 8120`;
- API tokens: `fetch` 0, `XMLHttpRequest` 0, `WebSocket` 0,
  `importScripts` 0, `navigator` 0, `console` 0, `print` 0, `Function` 0,
  `WebAssembly` 0, `SharedArrayBuffer` 0, `Atomics` 0;
- `document`/`window` once each (DOM marker), `eval` once (the parser 0day
  entrypoint);
- no `su`, `magisk`, `frida`, `ptrace`, `setuid`, `setgid`, `chmod`,
  `chown`, `mount`, `insmod`, `/system/bin`, `/data/adb`, `run-as`,
  `debugger`, `xposed`, `lsposed`, `zygisk`;
- the only command string is
  `id>/data/data/org.telegram.messenger.beta/files/n1` (50 B);
- `system` is found by scanning libc `.dynsym` from the runtime pointer;
  no hardcoded libc base, no `/proc/self/maps` read, no per-device address;
- the call is a normal libc `system` in the app uid; `id` output confirms
  `uid=10346`, not root.

## 6. Environment / root influence

- `crashblock` is a hosts-only module (no Zygisk); it does not inject code.
- `magisk-frida` is now disabled; frida-server stopped.
- SELinux is Enforcing, not permissive.
- The app is not debuggable and has no `run-as` path.
- The root shell is uid 2000 with an su policy; the app is uid 10346 with
  no su policy and no capabilities.
- Root can read the app-private proof for evidence, but cannot make the
  app process execute as root: the proof's owner/context and the `id`
  output show the app uid.

## 7. Reproducibility summary

| series | runs | Frida | delivery | proof |
|---|---:|---|---|---|
| original | 5/5 | server running, not attached | root DB harness | 185 B, same md5 |
| clean | 5/5 | stopped/disabled | root DB harness | 185 B, same md5 |
| no-root | 1/1 | stopped/disabled | bot `sendWidget` mid 16679 | 185 B, same md5 |

All proofs: `uid=10346`, `untrusted_app`, md5
`52258bc776f2f378542d1b2c736840e3`.

## 8. Residual caveats

1. The DB harness still uses root to place the test message. This is a
   delivery choice, not exploit privilege; the no-root bot run removes the
   caveat for the exploit itself.
2. The no-root run used root to delete the previous proof and to read the
   new proof; neither action executes the payload. The proof file is created
   by the app.
3. The parser proof is the `id` line only (no `MEGARCE`): the 50-byte
   command is bounded by the 64-byte forged AB data block.
4. The bot `sendWidget` path sends the HTML through Telegram's beta Bot API
   to the user's own bot/account; that is the intended delivery vector, but
   it is an external exposure of the payload.
5. The iOS 6s was not part of this audit; its jailbreak/root usage will be
   audited separately before any iOS proof is claimed.

## 9. Reproduce

```bash
# static
sha256sum device/widget/c2560_final_c2560q_72889.html
python3 - <<'PY'
import zlib
d=open('device/widget/c2560_final_c2560q_72889.html','rb').read()
print(len(d), len(zlib.compress(d,9)))
PY

# runtime
adb -s <SERIAL> shell 'pidof org.telegram.messenger.beta'
adb -s <SERIAL> shell 'cat /proc/<pid>/status' | grep -E 'Uid|Gid|CapEff|TracerPid|Seccomp'
adb -s <SERIAL> shell "su -c 'magisk --sqlite \"SELECT * FROM policies\"'"
adb -s <SERIAL> shell "su -c 'ls -laZ /data/user/0/org.telegram.messenger.beta/files/n1'"
adb -s <SERIAL> shell "ps -A | grep -iE 'frida|(^| )su( |$)'"
```

## 10. Evidence paths

- `device/logs/device_parser_rce/CERTIFICATION_5of5.md`
- `device/logs/device_parser_rce/proof_run1..5.txt` (original)
- `device/logs/device_parser_rce/clean_nofrida/proof_run1..5.txt`
- `device/logs/device_parser_rce/clean_nofrida/run1..5.log`
- `device/logs/device_parser_rce/noroot_bot/proof_run1_id.txt`
- `device/logs/device_parser_rce/noroot_bot/bot_send_run1.json`
- `device/logs/device_parser_rce/noroot_bot/run1.log`
- `device/logs/device_parser_rce/noroot_bot/after.png` (screenshot capture)
