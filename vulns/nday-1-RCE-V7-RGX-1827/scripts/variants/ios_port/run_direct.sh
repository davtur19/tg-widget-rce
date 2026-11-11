#!/usr/bin/env bash
# Host-only one-shot: IPA -> analyzed -> iOS payload + widget HTML.
#
#   ./run_direct.sh /path/to/Telegram_13.2.0_decrypted.ipa
#
# It does NOT touch the device.  The last lines are the orchestrator's next
# steps (post the widget, launch under DVT --stream).

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
IPA="${1:-$ROOT/ios_sideload/Telegram_13.2.0_decrypted.ipa}"
VENV="${VENV:-$ROOT/ios_sideload/venv/bin/python}"

if [ ! -f "$IPA" ]; then
  echo "missing IPA: $IPA" >&2
  echo "decrypt Telegram 13.2.0 on the 6s (TrollDecrypt) and pull it first." >&2
  exit 2
fi

echo "== 1. static triage =="
"$VENV" "$HERE/analyze_bundle.py" --ipa "$IPA" --stubs | tee /tmp/ios_port_triage.txt

echo
echo "== 2. build iOS payload + widget =="
"$VENV" "$HERE/make_ios_payload.py" --ipa "$IPA" \
  --out "$HERE/device_payload_ios_v1.js" \
  --html-out "$HERE/device_widget_ios_v1.html"

echo
echo "== 3. host checks =="
node --check "$HERE/device_payload_ios_v1.js"
node "$HERE/test_endgame_node.js"

echo
echo "== 4. next (orchestrator, device) =="
cat <<EOF
  1. Post $HERE/device_widget_ios_v1.html as a tgwidget rich message
     (Saved Messages / own test chat).  If the composer rejects it, use the
     DB-patch path; dump the Postbox schema first.
  2. Launch with stdout attached:
       pymobiledevice3 developer dvt launch 'ph.telegra.Telegraph' \\
         --kill-existing --stream
  3. Open the chat with the widget.  Expect:
       #iosout: RT=... / IOS_HOOK_PRINTF ... / IOS_OK ...
       stdout:  IOSPORT_R1827_OK
  4. If it stops earlier, the #iosout marker names the stage; pull the crash
     log with: pymobiledevice3 crash pull /tmp/opencode/tg_crashes --match Telegram
EOF
