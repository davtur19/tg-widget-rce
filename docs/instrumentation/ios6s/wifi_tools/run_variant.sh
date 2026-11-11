#!/bin/bash
# usage: run_variant.sh <name> <html> <pid>
NAME="$1"; HTML="$2"; PID="$3"
cd /tmp/opencode
echo "=== deliver $NAME ==="
timeout 200 ./frida1717/bin/python deliver_n1_wifi.py --pid "$PID" --html "$HTML" --chat-peer 0 --capture-printf --settle 20 2>&1 | tail -3
sleep 5
ALIVE=$(timeout 30 sshpass -f /tmp/opencode/ios_ssh_pass ssh -o StrictHostKeyChecking=no -o ConnectTimeout=8 mobile@<LAN_IP> 'ps aux | grep "/Telegram$" | grep -v grep | wc -l' 2>/dev/null)
echo "app_alive=$ALIVE"
if [ "$ALIVE" != "1" ]; then echo "NO_SCREENSHOT_APP_DEAD"; exit 2; fi
OUT=$(timeout 60 ./frida1717/bin/python ios_wifi_tools/run_js.py --pid "$PID" --js ios_wifi_tools/shot_now.js 2>&1 | grep -o '"v": "[^"]*png"' | tail -1 | cut -d'"' -f4)
echo "shot=$OUT"
[ -z "$OUT" ] && { echo "NO_SCREENSHOT"; exit 3; }
timeout 60 sshpass -f /tmp/opencode/ios_ssh_pass ssh -o StrictHostKeyChecking=no -o ConnectTimeout=8 mobile@<LAN_IP> "cat $OUT" > /tmp/opencode/ios_wifi_shots/${NAME}_result.png
ls -la /tmp/opencode/ios_wifi_shots/${NAME}_result.png
