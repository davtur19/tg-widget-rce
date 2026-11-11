#!/bin/bash
# Clean the bot chat (keep given ns=1 ids), push, relaunch, open chat.
# usage: cycle.sh [keep_ids]   (default 2 = tops test)
set -e
KEEP="${1:-2}"
D=/var/mobile/Containers/Shared/AppGroup/00000000-0000-0000-0000-000000000000/telegram-data/account-00000000000000000000/postbox/db
SSH="sshpass -f /tmp/opencode/ios_ssh_pass ssh -o StrictHostKeyChecking=no -o ConnectTimeout=8"
cd /tmp/opencode/ios_db_cycle
$SSH mobile@<LAN_IP> 'PID=$(ps aux | grep "/Telegram$" | grep -v grep | head -1 | tr -s " " | cut -d" " -f2); [ -n "$PID" ] && kill $PID; sleep 2; echo killed=$PID' || true
for f in db_sqlite db_sqlite-wal; do timeout 180 $SSH -o Compression=no mobile@<LAN_IP> "cat $D/$f" > $f 2>/dev/null || true; done
python3 /tmp/opencode/ios_wifi_tools/iosdb.py prune "$KEEP" db_sqlite 2>/dev/null
timeout 180 $SSH -o Compression=no mobile@<LAN_IP> "cat > $D/db_sqlite && rm -f $D/db_sqlite-wal $D/db_sqlite-shm && sha256sum $D/db_sqlite" < db_sqlite
$SSH mobile@<LAN_IP> 'uiopen --bundleid ph.telegra.Telegraph; sleep 3; uiopen --url "tg://resolve?domain=<BOT_USERNAME>"; sleep 4; ps aux | grep "/Telegram$" | grep -v grep'
