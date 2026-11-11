#!/usr/bin/env bash
# Read-only pull plan for the iPhone 6s (iOS 15.6, Dopamine, root SSH).
#
# The orchestrator owns live device operations.  This script is dry-run by
# default: it prints the exact commands.  Add --execute to run them.
#
#   DEV=root@<LAN_IP> ./ssh_pull.sh
#   DEV=root@<LAN_IP> OUT=/tmp/opencode/ios_port_pull ./ssh_pull.sh --execute
#
# It never installs, launches, or modifies anything on the device.

set -u

DEV="${DEV:-root@<LAN_IP>}"
OUT="${OUT:-/tmp/opencode/ios_port_pull}"
EXEC=0
[ "${1:-}" = "--execute" ] && EXEC=1

run() {
  echo "+ $*"
  [ "$EXEC" = 1 ] && "$@"
}
rsh() {
  echo "+ ssh $DEV \"$*\""
  [ "$EXEC" = 1 ] && ssh "$DEV" "$*"
}

mkdir -p "$OUT"

echo "== 0. host/device preflight =="
rsh 'uname -a; sw_vers 2>/dev/null; echo; id'
rsh 'ls -l /bin/sh /var/jb/bin/sh /var/jb/usr/bin/sh 2>&1'
rsh 'ls -d /var/jb 2>&1; ls /var/jb/usr/sbin/frida-server 2>&1'
rsh 'dpkg -l 2>/dev/null | grep -Ei "dopamine|ellekit|frida|trollstore|openssh" | head -20'

echo
echo "== 1. installed Telegram bundle =="
rsh 'ls -d /var/containers/Bundle/Application/*/Telegram.app 2>/dev/null'
rsh 'for p in /var/containers/Bundle/Application/*/Telegram.app; do echo "== $p"; /usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$p/Info.plist" 2>/dev/null; /usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$p/Info.plist" 2>/dev/null; /usr/libexec/PlistBuddy -c "Print :CFBundleVersion" "$p/Info.plist" 2>/dev/null; /usr/libexec/PlistBuddy -c "Print :MinimumOSVersion" "$p/Info.plist" 2>/dev/null; done'

echo
echo "== 2. data / app-group containers =="
rsh 'ls -d /var/mobile/Containers/Data/Application/* 2>/dev/null | head'
rsh 'find /var/mobile/Containers/Shared/AppGroup -maxdepth 2 -name telegram-data -type d 2>/dev/null'
rsh 'find /var/mobile/Containers/Data/Application -maxdepth 3 -name "*.sqlite" -o -maxdepth 3 -name "db_sqlite" 2>/dev/null | head'

echo
echo "== 3. decrypted IPA / .app already on device =="
rsh 'find /var/mobile /private/var/mobile /tmp -maxdepth 4 -iname "Telegram*.ipa" -o -maxdepth 4 -iname "Telegram_decrypted*" 2>/dev/null | head -20'
rsh 'ls -l /var/mobile/Documents 2>/dev/null | head'

echo
echo "== 4. dyld shared cache (for libc offsets/gadgets) =="
rsh 'ls -l /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64* 2>/dev/null'

echo
echo "== 5. crash reports =="
rsh 'ls -lt /var/mobile/Library/Logs/CrashReporter/ 2>/dev/null | grep -i telegram | head -10'

echo
echo "== 6. example pulls (uncomment/execute manually) =="
cat <<EOF
# IPA (if TrollDecrypt wrote one):
#   scp "$DEV:/var/mobile/Documents/Telegram_decrypted.ipa" "$OUT/"
# Decrypted .app bundle (if you prefer the bundle):
#   ssh "$DEV" 'tar -C /var/containers/Bundle/Application/<UUID> -cf - Telegram.app' | tar -C "$OUT" -xf -
# dyld cache (large; pull all subcaches too):
#   rsync -av "$DEV:/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64*" "$OUT/dsc/"
# App-group telegram-data (read-only copy):
#   ssh "$DEV" 'tar -C /var/mobile/Containers/Shared/AppGroup/<UUID> -cf - telegram-data' | tar -C "$OUT" -xf -
# Crashes:
#   scp -r "$DEV:/var/mobile/Library/Logs/CrashReporter/Telegram-*" "$OUT/crashes/"
EOF

echo
echo "output dir: $OUT"
