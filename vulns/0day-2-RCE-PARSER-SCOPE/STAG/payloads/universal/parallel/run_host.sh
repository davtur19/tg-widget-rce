#!/bin/sh
# Build H from docs/common/tools/quickjs-sibling-harness.c, or set H to an
# existing sibling-script harness. See the README.
# Host validation matrix for the parallel universal package (no device, no bot).
#   ./run_host.sh
set -e
cd "$(dirname "$0")"
H=${H:-/tmp/opencode/run_sib_plain}
mkdir -p logs
LOG=logs/host_matrix.txt
: > "$LOG"
echo "# $(date -Is) host matrix (run_sib_plain), profile=8MiB unless noted" >> "$LOG"
for f in host-mock-a host-mock-b host-mock-c host-mock-d host-mock-rearm; do
  for i in 1 2 3; do
    printf '%-5s 8M #%d ' "$f" "$i" >> "$LOG"
    timeout 90 "$H" -l 8 "$f.html" 2>&1 | tail -1 >> "$LOG"
  done
done
for f in host-mock-a host-mock-rearm; do
  printf '%-5s 6M ' "$f" >> "$LOG"
  timeout 90 "$H" -l 6 "$f.html" 2>&1 | tail -1 >> "$LOG"
done
printf '%-5s ' host-mock-stop >> "$LOG"
timeout 90 "$H" -l 8 host-mock-stop.html 2>&1 | tail -1 >> "$LOG"
if [ -f host-mock-device-a.html ]; then
  printf '%-5s ' host-mock-device-a >> "$LOG"
  timeout 90 "$H" -l 8 host-mock-device-a.html 2>&1 | tail -1 >> "$LOG"
fi
python3 bot_first_only.py --parallel-self-test 2>&1 | grep -E "PARALLEL SELF-TEST" >> "$LOG"
cat "$LOG"
