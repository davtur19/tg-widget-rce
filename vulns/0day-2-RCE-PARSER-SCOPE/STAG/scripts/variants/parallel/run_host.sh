#!/bin/sh
# Host validation matrix for the parallel universal package (no device, no bot).
#   ./run_host.sh
set -e
cd "$(dirname "$0")"
H=../qjs_fork_audit/zeroday_hunt_parser/build/run_sib_plain
mkdir -p logs
LOG=logs/host_matrix.txt
: > "$LOG"
echo "# $(date -Is) host matrix (run_sib_plain), profile=8MiB unless noted" >> "$LOG"
for f in m_v0 m_v1 m_v2 m_v3 m_ra; do
  for i in 1 2 3; do
    printf '%-5s 8M #%d ' "$f" "$i" >> "$LOG"
    timeout 90 "$H" -l 8 "$f.html" 2>&1 | tail -1 >> "$LOG"
  done
done
for f in m_v0 m_ra; do
  printf '%-5s 6M ' "$f" >> "$LOG"
  timeout 90 "$H" -l 6 "$f.html" 2>&1 | tail -1 >> "$LOG"
done
printf '%-5s ' m_stop >> "$LOG"
timeout 90 "$H" -l 8 m_stop.html 2>&1 | tail -1 >> "$LOG"
if [ -f m_dev_v0.html ]; then
  printf '%-5s ' m_dev_v0 >> "$LOG"
  timeout 90 "$H" -l 8 m_dev_v0.html 2>&1 | tail -1 >> "$LOG"
fi
python3 bot_first_only.py --parallel-self-test 2>&1 | grep -E "PARALLEL SELF-TEST" >> "$LOG"
cat "$LOG"
