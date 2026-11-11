#!/bin/sh
# Host validation matrix — two-phase, Android + iOS 15 + iOS 27 (no device/bot/network).
set -e
cd "$(dirname "$0")"
H=../qjs_fork_audit/zeroday_hunt_parser/build/run_sib_plain
mkdir -p logs
LOG=logs/host_matrix.txt
: > "$LOG"
echo "# $(date -Is) two-phase multiplatform host matrix (run_sib_plain -l 8)" >> "$LOG"

# Android detector/final: page-equal 9,176 B, P3 report
for f in m_det m_det_ra m_det_miss m_fin_dev m_fin_host; do
  for i in 1 2 3; do
    printf '%-18s #%d ' "$f" "$i" >> "$LOG"
    timeout 90 "$H" -l 8 "$f.html" 2>&1 | tail -1 >> "$LOG"
  done
done

# Android P3 JS->Python round-trip: the actual mock report must parse and map
for f in m_det m_det_ra m_det_miss; do
  R=$("$H" -l 8 "$f.html" 2>&1 | grep -o 'P3[0-9a-f]*' | head -1)
  printf '%-18s parse ' "$f" >> "$LOG"
  python3 bot_two_phase.py --check-report "$R" >> "$LOG" 2>&1
done

# iOS 27 safe handshake + the proven 5725 final (host stage B stops at LEN_72)
for f in ios27/detector_ios27 ios27/m_det ios27/final_ios27 ios27/final_ios27_m768 ios27/final_ios27_timed; do
  for i in 1 2; do
    printf '%-24s #%d ' "$f" "$i" >> "$LOG"
    timeout 90 "$H" -l 8 "$f.html" 2>&1 | tail -1 >> "$LOG"
  done
done
R=$("$H" -l 8 ios27/m_det.html 2>&1 | grep -o 'P3[0-9a-f]*' | head -1)
printf '%-24s parse ' "ios27/m_det" >> "$LOG"
python3 bot_two_phase.py --check-report "$R" >> "$LOG" 2>&1
printf '%-24s map   ' "ios27/m_det" >> "$LOG"
python3 - "$R" >> "$LOG" 2>&1 <<'PY'
import json, sys
sys.path.insert(0, '.')
import bot_two_phase as b
rep = b.parse_report(sys.argv[1])
table = json.load(open('platforms.json'))
print(b.target_for(rep, table))
PY

# iOS 15 pair: page-equal 6,801 B, marker -> P3 relay -> host mapping
for f in ios15/at_probe_h400 ios15/at_final_h400; do
  printf '%-24s ' "$f" >> "$LOG"
  timeout 90 "$H" -l 8 "$f.html" 2>&1 | tail -1 >> "$LOG"
done
R=$(python3 relay_ios15.py --marker "RESULT ATTR C=34 SZ=957 N=3000 H=400 HN=64 HIT=545 LEN=327744 PH=36 VK=598 NT=21 S2LEN=-1" | head -1)
printf '%-24s parse ' "relay_ios15_h400" >> "$LOG"
python3 bot_two_phase.py --check-report "$R" >> "$LOG" 2>&1
printf '%-24s map   ' "relay_ios15_h400" >> "$LOG"
python3 - "$R" >> "$LOG" 2>&1 <<'PY'
import json, sys
sys.path.insert(0, '.')
import bot_two_phase as b
rep = b.parse_report(sys.argv[1])
table = json.load(open('platforms.json'))
print(b.target_for(rep, table))
PY

python3 bot_two_phase.py --self-test >> "$LOG" 2>&1
python3 bot_two_phase.py --simulate 2>/dev/null | grep -E "^(SIMULATE|DRY SEND)" >> "$LOG"
cat "$LOG"
