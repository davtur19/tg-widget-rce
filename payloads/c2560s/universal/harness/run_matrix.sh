#!/usr/bin/env bash
# Host-only class-ladder matrix for the parser-0day stage A.
#
#   harness/run_matrix.sh            # full matrix, logs into harness/logs/
#
# It runs:
#   A. stage A final + probe for every generated class under the Scudo model
#      with the matching class map (4k ladder on 4k, alt ladder on alt);
#   B. cross-map controls (same artifacts under the other map) to show that
#      the model discriminates a class mismatch (SIGSEGV in
#      add_closure_variables) from a safe probe;
#   C. the full widgets (A+B+C) under the glibc sibling harness for script
#      integrity (VDOM markers; glibc is NOT the stage-A allocator).
#
# Expected: every same-map final -> RESULT ABLEN[599]=327744 VLEN=327744;
#           every same-map probe -> RESULT SAFE<C>C;
#           every same-map probe widget -> VDOM=S1 SAFE<C>C END=-.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
UNIV=$(dirname "$HERE")
ROOT=$(cd "$HERE/../../../.." && pwd)
LOGS="$HERE/logs"
BIN="$HERE/build/run_scudo_ladder"
SIB="$ROOT/build/run_sib_plain"
SRC="$ROOT/src"
mkdir -p "$LOGS" "$HERE/build"

if [ ! -x "$BIN" ] || [ "$HERE/scudo_ladder_sim.c" -nt "$BIN" ]; then
    echo "[build] $BIN"
    cc -O1 -g -DNDEBUG -I "$SRC" "$HERE/scudo_ladder_sim.c" \
        "$SRC/quickjs.c" "$SRC/libregexp.c" "$SRC/libunicode.c" "$SRC/dtoa.c" \
        -lm -o "$BIN" || exit 1
fi

CLASSES_4K="2048 2304 2560 3072 3584 4096 4608 5120"
CLASSES_ALT="2080 3104 4608"
CLASSES_ROBUST="3840 3072max"

verdict_final() {
    if grep -q "RESULT ABLEN\[599\]=327744 VLEN=327744" "$1"; then echo FORGE
    elif grep -q "RESULT NOCORR" "$1"; then echo NOCORR
    elif grep -q "Memory limit" "$1"; then echo OOM
    else echo CRASH_OR_OTHER; fi
}
verdict_probe() {
    if grep -q "RESULT SAFE[0-9]*C" "$1"; then echo SAFE
    elif grep -q "RESULT ABLEN" "$1"; then echo FORGED_UNEXPECTED
    elif grep -q "Memory limit" "$1"; then echo OOM
    else echo CRASH_OR_OTHER; fi
}

run_stage() { # map class kind outfile
    local map=$1 C=$2 kind=$3 out=$4
    timeout 180 "$BIN" -l 8 -m "$map" "$UNIV/stageA/c${C}_${kind}.js" >"$out" 2>&1
    echo $?
}

TSV="$LOGS/matrix.tsv"
: > "$TSV"

echo "== A. same-map stage A matrix =="
for C in $CLASSES_4K; do
    out="$LOGS/sim_4k_c${C}_final.txt"; rc=$(run_stage 4k "$C" final "$out")
    v=$(verdict_final "$out")
    pout="$LOGS/sim_4k_c${C}_probe.txt"; prc=$(run_stage 4k "$C" probe "$pout")
    pv=$(verdict_probe "$pout")
    printf "4k\t%s\tfinal\t%s\t%s\n" "$C" "$v" "$rc" | tee -a "$TSV"
    printf "4k\t%s\tprobe\t%s\t%s\n" "$C" "$pv" "$prc" | tee -a "$TSV"
done
for C in $CLASSES_ALT; do
    out="$LOGS/sim_alt_c${C}_final.txt"; rc=$(run_stage alt "$C" final "$out")
    v=$(verdict_final "$out")
    pout="$LOGS/sim_alt_c${C}_probe.txt"; prc=$(run_stage alt "$C" probe "$pout")
    pv=$(verdict_probe "$pout")
    printf "alt\t%s\tfinal\t%s\t%s\n" "$C" "$v" "$rc" | tee -a "$TSV"
    printf "alt\t%s\tprobe\t%s\t%s\n" "$C" "$pv" "$prc" | tee -a "$TSV"
done
# Map-robust candidates: 3840 under dense+4k, 3072max under 4k+dense.
for spec in "3840 dense" "3840 4k" "3072max 4k" "3072max dense"; do
    set -- $spec; C=$1; M=$2
    out="$LOGS/sim_${M}_c${C}_final.txt"; rc=$(run_stage "$M" "$C" final "$out")
    v=$(verdict_final "$out")
    printf "%s\t%s\tfinal\t%s\t%s\n" "$M" "$C" "$v" "$rc" | tee -a "$TSV"
done

echo "== B. cross-map controls =="
for C in $CLASSES_4K; do
    out="$LOGS/xmap_alt_c${C}_final.txt"; rc=$(run_stage alt "$C" final "$out")
    v=$(verdict_final "$out")
    printf "alt-on-4k\t%s\tfinal\t%s\t%s\n" "$C" "$v" "$rc" | tee -a "$TSV"
done
for C in 2080 3104; do
    out="$LOGS/xmap_4k_c${C}_final.txt"; rc=$(run_stage 4k "$C" final "$out")
    v=$(verdict_final "$out")
    printf "4k-on-alt\t%s\tfinal\t%s\t%s\n" "$C" "$v" "$rc" | tee -a "$TSV"
done

echo "== C. full widgets on glibc sibling harness (script integrity) =="
if [ -x "$SIB" ]; then
    : > "$LOGS/glibc_widgets.tsv"
    for C in $CLASSES_4K $CLASSES_ALT; do
        w="$UNIV/c${C}_probe_ladder_host.html"
        po=$(timeout 180 "$SIB" -l 8 "$w" 2>&1)
        pv=$(printf '%s\n' "$po" | grep -oE "VDOM=S1 SAFE[0-9]+C END=-" | tail -1)
        [ -z "$pv" ] && pv="VDOM_MISSING"
        w="$UNIV/c${C}_final_ladder_host.html"
        fo=$(timeout 180 "$SIB" -l 8 "$w" 2>&1)
        fv=$(printf '%s\n' "$fo" | grep -oE "END=HF [A-Z]+" | tail -1)
        [ -z "$fv" ] && fv="END_MISSING"
        fa=$(printf '%s\n' "$fo" | grep -oE "ABLEN\[599\]=327744" | head -1)
        [ -z "$fa" ] && fa="FORGE_MISSING"
        printf "%s\tprobe\t%s\n%s\tfinal\t%s\t%s\n" "$C" "$pv" "$C" "$fa" "$fv" \
            | tee -a "$LOGS/glibc_widgets.tsv"
    done
    # forge probes: final stage A + no-op B; expected ABLEN on the host (the
    # host forge is not a device predictor, this only checks the marker path).
    : > "$LOGS/glibc_forgeprobes.tsv"
    for C in $CLASSES_4K $CLASSES_ALT $CLASSES_ROBUST; do
        w="$UNIV/c${C}_forgeprobe_ladder_host.html"
        fo=$(timeout 180 "$SIB" -l 8 "$w" 2>&1)
        fv=$(printf '%s\n' "$fo" | grep -oE "VDOM=S1 .*" | tail -1)
        [ -z "$fv" ] && fv="VDOM_MISSING"
        printf "%s\t%s\n" "$C" "$fv" | tee -a "$LOGS/glibc_forgeprobes.tsv"
    done
    for w in "$UNIV"/c4096_forgeprobe_legacyB4957_72929.html \
             "$UNIV"/c4096_forgeprobe_nab900_72929.html; do
        fo=$(timeout 180 "$SIB" -l 8 "$w" 2>&1)
        fv=$(printf '%s\n' "$fo" | grep -oE "VDOM=S1 .*" | tail -1)
        [ -z "$fv" ] && fv="VDOM_MISSING"
        printf "%s\t%s\n" "$(basename "$w" .html)" "$fv" \
            | tee -a "$LOGS/glibc_forgeprobes.tsv"
    done
else
    echo "run_sib_plain not found at $SIB (skip full-widget checks)"
fi

echo "== E. c4096 fix4096 host finals =="
if ls "$UNIV"/fix4096/*final*host.html >/dev/null 2>&1; then
    : > "$LOGS/glibc_fix4096.tsv"
    for w in "$UNIV"/fix4096/*final*host.html; do
        b=$(basename "$w" .html)
        fo=$(timeout 180 "$SIB" -l 8 "$w" 2>&1)
        fv=$(printf '%s\n' "$fo" | grep -oE "VDOM=S1 .*" | tail -1)
        [ -z "$fv" ] && fv="VDOM_MISSING"
        printf "%s\t%s\n" "$b" "$fv" | tee -a "$LOGS/glibc_fix4096.tsv"
    done
else
    echo "no fix4096 host finals (run device/widget/universal/gen_c4096_layout.py)"
fi

echo "== F. real-bundle pre-A heap (probe vs final) =="
BHEAP="$HERE/build/lab_bundle_heap"
BUNDLE="$ROOT/../bundle_72889/WidgetJS/sandbox-bundle.js"
if [ -x "$BHEAP" ] && [ -f "$BUNDLE" ]; then
    for w in "$UNIV"/c4096_forgeprobe_ladder_72929.html \
             "$UNIV"/c4096_final_ladder_72929.html; do
        [ -f "$w" ] || continue
        printf "%s\t" "$(basename "$w")"
        timeout 180 "$BHEAP" -l 64 "$BUNDLE" "$w" 2>&1 \
            | grep "MEM post-boot" | head -1
    done
else
    echo "lab_bundle_heap or bundle missing (build: see harness/lab_bundle_heap.c)"
fi

echo "== summary =="
awk -F'\t' '{k=$1"/"$3; v=$4; c[k" "v]++} END {for (x in c) print c[x], x}' "$TSV" | sort
echo "logs: $LOGS"
