#!/bin/sh
set -e
cd "$(dirname "$0")"
PAY=${STAG_PAYLOAD_DIR:-../../../vulns/0day-2-RCE-PARSER-SCOPE/STAG/payloads}
python3 gen_parallel.py >/dev/null
check() {
  file=$PAY/universal/parallel/$1
  want=$2
  got=$(sha256sum "$file" | cut -d' ' -f1)
  if [ "$got" != "$want" ]; then
    echo "FAIL $1 $got"
    exit 1
  fi
}
check device-widget-a.html cc1881ca32d23321d37a2620df01099c164d375cdcb53aa8d92c461c3352ca39
check device-widget-b.html f77c198079b4b54b3856d5899b7a4322ac79282a0ca006f54f5be46c95a8ef63
check device-widget-c.html 4fa7621eb214abef80ef16d7f1c196e47d9f8cbd2f1c37e07c0c660efa5dc0ae
check device-widget-d.html 25a5fb54a28af04e954c1d4530707b5cbf88a2ca8141e0473b525d93aefb693c
check send-batch.json 79833b3d9165c5f3de8d02146297cf51cdf74d3d53ef8aa7185b60d8b2f0eb3b
echo "PARALLEL CHECK PASS"
