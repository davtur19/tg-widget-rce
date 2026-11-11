#!/bin/sh
# telegramandroidwidget/c2/mock/mock_implant.sh
#
# Host-only mock implant.  It deliberately reuses the REAL implant code in
# C2_MOCK=1 mode (same protocol, same FIFO transport, same exec/file paths)
# instead of duplicating the protocol in a second implementation that would
# drift.  The fake identity line is printed here and also sent in `hello`.
#
# usage:
#   C2_HOST=127.0.0.1 C2_PORT=14444 C2_ID=mock1 ./mock/mock_implant.sh
#   ./mock/mock_implant.sh --diag      # one-shot hello/transport diagnostic
#
# This script never runs on a phone: it refuses to run when /system/bin/sh
# exists unless C2_ALLOW_MOCK_ON_DEVICE=1 is set.

set -eu

if [ -x /system/bin/sh ] && [ "${C2_ALLOW_MOCK_ON_DEVICE:-0}" != "1" ]; then
    echo "mock_implant: refusing to run on Android (uses host nc/base64)" >&2
    exit 2
fi

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

C2_MOCK=1
export C2_MOCK
case "${1:-}" in
    --diag) C2_DIAG=1; export C2_DIAG ;;
esac
: "${C2_ID:=mock-$$}"
export C2_ID
: "${C2_MOCK_UID:=10123}"
: "${C2_MOCK_USER:=u0_a123}"
: "${C2_MOCK_DEVICE:=Mock-Device}"
: "${C2_DIR:=$HERE/../.mock-$C2_ID}"
export C2_MOCK_UID C2_MOCK_USER C2_MOCK_DEVICE C2_DIR

echo "MOCK_UID=$C2_MOCK_UID MOCK_USER=$C2_MOCK_USER implant=$C2_ID dir=$C2_DIR"

exec sh "$ROOT/implant/implant.sh"
