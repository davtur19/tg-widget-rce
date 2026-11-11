# scripts/two_phase (repo mirror)

`bot_two_phase.py` (P3, 64-char report) now runs from the repo:
`python3 scripts/two_phase/bot_two_phase.py --self-test` prints
`SELF-TEST PASS | report len 64`. It falls back to `bot/bot_server.py` for the
Bot API client and reads the pages from `payloads/two_phase/`.

`gen_two_phase.py` and the gate post-processors still expect the lab tree
(`../pixel72801_route2/oob/`) and are not runnable from the repo alone. The
shipped page hashes are checked by `scripts/verify_payloads.py`; the gated
generator path is documented in `docs/PAYLOAD_CHAIN.md` §6 with that caveat.

`gen_ios27_safe.py` is the iOS 27 generator; `gen_ios27_univA.py` is the
superseded 6,295-B twin generator (not the msg-5725 payload).
