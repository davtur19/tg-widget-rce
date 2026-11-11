#!/usr/bin/env python3
"""Offline timing model for the iOS 27 two-phase path (host-only).

Measured here: the host in-process detector-report -> parse -> map -> dry
sendWidget chain (P3, cached final).  Inferred from the 5725 run / notes:
Telegram delivery+bind and the device stage-A time.  The model is explicit:
it is a budget, not a device measurement.  The device T0/T1 markers decide.

Run: python3 sim_timing.py
"""
import contextlib
import io
import json
import os
import statistics
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bot_two_phase as b  # noqa: E402


def host_chain(n=300):
    log = os.path.join(HERE, "state", "timing_dry.log")
    os.makedirs(os.path.dirname(log), exist_ok=True)
    open(log, "w").close()
    tp = b.TwoPhase("-", os.path.join(HERE, "chunks"), 10290, "answerWidgetQuery",
                    True, log, ["data"])
    tp.cooldown = 0.0
    rep = b.pack_report(3, 4, safe=True, padM=768, n=545, hd=598, cb=12,
                        N=2600, SZ=957, UBn=24, UBsz=576, dpr=3.0, sw=420, sh=912,
                        lang="it", tz=-60, elapsed=20, t_rep=123456)
    q = {"update_id": 1, "widget_query": {"id": "q", "data": rep,
         "from": {"id": 10290}, "chat": {"id": 0}, "message_id": 1}}
    ts = []
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        for i in range(n):
            t = time.perf_counter()
            tp.handle(q, t)
            ts.append((time.perf_counter() - t) * 1000)
    return {"n": n, "min": min(ts), "p50": statistics.median(ts),
            "p95": sorted(ts)[int(0.95 * len(ts)) - 1], "max": max(ts)}


def main():
    h = host_chain()
    print("HOST CHAIN (P3 parse + map + dry sendWidget, cached):")
    print("  n=%d min=%.3f ms p50=%.3f ms p95=%.3f ms max=%.3f ms" % (
        h["n"], h["min"], h["p50"], h["p95"], h["max"]))

    # Segment budget, seconds.  "measured" = host or 5725 screenshot bound;
    # "inferred" = Telegram delivery/device model.
    seg = [
        ("detector bind + safe probe + request", 0.10, 0.30, "inferred (host safe probe 1.6 ms)"),
        ("request update -> bot long-poll", 0.05, 0.30, "inferred (bot long-poll)"),
        ("host parse+map+ACK", h["p50"] / 1000, h["p95"] / 1000, "measured here"),
        ("sendWidget API round trip", 0.10, 0.17, "inferred from Android RT; iOS beta same API"),
        ("final Telegram delivery + bind", 0.50, 1.50, "inferred; 5725 marker <=2 s after send"),
        ("final stage A self-sweep", 0.30, 1.00, "inferred; host timed-miss 0.52 s / 375 attempts"),
        ("inline ROP + write + pthread_exit", 0.01, 0.05, "inferred; stage B host ms"),
    ]
    print("\nSEGMENT BUDGET (two-phase, fast path = detector then final):")
    lo = hi = 0.0
    for name, a, z, src in seg:
        lo += a
        hi += z
        print("  %-42s %7.4f - %6.4f s  [%s]" % (name, a, z, src))
    print("  %-42s %7.4f - %6.4f s" % ("TOTAL two-phase", lo, hi))

    # The hot path: known platform -> send the proven final directly.
    direct_lo = 0.50 + 0.30 + 0.01
    direct_hi = 1.50 + 1.00 + 0.05
    print("\nHOT PATH (known 17e chat, no detector, one delivery):")
    print("  final delivery+bind + stage A + ROP = %.2f - %.2f s" % (direct_lo, direct_hi))
    print("  the 2-3 s target is met if delivery <=1.5 s and stage A <=1.0 s")
    print("\n5725 RUN BOUNDS (no send timestamp in the log):")
    print("  v8 burst 16:26:16 and w8 burst 16:27:06 both show a widget result")
    print("  within <=2 s of the message send (screenshot cadence ~1.2 s).")
    print("  ss8_final built 16:27:33.75; RCE proof alive 16:28:57 -> send-to-proof <=5.1 s.")
    print("\nVERDICT: two-phase 1.1-3.5 s nominal; the direct final is 0.8-2.5 s.")
    print("Use the detector only for an unknown chat/platform or a stale last_m.")


if __name__ == "__main__":
    main()
