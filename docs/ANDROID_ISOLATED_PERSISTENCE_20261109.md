# Android 72989 — isolated-process persistence and harness runner (2026-11-09)

Latest build only: Sony XQ-BT52, Telegram beta **72989** (13.2.2, UID 10346),
no downgrade. The 72929 session proof is archived.

## Persistence measurements (preliminary)

| event | isolated `:widgets` |
|---|---|
| widget open | isolated PID/UID created (e.g. 16756, UID 990xx) |
| delete the widget message | **killed within ~4 s** |
| reopen the old widget from history | new isolated PID (20071) created |
| home / foreground / change chat (widget still in history) | **survives** |
| 120 s poll with app backgrounded | running |

Conclusion so far: **deleting the message is the kill trigger; changing chat,
going home, or foregrounding does not kill the isolate while the widget is in
history.** For reliability, deliver the widget once and do not delete it; the
user can switch chats while the native payload/isolate remains alive. A
force-stop or app-process kill still kills it; the 120 s backgrounded poll
confirmed survival
(`path_deterministic/device_results/persistence/poll120_home_20261109_100038.log`,
PID 20071 throughout).

This is useful for the exploit: a staged payload can survive a chat change and
run later, as long as the message is kept and the app is not killed.

## Harness runner note

The official Python Frida runner lacks the Java bridge in its Python agent
(`ReferenceError: 'Java' is not defined`), so the device owner is driving the
control/force through the **Frida CLI**, which has the bridge. The CLI scripts
expose `MARKER_SYSTEM`/`[RECLAIM]` and a duration self-stop; the 5-minute
control and 30–60-minute force use the exact speed_force parameters, logcat,
and no `kill -9`.

## Status

- No stock `41414141`/`system` marker yet.
- Force: 13,659 preemptions/s **windowed** A/B rate; the derived ~2.2 min
  mean is falsified (ANDROID_FASTER_ESCAPE_20261109.md). Timing fix
  239 cycles/18 s with no Scudo/RT UAF in that run. Phase 0 σ gate failed
  (0.83–5.5 ms vs ≤10 µs); Phase 1 0 markers in 25.2 min (reclaim-order
  tombstone); 73029 Phase 1 partial, cancelled by the owner.
- Latest build is **73029** (updated 2026-11-09 16:27); older builds are
  archived.
