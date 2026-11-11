# Scudo bypass notes — Telegram 13.2.0 widget QuickJS UAF (phase 2)

> **Status update (2026-11-01 14:27, device-verified): phase 2 is cancelled
> for this bug.** The M1 test showed `runScripts` breaks after `die()` and no
> post-interrupt JS executes, so there is no grooming window. In addition,
> ≤512 B JS blocks come from QuickJS's small-block arena, not Scudo (see the
> arena notes). Keep this file only as an allocator/quarantine reference for
> other bugs.

Status: phase 1 (reliable crash) is being tested on-device; this note is the
exploitation design once the interrupt reliably fires inside
`Array.prototype.find`.

## Device facts

- Sony XQ-BT52 (Snapdragon 690, ARMv8.2): **no MTE** (`arm64.memtag.process.system_server=off`,
  CPU features lack `mte`), user/release-keys build (`ro.debuggable=0`).
- `libtmessages.49.so` imports `malloc`/`free` from bionic and has no
  mimalloc/jemalloc strings → QuickJS **large** allocations (>512 B) go to
  **Scudo**; ≤512 B blocks use the internal small-block arena (later finding,
  see `arena_type_confusion_notes.md`).

## Scudo 64-bit defaults (source.android.com/docs/security/test/scudo)

| Option | Default |
|---|---|
| QuarantineSizeKb | 256 |
| ThreadLocalQuarantineSizeKb | 64 |
| QuarantineChunksUpToSize | **2048 bytes** |

Two properties:

1. Back-to-back double free of a quarantined chunk → Scudo detects and aborts.
   Good for phase 1 (crash evidence), fatal for exploitation.
2. Chunks **larger than 2048 bytes are not quarantined** — `free()` returns them
   to the allocator immediately. That is the bypass.

## Primitive (quickjs-ng #1792)

`js_array_find` frees each non-matching element at the bottom of the loop but
does not reset `val`. If an interrupt fires at the next loop-top poll, the
exception path frees the stale `val` again. With a shared element `o` repeated
in the array, the refcount is under-counted by one: when the array is released,
`o` is freed while array slots still reference it.

- If the chunk is small (JSString/JSObject ≤2048 B) it sits in the Scudo
  quarantine; the later stale free is detected → abort (phase 1).
- If the chunk is >2048 B (e.g. a long JSString, or a large ArrayBuffer
  backing store), it is immediately reusable: allocate a replacement of the
  same size class with attacker-controlled contents, and the stale array slot
  now aliases the replacement. No double-free check is hit.

## Grooming sketch (phase 2, requires script to survive the interrupt)

```js
var o = 'A'.repeat(4096);            // > 2048: not quarantined
var a = new Array(200000).fill(o);

try { Array.prototype.find.call(a, Number); } catch (e) {}
// If the context is still alive and `o` was freed early:
// allocate replacements of the same size class; a[0..] still points at the
// freed chunk, which may now be one of the replacements.
var repl = [];
for (var i = 0; i < 64; i++) repl.push('B'.repeat(4096));
// use a[0].length / a[0][0] etc. to detect the aliasing
```

If the app's engine makes `InternalError: interrupted` uncatchable (quickjs-ng
commit "Make InternalErrors uncatchable", Oct 2026), the script cannot continue
after the interrupt. In that case the grooming must happen **before** the
interrupt (e.g. allocate a large pool and free it just before `find`, so the
quarantine is drained and the target chunk is recycled during the find loop),
or a previously registered event handler (tap) must perform the allocation
after the exception unwinds — to be verified by the RE subagent.

For small JSObject chunks (80 B), the global quarantine is only ~256 KB
(~3.2k chunks); bulk alloc/free of the same size class drains it and makes
the freed object's chunk reusable, but the >2048 B route is cleaner.

## Open questions for phase 2

- Does the engine keep the JS context alive after `"interrupted"` (needed for
  post-interrupt grooming / event handlers)?
- Is `InternalError` catchable in the app's QuickJS fork?
- Exact `memoryLimitBytes` (how large can the shared element/pool be?)
- Whether widget JS can register a tap/click handler that survives the abort.
