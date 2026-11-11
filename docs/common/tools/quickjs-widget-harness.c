/* App-model harness for the quickjs-ng parser/compiler audit.
 *
 * One synchronous eval of a file's contents in a fresh runtime with a
 * 6 MiB heap cap (the Telegram widget model). No host APIs are installed:
 * the only JS surface is the ECMAScript builtins, eval/Function included.
 *
 * Usage:
 *   ./run6m [-l MiB] [-t ms] file.js
 *
 * Exit codes: 0 = eval returned, 2 = JS exception, other = crash.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include "quickjs.h"

static void *read_file(const char *path, size_t *plen)
{
    FILE *f = fopen(path, "rb");
    long n;
    void *buf;
    if (!f) { perror(path); exit(1); }
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = malloc(n + 1);
    if (!buf) exit(1);
    if (fread(buf, 1, n, f) != (size_t)n) exit(1);
    ((char *)buf)[n] = 0;
    fclose(f);
    *plen = n;
    return buf;
}

int main(int argc, char **argv)
{
    const char *path = NULL;
    double limit_mb = 6.0;
    int timeout_ms = 0;
    size_t len;
    char *src;
    JSRuntime *rt;
    JSContext *ctx;
    JSValue v;
    int opt;

    while ((opt = getopt(argc, argv, "l:t:")) != -1) {
        switch (opt) {
        case 'l': limit_mb = atof(optarg); break;
        case 't': timeout_ms = atoi(optarg); break;
        default: break;
        }
    }
    if (optind >= argc) {
        fprintf(stderr, "usage: %s [-l MiB] [-t ms] file.js\n", argv[0]);
        return 1;
    }
    path = argv[optind];
    src = read_file(path, &len);

    if (timeout_ms > 0)
        alarm((timeout_ms + 999) / 1000);

    rt = JS_NewRuntime();
    if (!rt) return 1;
    JS_SetMemoryLimit(rt, (size_t)(limit_mb * 1024.0 * 1024.0));
    JS_SetMaxStackSize(rt, 1024 * 1024);
    ctx = JS_NewContext(rt);
    if (!ctx) return 1;

    v = JS_Eval(ctx, src, len, "<widget>", JS_EVAL_TYPE_GLOBAL);
    if (JS_IsException(v)) {
        JSValue e = JS_GetException(ctx);
        const char *s = JS_ToCString(ctx, e);
        fprintf(stderr, "EXCEPTION: %s\n", s ? s : "(null)");
        JS_FreeCString(ctx, s);
        JS_FreeValue(ctx, e);
        JS_FreeValue(ctx, v);
        JS_FreeContext(ctx);
        JS_FreeRuntime(rt);
        free(src);
        return 2;
    }
    {
        const char *s = JS_ToCString(ctx, v);
        printf("OK: %s\n", s ? s : "(null)");
        JS_FreeCString(ctx, s);
        if (getenv("QJS_MEM")) {
            JSMemoryUsage u;
            JS_ComputeMemoryUsage(rt, &u);
            fprintf(stderr, "MEM malloc_size=%zu malloc_count=%zu\n",
                    u.malloc_size, u.malloc_count);
        }
    }
    JS_FreeValue(ctx, v);
    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);
    free(src);
    return 0;
}
