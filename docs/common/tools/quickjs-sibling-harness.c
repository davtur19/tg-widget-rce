/* run_multi.c - app-model multi-script harness for the widget boundary.
 *
 * One JSRuntime/JSContext; each argument is a separate JS_Eval(GLOBAL)
 * followed by JS_HasException + JS_GetException (the SandboxEngine_runScripts
 * boundary).  The loop continues after an exception, like the widget loader.
 *
 * usage: run_multi [-l MiB] file1 [file2 ...]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "quickjs.h"

static char *readfile(const char *path, long *plen)
{
    FILE *f = fopen(path, "rb");
    long n;
    char *s;
    if (!f) { perror(path); return NULL; }
    fseek(f, 0, SEEK_END); n = ftell(f); fseek(f, 0, SEEK_SET);
    s = malloc((size_t)n + 1);
    if (!s) { fclose(f); return NULL; }
    if (fread(s, 1, (size_t)n, f) != (size_t)n) { fclose(f); free(s); return NULL; }
    fclose(f); s[n] = 0; *plen = n;
    return s;
}

int main(int argc, char **argv)
{
    size_t limit = 8u * 1024u * 1024u;
    int argi = 1, i;
    JSRuntime *rt;
    JSContext *ctx;
    if (argc > 2 && strcmp(argv[1], "-l") == 0) {
        limit = (size_t)strtoull(argv[2], NULL, 0) * 1024u * 1024u;
        argi = 3;
    }
    if (argi >= argc) { fprintf(stderr, "usage: %s [-l MiB] f1 [f2 ...]\n", argv[0]); return 2; }
    rt = JS_NewRuntime();
    if (!rt) return 2;
    JS_SetMemoryLimit(rt, limit);
    JS_SetMaxStackSize(rt, 1024u * 1024u);
    ctx = JS_NewContext(rt);
    if (!ctx) return 2;
    for (i = argi; i < argc; i++) {
        long n = 0;
        char *src = readfile(argv[i], &n);
        JSValue v;
        if (!src) break;
        fprintf(stderr, "=== SCRIPT %d %s (%ld bytes)\n", i - argi + 1, argv[i], n);
        v = JS_Eval(ctx, src, (size_t)n, argv[i], JS_EVAL_TYPE_GLOBAL);
        if (JS_HasException(ctx)) {
            JSValue e = JS_GetException(ctx);
            const char *s = JS_ToCString(ctx, e);
            fprintf(stderr, "[%s] %s: %s\n", argv[i], JS_IsError(e) ? "Error" : "Thrown", s ? s : "(?)");
            if (s) JS_FreeCString(ctx, s);
            JS_FreeValue(ctx, e);
        }
        JS_FreeValue(ctx, v);
        free(src);
        fprintf(stderr, "=== DONE %d\n", i - argi + 1);
    }
    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);
    return 0;
}
