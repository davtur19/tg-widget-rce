// Host-only bundle heap probe: runs the real sandbox-bundle.js (quickjs-ng)
// with a widget HTML, dispatches boot/nextScript/scriptDone, and prints the
// JS heap usage after HTML parse (pre-stage-A) and around each script.
//
// Purpose: measure whether a stage-B change alters the pre-stage-A heap that
// the parser stage A is sensitive to on the device (c4096 final vs forge
// probe).  The bundle is the 72889 one; the relative HTML/parse allocation
// effect is what matters, not the Telegram fork's allocator.
//
// Build (from zeroday_hunt_parser):
//   cc -O1 -g -I ../../../../../../lab/qjs_async_app/src lab_bundle_heap.c \
//      ../../../../../../lab/qjs_async_app/build-rel/libqjs.a -lm -lpthread \
//      -o build/lab_bundle_heap
// Usage: lab_bundle_heap [-l MiB] [-n] bundle.js widget.html
#include "quickjs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void mem(JSContext *ctx, const char *tag) {
    JSMemoryUsage u;
    JS_ComputeMemoryUsage(JS_GetRuntime(ctx), &u);
    fprintf(stderr, "MEM %-22s malloc_size=%lld count=%lld used=%lld "
            "str=%lld/%lld obj=%lld/%lld atom=%lld/%lld\n",
            tag, (long long)u.malloc_size, (long long)u.malloc_count,
            (long long)u.memory_used_size,
            (long long)u.str_count, (long long)u.str_size,
            (long long)u.obj_count, (long long)u.obj_size,
            (long long)u.atom_count, (long long)u.atom_size);
}

static char *rf(const char *p, long *n) {
    FILE *f = fopen(p, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); long l = ftell(f); fseek(f, 0, SEEK_SET);
    char *b = malloc((size_t)l + 1);
    if (fread(b, 1, (size_t)l, f) != (size_t)l) { fclose(f); free(b); return NULL; }
    b[l] = 0; fclose(f); *n = l; return b;
}

static JSValue js_host(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    (void)this_val; (void)argc; (void)argv;
    return JS_NewString(ctx, "{}");
}
static JSValue js_host_undef(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    (void)ctx; (void)this_val; (void)argc; (void)argv;
    return JS_UNDEFINED;
}

int main(int argc, char **argv) {
    long blen = 0, hlen = 0;
    size_t limit = 64u << 20;
    int opt;
    while ((opt = getopt(argc, argv, "l:n")) != -1) {
        if (opt == 'l') limit = (size_t)strtoull(optarg, NULL, 0) << 20;
    }
    if (optind + 2 > argc) {
        fprintf(stderr, "usage: %s [-l MiB] bundle.js widget.html\n", argv[0]);
        return 2;
    }
    char *bundle = rf(argv[optind], &blen);
    char *html = rf(argv[optind + 1], &hlen);
    if (!bundle || !html) { fprintf(stderr, "read failed\n"); return 1; }
    fprintf(stderr, "INPUT bundle=%ld html=%ld limit=%zu\n", blen, hlen, limit);

    JSRuntime *rt = JS_NewRuntime();
    JS_SetMemoryLimit(rt, limit);
    JS_SetMaxStackSize(rt, 1u << 20);
    JSContext *ctx = JS_NewContext(rt);
    JSValue g = JS_GetGlobalObject(ctx);
    // Minimal host stubs: the bundle's __host dispatcher.
    JS_SetPropertyStr(ctx, g, "__host", JS_NewCFunction(ctx, js_host, "__host", 2));
    JS_SetPropertyStr(ctx, g, "__hostCanvas", JS_NewCFunction(ctx, js_host_undef, "__hostCanvas", 4));
    JS_SetPropertyStr(ctx, g, "__hostOps", JS_NewCFunction(ctx, js_host_undef, "__hostOps", 4));
    JS_SetPropertyStr(ctx, g, "__hostBinary", JS_NewCFunction(ctx, js_host_undef, "__hostBinary", 2));
    JS_FreeValue(ctx, g);

    mem(ctx, "runtime");
    JSValue r = JS_Eval(ctx, bundle, (size_t)blen, "sandbox-bundle.js", JS_EVAL_TYPE_GLOBAL);
    if (JS_IsException(r)) { fprintf(stderr, "bundle exception\n"); return 1; }
    JS_FreeValue(ctx, r);
    mem(ctx, "bundle");

    JSValue global = JS_GetGlobalObject(ctx);
    JSValue dispatch = JS_GetPropertyStr(ctx, global, "__twDispatch");
    if (!JS_IsFunction(ctx, dispatch)) { fprintf(stderr, "no __twDispatch\n"); return 1; }

    // Build boot JSON inside the context (proper HTML escaping).
    JS_SetPropertyStr(ctx, global, "__html", JS_NewString(ctx, html));
    const char *mk =
        "globalThis.__boot=JSON.stringify({html:__html,config:{maxTimers:64,"
        "policy:'compat',features:[],theme:'{\"colorScheme\":\"light\",\"params\":{}}',"
        "themeParams:{},contentSafeArea:{},locale:'en-US',storage:{},profile:1,"
        "viewport:{width:400,height:600,scale:1},visible:true}});";
    JSValue mkv = JS_Eval(ctx, mk, strlen(mk), "mkboot", JS_EVAL_TYPE_GLOBAL);
    if (JS_IsException(mkv)) { fprintf(stderr, "mkboot exception\n"); return 1; }
    JS_FreeValue(ctx, mkv);
    JSValue bootv = JS_GetPropertyStr(ctx, global, "__boot");
    const char *boot = JS_ToCString(ctx, bootv);
    JS_FreeValue(ctx, bootv);

    mem(ctx, "pre-boot");
    JSValue cmd = JS_NewString(ctx, "boot");
    JSValue arg = JS_NewString(ctx, boot);
    JSValue br = JS_Call(ctx, dispatch, JS_UNDEFINED, 2, (JSValue[]){cmd, arg});
    JS_FreeValue(ctx, cmd); JS_FreeValue(ctx, arg);
    if (JS_IsException(br)) { fprintf(stderr, "boot exception\n"); return 1; }
    JS_FreeValue(ctx, br);
    mem(ctx, "post-boot(pre-A)");
    {
        const char *dbg =
            "var _o='';['stageA','stageB','stageC','e'].forEach(function(id){"
            "var E=document.getElementById(id);_o+=id+':'+(E?String(E.textContent).length:-1)+' ';});"
            "globalThis.__dbg=_o; globalThis.__S=document.getElementById('stageB')?"
            "document.getElementById('stageB').textContent:null;";
        JSValue dv = JS_Eval(ctx, dbg, strlen(dbg), "dbg", JS_EVAL_TYPE_GLOBAL);
        if (!JS_IsException(dv)) {
            JSValue dbgv = JS_GetPropertyStr(ctx, global, "__dbg");
            const char *s = JS_ToCString(ctx, dbgv);
            fprintf(stderr, "TEXTLEN %s\n", s ? s : "?");
            JS_FreeCString(ctx, s);
            JS_FreeValue(ctx, dbgv);
        } else {
            JS_FreeValue(ctx, JS_GetException(ctx));
        }
        JS_FreeValue(ctx, dv);
    }
    mem(ctx, "post-boot+__S");

    for (int guard = 0; guard < 1000; guard++) {
        JSValue ncmd = JS_NewString(ctx, "nextScript");
        JSValue sret = JS_Call(ctx, dispatch, JS_UNDEFINED, 1, &ncmd);
        JS_FreeValue(ctx, ncmd);
        if (JS_IsException(sret)) { fprintf(stderr, "nextScript exception\n"); break; }
        const char *sjson = JS_ToCString(ctx, sret);
        if (!sjson || !*sjson) { JS_FreeCString(ctx, sjson); JS_FreeValue(ctx, sret); break; }
        JSValue parsed = JS_ParseJSON(ctx, sjson, strlen(sjson), "script");
        if (JS_IsException(parsed)) { fprintf(stderr, "parse exception\n"); break; }
        JSValue idv = JS_GetPropertyStr(ctx, parsed, "id");
        JSValue codev = JS_GetPropertyStr(ctx, parsed, "code");
        JS_FreeValue(ctx, parsed);
        int id = 0; JS_ToInt32(ctx, &id, idv);
        const char *code = JS_IsString(codev) ? JS_ToCString(ctx, codev) : NULL;
        fprintf(stderr, "SCRIPT id=%d json=%zu code=%zu\n", id, strlen(sjson), code ? strlen(code) : 0);
        mem(ctx, "pre-script");
        JS_FreeValue(ctx, idv);
        if (code && *code) {
            JSValue cr = JS_Eval(ctx, code, strlen(code), "widget-script", JS_EVAL_TYPE_GLOBAL);
            if (JS_IsException(cr)) {
                JSValue e = JS_GetException(ctx);
                const char *es = JS_ToCString(ctx, e);
                fprintf(stderr, "  EXC %s\n", es ? es : "?");
                JS_FreeCString(ctx, es);
                JS_FreeValue(ctx, e);
                JS_FreeValue(ctx, cr);
                // engine continues after a JSError (except die paths)
            } else {
                JS_FreeValue(ctx, cr);
            }
            JS_FreeCString(ctx, code);
        }
        JS_FreeValue(ctx, codev);
        char sd[64]; snprintf(sd, sizeof sd, "[%d,true]", id);
        JSValue sdcmd = JS_NewString(ctx, "scriptDone");
        JSValue sda = JS_NewString(ctx, sd);
        JSValue sdargs[2] = { sdcmd, sda };
        JSValue sdret = JS_Call(ctx, dispatch, JS_UNDEFINED, 2, sdargs);
        JS_FreeValue(ctx, sdcmd); JS_FreeValue(ctx, sda); JS_FreeValue(ctx, sdret);
        JS_FreeCString(ctx, sjson);
        JS_FreeValue(ctx, sret);
        mem(ctx, "post-script");
    }
    JS_FreeCString(ctx, boot);
    JS_FreeValue(ctx, dispatch);
    JS_FreeValue(ctx, global);
    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);
    free(bundle); free(html);
    return 0;
}
