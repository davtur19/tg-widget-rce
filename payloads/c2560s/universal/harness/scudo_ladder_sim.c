/* scudo_ladder_sim.c - QuickJS runtime with a Scudo-primary model for the
 * parser-0day class ladder (host-only).
 *
 * Model (matches the in-tree measured geometry, REPORT_parser_hunt §17-18):
 *   - class_of(request) = smallest class >= request, where request is what
 *     QuickJS passes to mf.js_malloc/js_calloc (the 8-byte
 *     JSMallocBlockHeader is already included by the caller);
 *   - class tables: "4k" = measured/generic ladder used by the c2560/c4096
 *     packages; "alt" = AOSP AndroidSizeClassMap-derived usable ladder
 *     (provisional 16K / revised-Scudo fallback);
 *   - one 256 MiB PROT_NONE reservation per class, committed in 256 KiB
 *     increments (Scudo PrimaryRegion/MapSizeIncrement model);
 *   - chunks are handed out in increasing address order inside a class
 *     region ("bump"); freed chunks go to a per-class LIFO free list;
 *   - malloc_usable_size returns the class size (the "usable" ladder the
 *     packages were derived against).
 *
 * This is a containment/geometry model, not a Scudo emulator: it answers
 * "would a spray of class X cover b + 1,310,700 with attacker data?" and
 * "does a class mismatch fault/nocorr?".
 *
 * Build (from the zeroday_hunt_parser root, fork sources in ./src):
 *   cc -O1 -g -DNDEBUG -I src harness/scudo_ladder_sim.c src/quickjs.c \
 *      src/libregexp.c src/libunicode.c src/dtoa.c -lm -o harness/run_scudo_ladder
 *
 * Usage: run_scudo_ladder [-l MiB] [-m 4k|alt] [-t] script.js ...
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>
#include "quickjs.h"

#define MAXC 64

/* Measured/generic Scudo ladder (usable sizes; REPORT §17/§18). */
static const size_t CLS_4K[] = {
    16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 256,
    288, 320, 352, 384, 416, 448, 480, 512, 576, 640, 704, 768, 896, 1024,
    1152, 1280, 1536, 1792, 2048, 2304, 2560, 3072, 3584, 4096, 4608, 5120,
    6144, 7168, 8192, 9216, 10240, 12288, 14336, 16384, 18432, 20480, 24576,
    28672, 32768, 36864, 40960, 49152, 57344, 65536, 81920, 98304, 114688, 131072
};
/* Provisional alternative: AOSP AndroidSizeClassMap chunk sizes minus the
 * 16-byte Scudo chunk header (usable sizes), see notes/scudo_bypass_notes.md
 * and lab/sony_webp_chain/harness/scudo_map.py. */
static const size_t CLS_ALT[] = {
    16, 32, 48, 64, 80, 96, 128, 160, 176, 208, 272, 336, 432, 576, 784,
    1040, 1648, 2080, 2560, 3104, 4096, 4608, 7104, 8704, 11648, 14208,
    16384, 18432, 23040, 29440, 33280, 65536
};
/* Dense 1.25x/256-step hypothesis from REPORT_scudo_classmap.md §2. */
static const size_t CLS_DENSE[] = {
    16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 256,
    288, 320, 352, 384, 416, 448, 480, 512, 576, 640, 704, 768, 896, 1024,
    1280, 1536, 1792, 2048, 2304, 2560, 2816, 3072, 3328, 3584, 3840, 4096,
    4352, 4608, 4864, 5120, 6144, 7168, 8192
};

static const size_t *CLS = CLS_4K;
static int NCLS = (int)(sizeof(CLS_4K) / sizeof(CLS_4K[0]));

#define REGION_BYTES (256u << 20)
#define INC_BYTES    (256u << 10)

typedef struct {
    uint8_t *base;
    size_t committed;
    size_t used;
    size_t nfree;
    size_t freecap;
    void **freev;
    int created;
} Class;
static Class g_cls[MAXC];
static int g_trace;

typedef struct { const void *p; int ci; } Slot;
static Slot *g_map;
static size_t g_map_cap, g_map_n;

static uint64_t hashp(const void *p) {
    return ((uint64_t)(uintptr_t)p >> 4) * 11400714819323198485ull;
}
static void map_grow(void) {
    size_t ncap = g_map_cap ? g_map_cap * 2 : 8192;
    Slot *nm = calloc(ncap, sizeof(*nm));
    if (!nm) { fprintf(stderr, "sim: map OOM\n"); exit(9); }
    for (size_t i = 0; i < g_map_cap; i++) {
        if (!g_map[i].p) continue;
        size_t j = hashp(g_map[i].p) & (ncap - 1);
        while (nm[j].p) j = (j + 1) & (ncap - 1);
        nm[j] = g_map[i];
    }
    free(g_map); g_map = nm; g_map_cap = ncap;
}
static void map_put(const void *p, int ci) {
    if ((g_map_n + 1) * 2 >= g_map_cap) map_grow();
    size_t j = hashp(p) & (g_map_cap - 1);
    while (g_map[j].p) {
        if (g_map[j].p == p) { g_map[j].ci = ci; return; }
        j = (j + 1) & (g_map_cap - 1);
    }
    g_map[j].p = p; g_map[j].ci = ci; g_map_n++;
}
static int map_get(const void *p) {
    if (!g_map_cap) return -1;
    size_t j = hashp(p) & (g_map_cap - 1);
    while (g_map[j].p) {
        if (g_map[j].p == p) return g_map[j].ci;
        j = (j + 1) & (g_map_cap - 1);
    }
    return -1;
}
static void map_del(const void *p) {
    if (!g_map_cap) return;
    size_t j = hashp(p) & (g_map_cap - 1);
    while (g_map[j].p) {
        if (g_map[j].p == p) { g_map[j].p = (void *)-1; g_map_n--; return; }
        j = (j + 1) & (g_map_cap - 1);
    }
}

static int cls_index(size_t n) {
    for (int i = 0; i < NCLS; i++) if (n <= CLS[i]) return i;
    return -1;
}

static void region_init(Class *c, int ci) {
    if (c->base) return;
    uint8_t *b = mmap(NULL, REGION_BYTES, PROT_NONE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (b == MAP_FAILED) { fprintf(stderr, "sim: region mmap failed\n"); exit(9); }
    c->base = b; c->committed = 0; c->used = 0; c->created = 1;
    if (g_trace) fprintf(stderr, "SIM region class=%zu base=%p\n", CLS[ci], (void *)b);
}

static int region_commit(Class *c, int ci, size_t need) {
    region_init(c, ci);
    if (c->committed >= need) return 0;
    size_t target = ((need + INC_BYTES - 1) / INC_BYTES) * INC_BYTES;
    if (target > REGION_BYTES) return -1;
    if (mprotect(c->base + c->committed, target - c->committed,
                 PROT_READ | PROT_WRITE) != 0) {
        perror("sim: mprotect");
        return -1;
    }
    c->committed = target;
    return 0;
}

static void free_push(Class *c, void *p) {
    if (c->nfree == c->freecap) {
        c->freecap = c->freecap ? c->freecap * 2 : 256;
        c->freev = realloc(c->freev, c->freecap * sizeof(void *));
        if (!c->freev) { fprintf(stderr, "sim: free list OOM\n"); exit(9); }
    }
    c->freev[c->nfree++] = p;
}

static void *sim_malloc(void *op, size_t n) {
    (void)op;
    if (n == 0) n = 1;
    int ci = cls_index(n);
    if (ci < 0) {
        size_t total = ((n + 4095) & ~(size_t)4095) + 4096;
        uint8_t *p = mmap(NULL, total, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) return NULL;
        map_put(p, -1);
        if (g_trace) fprintf(stderr, "SIM secondary req=%zu mmap=%p\n", n, (void *)p);
        return p;
    }
    Class *c = &g_cls[ci];
    if (c->nfree) {
        void *p = c->freev[--c->nfree];
        map_put(p, ci);
        return p;
    }
    size_t C = CLS[ci];
    if (c->used + C > c->committed) {
        if (region_commit(c, ci, c->used + C) != 0) return NULL;
    }
    void *p = c->base + c->used;
    c->used += C;
    map_put(p, ci);
    return p;
}

static void *sim_calloc(void *op, size_t cnt, size_t sz) {
    size_t n = cnt * sz;
    void *p = sim_malloc(op, n);
    if (p) memset(p, 0, n);
    return p;
}

static void sim_free(void *op, void *p) {
    (void)op;
    if (!p) return;
    int ci = map_get(p);
    if (ci < 0) return;             /* secondary: leak the mapping (safe model) */
    map_del(p);
    free_push(&g_cls[ci], p);
}

static void *sim_realloc(void *op, void *p, size_t n) {
    if (!p) return sim_malloc(op, n);
    int ci = map_get(p);
    size_t old = ci >= 0 ? CLS[ci] : n;
    void *q = sim_malloc(op, n);
    if (q) { memcpy(q, p, old < n ? old : n); sim_free(op, p); }
    return q;
}

static size_t sim_usable(const void *p) {
    int ci = map_get(p);
    return ci >= 0 ? CLS[ci] : 0;
}

static JSMallocFunctions sim_mf = { sim_calloc, sim_malloc, sim_free, sim_realloc, sim_usable };

static char *rf(const char *path, long *n) {
    FILE *f = fopen(path, "rb"); long l; char *s;
    if (!f) { perror(path); return NULL; }
    fseek(f, 0, SEEK_END); l = ftell(f); fseek(f, 0, SEEK_SET);
    s = malloc((size_t)l + 1);
    if (fread(s, 1, (size_t)l, f) != (size_t)l) { fclose(f); free(s); return NULL; }
    fclose(f); s[l] = 0; *n = l; return s;
}

int main(int argc, char **argv) {
    size_t limit = 8u << 20;
    const char *map_name = "4k";
    int opt;
    while ((opt = getopt(argc, argv, "l:m:t")) != -1) {
        if (opt == 'l') limit = (size_t)strtoull(optarg, NULL, 0) << 20;
        else if (opt == 'm') map_name = optarg;
        else if (opt == 't') g_trace = 1;
    }
    if (!strcmp(map_name, "alt")) {
        CLS = CLS_ALT; NCLS = (int)(sizeof(CLS_ALT) / sizeof(CLS_ALT[0]));
    } else if (!strcmp(map_name, "dense")) {
        CLS = CLS_DENSE; NCLS = (int)(sizeof(CLS_DENSE) / sizeof(CLS_DENSE[0]));
    } else if (!strcmp(map_name, "4k")) {
        CLS = CLS_4K; NCLS = (int)(sizeof(CLS_4K) / sizeof(CLS_4K[0]));
    } else {
        fprintf(stderr, "unknown map %s (4k|alt|dense)\n", map_name);
        return 2;
    }
    if (optind >= argc) {
        fprintf(stderr, "usage: %s [-l MiB] [-m 4k|alt] [-t] script.js ...\n", argv[0]);
        return 2;
    }
    fprintf(stderr, "SIM map=%s classes=%d limit=%zu\n", map_name, NCLS, limit);
    JSRuntime *rt = JS_NewRuntime2(&sim_mf, NULL);
    if (!rt) return 2;
    JS_SetMemoryLimit(rt, limit);
    JS_SetMaxStackSize(rt, 1u << 20);
    JSContext *ctx = JS_NewContext(rt);
    if (!ctx) return 2;

    for (int i = optind; i < argc; i++) {
        long n = 0; char *src = rf(argv[i], &n);
        if (!src) return 2;
        fprintf(stderr, "=== SCRIPT %s (%ld)\n", argv[i], n);
        JSValue v = JS_Eval(ctx, src, (size_t)n, argv[i], JS_EVAL_TYPE_GLOBAL);
        if (JS_IsException(v)) {
            JSValue e = JS_GetException(ctx);
            const char *s = JS_ToCString(ctx, e);
            fprintf(stderr, "[%s] %s: %s\n", argv[i], JS_IsError(e) ? "Error" : "Thrown",
                    s ? s : "(?)");
            if (s) JS_FreeCString(ctx, s);
            JS_FreeValue(ctx, e);
        }
        JS_FreeValue(ctx, v);
        free(src);
        fprintf(stderr, "=== DONE %s\n", argv[i]);
    }
    if (g_trace) {
        for (int ci = 0; ci < NCLS; ci++) {
            if (!g_cls[ci].created) continue;
            fprintf(stderr, "SIM class=%zu used=%zu committed=%zu nfree=%zu\n",
                    CLS[ci], g_cls[ci].used, g_cls[ci].committed, g_cls[ci].nfree);
        }
    }
    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);
    return 0;
}
