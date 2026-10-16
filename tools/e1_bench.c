/* e1_bench.c - E1 host microbenchmark runner (plan B-51).
 *
 * Measures TIME, CYCLES, STACK and HEAP per operation x level through the
 * production adapter entry points (B-51.1). Deliberately does NOT emit
 * any energy field: B-51.3 forbids joules on host (host power is
 * unrepresentative of the target; energy is B-62's rig plus the model).
 * The schema's ABSENCE of an energy key is the enforcement.
 *
 * Determinism, stated honestly: the SETUP is deterministic - fixed seed,
 * stated N per cell, stated warmup fraction, fixed loop counts, fixed
 * size sweep - so two runs measure the same work. The TIMINGS are
 * physical measurements and are not bit-reproducible; that is what the
 * dataset retains verbatim. Claiming reproducible microseconds would be
 * the vacuous pass B-51.5 forbids.
 *
 * The runner is driven by tools/e1_run.py, which owns the gate-ID check,
 * host-spec capture, dataset versioning and the B-33 fill.
 */
/* clock_gettime/CLOCK_MONOTONIC are POSIX, not ISO C11. The tree builds
 * with -std=c11 -Werror (CMAKE_C_EXTENSIONS OFF), so glibc hides them
 * unless the feature-test macro is set BEFORE the first include. */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "qc_aead.h"
#include "qc_dsa.h"
#include "qc_hkdf.h"
#include "qc_hmac.h"
#include "qc_kem.h"
#include "qc_prof.h"
#include "qc_sha256.h"

#define E1_N_DEFAULT 200
#define E1_N_DSA_SIGN 500
#define E1_WARMUP_PCT 10
#define E1_MAX_SAMPLES (E1_N_DSA_SIGN + 64)
#define E1_MAX_PAYLOAD 4096
#define E1_LOOP_THRESHOLD_NS 10000u   /* under 10 us -> loop-timed */

/* Fixed seed: E1 compares operations against each other, not across
 * machines, so the coins must be identical run to run. */
#define E1_SEED 0x5A17C0DEu

static uint64_t rng_state;

static uint32_t next_u32(void) {
    rng_state = rng_state * 6364136223846793005ULL + 1442695040888963407ULL;
    return (uint32_t)(rng_state >> 33);
}

static void rng_seed(uint64_t s) { rng_state = s; }

static void fill_bytes(uint8_t *p, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        p[i] = (uint8_t)(next_u32() >> 13);
    }
}

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* ---- statistics (no libm: sorting is enough) --------------------------- */

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x < y) ? -1 : (x > y) ? 1 : 0;
}

static uint64_t pct(const uint64_t *sorted, size_t n, unsigned p) {
    /* Nearest-rank percentile: index = ceil(p/100 * n) - 1. */
    size_t idx = ((size_t)p * n + 99u) / 100u;
    if (idx == 0) {
        idx = 1;
    }
    if (idx > n) {
        idx = n;
    }
    return sorted[idx - 1];
}

/* ---- cell plumbing ----------------------------------------------------- */

typedef struct {
    const char *op;
    const char *level;
    size_t payload;
    uint64_t ns[E1_MAX_SAMPLES];
    uint64_t cyc[E1_MAX_SAMPLES];
    size_t n;
    size_t loops;
    size_t heap_live;
} e1_cell;

typedef int (*e1_fn)(e1_cell *c, size_t i);

static size_t warmup_count(size_t n) { return (n * E1_WARMUP_PCT) / 100u; }

/* Runs `fn` n+warmup times, keeping the last n samples. Chooses the loop
 * count from a 10-iteration probe so sub-10us ops are amortised (their
 * timer resolution would otherwise dominate). */
static void run_cell(e1_cell *c, e1_fn fn, size_t n) {
    size_t warm = warmup_count(n);
    size_t total = n + warm;
    size_t i, l;

    c->n = 0;
    c->loops = 1;

    /* Probe with 10 iterations to size the loop. */
    for (i = 0; i < 10; i++) {
        (void)fn(c, i);
    }
    {
        uint64_t t0 = now_ns();
        uint64_t t1;
        for (i = 0; i < 10; i++) {
            (void)fn(c, i);
        }
        t1 = now_ns();
        {
            uint64_t per = (t1 - t0) / 10u;
            if (per < E1_LOOP_THRESHOLD_NS && per > 0) {
                c->loops = (size_t)(E1_LOOP_THRESHOLD_NS / per);
                if (c->loops > 10000u) {
                    c->loops = 10000u;
                }
                if (c->loops < 1) {
                    c->loops = 1;
                }
            }
        }
    }

    for (i = 0; i < total; i++) {
        uint64_t t0, t1, c0, c1;
        size_t slot = (i < warm) ? (size_t)-1 : (i - warm);
        int ok = 1;

        qc_heap_track_begin();
        c0 = qc_cycles();
        t0 = now_ns();
        for (l = 0; l < c->loops; l++) {
            ok = fn(c, i);
        }
        t1 = now_ns();
        c1 = qc_cycles();
        c->heap_live = qc_heap_stat_get().live_bytes;
        qc_heap_track_end();

        if (slot == (size_t)-1) {
            continue;                    /* warmup discarded, per B-51.2 */
        }
        if (!ok) {
            fprintf(stderr, "e1_bench: op %s/%s returned failure at i=%zu\n",
                    c->op, c->level, i);
            exit(3);
        }
        c->ns[slot] = (t1 - t0) / c->loops;
        c->cyc[slot] = (c1 - c0) / c->loops;
        c->n++;
    }
}

static void emit(const e1_cell *c, const char *gate_hint) {
    uint64_t *ns = (uint64_t *)malloc(c->n * sizeof(uint64_t));
    uint64_t *cy = (uint64_t *)malloc(c->n * sizeof(uint64_t));
    uint64_t sum = 0, mean;
    size_t i;

    if (ns == NULL || cy == NULL) {
        fprintf(stderr, "e1_bench: out of memory\n");
        exit(3);
    }
    memcpy(ns, c->ns, c->n * sizeof(uint64_t));
    memcpy(cy, c->cyc, c->n * sizeof(uint64_t));
    for (i = 0; i < c->n; i++) {
        sum += ns[i];
    }
    mean = c->n ? sum / c->n : 0;
    qsort(ns, c->n, sizeof(uint64_t), cmp_u64);
    qsort(cy, c->n, sizeof(uint64_t), cmp_u64);

    printf("{\"op\":\"%s\",\"level\":\"%s\",\"payload\":%zu,"
           "\"n\":%zu,\"warmup_discarded\":%zu,\"loops\":%zu,"
           "\"ns_mean\":%llu,\"ns_p50\":%llu,\"ns_p95\":%llu,"
           "\"ns_p99\":%llu,\"ns_max\":%llu,"
           "\"cycles_p50\":%llu,"
           "\"heap_live_bytes\":\"pending-verification\",\"cycle_source\":\"%s\","
           "\"stack_metric\":\"pending-verification\","
           "\"energy_field\":\"absent-by-design\",\"record\":\"%s\"}\n",
           c->op, c->level, c->payload, c->n, warmup_count(c->n), c->loops,
           (unsigned long long)mean,
           (unsigned long long)pct(ns, c->n, 50),
           (unsigned long long)pct(ns, c->n, 95),
           (unsigned long long)pct(ns, c->n, 99),
           (unsigned long long)ns[c->n - 1],
           (unsigned long long)pct(cy, c->n, 50),
           QC_PROF_CYCLE_SOURCE, gate_hint);
    free(ns);
    free(cy);
}

/* ---- operations -------------------------------------------------------- */

/* Buffers sized to the LARGEST requirement across BOTH families, not to
 * the family written first. ML-KEM-1024 and ML-DSA-87 share bench_pk /
 * bench_sk / bench_sig, and DSING past ML-KEM's maximum is what an
 * earlier revision got wrong: pk[1568] and sk[3168] are exactly the
 * ML-KEM-1024 sizes, so the 65 and 87 rows wrote 1952/2592 and 4032/4896
 * bytes into them. The overflow was invisible only because the binary was
 * never executed - it compiled, and nothing ran it.
 *
 * These are compile-time checked below, so a future level addition fails
 * the build instead of the campaign. */
#define E1_BUF_PK 2592u   /* ML-DSA-87 */
#define E1_BUF_SK 4896u   /* ML-DSA-87 */
#define E1_BUF_CT 1568u   /* ML-KEM-1024 */
#define E1_BUF_SIG 4627u  /* ML-DSA-87 */

_Static_assert(E1_BUF_PK >= QC_KEM1024_PK_BYTES, "pk too small for KEM");
_Static_assert(E1_BUF_SK >= QC_KEM1024_SK_BYTES, "sk too small for KEM");
_Static_assert(E1_BUF_CT >= QC_KEM1024_CT_BYTES, "ct too small for KEM");
_Static_assert(E1_BUF_PK >= QC_DSA87_PK_BYTES, "pk too small for DSA");
_Static_assert(E1_BUF_SK >= QC_DSA87_SK_BYTES, "sk too small for DSA");
_Static_assert(E1_BUF_SIG >= QC_DSA87_SIG_BYTES, "sig too small for DSA");

static uint8_t bench_pk[E1_BUF_PK], bench_sk[E1_BUF_SK];
static uint8_t bench_ct[E1_BUF_CT], bench_ss[QC_KEM_SS_BYTES];
static uint8_t bench_coins[64];
static uint8_t bench_msg[64];
static uint8_t bench_sig[E1_BUF_SIG];
static uint8_t bench_seed[QC_DSA_SEED_BYTES];
static uint8_t bench_rnd[QC_DSA_RND_BYTES];
static uint8_t bench_payload[E1_MAX_PAYLOAD];
static uint8_t bench_ctbuf[E1_MAX_PAYLOAD + QC_AEAD_TAG_LEN];
static uint8_t bench_key[QC_AEAD_KEY_LEN];
static uint8_t bench_nonce[QC_AEAD_NONCE_LEN];
static uint8_t bench_prk[32], bench_okm[64];

/* Digest consumption: the result is written to a volatile sink so the
 * call cannot be optimised away. An earlier revision used
 * `return out[0] != 0xFF ? 1 : 1`, which is an always-true comparison -
 * it happened to create the data dependency, but it reads exactly like a
 * broken assertion and would be the first thing a reviewer flagged. */
static volatile uint8_t qc_e1_sink8;
static volatile size_t qc_e1_sink;

static int op_sha256(e1_cell *c, size_t i) {
    uint8_t out[QC_SHA256_DIGEST_LEN];
    (void)i;
    qc_sha256(bench_payload, c->payload, out);
    qc_e1_sink8 = out[0];
    qc_e1_sink = (size_t)out[QC_SHA256_DIGEST_LEN - 1];
    return 1;
}

static int op_hmac(e1_cell *c, size_t i) {
    uint8_t out[32];
    (void)i;
    qc_hmac_sha256(bench_key, sizeof(bench_key), bench_payload, c->payload,
                   out);
    qc_e1_sink8 = out[0];
    qc_e1_sink = (size_t)out[31];
    return 1;
}

static int op_aead_encrypt(e1_cell *c, size_t i) {
    uint8_t tag[QC_AEAD_TAG_LEN];
    (void)i;
    return qc_aead_encrypt(bench_key, sizeof(bench_key), bench_nonce,
                           sizeof(bench_nonce), NULL, 0, bench_payload,
                           c->payload, bench_ctbuf, tag) == 0;
}

static int op_hkdf_expand(e1_cell *c, size_t i) {
    (void)c; (void)i;
    return qc_hkdf_expand(bench_prk, NULL, 0, bench_okm,
                          sizeof(bench_okm)) == 0;
}

/* ---- matrix ------------------------------------------------------------ */

typedef struct {
    const char *op;
    const char *level;
    e1_fn fn;
    size_t n;
    size_t payload;
    qc_kem_level kem;
    qc_dsa_level dsa;
} e1_spec;

/* Level-parameterised wrappers: the B-51 matrix is op x level, and the
 * adapter entry points take the level as data, so one wrapper per level
 * per family keeps the matrix table flat. */
static qc_kem_level g_kem_lvl;
static qc_dsa_level g_dsa_lvl;

/* Coins and seeds are filled ONCE, before the timed region, and reused by
 * every sample. An earlier revision refilled them inside each measured
 * call, which charged RNG setup to the primitive: a fixed ~100 ns added to
 * operations of 50 us to 1 ms, so 0.01-0.2% - small enough to hide under
 * run-to-run noise but a systematic bias sitting inside a per-level
 * comparison. Reusing fixed coins also makes a run exactly reproducible
 * for the same binary. */
static int op_kem_keygen_l(e1_cell *c, size_t i) {
    (void)c; (void)i;
    return qc_kem_keypair(g_kem_lvl, bench_pk, bench_sk, bench_coins) == 0;
}

static int op_kem_encaps_l(e1_cell *c, size_t i) {
    (void)c; (void)i;
    return qc_kem_encaps(g_kem_lvl, bench_ct, bench_ss, bench_pk,
                         bench_coins) == 0;
}

static int op_kem_decaps_l(e1_cell *c, size_t i) {
    (void)c; (void)i;
    return qc_kem_decaps(g_kem_lvl, bench_ss, bench_ct, bench_sk) == 0;
}

static int op_dsa_sign_l(e1_cell *c, size_t i) {
    (void)c; (void)i;
    return qc_dsa_sign(g_dsa_lvl, bench_sig, bench_msg, sizeof(bench_msg),
                       NULL, 0, bench_rnd, bench_sk) == 0;
}

static int op_dsa_verify_l(e1_cell *c, size_t i) {
    (void)c; (void)i;
    return qc_dsa_verify(g_dsa_lvl, bench_msg, sizeof(bench_msg), NULL, 0,
                         bench_sig, bench_pk) == 0;
}

static int op_dsa_keygen_l(e1_cell *c, size_t i) {
    (void)c; (void)i;
    return qc_dsa_keypair(g_dsa_lvl, bench_pk, bench_sk, bench_seed) == 0;
}

int main(int argc, char **argv) {
    const char *tag = (argc > 1) ? argv[1] : "untagged";
    size_t n_override = (argc > 2) ? (size_t)atoi(argv[2]) : 0;
    e1_cell c;
    size_t i;

    rng_seed(E1_SEED);
    memset(&c, 0, sizeof(c));
    fill_bytes(bench_payload, sizeof(bench_payload));
    fill_bytes(bench_key, sizeof(bench_key));
    fill_bytes(bench_nonce, sizeof(bench_nonce));
    fill_bytes(bench_msg, sizeof(bench_msg));
    fill_bytes(bench_rnd, sizeof(bench_rnd));
    fill_bytes(bench_prk, sizeof(bench_prk));
    /* KEM coins / DSA seed filled ONCE here, never inside a timed call
     * (see op_kem_keygen_l). The first fill leaves 64 bytes for keygen
     * coins; encaps uses the first 32 of the same buffer, which is its
     * own 32-byte requirement. */
    fill_bytes(bench_coins, sizeof(bench_coins));
    fill_bytes(bench_seed, sizeof(bench_seed));

    /* SHA-256 / HMAC / AEAD size sweep: 16 B .. 4 KB per B-51.3 (no
     * single-number summary; each size is its own row). */
    {
        static const size_t sizes[] = {16, 32, 64, 128, 256, 512, 1024,
                                       2048, 3072, 4096};
        for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
            memset(&c, 0, sizeof(c));
            c.op = "sha256"; c.level = "host"; c.payload = sizes[i];
            run_cell(&c, op_sha256, n_override ? n_override : E1_N_DEFAULT);
            emit(&c, tag);

            memset(&c, 0, sizeof(c));
            c.op = "hmac-sha256"; c.level = "host"; c.payload = sizes[i];
            run_cell(&c, op_hmac, n_override ? n_override : E1_N_DEFAULT);
            emit(&c, tag);

            memset(&c, 0, sizeof(c));
            c.op = "aes-256-gcm-encrypt"; c.level = "host";
            c.payload = sizes[i];
            run_cell(&c, op_aead_encrypt,
                     n_override ? n_override : E1_N_DEFAULT);
            emit(&c, tag);
        }
    }

    memset(&c, 0, sizeof(c));
    c.op = "hkdf-expand-64"; c.level = "host"; c.payload = 64;
    run_cell(&c, op_hkdf_expand, n_override ? n_override : E1_N_DEFAULT);
    emit(&c, tag);

    /* ML-KEM x level */
    {
        static const qc_kem_level lv[] = {QC_KEM_512, QC_KEM_768,
                                          QC_KEM_1024};
        static const char *ln[] = {"512", "768", "1024"};
        size_t k;
        for (k = 0; k < 3; k++) {
            g_kem_lvl = lv[k];
            memset(&c, 0, sizeof(c));
            c.op = "ml-kem-keygen"; c.level = ln[k];
            run_cell(&c, op_kem_keygen_l,
                     n_override ? n_override : E1_N_DEFAULT);
            emit(&c, tag);
            memset(&c, 0, sizeof(c));
            c.op = "ml-kem-encaps"; c.level = ln[k];
            run_cell(&c, op_kem_encaps_l,
                     n_override ? n_override : E1_N_DEFAULT);
            emit(&c, tag);
            memset(&c, 0, sizeof(c));
            c.op = "ml-kem-decaps"; c.level = ln[k];
            run_cell(&c, op_kem_decaps_l,
                     n_override ? n_override : E1_N_DEFAULT);
            emit(&c, tag);
        }
    }

    /* ML-DSA x level; sign carries the N=500 requirement. */
    {
        static const qc_dsa_level lv[] = {QC_DSA_44, QC_DSA_65, QC_DSA_87};
        static const char *ln[] = {"44", "65", "87"};
        size_t k;
        for (k = 0; k < 3; k++) {
            g_dsa_lvl = lv[k];
            memset(&c, 0, sizeof(c));
            c.op = "ml-dsa-keygen"; c.level = ln[k];
            run_cell(&c, op_dsa_keygen_l,
                     n_override ? n_override : E1_N_DEFAULT);
            emit(&c, tag);
            memset(&c, 0, sizeof(c));
            c.op = "ml-dsa-sign"; c.level = ln[k];
            run_cell(&c, op_dsa_sign_l,
                     n_override ? n_override : E1_N_DSA_SIGN);
            emit(&c, tag);
            memset(&c, 0, sizeof(c));
            c.op = "ml-dsa-verify"; c.level = ln[k];
            run_cell(&c, op_dsa_verify_l,
                     n_override ? n_override : E1_N_DEFAULT);
            emit(&c, tag);
        }
    }

    return 0;
}
