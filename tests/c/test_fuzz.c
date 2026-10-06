/* test_fuzz.c — seeded deterministic negative-matrix fuzz (B-10.6/B-11.6).
 *
 * NOT coverage-guided fuzzing: a fixed-seed SplitMix64 stream (test_rng.c)
 * generates N cases per level per class, so every run replays bit-for-bit.
 * The seed is printed first; any failure reproduces from that seed alone.
 *
 * Oracles (taxonomy, never crash/hang):
 * - KEM encaps: OK (all-zero pk passes the modulus check) or BAD_KEY
 *   (all-one pk fails it); flipped pk either way, never INTERNAL. On OK
 *   with a flipped pk, decaps under the original sk must implicitly
 *   reject (OK, unrelated ss) — a changed pk can never roundtrip.
 * - KEM decaps: always OK in this harness (only ever called with the
 *   valid sk; a corrupt sk would report BAD_KEY per qc_kem.h).
 *   Tampered ct must yield ss != the encaps ss (rejection correctness,
 *   collision 2^-256, pinned by the fixed seed).
 * - DSA sign: always OK (backend assumes valid sk — documents B-11
 *   no-validation property; a destroyed sk signs blindly).
 * - DSA verify: OK only for the exact (msg, ctx, sig, pk) tuple;
 *   everything else BAD_SIG. Never INTERNAL, never OK-on-tamper.
 *
 * Buffers are statically max-sized (KEM-1024 / DSA-87 extents) so no
 * malformed input can read out of bounds — over/under-size inputs do not
 * exist in this fixed-size API; the classes below are the full reachable
 * negative space (bit-flips, all-zero, all-one, cross-key).
 */
#include "unity.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "qc_dsa.h"
#include "qc_kem.h"
#include "qc_rng.h"

void test_rng_seed(uint64_t seed);

#ifndef QC_FUZZ_N
#define QC_FUZZ_N 200
#endif

#define FUZZ_SEED 0x51AB3F7C9D2E4011ull

static void rand_bytes(uint8_t *out, size_t n) {
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, qc_rng_generate(out, n), "rng");
}

/* Flip nbits DISTINCT bytes (one random nonzero bit each). Distinct
 * positions guarantee the buffer actually changes: naive reselection can
 * cancel (same offset twice with equal masks), silently weakening a
 * must-differ/BAD_SIG oracle into a vacuous pass. */
static void flip_bits(uint8_t *buf, size_t len, int nbits) {
    size_t used[8];
    int b = 0;

    TEST_ASSERT_TRUE_MESSAGE(nbits <= 8 && (size_t)nbits <= len, "flip");
    while (b < nbits) {
        uint64_t draw;
        size_t at;
        uint8_t mask;
        int seen = 0;
        /* Fixed-width draw: replay is bit-identical across 32/64-bit. */
        rand_bytes((uint8_t *)&draw, sizeof(draw));
        at = (size_t)(draw % (uint64_t)len);
        for (int k = 0; k < b; k++) {
            if (used[k] == at) {
                seen = 1;
                break;
            }
        }
        if (seen) {
            continue;
        }
        used[b] = at;
        rand_bytes(&mask, 1);
        mask |= 0x01;
        buf[at] ^= mask;
        b++;
    }
}

/* ---------------- KEM ---------------- */

static void fuzz_kem_level(qc_kem_level level, const char *label) {
    /* Max extents cover 1024; real lengths from queries. */
    static uint8_t pk[1568], sk[3168], ct[1568], ss[32], back[32];
    static uint8_t coins64[64], coins32[32], pk2[1568], ss2[32], ct2[1568];
    size_t pk_len = qc_kem_pk_bytes(level);
    size_t sk_len = qc_kem_sk_bytes(level);
    size_t ct_len = qc_kem_ct_bytes(level);
    int rc;

    TEST_ASSERT_TRUE_MESSAGE(pk_len > 0 && sk_len > 0 && ct_len > 0, label);

    for (int i = 0; i < QC_FUZZ_N; i++) {
        /* Valid roundtrip with fresh coins (liveness). */
        rand_bytes(coins64, sizeof(coins64));
        rand_bytes(coins32, sizeof(coins32));
        TEST_ASSERT_EQUAL_INT_MESSAGE(QC_KEM_OK,
                                      qc_kem_keypair(level, pk, sk, coins64),
                                      label);
        TEST_ASSERT_EQUAL_INT_MESSAGE(QC_KEM_OK,
                                      qc_kem_encaps(level, ct, ss, pk, coins32),
                                      label);
        TEST_ASSERT_EQUAL_INT_MESSAGE(QC_KEM_OK,
                                      qc_kem_decaps(level, back, ct, sk),
                                      label);
        TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(ss, back, 32, label);

        /* Bit-flipped ct: decaps OK but ss must differ (rejection). */
        memcpy(pk2, ct, ct_len);
        flip_bits(pk2, ct_len, 1 + (i % 8));
        TEST_ASSERT_EQUAL_INT_MESSAGE(QC_KEM_OK,
                                      qc_kem_decaps(level, back, pk2, sk),
                                      label);
        TEST_ASSERT_TRUE_MESSAGE(memcmp(ss, back, 32) != 0, label);

        /* Bit-flipped pk: OK or BAD_KEY, never INTERNAL. On OK the
         * flipped key differs from sk's embedded pk, so decaps must
         * implicitly reject (OK, unrelated ss) — a flipped pk can never
         * roundtrip against the original sk. ct2/ss2 are dedicated
         * outputs: aliasing is outside the adapter contract, and ct
         * (up to 1568 B) must never share ss's 32 B. */
        memcpy(pk2, pk, pk_len);
        flip_bits(pk2, pk_len, 1 + (i % 5));
        rc = qc_kem_encaps(level, ct2, ss2, pk2, coins32);
        TEST_ASSERT_TRUE_MESSAGE(rc == QC_KEM_OK || rc == QC_KEM_BAD_KEY,
                                 label);
        if (rc == QC_KEM_OK) {
            TEST_ASSERT_EQUAL_INT_MESSAGE(QC_KEM_OK,
                                          qc_kem_decaps(level, back, ct2, sk),
                                          label);
            TEST_ASSERT_TRUE_MESSAGE(memcmp(ss2, back, 32) != 0, label);
        }

        /* Cross-key decaps: OK (rejection), ss differs. */
        rand_bytes(coins64, sizeof(coins64));
        {
            static uint8_t sk2[3168];
            TEST_ASSERT_EQUAL_INT_MESSAGE(QC_KEM_OK,
                                          qc_kem_keypair(level, pk2, sk2,
                                                         coins64),
                                          label);
            TEST_ASSERT_EQUAL_INT_MESSAGE(QC_KEM_OK,
                                          qc_kem_decaps(level, back, ct, sk2),
                                          label);
            TEST_ASSERT_TRUE_MESSAGE(memcmp(ss, back, 32) != 0, label);
        }
    }

    /* All-zero pk: all coefficients 0 < q, so the modulus check passes
     * and encaps returns OK — but against the real sk it must implicitly
     * reject (zero key differs from sk's embedded pk). All-one pk:
     * coefficients 0xFFF >= q, so BAD_KEY. Both pinned (deterministic
     * backend, no probability). */
    memset(pk2, 0, pk_len);
    TEST_ASSERT_EQUAL_INT_MESSAGE(QC_KEM_OK,
                                  qc_kem_encaps(level, ct2, ss2, pk2, coins32),
                                  label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(QC_KEM_OK,
                                  qc_kem_decaps(level, back, ct2, sk),
                                  label);
    TEST_ASSERT_TRUE_MESSAGE(memcmp(ss2, back, 32) != 0, label);
    memset(pk2, 0xFF, pk_len);
    TEST_ASSERT_EQUAL_INT_MESSAGE(QC_KEM_BAD_KEY,
                                  qc_kem_encaps(level, ct2, ss2, pk2, coins32),
                                  label);

    /* All-zero ct: decaps OK (rejection path). */
    memset(pk2, 0, ct_len);
    TEST_ASSERT_EQUAL_INT_MESSAGE(QC_KEM_OK,
                                  qc_kem_decaps(level, back, pk2, sk), label);
}

static void test_fuzz_kem_512(void) {
    fuzz_kem_level(QC_KEM_512, "fuzz512");
}

static void test_fuzz_kem_768(void) {
    fuzz_kem_level(QC_KEM_768, "fuzz768");
}

static void test_fuzz_kem_1024(void) {
    fuzz_kem_level(QC_KEM_1024, "fuzz1024");
}

/* ---------------- DSA ---------------- */

static void fuzz_dsa_level(qc_dsa_level level, const char *label) {
    /* bad doubles for flipped sk (4896 max) — sized to the largest.
     * sig2 keeps destroyed-key signatures off the live sig. */
    static uint8_t pk[2592], sk[4896], sig[4627], bad[4896], sig2[4627];
    static uint8_t seed[32], rnd[32], msg[64];
    static const uint8_t ctx[] = { 'f', 'u', 'z', 'z' };
    size_t pk_len = qc_dsa_pk_bytes(level);
    size_t sk_len = qc_dsa_sk_bytes(level);
    size_t sig_len = qc_dsa_sig_bytes(level);
    int rc;

    TEST_ASSERT_TRUE_MESSAGE(pk_len > 0 && sk_len > 0 && sig_len > 0, label);

    for (int i = 0; i < QC_FUZZ_N; i++) {
        /* Valid roundtrip (liveness). */
        rand_bytes(seed, sizeof(seed));
        rand_bytes(rnd, sizeof(rnd));
        rand_bytes(msg, sizeof(msg));
        TEST_ASSERT_EQUAL_INT_MESSAGE(QC_DSA_OK,
                                      qc_dsa_keypair(level, pk, sk, seed),
                                      label);
        TEST_ASSERT_EQUAL_INT_MESSAGE(QC_DSA_OK,
                                      qc_dsa_sign(level, sig, msg, sizeof(msg),
                                                  ctx, sizeof(ctx), rnd, sk),
                                      label);
        TEST_ASSERT_EQUAL_INT_MESSAGE(QC_DSA_OK,
                                      qc_dsa_verify(level, msg, sizeof(msg),
                                                    ctx, sizeof(ctx), sig, pk),
                                      label);

        /* Flipped signature: BAD_SIG, never OK. */
        memcpy(bad, sig, sig_len);
        flip_bits(bad, sig_len, 1 + (i % 8));
        TEST_ASSERT_EQUAL_INT_MESSAGE(QC_DSA_BAD_SIG,
                                      qc_dsa_verify(level, msg, sizeof(msg),
                                                    ctx, sizeof(ctx), bad, pk),
                                      label);

        /* Flipped message: BAD_SIG. */
        {
            static uint8_t m2[64];
            memcpy(m2, msg, sizeof(m2));
            flip_bits(m2, sizeof(m2), 1);
            TEST_ASSERT_EQUAL_INT_MESSAGE(QC_DSA_BAD_SIG,
                                          qc_dsa_verify(level, m2, sizeof(m2),
                                                        ctx, sizeof(ctx),
                                                        sig, pk),
                                          label);
        }

        /* Destroyed sk (whole key overwritten with stream bytes) signs
         * blindly OK (no-validation property); the result fails under
         * the ORIGINAL pk except with negligible forgery probability.
         * NOTE: single-bit flips are NOT used here: Dilithium's hint
         * mechanism can tolerate a 1-bit t0 perturbation, which may leave
         * the signature valid — and whole-key replacement assumes no sk
         * layout (rho/key/tr positions are backend detail). Signs into
         * sig2 so the live sig survives for the flipped-pk oracle below. */
        memcpy(bad, sk, sk_len);
        rand_bytes(bad, sk_len);
        rc = qc_dsa_sign(level, sig2, msg, sizeof(msg),
                         ctx, sizeof(ctx), rnd, bad);
        TEST_ASSERT_EQUAL_INT_MESSAGE(QC_DSA_OK, rc, label);
        TEST_ASSERT_EQUAL_INT_MESSAGE(QC_DSA_BAD_SIG,
                                      qc_dsa_verify(level, msg, sizeof(msg),
                                                    ctx, sizeof(ctx), sig2, pk),
                                      label);

        /* Flipped pk: the ORIGINAL sig fails (wrong-key reads BAD_SIG). */
        memcpy(bad, pk, pk_len);
        flip_bits(bad, pk_len, 1 + (i % 3));
        TEST_ASSERT_EQUAL_INT_MESSAGE(QC_DSA_BAD_SIG,
                                      qc_dsa_verify(level, msg, sizeof(msg),
                                                    ctx, sizeof(ctx), sig, bad),
                                      label);
    }

    /* All-zero / all-one signatures: BAD_SIG. */
    memset(bad, 0, sig_len);
    TEST_ASSERT_EQUAL_INT_MESSAGE(QC_DSA_BAD_SIG,
                                  qc_dsa_verify(level, msg, sizeof(msg),
                                                ctx, sizeof(ctx), bad, pk),
                                  label);
    memset(bad, 0xFF, sig_len);
    TEST_ASSERT_EQUAL_INT_MESSAGE(QC_DSA_BAD_SIG,
                                  qc_dsa_verify(level, msg, sizeof(msg),
                                                ctx, sizeof(ctx), bad, pk),
                                  label);
}

static void test_fuzz_dsa_44(void) {
    fuzz_dsa_level(QC_DSA_44, "fuzz44");
}

static void test_fuzz_dsa_65(void) {
    fuzz_dsa_level(QC_DSA_65, "fuzz65");
}

static void test_fuzz_dsa_87(void) {
    fuzz_dsa_level(QC_DSA_87, "fuzz87");
}

void setUp(void) {
    test_rng_seed(FUZZ_SEED);
    printf("fuzz seed: 0x%llX\n", (unsigned long long)FUZZ_SEED);
}

void tearDown(void) {}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_fuzz_kem_512);
    RUN_TEST(test_fuzz_kem_768);
    RUN_TEST(test_fuzz_kem_1024);
    RUN_TEST(test_fuzz_dsa_44);
    RUN_TEST(test_fuzz_dsa_65);
    RUN_TEST(test_fuzz_dsa_87);
    return UNITY_END();
}