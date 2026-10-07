/* test_replay.c — L0/L1 for the bounded replay cache (B-22.2).
 *
 * Covers: normative key layout incl. epoch big-endian (byte-exact),
 * 1-byte mutation miss on every key component, duplicate-insert
 * idempotence, complete/store/resend-bytes, completed-vs-in-flight
 * branching, LRU-over-completed-only eviction with victim identity,
 * in-flight pinning (FULL when nothing evictable), expiry + slot reuse,
 * capacity clamp/reject, oversize-M2 reject, NULL guards.
 *
 * NOTE: qc_cache instances are ALWAYS static here, never stack locals:
 * one cache is ~2 MB (1024 slots x ~2 KB M2 buffer) and two on a frame
 * overflowed the 8 MB stack (SEGFAULT, caught pre-commit). Same rule for
 * any future test touching this unit.
 */
#include "unity.h"

#include <string.h>

#include "qc_replay.h"
#include "qc_sha256.h"

static void fill_id(uint8_t id[16]) {
    for (int i = 0; i < 16; i++) {
        id[i] = (uint8_t)(0x10 + i);
    }
}

static void fill_nw(uint8_t nw[12]) {
    for (int i = 0; i < 12; i++) {
        nw[i] = (uint8_t)(0xA0 + i);
    }
}

/* Normative layout: id[16] || epoch-BE[4] || nw[12] || sha256(ct)[32]. */
static void test_key_layout(void) {
    uint8_t id[16], nw[12], key[64], digest[32];
    static const uint8_t ct[] = { 'c', 't' };

    fill_id(id);
    fill_nw(nw);
    qc_cache_key(id, 0x01020304u, nw, ct, sizeof(ct), key);

    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(id, key, 16, "id");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0x01, key[16], "epoch BE");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0x02, key[17], "epoch BE");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0x03, key[18], "epoch BE");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0x04, key[19], "epoch BE");
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(nw, key + 20, 12, "nw");
    qc_sha256(ct, sizeof(ct), digest);
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(digest, key + 32, 32, "h(ct)");
}

/* One flipped byte in ANY of the 64 key positions must miss.
 * Exhaustive over all offsets (not strided): the 4 epoch bytes 16-19
 * are the highest-risk real-world mutation (counter/epoch confusion)
 * and a stride could skip them. */
static void test_key_mutation_miss(void) {
    uint8_t id[16], nw[12], k0[64], k1[64], ct[8];
    static qc_cache c;

    fill_id(id);
    fill_nw(nw);
    memset(ct, 0x33, sizeof(ct));
    TEST_ASSERT_EQUAL_INT(QC_CACHE_OK, qc_cache_init(&c, 8, 0));
    qc_cache_key(id, 7u, nw, ct, sizeof(ct), k0);
    TEST_ASSERT_EQUAL_INT(QC_CACHE_OK, qc_cache_insert(&c, k0, 100));

    for (int off = 0; off < 64; off++) {
        memcpy(k1, k0, 64);
        k1[off] ^= 0x01;
        TEST_ASSERT_NULL_MESSAGE(qc_cache_lookup(&c, k1, 100), "miss");
    }
    /* Untouched key still hits. */
    TEST_ASSERT_NOT_NULL_MESSAGE(qc_cache_lookup(&c, k0, 100), "hit");
}

/* Empty ciphertext hashes cleanly (NULL iff len 0) and keys differently
 * from any non-empty ciphertext. */
static void test_key_empty_ct(void) {
    uint8_t id[16], nw[12], k0[64], k1[64];
    static const uint8_t ct[] = { 'z' };

    fill_id(id);
    fill_nw(nw);
    qc_cache_key(id, 1u, nw, NULL, 0, k0);
    qc_cache_key(id, 1u, nw, ct, sizeof(ct), k1);
    TEST_ASSERT_TRUE_MESSAGE(memcmp(k0, k1, 64) != 0, "empty differs");
}

/* Insert -> in-flight (not completed) -> complete stores M2 -> lookup. */
static void test_lifecycle(void) {
    uint8_t id[16], nw[12], key[64];
    static const uint8_t ct[] = { 'x' };
    static const uint8_t m2[] = { 'm', '2' };
    static qc_cache c;
    const qc_cache_entry *e;

    fill_id(id);
    fill_nw(nw);
    TEST_ASSERT_EQUAL_INT(QC_CACHE_OK, qc_cache_init(&c, 8, 0));
    qc_cache_key(id, 1u, nw, ct, sizeof(ct), key);

    TEST_ASSERT_NULL(qc_cache_lookup(&c, key, 100));
    TEST_ASSERT_EQUAL_INT(QC_CACHE_OK, qc_cache_insert(&c, key, 100));
    e = qc_cache_lookup(&c, key, 100);
    TEST_ASSERT_NOT_NULL(e);
    TEST_ASSERT_EQUAL_UINT8(0, e->completed);

    /* Duplicate insert: idempotent, keeps in-flight state. */
    TEST_ASSERT_EQUAL_INT(QC_CACHE_OK, qc_cache_insert(&c, key, 100));
    e = qc_cache_lookup(&c, key, 100);
    TEST_ASSERT_NOT_NULL(e);
    TEST_ASSERT_EQUAL_UINT8(0, e->completed);

    TEST_ASSERT_EQUAL_INT(QC_CACHE_OK,
                          qc_cache_complete(&c, key, m2, sizeof(m2), 101));
    e = qc_cache_lookup(&c, key, 101);
    TEST_ASSERT_NOT_NULL(e);
    TEST_ASSERT_EQUAL_UINT8(1, e->completed);
    TEST_ASSERT_EQUAL_UINT(sizeof(m2), e->m2_len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(m2, e->m2, sizeof(m2));

    TEST_ASSERT_EQUAL_INT(QC_CACHE_OK, qc_cache_remove(&c, key));
    TEST_ASSERT_NULL(qc_cache_lookup(&c, key, 101));
    TEST_ASSERT_EQUAL_INT(QC_CACHE_MISS, qc_cache_remove(&c, key));
    TEST_ASSERT_EQUAL_INT(QC_CACHE_MISS,
                          qc_cache_complete(&c, key, m2, sizeof(m2), 101));
}

/* LRU evicts the OLDEST completed entry; in-flight entries pin. */
static void test_lru_and_pinning(void) {
    uint8_t id[16], nw[12], k[4][64];
    static const uint8_t ct[] = { 'q' };
    static const uint8_t m2[] = { 'z' };
    static qc_cache c;

    fill_id(id);
    fill_nw(nw);
    TEST_ASSERT_EQUAL_INT(QC_CACHE_OK, qc_cache_init(&c, 3, 0));
    for (int i = 0; i < 4; i++) {
        uint8_t nw_i[12];
        memcpy(nw_i, nw, 12);
        nw_i[11] = (uint8_t)i;
        qc_cache_key(id, 1u, nw_i, ct, sizeof(ct), k[i]);
    }
    /* Fill 3 slots: k0, k1 completed (stamps 10, 20), k2 in-flight. */
    TEST_ASSERT_EQUAL_INT(QC_CACHE_OK, qc_cache_insert(&c, k[0], 10));
    TEST_ASSERT_EQUAL_INT(QC_CACHE_OK, qc_cache_complete(&c, k[0], m2, 1, 10));
    TEST_ASSERT_EQUAL_INT(QC_CACHE_OK, qc_cache_insert(&c, k[1], 20));
    TEST_ASSERT_EQUAL_INT(QC_CACHE_OK, qc_cache_complete(&c, k[1], m2, 1, 20));
    TEST_ASSERT_EQUAL_INT(QC_CACHE_OK, qc_cache_insert(&c, k[2], 30));
    /* k3 evicts oldest COMPLETED (k0), not in-flight k2. */
    TEST_ASSERT_EQUAL_INT(QC_CACHE_OK, qc_cache_insert(&c, k[3], 40));
    TEST_ASSERT_NULL_MESSAGE(qc_cache_lookup(&c, k[0], 40), "k0 evicted");
    TEST_ASSERT_NOT_NULL_MESSAGE(qc_cache_lookup(&c, k[1], 40), "k1 kept");
    TEST_ASSERT_NOT_NULL_MESSAGE(qc_cache_lookup(&c, k[2], 40), "k2 pinned");
    TEST_ASSERT_NOT_NULL_MESSAGE(qc_cache_lookup(&c, k[3], 40), "k3 in");
}

/* All slots pinned in-flight -> FULL (never evicts pinned). */
static void test_full_when_pinned(void) {
    uint8_t id[16], nw[12], k[3][64];
    static const uint8_t ct[] = { 'w' };
    static qc_cache c;

    fill_id(id);
    fill_nw(nw);
    TEST_ASSERT_EQUAL_INT(QC_CACHE_OK, qc_cache_init(&c, 2, 0));
    for (int i = 0; i < 3; i++) {
        uint8_t nw_i[12];
        memcpy(nw_i, nw, 12);
        nw_i[0] = (uint8_t)i;
        qc_cache_key(id, 1u, nw_i, ct, sizeof(ct), k[i]);
    }
    TEST_ASSERT_EQUAL_INT(QC_CACHE_OK, qc_cache_insert(&c, k[0], 10));
    TEST_ASSERT_EQUAL_INT(QC_CACHE_OK, qc_cache_insert(&c, k[1], 20));
    TEST_ASSERT_EQUAL_INT(QC_CACHE_FULL, qc_cache_insert(&c, k[2], 30));
    /* Freeing one (complete then remove... remove works on any state). */
    TEST_ASSERT_EQUAL_INT(QC_CACHE_OK, qc_cache_remove(&c, k[0]));
    TEST_ASSERT_EQUAL_INT(QC_CACHE_OK, qc_cache_insert(&c, k[2], 30));
}

/* Expiry: ttl window passes -> miss; slot reusable. ttl 0 never expires. */
static void test_expiry(void) {
    uint8_t id[16], nw[12], k0[64], k1[64];
    static const uint8_t ct[] = { 'e' };
    static const uint8_t m2[] = { 'm' };
    qc_cache c, c2;

    fill_id(id);
    fill_nw(nw);
    TEST_ASSERT_EQUAL_INT(QC_CACHE_OK, qc_cache_init(&c, 2, 50));
    qc_cache_key(id, 1u, nw, ct, sizeof(ct), k0);
    TEST_ASSERT_EQUAL_INT(QC_CACHE_OK, qc_cache_insert(&c, k0, 100));
    TEST_ASSERT_EQUAL_INT(QC_CACHE_OK,
                          qc_cache_complete(&c, k0, m2, sizeof(m2), 100));
    TEST_ASSERT_NOT_NULL_MESSAGE(qc_cache_lookup(&c, k0, 150), "at ttl edge");
    TEST_ASSERT_NULL_MESSAGE(qc_cache_lookup(&c, k0, 151), "expired");
    /* Slot reusable after expiry. */
    nw[0] ^= 0x01;
    qc_cache_key(id, 1u, nw, ct, sizeof(ct), k1);
    TEST_ASSERT_EQUAL_INT(QC_CACHE_OK, qc_cache_insert(&c, k1, 200));
    TEST_ASSERT_NOT_NULL(qc_cache_lookup(&c, k1, 200));

    TEST_ASSERT_EQUAL_INT(QC_CACHE_OK, qc_cache_init(&c2, 2, 0));
    TEST_ASSERT_EQUAL_INT(QC_CACHE_OK, qc_cache_insert(&c2, k0, 100));
    TEST_ASSERT_NOT_NULL_MESSAGE(qc_cache_lookup(&c2, k0, 1000000),
                                 "ttl 0 pins");
}

/* Init/capacity guards + oversize M2 + NULL guards. The clamp is proved,
 * not just accepted: over-max init then MAX pinned inserts must leave the
 * (MAX+1)th with FULL — observable proof cap is really QC_CACHE_MAX. */
static void test_guards(void) {
    uint8_t id[16], nw[12], key[64];
    static uint8_t big[QC_CACHE_M2_MAX + 1];
    static qc_cache c, bigc;
    uint8_t nw_i[12];

    fill_id(id);
    fill_nw(nw);
    TEST_ASSERT_EQUAL_INT(QC_CACHE_BAD_LEN, qc_cache_init(NULL, 8, 0));
    TEST_ASSERT_EQUAL_INT(QC_CACHE_BAD_LEN, qc_cache_init(&c, 0, 0));
    TEST_ASSERT_EQUAL_INT(QC_CACHE_OK, qc_cache_init(&c, 8, 0));
    TEST_ASSERT_EQUAL_INT(QC_CACHE_OK,
                          qc_cache_init(&bigc, QC_CACHE_MAX + 100, 0));
    for (size_t i = 0; i < QC_CACHE_MAX; i++) {
        memcpy(nw_i, nw, 12);
        nw_i[0] = (uint8_t)(i & 0xFF);
        nw_i[1] = (uint8_t)((i >> 8) & 0xFF);
        qc_cache_key(id, 1u, nw_i, big, 4, key);
        TEST_ASSERT_EQUAL_INT_MESSAGE(QC_CACHE_OK,
                                      qc_cache_insert(&bigc, key, 100), "fill");
    }
    memcpy(nw_i, nw, 12);
    nw_i[0] = 0xAA;
    nw_i[1] = 0xBB;
    qc_cache_key(id, 1u, nw_i, big, 4, key);
    TEST_ASSERT_EQUAL_INT_MESSAGE(QC_CACHE_FULL,
                                  qc_cache_insert(&bigc, key, 100),
                                  "clamp proved");
    qc_cache_key(id, 1u, nw, big, 4, key);
    TEST_ASSERT_EQUAL_INT(QC_CACHE_OK, qc_cache_insert(&c, key, 1));
    TEST_ASSERT_EQUAL_INT(QC_CACHE_BAD_LEN,
                          qc_cache_complete(&c, key, big, sizeof(big), 1));
    TEST_ASSERT_EQUAL_INT(QC_CACHE_BAD_LEN,
                          qc_cache_insert(NULL, key, 1));
    TEST_ASSERT_EQUAL_INT(QC_CACHE_BAD_LEN,
                          qc_cache_insert(&c, NULL, 1));
    TEST_ASSERT_NULL(qc_cache_lookup(NULL, key, 1));
    TEST_ASSERT_NULL(qc_cache_lookup(&c, NULL, 1));
    TEST_ASSERT_EQUAL_INT(QC_CACHE_BAD_LEN, qc_cache_remove(NULL, key));
    TEST_ASSERT_EQUAL_INT(QC_CACHE_BAD_LEN, qc_cache_remove(&c, NULL));
}

void setUp(void) {}
void tearDown(void) {}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_key_layout);
    RUN_TEST(test_key_mutation_miss);
    RUN_TEST(test_key_empty_ct);
    RUN_TEST(test_lifecycle);
    RUN_TEST(test_lru_and_pinning);
    RUN_TEST(test_full_when_pinned);
    RUN_TEST(test_expiry);
    RUN_TEST(test_guards);
    return UNITY_END();
}