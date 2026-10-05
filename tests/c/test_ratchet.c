/* test_ratchet.c — L1/L2: chain vectors, fast-forward equivalence,
 * over-skip/stale rules, crash recovery, wraparound refusal.
 * Oracle: Python hmac/hashlib implementing B-21.4 equation independently
 * (R0 = bytes 0..31; info "ratchet"||i-be64; L=96; split R/c2s/s2c).
 */
#include "unity.h"

#include <string.h>

#include "qc_ratchet.h"

static void init_r0(qc_ratchet_state *st) {
    memset(st, 0, sizeof(*st));
    for (int i = 0; i < 32; i++) {
        st->r_cur[i] = (uint8_t)i;
    }
    st->i = 0;
}

static void expect_hex_n(const char *label, const uint8_t *got, size_t n,
                         const char *want_hex) {
    char buf[65];
    static const char hd[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        buf[2 * i] = hd[(got[i] >> 4) & 0xF];
        buf[2 * i + 1] = hd[got[i] & 0xF];
    }
    buf[2 * n] = '\0';
    TEST_ASSERT_EQUAL_STRING_MESSAGE(want_hex, buf, label);
}

static void test_chain_vectors_1_to_3(void) {
    qc_ratchet_state st;
    qc_ratchet_keys k;

    init_r0(&st);
    TEST_ASSERT_EQUAL_INT(0, qc_ratchet_advance(&st, &k));
    TEST_ASSERT_EQUAL_UINT64(1, st.i);
    expect_hex_n("R1", st.r_cur, 32,
                 "8cdb4c1ee47c6d7f04f2b610a16cb92bd8a3c9d7da1747b5bed4620a380032bf");
    expect_hex_n("c2s1", k.k_c2s, 32,
                 "862d54adf8288b73a0efcb56d1ac6acdd1dd4564dda623bb8443c25b31fb3048");
    expect_hex_n("s2c1", k.k_s2c, 32,
                 "2b2d032d4cd6b6bbe39cf07fded7e19aa56f31eba47257dee6b361ad87c61968");

    TEST_ASSERT_EQUAL_INT(0, qc_ratchet_advance(&st, &k));
    TEST_ASSERT_EQUAL_UINT64(2, st.i);
    expect_hex_n("R2", st.r_cur, 32,
                 "6397a3a9359a17bab366a0c00bf7548fa113a7848af16a01005c324c855be5a0");
    expect_hex_n("c2s2", k.k_c2s, 32,
                 "e75d02ee14d27ee214e5ce5b8e55111648b5ebe09ce89a81e1015dca0e5df27e");
    expect_hex_n("s2c2", k.k_s2c, 32,
                 "dcef760682f6b12000c51fcccd11359ebed6947a47f28c6414df33c9be88caff");

    TEST_ASSERT_EQUAL_INT(0, qc_ratchet_advance(&st, &k));
    TEST_ASSERT_EQUAL_UINT64(3, st.i);
    expect_hex_n("R3", st.r_cur, 32,
                 "c4e28377cbb6be522ef8bf97ab3b647cc127380e15a3981b574b6ac87f6abb99");
    expect_hex_n("c2s3", k.k_c2s, 32,
                 "dc7839222dc1e35a4d39a10f411ff30ae59ae45695128052ef8bc35cd1833d40");
    expect_hex_n("s2c3", k.k_s2c, 32,
                 "152b53fae744159ed82fbc82a4530e9d7b8f64b4d1a2fb09995946b236ecf9f0");
}

static void test_forward_equivalence(void) {
    /* forward_to(5) == 5x advance: fast-forward derives identically. */
    qc_ratchet_state a, b;
    qc_ratchet_keys ka, kb;

    init_r0(&a);
    init_r0(&b);
    TEST_ASSERT_EQUAL_INT(0, qc_ratchet_forward_to(&a, 5, 16, &ka));
    for (int n = 0; n < 5; n++) {
        TEST_ASSERT_EQUAL_INT(0, qc_ratchet_advance(&b, &kb));
    }
    TEST_ASSERT_EQUAL_UINT64(a.i, b.i);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(a.r_cur, b.r_cur, 32);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ka.k_c2s, kb.k_c2s, 32);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ka.k_s2c, kb.k_s2c, 32);
}

static void test_stale_and_overskip(void) {
    qc_ratchet_state st;
    qc_ratchet_keys k, before;

    init_r0(&st);
    TEST_ASSERT_EQUAL_INT(0, qc_ratchet_forward_to(&st, 3, 16, &k));
    memcpy(&before, &k, sizeof(before));
    /* Stale (equal/past): no-op, no keys, code 1. */
    TEST_ASSERT_EQUAL_INT(1, qc_ratchet_forward_to(&st, 3, 16, &k));
    TEST_ASSERT_EQUAL_INT(1, qc_ratchet_forward_to(&st, 1, 16, &k));
    TEST_ASSERT_EQUAL_UINT64(3, st.i);
    /* Over-skip: no state change, code 2 (caller resyncs per B-26). */
    memcpy(&k, &before, sizeof(k));
    TEST_ASSERT_EQUAL_INT(2, qc_ratchet_forward_to(&st, 3 + 17, 16, &k));
    TEST_ASSERT_EQUAL_UINT64(3, st.i);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(before.k_c2s, k.k_c2s, 32);
    /* Boundary: exactly max_skip advances. */
    TEST_ASSERT_EQUAL_INT(0, qc_ratchet_forward_to(&st, 3 + 16, 16, &k));
    TEST_ASSERT_EQUAL_UINT64(19, st.i);
}

static void test_crash_recovery(void) {
    /* White-box crash injection: power dies after spare-write (R2+keys2)
     * but before activation. Crashed state = r_cur R1 at i=1, valid spare
     * holding R2 and generation-2 keys. recover() must complete the
     * activation exactly as advance() would have. */
    qc_ratchet_state ref1, ref2, crash;
    qc_ratchet_keys k1, k2, kr;

    init_r0(&ref1);
    TEST_ASSERT_EQUAL_INT(0, qc_ratchet_advance(&ref1, &k1)); /* i=1: R1 */

    init_r0(&ref2);
    TEST_ASSERT_EQUAL_INT(0, qc_ratchet_advance(&ref2, &k2)); /* i=1 */
    TEST_ASSERT_EQUAL_INT(0, qc_ratchet_advance(&ref2, &k2)); /* i=2: R2 */
    (void)k1;

    memcpy(&crash, &ref1, sizeof(crash)); /* r_cur=R1, i=1, spare clear */
    memcpy(crash.r_spare, ref2.r_cur, 32); /* spare=R2 */
    memcpy(crash.k_spare_c2s, k2.k_c2s, 32);
    memcpy(crash.k_spare_s2c, k2.k_s2c, 32);
    crash.spare_valid = 1;

    TEST_ASSERT_EQUAL_INT(1, qc_ratchet_recover(&crash, &kr));
    TEST_ASSERT_EQUAL_UINT64(2, crash.i);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ref2.r_cur, crash.r_cur, 32);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(k2.k_c2s, kr.k_c2s, 32);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(k2.k_s2c, kr.k_s2c, 32);
    TEST_ASSERT_EQUAL_INT(0, crash.spare_valid);

    /* No-spare recovery: keep state, out untouched. */
    {
        qc_ratchet_state s2;
        qc_ratchet_keys kx;
        uint8_t r1[32];
        init_r0(&s2);
        TEST_ASSERT_EQUAL_INT(0, qc_ratchet_advance(&s2, &kx));
        memcpy(r1, s2.r_cur, 32);
        memset(&kx, 0x5A, sizeof(kx));
        TEST_ASSERT_EQUAL_INT(0, qc_ratchet_recover(&s2, &kx));
        TEST_ASSERT_EQUAL_UINT64(1, s2.i);
        TEST_ASSERT_EQUAL_UINT8_ARRAY(r1, s2.r_cur, 32);
        for (size_t n = 0; n < sizeof(kx); n++) {
            TEST_ASSERT_EQUAL_UINT8_MESSAGE(0x5A, ((uint8_t *)&kx)[n],
                                            "out untouched");
        }
    }
}

static void test_no_wrap(void) {
    qc_ratchet_state st;
    qc_ratchet_keys k;
    memset(&st, 0, sizeof(st));
    st.i = UINT64_MAX;
    TEST_ASSERT_EQUAL_INT(-1, qc_ratchet_advance(&st, &k));
    TEST_ASSERT_EQUAL_UINT64(UINT64_MAX, st.i);
    /* Crafted full state at MAX still refuses (no generation beyond MAX). */
    st.spare_valid = 1;
    memset(&k, 0x5A, sizeof(k));
    TEST_ASSERT_EQUAL_INT(-1, qc_ratchet_recover(&st, &k));
    TEST_ASSERT_EQUAL_UINT64(UINT64_MAX, st.i);
}

void setUp(void) {}
void tearDown(void) {}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_chain_vectors_1_to_3);
    RUN_TEST(test_forward_equivalence);
    RUN_TEST(test_stale_and_overskip);
    RUN_TEST(test_crash_recovery);
    RUN_TEST(test_no_wrap);
    return UNITY_END();
}
