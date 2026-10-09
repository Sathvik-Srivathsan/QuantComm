/* test_manifest.c — L0/L1/L2 for manifest schema + verify + store.
 *
 * Covers: canonical roundtrip + field echo, order/dupe/codepoint
 * rejects, truncation/length rejects, oversize, verify-apply happy
 * path, stale (incl. corrupt-sig-still-STALE proving zero pk work),
 * bad-sig, wrong-key, 6/hour rate cap, rotation (old key dies, new
 * key rules), unknown next-key length, NULL guards.
 * Signing key: fixed-seed DSA-65 keypair (deterministic); attacker key
 * from a second seed. Manifest store is ~7 KB: static, never stack.
 */
#include "unity.h"

#include <string.h>

#include "qc_dsa.h"
#include "qc_manifest.h"

static const uint8_t SEED[32] = {
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11
};

static const uint8_t SEED2[32] = {
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22
};

static uint8_t PK[1952], SK[4032], PK2[1952], SK2[4032];
static qc_manifest_store store;

static const qc_floor_entry FLOORS[3] = {
    { 0, 1 }, { 1, 2 }, { 2, 2 }
};

static const uint8_t PROFILES[4] = { 3, 7, 9, 12 };

static void base_fields(qc_manifest_fields *f) {
    f->version = 1;
    f->floors = FLOORS;
    f->n_floors = 3;
    f->profiles = PROFILES;
    f->n_profiles = 4;
    f->hmax = 100;
    f->t_cool = 60;
    f->c2_threshold = 500;
    f->next_key = NULL;
    f->next_key_len = 0;
}

static void setup_keys(void) {
    TEST_ASSERT_EQUAL_INT(QC_DSA_OK,
        qc_dsa_keypair(QC_DSA_65, PK, SK, SEED));
    TEST_ASSERT_EQUAL_INT(QC_DSA_OK,
        qc_dsa_keypair(QC_DSA_65, PK2, SK2, SEED2));
    TEST_ASSERT_EQUAL_INT(QC_MFT_OK_APPLIED,
        qc_manifest_init(&store, QC_DSA_65, PK));
}

/* body bytes + sig for fields (caller pseed selects signing key). */
static size_t make_signed(qc_manifest_fields *f, const uint8_t *sk,
                          uint8_t *body, uint8_t *sig) {
    size_t n = qc_manifest_encode_len(f);
    TEST_ASSERT_TRUE_MESSAGE(n > 0, "encodable");
    TEST_ASSERT_EQUAL_INT(QC_MFT_OK_APPLIED,
        qc_manifest_encode(f, body, n));
    TEST_ASSERT_EQUAL_INT(QC_DSA_OK,
        qc_dsa_sign(QC_DSA_65, sig, body, n, NULL, 0, SEED, sk));
    return n;
}

static void test_roundtrip(void) {
    static uint8_t body[4096];
    qc_manifest_fields f;
    qc_manifest_parsed p;
    size_t n;

    base_fields(&f);
    /* 4+2+3*2+2+4+4+4+2+2+0 = 30 B. */
    n = qc_manifest_encode_len(&f);
    TEST_ASSERT_EQUAL_UINT(30, n);
    TEST_ASSERT_EQUAL_INT(QC_MFT_OK_APPLIED,
        qc_manifest_encode(&f, body, n));
    TEST_ASSERT_EQUAL_INT(QC_MFT_OK_APPLIED,
        qc_manifest_parse(body, n, &p));
    TEST_ASSERT_EQUAL_UINT(1, p.version);
    TEST_ASSERT_EQUAL_UINT(3, p.n_floors);
    TEST_ASSERT_EQUAL_UINT8(0, p.floors[0].cls);
    TEST_ASSERT_EQUAL_UINT8(1, p.floors[0].min_level);
    TEST_ASSERT_EQUAL_UINT8(2, p.floors[2].cls);
    TEST_ASSERT_EQUAL_UINT(4, p.n_profiles);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(PROFILES, p.profiles, 4);
    TEST_ASSERT_EQUAL_UINT(100, p.hmax);
    TEST_ASSERT_EQUAL_UINT(60, p.t_cool);
    TEST_ASSERT_EQUAL_UINT(500, p.c2_threshold);
    TEST_ASSERT_EQUAL_UINT(0, p.next_key_len);
}

static void test_canonical_rejects(void) {
    static uint8_t body[4096];
    qc_manifest_fields f;
    static const qc_floor_entry unsorted[2] = { { 1, 2 }, { 0, 1 } };
    static const qc_floor_entry dup[2] = { { 0, 1 }, { 0, 2 } };
    static const qc_floor_entry badc[1] = { { 9, 1 } };
    static const qc_floor_entry badl[1] = { { 0, 9 } };

    base_fields(&f);
    f.floors = unsorted;
    f.n_floors = 2;
    TEST_ASSERT_EQUAL_UINT(0, qc_manifest_encode_len(&f));
    f.floors = dup;
    TEST_ASSERT_EQUAL_UINT(0, qc_manifest_encode_len(&f));
    f.floors = badc;
    f.n_floors = 1;
    TEST_ASSERT_EQUAL_UINT(0, qc_manifest_encode_len(&f));
    f.floors = badl;
    TEST_ASSERT_EQUAL_UINT(0, qc_manifest_encode_len(&f));
    /* Oversize: profiles blow past the 4 KB cap. */
    {
        static uint8_t many[5000];
        memset(many, 1, sizeof(many));
        base_fields(&f);
        f.profiles = many;
        f.n_profiles = sizeof(many);
        TEST_ASSERT_EQUAL_UINT(0, qc_manifest_encode_len(&f));
    }
    /* Truncated / length-mismatch bodies. */
    base_fields(&f);
    {
        size_t n = qc_manifest_encode_len(&f);
        TEST_ASSERT_EQUAL_INT(QC_MFT_OK_APPLIED,
            qc_manifest_encode(&f, body, n));
        TEST_ASSERT_EQUAL_INT(QC_MFT_MALFORMED,
            qc_manifest_parse(body, n - 1, &(qc_manifest_parsed){ 0 }));
        TEST_ASSERT_EQUAL_INT(QC_MFT_MALFORMED,
            qc_manifest_parse(body, 10, &(qc_manifest_parsed){ 0 }));
    }
    (void)body;
}

static void test_happy_stale_bad(void) {
    static uint8_t body[4096], sig[3309];
    qc_manifest_fields f;
    size_t n;

    setup_keys();
    base_fields(&f);
    n = make_signed(&f, SK, body, sig);
    TEST_ASSERT_EQUAL_INT(QC_MFT_OK_APPLIED,
        qc_manifest_verify_apply(&store, body, n, sig, sizeof(sig), 1000));
    TEST_ASSERT_EQUAL_UINT(1, store.version);
    /* Same version again, CORRUPT sig: still STALE (zero pk work —
     * a verify would have reported BAD_SIG instead). */
    sig[0] ^= 0x01;
    TEST_ASSERT_EQUAL_INT(QC_MFT_STALE,
        qc_manifest_verify_apply(&store, body, n, sig, sizeof(sig), 1001));
    sig[0] ^= 0x01;
    /* Older version: STALE. */
    f.version = 0;
    n = make_signed(&f, SK, body, sig);
    TEST_ASSERT_EQUAL_INT(QC_MFT_STALE,
        qc_manifest_verify_apply(&store, body, n, sig, sizeof(sig), 1002));
    /* Higher version, bad sig: BAD_SIG. */
    f.version = 2;
    n = make_signed(&f, SK, body, sig);
    sig[10] ^= 0x01;
    TEST_ASSERT_EQUAL_INT(QC_MFT_BAD_SIG,
        qc_manifest_verify_apply(&store, body, n, sig, sizeof(sig), 1003));
    /* Higher version signed by the WRONG key: BAD_SIG. */
    n = make_signed(&f, SK2, body, sig);
    TEST_ASSERT_EQUAL_INT(QC_MFT_BAD_SIG,
        qc_manifest_verify_apply(&store, body, n, sig, sizeof(sig), 1004));
}

static void test_rate_cap(void) {
    static uint8_t body[4096], sig[3309];
    qc_manifest_fields f;
    size_t n;
    uint32_t v;

    setup_keys();
    /* Six verifies in the hour pass (versions 1..6, all validly signed). */
    for (v = 1; v <= 6; v++) {
        base_fields(&f);
        f.version = v;
        n = make_signed(&f, SK, body, sig);
        TEST_ASSERT_EQUAL_INT_MESSAGE(QC_MFT_OK_APPLIED,
            qc_manifest_verify_apply(&store, body, n, sig, sizeof(sig),
                                     1000 + v), "within cap");
    }
    /* Seventh: RATE_LIMITED (validly signed — cap, not crypto). */
    base_fields(&f);
    f.version = 7;
    n = make_signed(&f, SK, body, sig);
    TEST_ASSERT_EQUAL_INT(QC_MFT_RATE_LIMITED,
        qc_manifest_verify_apply(&store, body, n, sig, sizeof(sig), 1007));
    /* An hour later: window slid, allowed again. */
    TEST_ASSERT_EQUAL_INT(QC_MFT_OK_APPLIED,
        qc_manifest_verify_apply(&store, body, n, sig, sizeof(sig),
                                 1000 + 3601));
}

static void test_rotation(void) {
    static uint8_t body[4096], sig[3309];
    qc_manifest_fields f;
    size_t n;

    setup_keys();
    base_fields(&f);
    n = make_signed(&f, SK, body, sig);
    TEST_ASSERT_EQUAL_INT(QC_MFT_OK_APPLIED,
        qc_manifest_verify_apply(&store, body, n, sig, sizeof(sig), 1000));
    /* v2 carries PK2 as next key (signed by enrolled SK): applies AND
     * rotates enrollment to PK2. */
    f.version = 2;
    f.next_key = PK2;
    f.next_key_len = sizeof(PK2);
    n = make_signed(&f, SK, body, sig);
    TEST_ASSERT_EQUAL_INT(QC_MFT_OK_APPLIED,
        qc_manifest_verify_apply(&store, body, n, sig, sizeof(sig), 1001));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(PK2, store.enrolled_pk, sizeof(PK2));
    /* Old key dead: v3 signed by SK now fails... */
    f.version = 3;
    f.next_key = NULL;
    f.next_key_len = 0;
    n = make_signed(&f, SK, body, sig);
    TEST_ASSERT_EQUAL_INT(QC_MFT_BAD_SIG,
        qc_manifest_verify_apply(&store, body, n, sig, sizeof(sig), 1002));
    /* ...new key rules. */
    n = make_signed(&f, SK2, body, sig);
    TEST_ASSERT_EQUAL_INT(QC_MFT_OK_APPLIED,
        qc_manifest_verify_apply(&store, body, n, sig, sizeof(sig), 1003));
    /* Unrecognized next-key length refuses rotation (MALFORMED). */
    {
        static uint8_t odd[100];
        memset(odd, 0x77, sizeof(odd));
        f.version = 4;
        f.next_key = odd;
        f.next_key_len = sizeof(odd);
        n = make_signed(&f, SK2, body, sig);
        TEST_ASSERT_EQUAL_INT(QC_MFT_MALFORMED,
            qc_manifest_verify_apply(&store, body, n, sig, sizeof(sig), 1004));
    }
}

/* First manifest may carry version 0; wrong-size sig and bad init. */
static void test_first_v0_and_sig_len(void) {
    static uint8_t body[4096], sig[3309];
    qc_manifest_fields f;
    size_t n;

    setup_keys();
    base_fields(&f);
    f.version = 0;
    n = make_signed(&f, SK, body, sig);
    TEST_ASSERT_EQUAL_INT(QC_MFT_OK_APPLIED,
        qc_manifest_verify_apply(&store, body, n, sig, sizeof(sig), 1000));
    /* Truncated sig: MALFORMED (structural, before any crypto). */
    f.version = 1;
    n = make_signed(&f, SK, body, sig);
    TEST_ASSERT_EQUAL_INT(QC_MFT_MALFORMED,
        qc_manifest_verify_apply(&store, body, n, sig, sizeof(sig) - 1, 1001));
    /* NULL next_key with nonzero length: MALFORMED. */
    f.next_key = NULL;
    f.next_key_len = 4;
    TEST_ASSERT_EQUAL_UINT(0, qc_manifest_encode_len(&f));
}

static void test_guards(void) {
    static uint8_t body[4096], sig[3309];
    qc_manifest_fields f;

    setup_keys();
    base_fields(&f);
    TEST_ASSERT_EQUAL_INT(QC_MFT_BAD_ARG,
        qc_manifest_init(NULL, QC_DSA_65, PK));
    TEST_ASSERT_EQUAL_INT(QC_MFT_BAD_ARG,
        qc_manifest_init(&store, 0, PK));
    TEST_ASSERT_EQUAL_INT(QC_MFT_BAD_ARG,
        qc_manifest_init(&store, QC_DSA_65, NULL));
    TEST_ASSERT_EQUAL_INT(QC_MFT_BAD_ARG,
        qc_manifest_encode(NULL, body, sizeof(body)));
    TEST_ASSERT_EQUAL_INT(QC_MFT_BAD_ARG,
        qc_manifest_parse(NULL, 10, &(qc_manifest_parsed){ 0 }));
    TEST_ASSERT_EQUAL_INT(QC_MFT_BAD_ARG,
        qc_manifest_verify_apply(NULL, body, 10, sig, sizeof(sig), 1));
    TEST_ASSERT_EQUAL_INT(QC_MFT_BAD_ARG,
        qc_manifest_verify_apply(&store, NULL, 10, sig, sizeof(sig), 1));
}

void setUp(void) {}
void tearDown(void) {}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_roundtrip);
    RUN_TEST(test_canonical_rejects);
    RUN_TEST(test_happy_stale_bad);
    RUN_TEST(test_rate_cap);
    RUN_TEST(test_rotation);
    RUN_TEST(test_first_v0_and_sig_len);
    RUN_TEST(test_guards);
    return UNITY_END();
}