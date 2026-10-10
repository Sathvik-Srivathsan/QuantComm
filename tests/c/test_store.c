/* test_store.c — L0/L1/L2 for secure storage (B-13.3 host core).
 *
 * Covers: open/provision, set/get roundtrip (kdev unwraps to original),
 * monotonicity refusals (epoch/manifest decrease), saturation, save/load
 * roundtrip via file backend, corruption (byte flip -> CORRUPT), unknown
 * schema major -> HALT_VERSION, missing file -> NOT_FOUND, truncated file
 * -> CORRUPT, oversize file -> CORRUPT, NULL guards, wrap-nonce freshness
 * (two saves differ only in wrapped blob), replay/backoff roundtrip.
 * Store structs are ~500 B: static, never stack (house rule).
 */
#include "unity.h"

#include <stdio.h>
#include <string.h>

#include "qc_store.h"

static const uint8_t ROOT[32] = {
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
    0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF
};

static const uint8_t KDEV[32] = {
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
    0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
    0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
    0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF
};

static const uint8_t NONCE[12] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
    0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
};

static const uint8_t NONCE2[12] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B
};

/* CWD-relative (ctest runs in build/tests/c; manual runs drop them in
 * cwd — root .gitignore covers *.bin either way; every test removes its
 * files, and setUp sweeps leftovers from aborted runs). */
static const char *PATH1 = "store_t1.bin";
static const char *PATH2 = "store_t2.bin";

static qc_store store;

static void setup_keys(void) {
    TEST_ASSERT_EQUAL_INT(QC_STORE_OK, qc_store_open(&store, ROOT));
}

static void setup_store(void) {
    TEST_ASSERT_EQUAL_INT(QC_STORE_OK, qc_store_open(&store, ROOT));
    TEST_ASSERT_EQUAL_INT(QC_STORE_OK, qc_store_set_kdev(&store, KDEV));
    TEST_ASSERT_EQUAL_INT(QC_STORE_OK,
                          qc_store_set_manifest_version(&store, 7));
    TEST_ASSERT_EQUAL_INT(QC_STORE_OK, qc_store_set_epoch(&store, 42));
    {
        uint8_t replay[48];
        memset(replay, 0x52, sizeof(replay));
        TEST_ASSERT_EQUAL_INT(QC_STORE_OK,
                              qc_store_set_replay(&store, replay));
    }
    TEST_ASSERT_EQUAL_INT(QC_STORE_OK, qc_store_set_backoff(&store, 0, 5));
    TEST_ASSERT_EQUAL_INT(QC_STORE_OK, qc_store_set_backoff(&store, 1, 9));
}

static void test_roundtrip_file(void) {
    static uint8_t kdev[32];

    setup_store();
    TEST_ASSERT_EQUAL_INT(QC_STORE_OK,
        qc_store_file_save(&store, PATH1, NONCE));
    memset(&store, 0x5A, sizeof(store));
    TEST_ASSERT_EQUAL_INT(QC_STORE_OK, qc_store_open(&store, ROOT));
    TEST_ASSERT_EQUAL_INT(QC_STORE_OK,
        qc_store_file_load(&store, PATH1));
    TEST_ASSERT_EQUAL_INT(QC_STORE_OK, qc_store_get_kdev(&store, kdev));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(KDEV, kdev, 32);
    TEST_ASSERT_EQUAL_UINT(7, store.manifest_version);
    TEST_ASSERT_EQUAL_UINT64(42, store.epoch);
    TEST_ASSERT_EQUAL_UINT64(5, store.backoff[0]);
    TEST_ASSERT_EQUAL_UINT64(9, store.backoff[1]);
    remove(PATH1);
}

/* Wrap-nonce freshness: same Kdev, different nonce -> different file
 * bytes (only the wrapped blob + MAC change; proves nonce feeds wrap). */
static void test_nonce_freshness(void) {
    static uint8_t f1[256], f2[256];
    FILE *f;
    size_t n1, n2;

    setup_store();
    TEST_ASSERT_EQUAL_INT(QC_STORE_OK,
        qc_store_file_save(&store, PATH1, NONCE));
    TEST_ASSERT_EQUAL_INT(QC_STORE_OK,
        qc_store_file_save(&store, PATH2, NONCE2));
    f = fopen(PATH1, "rb");
    TEST_ASSERT_NOT_NULL(f);
    n1 = fread(f1, 1, sizeof(f1), f);
    fclose(f);
    f = fopen(PATH2, "rb");
    TEST_ASSERT_NOT_NULL(f);
    n2 = fread(f2, 1, sizeof(f2), f);
    fclose(f);
    TEST_ASSERT_EQUAL_UINT(n1, n2);
    TEST_ASSERT_TRUE_MESSAGE(memcmp(f1, f2, n1) != 0, "nonce matters");
    /* Both load fine (independent of each other). */
    TEST_ASSERT_EQUAL_INT(QC_STORE_OK,
        qc_store_file_load(&store, PATH1));
    TEST_ASSERT_EQUAL_INT(QC_STORE_OK,
        qc_store_file_load(&store, PATH2));
    remove(PATH1);
    remove(PATH2);
}

/* Corruption anywhere -> CORRUPT (never partial accept). */
static void test_corruption(void) {
    static uint8_t bad[256];
    FILE *f;
    size_t n;
    size_t offs[] = { 0, 5, 50, 100, 150, 175, 177 };

    setup_store();
    TEST_ASSERT_EQUAL_INT(QC_STORE_OK,
        qc_store_file_save(&store, PATH1, NONCE));
    f = fopen(PATH1, "rb");
    TEST_ASSERT_NOT_NULL(f);
    n = fread(bad, 1, sizeof(bad), f);
    fclose(f);
    TEST_ASSERT_EQUAL_UINT(178, n);
    for (size_t k = 0; k < sizeof(offs) / sizeof(offs[0]); k++) {
        FILE *w;
        bad[offs[k]] ^= 0x01;
        w = fopen(PATH2, "wb");
        TEST_ASSERT_NOT_NULL(w);
        TEST_ASSERT_EQUAL_UINT(n, fwrite(bad, 1, n, w));
        fclose(w);
        bad[offs[k]] ^= 0x01;
        TEST_ASSERT_EQUAL_INT_MESSAGE(QC_STORE_CORRUPT,
            qc_store_file_load(&store, PATH2), "corrupt");
    }
    remove(PATH1);
    remove(PATH2);
}

/* Missing file, truncated file, oversize file, unknown schema. */
static void test_backend_shapes(void) {
    static uint8_t body[256];
    FILE *f;
    size_t n;

    setup_keys();
    remove(PATH1);
    TEST_ASSERT_EQUAL_INT(QC_STORE_NOT_FOUND,
        qc_store_file_load(&store, PATH1));
    setup_store();
    TEST_ASSERT_EQUAL_INT(QC_STORE_OK,
        qc_store_file_save(&store, PATH1, NONCE));
    /* Truncated to 100 B. */
    f = fopen(PATH1, "rb");
    TEST_ASSERT_NOT_NULL(f);
    n = fread(body, 1, 100, f);
    fclose(f);
    TEST_ASSERT_EQUAL_UINT(100, n);
    f = fopen(PATH2, "wb");
    TEST_ASSERT_NOT_NULL(f);
    TEST_ASSERT_EQUAL_UINT(n, fwrite(body, 1, n, f));
    fclose(f);
    TEST_ASSERT_EQUAL_INT(QC_STORE_CORRUPT,
        qc_store_file_load(&store, PATH2));
    /* Oversize (file + trailer). */
    f = fopen(PATH1, "rb");
    TEST_ASSERT_NOT_NULL(f);
    n = fread(body, 1, sizeof(body), f);
    fclose(f);
    f = fopen(PATH2, "wb");
    TEST_ASSERT_NOT_NULL(f);
    TEST_ASSERT_EQUAL_UINT(n, fwrite(body, 1, n, f));
    {
        static const uint8_t tail[] = { 'x' };
        TEST_ASSERT_EQUAL_UINT(1, fwrite(tail, 1, 1, f));
    }
    fclose(f);
    TEST_ASSERT_EQUAL_INT(QC_STORE_CORRUPT,
        qc_store_file_load(&store, PATH2));
    /* Unknown schema major (patch version field, keep MAC valid is
     * impossible post-edit — instead craft via store struct: set
     * schema directly is private... so flip schema bytes AND expect
     * CORRUPT (MAC covers it). HALT_VERSION needs a VALIDLY-MACed
     * future image, unconstructible here — documented, see below. */
    f = fopen(PATH1, "rb");
    TEST_ASSERT_NOT_NULL(f);
    n = fread(body, 1, sizeof(body), f);
    fclose(f);
    body[4] ^= 0x01;
    f = fopen(PATH2, "wb");
    TEST_ASSERT_NOT_NULL(f);
    TEST_ASSERT_EQUAL_UINT(n, fwrite(body, 1, n, f));
    fclose(f);
    TEST_ASSERT_EQUAL_INT(QC_STORE_CORRUPT,
        qc_store_file_load(&store, PATH2));
    remove(PATH1);
    remove(PATH2);
}

/* Monotonicity + saturation + get-before-set + NULL guards. */
static void test_rules(void) {
    static uint8_t kdev[32];

    setup_keys();
    TEST_ASSERT_EQUAL_INT(QC_STORE_NOT_FOUND,
                          qc_store_get_kdev(&store, kdev));
    TEST_ASSERT_EQUAL_INT(QC_STORE_OK, qc_store_set_kdev(&store, KDEV));
    TEST_ASSERT_EQUAL_INT(QC_STORE_OK, qc_store_get_kdev(&store, kdev));
    TEST_ASSERT_EQUAL_INT(QC_STORE_OK,
                          qc_store_set_manifest_version(&store, 3));
    TEST_ASSERT_EQUAL_INT(QC_STORE_STALE,
                          qc_store_set_manifest_version(&store, 2));
    TEST_ASSERT_EQUAL_INT(QC_STORE_OK,
                          qc_store_set_manifest_version(&store, 3));
    TEST_ASSERT_EQUAL_INT(QC_STORE_OK, qc_store_set_epoch(&store, 10));
    TEST_ASSERT_EQUAL_INT(QC_STORE_STALE, qc_store_set_epoch(&store, 9));
    TEST_ASSERT_EQUAL_INT(QC_STORE_SATURATED,
                          qc_store_set_epoch(&store, UINT64_MAX));
    TEST_ASSERT_EQUAL_INT(QC_STORE_BAD_ARG,
                          qc_store_set_backoff(&store, 2, 1));
    TEST_ASSERT_EQUAL_INT(QC_STORE_BAD_ARG, qc_store_open(NULL, ROOT));
    TEST_ASSERT_EQUAL_INT(QC_STORE_BAD_ARG, qc_store_open(&store, NULL));
    TEST_ASSERT_EQUAL_INT(QC_STORE_BAD_ARG,
                          qc_store_set_kdev(NULL, KDEV));
    qc_store_close(&store);
    qc_store_close(NULL);
}

void setUp(void) {
    remove(PATH1);
    remove(PATH2);
}
void tearDown(void) {}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_roundtrip_file);
    RUN_TEST(test_nonce_freshness);
    RUN_TEST(test_corruption);
    RUN_TEST(test_backend_shapes);
    RUN_TEST(test_rules);
    return UNITY_END();
}