/* test_manifest_nvs.c — L0/L1/L2 for manifest NVS wiring (B-25 over B-13).
 *
 * Covers: persist/restore roundtrip (version/body/key/level exact),
 * version increase + slot sync, rollback-by-patch -> STALE (RAM
 * untouched), torn pairs (store-only / image-only -> MALFORMED, neither
 * -> NOT_FOUND/SL1 path), corrupt image -> MALFORMED, bad level/pk_len
 * -> MALFORMED, guards (NULLs, uninit/empty store, version 0).
 * Crafted-image tests re-MAC via the documented label (test knows the
 * root — same privilege as the unit, not an attacker break).
 * Stores are ~7 KB + ~500 B: static, never stack (house rule).
 */
#include "unity.h"

#include <stdio.h>
#include <string.h>

#include "qc_dsa.h"
#include "qc_hkdf.h"
#include "qc_hmac.h"
#include "qc_manifest.h"
#include "qc_manifest_persist.h"
#include "qc_store.h"

static const char *STORE_PATH = "mft_store_t.bin";
static const char *IMG_PATH = "mft_img_t.bin";

static const uint8_t ROOT[32] = {
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
    0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
    0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF
};

static qc_manifest_store ms;
static qc_store ns;
static uint8_t pk44[1312];
static uint8_t fileimg[8192];

/* Build an applied-manifest RAM store (no signing needed: persist
 * serializes state, it does not verify). */
static void craft_ms(uint32_t version) {
    size_t i;

    for (i = 0; i < sizeof(pk44); i++) {
        pk44[i] = (uint8_t)(0xA0 + (i & 0x3F));
    }
    TEST_ASSERT_EQUAL_INT(QC_MFT_OK,
        qc_manifest_init(&ms, QC_DSA_44, pk44));
    ms.version = version;
    ms.has_manifest = 1;
    ms.body_len = 64;
    for (i = 0; i < ms.body_len; i++) {
        ms.body[i] = (uint8_t)(0x50 + i);
    }
}

static void open_ns(void) {
    TEST_ASSERT_EQUAL_INT(QC_STORE_OK, qc_store_open(&ns, ROOT));
}

/* Re-MAC a patched image buffer (test-side twin of the unit's MAC). */
static void remac(uint8_t *img, size_t n) {
    static const uint8_t label[] = "QC-STORE-MFT";
    uint8_t key[32];

    TEST_ASSERT_EQUAL_INT(0,
        qc_hkdf_expand(ROOT, label, sizeof(label) - 1, key, 32));
    qc_hmac_sha256(key, 32, img, n - 32, img + n - 32);
    memset(key, 0, sizeof(key));
}

static size_t read_img(uint8_t *out, size_t cap) {
    FILE *f = fopen(IMG_PATH, "rb");
    size_t n = 0;

    TEST_ASSERT_NOT_NULL(f);
    n = fread(out, 1, cap, f);
    fclose(f);
    return n;
}

static void write_img(const uint8_t *in, size_t n) {
    FILE *f = fopen(IMG_PATH, "wb");

    TEST_ASSERT_NOT_NULL(f);
    TEST_ASSERT_EQUAL_UINT(n, fwrite(in, 1, n, f));
    fclose(f);
}

static void test_roundtrip(void) {
    qc_manifest_store ms2;
    qc_store ns2;

    craft_ms(3);
    open_ns();
    TEST_ASSERT_EQUAL_INT(QC_MFT_OK,
        qc_manifest_persist(&ms, &ns, STORE_PATH, IMG_PATH, NULL));
    memset(&ms2, 0, sizeof(ms2));
    TEST_ASSERT_EQUAL_INT(QC_MFT_OK,
        qc_manifest_restore(&ms2, &ns2, ROOT, STORE_PATH, IMG_PATH));
    TEST_ASSERT_EQUAL_INT(1, ms2.initialized);
    TEST_ASSERT_EQUAL_INT(1, ms2.has_manifest);
    TEST_ASSERT_EQUAL_UINT(3, ms2.version);
    TEST_ASSERT_EQUAL_UINT(64, ms2.body_len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ms.body, ms2.body, 64);
    TEST_ASSERT_EQUAL_INT(QC_DSA_44, (int)ms2.enrolled_level);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(pk44, ms2.enrolled_pk, sizeof(pk44));
    TEST_ASSERT_EQUAL_UINT(0, ms2.n_times);
    /* Slot anchor synced. */
    TEST_ASSERT_EQUAL_INT(1, ns2.has_manifest_version);
    TEST_ASSERT_EQUAL_UINT(3, ns2.manifest_version);
    remove(STORE_PATH);
    remove(IMG_PATH);
}

/* Increase persists forward; restore adopts max. */
static void test_increase(void) {
    qc_manifest_store ms2;
    qc_store ns2;

    craft_ms(3);
    open_ns();
    TEST_ASSERT_EQUAL_INT(QC_MFT_OK,
        qc_manifest_persist(&ms, &ns, STORE_PATH, IMG_PATH, NULL));
    craft_ms(5);
    TEST_ASSERT_EQUAL_INT(QC_MFT_OK,
        qc_manifest_persist(&ms, &ns, STORE_PATH, IMG_PATH, NULL));
    memset(&ms2, 0, sizeof(ms2));
    TEST_ASSERT_EQUAL_INT(QC_MFT_OK,
        qc_manifest_restore(&ms2, &ns2, ROOT, STORE_PATH, IMG_PATH));
    TEST_ASSERT_EQUAL_UINT(5, ms2.version);
    TEST_ASSERT_EQUAL_UINT(5, ns2.manifest_version);
    remove(STORE_PATH);
    remove(IMG_PATH);
}

/* Older MAC-valid image vs slot 5 -> STALE, RAM untouched. */
static void test_rollback(void) {
    qc_manifest_store ms2;
    qc_store ns2;
    size_t n;

    craft_ms(5);
    open_ns();
    TEST_ASSERT_EQUAL_INT(QC_MFT_OK,
        qc_manifest_persist(&ms, &ns, STORE_PATH, IMG_PATH, NULL));
    n = read_img(fileimg, sizeof(fileimg));
    /* Patch version 5 -> 3 (offset 4) + re-MAC (still authentic). */
    fileimg[4] = 0;
    fileimg[5] = 0;
    fileimg[6] = 0;
    fileimg[7] = 3;
    remac(fileimg, n);
    write_img(fileimg, n);
    memset(&ms2, 0x5A, sizeof(ms2));
    TEST_ASSERT_EQUAL_INT(QC_MFT_STALE,
        qc_manifest_restore(&ms2, &ns2, ROOT, STORE_PATH, IMG_PATH));
    TEST_ASSERT_EQUAL_UINT8(0x5A, ms2.has_manifest); /* untouched */
    remove(STORE_PATH);
    remove(IMG_PATH);
}

/* Torn-forward convergence: image newer than slot adopts + syncs up. */
static void test_sync_up(void) {
    qc_manifest_store ms2;
    qc_store ns2;
    size_t n;

    craft_ms(3);
    open_ns();
    TEST_ASSERT_EQUAL_INT(QC_MFT_OK,
        qc_manifest_persist(&ms, &ns, STORE_PATH, IMG_PATH, NULL));
    /* Patch image 3 -> 6 (crash-between-files simulation) + re-MAC. */
    n = read_img(fileimg, sizeof(fileimg));
    fileimg[7] = 6;
    remac(fileimg, n);
    write_img(fileimg, n);
    memset(&ms2, 0, sizeof(ms2));
    TEST_ASSERT_EQUAL_INT(QC_MFT_OK,
        qc_manifest_restore(&ms2, &ns2, ROOT, STORE_PATH, IMG_PATH));
    TEST_ASSERT_EQUAL_UINT(6, ms2.version);
    TEST_ASSERT_EQUAL_UINT(6, ns2.manifest_version);
    remove(STORE_PATH);
    remove(IMG_PATH);
}

/* Torn pairs and absence. */
static void test_shapes(void) {
    qc_manifest_store ms2;
    qc_store ns2;

    /* Neither: fresh device -> NOT_FOUND (SL1 + enroll own it). */
    remove(STORE_PATH);
    remove(IMG_PATH);
    memset(&ms2, 0, sizeof(ms2));
    TEST_ASSERT_EQUAL_INT(QC_MFT_NOT_FOUND,
        qc_manifest_restore(&ms2, &ns2, ROOT, STORE_PATH, IMG_PATH));
    /* Store only (image deleted): tamper, not loss. */
    craft_ms(3);
    open_ns();
    TEST_ASSERT_EQUAL_INT(QC_MFT_OK,
        qc_manifest_persist(&ms, &ns, STORE_PATH, IMG_PATH, NULL));
    remove(IMG_PATH);
    memset(&ms2, 0, sizeof(ms2));
    TEST_ASSERT_EQUAL_INT(QC_MFT_MALFORMED,
        qc_manifest_restore(&ms2, &ns2, ROOT, STORE_PATH, IMG_PATH));
    /* Image only (store deleted): anchor gone. */
    TEST_ASSERT_EQUAL_INT(QC_MFT_OK,
        qc_manifest_persist(&ms, &ns, STORE_PATH, IMG_PATH, NULL));
    remove(STORE_PATH);
    memset(&ms2, 0, sizeof(ms2));
    TEST_ASSERT_EQUAL_INT(QC_MFT_MALFORMED,
        qc_manifest_restore(&ms2, &ns2, ROOT, STORE_PATH, IMG_PATH));
    remove(STORE_PATH);
    remove(IMG_PATH);
}

/* Corrupt byte / bad level / bad pk_len (all re-MACed) -> MALFORMED. */
static void test_tamper(void) {
    qc_manifest_store ms2;
    qc_store ns2;
    size_t n;

    craft_ms(3);
    open_ns();
    TEST_ASSERT_EQUAL_INT(QC_MFT_OK,
        qc_manifest_persist(&ms, &ns, STORE_PATH, IMG_PATH, NULL));
    /* Flip a body byte WITHOUT re-MAC: MAC failure. */
    n = read_img(fileimg, sizeof(fileimg));
    fileimg[20] ^= 0x01;
    write_img(fileimg, n);
    memset(&ms2, 0, sizeof(ms2));
    TEST_ASSERT_EQUAL_INT(QC_MFT_MALFORMED,
        qc_manifest_restore(&ms2, &ns2, ROOT, STORE_PATH, IMG_PATH));
    /* Bad level (offset 12+64=76) + re-MAC: structural refusal. */
    n = read_img(fileimg, sizeof(fileimg));
    fileimg[20] ^= 0x01; /* undo flip */
    fileimg[76] = 0;
    fileimg[77] = 0;
    fileimg[78] = 0;
    fileimg[79] = 99;
    remac(fileimg, n);
    write_img(fileimg, n);
    memset(&ms2, 0, sizeof(ms2));
    TEST_ASSERT_EQUAL_INT(QC_MFT_MALFORMED,
        qc_manifest_restore(&ms2, &ns2, ROOT, STORE_PATH, IMG_PATH));
    /* Bad pk_len (offset 80) + re-MAC. */
    n = read_img(fileimg, sizeof(fileimg));
    fileimg[76] = 0;
    fileimg[77] = 0;
    fileimg[78] = 0;
    fileimg[79] = 44; /* level back */
    fileimg[80] = 0x05;
    fileimg[81] = 0x00; /* 1280 != 1312 */
    remac(fileimg, n);
    write_img(fileimg, n);
    memset(&ms2, 0, sizeof(ms2));
    TEST_ASSERT_EQUAL_INT(QC_MFT_MALFORMED,
        qc_manifest_restore(&ms2, &ns2, ROOT, STORE_PATH, IMG_PATH));
    remove(STORE_PATH);
    remove(IMG_PATH);
}

static void test_guards(void) {
    qc_manifest_store ms2;
    qc_store ns2;

    craft_ms(3);
    open_ns();
    TEST_ASSERT_EQUAL_INT(QC_MFT_BAD_ARG,
        qc_manifest_persist(NULL, &ns, STORE_PATH, IMG_PATH, NULL));
    TEST_ASSERT_EQUAL_INT(QC_MFT_BAD_ARG,
        qc_manifest_persist(&ms, NULL, STORE_PATH, IMG_PATH, NULL));
    TEST_ASSERT_EQUAL_INT(QC_MFT_BAD_ARG,
        qc_manifest_restore(NULL, &ns2, ROOT, STORE_PATH, IMG_PATH));
    TEST_ASSERT_EQUAL_INT(QC_MFT_BAD_ARG,
        qc_manifest_restore(&ms2, &ns2, NULL, STORE_PATH, IMG_PATH));
    /* Uninitialized / empty / version-0 stores never persist. */
    memset(&ms2, 0, sizeof(ms2));
    TEST_ASSERT_EQUAL_INT(QC_MFT_BAD_ARG,
        qc_manifest_persist(&ms2, &ns, STORE_PATH, IMG_PATH, NULL));
    TEST_ASSERT_EQUAL_INT(QC_MFT_OK,
        qc_manifest_init(&ms2, QC_DSA_44, pk44));
    TEST_ASSERT_EQUAL_INT(QC_MFT_BAD_ARG,
        qc_manifest_persist(&ms2, &ns, STORE_PATH, IMG_PATH, NULL));
    ms2.has_manifest = 1; /* still version 0 */
    TEST_ASSERT_EQUAL_INT(QC_MFT_BAD_ARG,
        qc_manifest_persist(&ms2, &ns, STORE_PATH, IMG_PATH, NULL));
    remove(STORE_PATH);
    remove(IMG_PATH);
}

void setUp(void) {
    remove(STORE_PATH);
    remove(IMG_PATH);
}
void tearDown(void) {}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_roundtrip);
    RUN_TEST(test_increase);
    RUN_TEST(test_sync_up);
    RUN_TEST(test_rollback);
    RUN_TEST(test_shapes);
    RUN_TEST(test_tamper);
    RUN_TEST(test_guards);
    return UNITY_END();
}
