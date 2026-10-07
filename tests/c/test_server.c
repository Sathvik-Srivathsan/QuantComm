/* test_server.c — L0/L1/L2 for the server handshake pipeline (B-20.3/B-22).
 *
 * The test harness plays the device with direct adapter calls
 * (keypair/encaps/M1-encode/HMAC/decaps/derive); the implementation under
 * test is the server side only. The device-driver code here is scaffolding
 * that later becomes qc_client — it is not itself audited as product code.
 * Determinism: test RNG seeded in setUp (N_S + encaps coins reproducible).
 *
 * Covers: full handshake all levels (server+device key agreement on all 4
 * keys), retry-identical RESEND with zero new KEM work (op counters),
 * bad-HMAC DROP + auth path (never replay path), equal-nonce-different
 * bytes DROP_REPLAY, stale-epoch DROP_EPOCH, floor ABORT + counter,
 * unknown-L/version/truncation DROP_PARSE, corrupt-sk ABORT_DECAPS,
 * session keys stored + match device view.
 */
#include "unity.h"

#include <stdio.h>
#include <string.h>

#include "qc_codec.h"
#include "qc_hmac.h"
#include "qc_kdf.h"
#include "qc_kem.h"
#include "qc_rng.h"
#include "qc_server.h"

void test_rng_seed(uint64_t seed);

#define DEV_ID_BYTES                                                 \
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,                   \
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F

static const uint8_t KDEV[32] = {
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
    0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
    0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
    0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF
};

static const uint8_t COINS64[64] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F
};

static const uint8_t COINS32[32] = {
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
    0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F
};

typedef struct {
    uint8_t wire;
    qc_kem_level level;
    size_t pk_len;
    size_t ct_len;
} level_case;

static const level_case LEVELS[3] = {
    { QC_WIRE_L512, QC_KEM_512, 800, 768 },
    { QC_WIRE_L768, QC_KEM_768, 1184, 1088 },
    { QC_WIRE_L1024, QC_KEM_1024, 1568, 1568 },
};

/* Server context is ~2.1 MB (embedded cache): static, never stack. */
static qc_server srv;
static uint8_t srv_pk[1568], srv_sk[3168];

static void server_up(uint8_t wire, uint8_t floor) {
    static const uint8_t id[16] = { DEV_ID_BYTES };
    const level_case *lc = NULL;

    for (int i = 0; i < 3; i++) {
        if (LEVELS[i].wire == wire) {
            lc = &LEVELS[i];
        }
    }
    TEST_ASSERT_NOT_NULL_MESSAGE(lc, "wire level");
    TEST_ASSERT_EQUAL_INT_MESSAGE(QC_KEM_OK,
        qc_kem_keypair(lc->level, srv_pk, srv_sk, COINS64), "srv keygen");
    TEST_ASSERT_EQUAL_INT_MESSAGE(QC_SRV_OK_EMIT,
        qc_server_init(&srv, id, KDEV, floor, wire,
                       srv_pk, srv_sk, 16, 1000000), "init");
}

/* Device builds M1: ephemeral keypair, encaps K1, encode, HMAC. */
static void device_m1(uint8_t wire, uint32_t epoch, uint64_t counter,
                      uint8_t *m1, size_t *m1_len,
                      uint8_t *eph_sk, uint8_t *k1_out) {
    const level_case *lc = NULL;
    qc_m1_fields f;
    static const uint8_t id[16] = { DEV_ID_BYTES };
    static uint8_t ek[1568], ct[1568], k1[32];
    uint8_t tag[32];

    for (int i = 0; i < 3; i++) {
        if (LEVELS[i].wire == wire) {
            lc = &LEVELS[i];
        }
    }
    TEST_ASSERT_NOT_NULL(lc);
    TEST_ASSERT_EQUAL_INT(QC_KEM_OK,
        qc_kem_keypair(lc->level, ek, eph_sk, COINS64));
    TEST_ASSERT_EQUAL_INT(QC_KEM_OK,
        qc_kem_encaps(lc->level, ct, k1, srv_pk, COINS32));
    if (k1_out != NULL) {
        memcpy(k1_out, k1, 32);
    }
    f.version = QC_M1_VERSION;
    memcpy(f.identity, id, 16);
    f.level = wire;
    f.ek = ek;
    f.ek_len = lc->pk_len;
    f.ct_s = ct;
    f.ct_len = lc->ct_len;
    f.nonce[0] = (uint8_t)(epoch >> 24);
    f.nonce[1] = (uint8_t)(epoch >> 16);
    f.nonce[2] = (uint8_t)(epoch >> 8);
    f.nonce[3] = (uint8_t)epoch;
    for (int i = 0; i < 8; i++) {
        f.nonce[4 + i] = (uint8_t)(counter >> (8 * (7 - i)));
    }
    *m1_len = qc_m1_len(lc->pk_len, lc->ct_len);
    TEST_ASSERT_EQUAL_INT(QC_CODEC_OK, qc_m1_encode(&f, m1, *m1_len));
    /* HMAC over all preceding bytes (M1 tag position = tail 32 B). */
    qc_hmac_sha256(KDEV, 32, m1, *m1_len - 32, tag);
    memcpy(m1 + *m1_len - 32, tag, 32);
}

/* Device completes on M2: parse, decaps K2, derive, verify confirm. */
static int device_complete(uint8_t wire,
                           const uint8_t *m1, size_t m1_len,
                           const uint8_t *m2, size_t m2_len,
                           const uint8_t *eph_sk, const uint8_t *k1,
                           qc_kdf_keys *out) {
    const level_case *lc = NULL;
    qc_m2_fields f;
    uint8_t k2[32], ns[32], mac[32];
    uint8_t transcript[8192];
    size_t tblen;
    qc_kdf_keys keys;

    for (int i = 0; i < 3; i++) {
        if (LEVELS[i].wire == wire) {
            lc = &LEVELS[i];
        }
    }
    if (lc == NULL) {
        return -1;
    }
    if (qc_m2_parse(m2, m2_len, lc->ct_len, QC_M1_VERSION, &f) != QC_CODEC_OK) {
        return -1;
    }
    if (qc_kem_decaps(lc->level, k2, f.ct_w, eph_sk) != QC_KEM_OK) {
        return -1;
    }
    memcpy(ns, f.nonce_s, 32);
    /* transcript = M1 || M2-body (confirm excluded). */
    tblen = m1_len + m2_len - 32;
    if (tblen > sizeof(transcript)) {
        return -1;
    }
    memcpy(transcript, m1, m1_len);
    memcpy(transcript + m1_len, m2, m2_len - 32);
    {
        uint8_t nw[12];
        memcpy(nw, m1 + 1 + 16 + 1 + lc->pk_len + lc->ct_len, 12);
        if (qc_kdf_derive(nw, ns, k1, 32, k2, 32, KDEV,
                          transcript, tblen, &keys) != 0) {
            return -1;
        }
    }
    qc_hmac_sha256(keys.k_conf, 32, transcript, tblen, mac);
    if (memcmp(mac, f.confirm, 32) != 0) {
        return -2;
    }
    if (out != NULL) {
        memcpy(out, &keys, sizeof(keys));
    }
    return 0;
}

/* Full handshake one level: server emits, device completes, keys agree
 * on all four session keys with the stored server session. */
static void run_handshake(uint8_t wire, const char *label) {
    static uint8_t m1[8192], m2[QC_SRV_M2_MAX], eph_sk[3168], k1[32];
    static uint8_t m2b[QC_SRV_M2_MAX];
    size_t m1_len, m2_len, m2_len2;
    qc_kdf_keys dev;
    uint64_t dec0, enc0;

    server_up(wire, wire);
    device_m1(wire, 1u, 0u, m1, &m1_len, eph_sk, k1);
    dec0 = srv.decaps_calls;
    enc0 = srv.encaps_calls;
    TEST_ASSERT_EQUAL_INT_MESSAGE(QC_SRV_OK_EMIT,
        qc_server_m1(&srv, m1, m1_len, m2, sizeof(m2), 1000, &m2_len),
        label);
    TEST_ASSERT_EQUAL_UINT64_MESSAGE(dec0 + 1, srv.decaps_calls, label);
    TEST_ASSERT_EQUAL_UINT64_MESSAGE(enc0 + 1, srv.encaps_calls, label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, device_complete(wire, m1, m1_len,
        m2, m2_len, eph_sk, k1, &dev), label);
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(dev.k_c2s, srv.session.k_c2s, 32,
                                          label);
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(dev.k_s2c, srv.session.k_s2c, 32,
                                          label);
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(dev.k_rat, srv.session.k_rat, 32,
                                          label);
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(dev.k_conf, srv.session.k_conf, 32,
                                          label);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(1, srv.session_valid, label);

    /* Identical retry: RESEND, byte-identical M2, zero new KEM work. */
    dec0 = srv.decaps_calls;
    enc0 = srv.encaps_calls;
    TEST_ASSERT_EQUAL_INT_MESSAGE(QC_SRV_RESEND,
        qc_server_m1(&srv, m1, m1_len, m2b, sizeof(m2b), 1001, &m2_len2),
        label);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(m2_len, m2_len2, label);
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(m2, m2b, m2_len, label);
    TEST_ASSERT_EQUAL_UINT64_MESSAGE(dec0, srv.decaps_calls, label);
    TEST_ASSERT_EQUAL_UINT64_MESSAGE(enc0, srv.encaps_calls, label);
}

static void test_handshake_512(void) {
    run_handshake(QC_WIRE_L512, "hs512");
}

static void test_handshake_768(void) {
    run_handshake(QC_WIRE_L768, "hs768");
}

static void test_handshake_1024(void) {
    run_handshake(QC_WIRE_L1024, "hs1024");
}

/* Bad HMAC: DROP_HMAC + auth path (counter), zero KEM work, no M2. */
static void test_bad_hmac(void) {
    static uint8_t m1[8192], m2[QC_SRV_M2_MAX], eph_sk[3168];
    size_t m1_len, m2_len = 0;

    server_up(QC_WIRE_L768, QC_WIRE_L768);
    device_m1(QC_WIRE_L768, 1u, 0u, m1, &m1_len, eph_sk, NULL);
    m1[m1_len - 1] ^= 0x01;
    TEST_ASSERT_EQUAL_INT(QC_SRV_DROP_HMAC,
        qc_server_m1(&srv, m1, m1_len, m2, sizeof(m2), 1000, &m2_len));
    TEST_ASSERT_EQUAL_UINT64(1, srv.cnt.auth_fail);
    TEST_ASSERT_EQUAL_UINT64(0, srv.decaps_calls);
    TEST_ASSERT_EQUAL_UINT64(0, srv.encaps_calls);
    TEST_ASSERT_EQUAL_UINT(0, m2_len);
    TEST_ASSERT_EQUAL_UINT64(0, srv.cnt.replay_drop);
}

/* Equal (epoch,counter), different ct_S bytes (valid HMAC recomputed
 * by the harness holding Kdev): cache key binds H(ct_S), so this MISSES
 * and the epoch gate drops it as a replay attempt (retry path is
 * identical-bytes only). A different ek_W with the SAME ct_S hits the
 * same key and resends (ek is not in the key: safe, same bytes on wire).
 * Both pinned. */
static void test_replay_equal_nonce(void) {
    static uint8_t m1[8192], m2[QC_SRV_M2_MAX], eph_sk[3168];
    static uint8_t m2b[QC_SRV_M2_MAX];
    size_t m1_len, m2_len, m2_len2, m2_emit_len;
    uint64_t dec0, enc0;

    server_up(QC_WIRE_L768, QC_WIRE_L768);
    device_m1(QC_WIRE_L768, 5u, 7u, m1, &m1_len, eph_sk, NULL);
    TEST_ASSERT_EQUAL_INT(QC_SRV_OK_EMIT,
        qc_server_m1(&srv, m1, m1_len, m2, sizeof(m2), 1000, &m2_len));
    m2_emit_len = m2_len;
    /* Same triple, different ct_S -> key miss -> epoch-equal -> DROP. */
    m1[1 + 16 + 1 + 1184 + 100] ^= 0x01;
    {
        uint8_t tag[32];
        qc_hmac_sha256(KDEV, 32, m1, m1_len - 32, tag);
        memcpy(m1 + m1_len - 32, tag, 32);
    }
    dec0 = srv.decaps_calls;
    TEST_ASSERT_EQUAL_INT(QC_SRV_DROP_REPLAY,
        qc_server_m1(&srv, m1, m1_len, m2, sizeof(m2), 1001, &m2_len));
    TEST_ASSERT_EQUAL_UINT64(1, srv.cnt.replay_drop);
    TEST_ASSERT_EQUAL_UINT64(dec0, srv.decaps_calls);
    /* Same triple, different ek_W, same ct_S -> same key -> RESEND. */
    device_m1(QC_WIRE_L768, 5u, 7u, m1, &m1_len, eph_sk, NULL);
    m1[1 + 16 + 1 + 100] ^= 0x01;
    {
        uint8_t tag[32];
        qc_hmac_sha256(KDEV, 32, m1, m1_len - 32, tag);
        memcpy(m1 + m1_len - 32, tag, 32);
    }
    dec0 = srv.decaps_calls;
    enc0 = srv.encaps_calls;
    TEST_ASSERT_EQUAL_INT(QC_SRV_RESEND,
        qc_server_m1(&srv, m1, m1_len, m2b, sizeof(m2b), 1002, &m2_len2));
    TEST_ASSERT_EQUAL_UINT_MESSAGE(m2_emit_len, m2_len2, "same M2");
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(m2, m2b, m2_emit_len, "same bytes");
    TEST_ASSERT_EQUAL_UINT64_MESSAGE(dec0, srv.decaps_calls, "no KEM");
    TEST_ASSERT_EQUAL_UINT64_MESSAGE(enc0, srv.encaps_calls, "no KEM");
}

/* Lower epoch: DROP_EPOCH (stale). */
static void test_stale_epoch(void) {
    static uint8_t m1[8192], m2[QC_SRV_M2_MAX], eph_sk[3168];
    size_t m1_len, m2_len;

    server_up(QC_WIRE_L768, QC_WIRE_L768);
    device_m1(QC_WIRE_L768, 9u, 0u, m1, &m1_len, eph_sk, NULL);
    TEST_ASSERT_EQUAL_INT(QC_SRV_OK_EMIT,
        qc_server_m1(&srv, m1, m1_len, m2, sizeof(m2), 1000, &m2_len));
    device_m1(QC_WIRE_L768, 8u, 99u, m1, &m1_len, eph_sk, NULL);
    TEST_ASSERT_EQUAL_INT(QC_SRV_DROP_EPOCH,
        qc_server_m1(&srv, m1, m1_len, m2, sizeof(m2), 1001, &m2_len));
}

/* Below-floor L: ABORT_FLOOR + counter, no M2, no decaps. */
static void test_floor_refuse(void) {
    static uint8_t m1[8192], m2[QC_SRV_M2_MAX], eph_sk[3168];
    size_t m1_len, m2_len = 0;

    server_up(QC_WIRE_L768, QC_WIRE_L768);
    device_m1(QC_WIRE_L512, 1u, 0u, m1, &m1_len, eph_sk, NULL);
    TEST_ASSERT_EQUAL_INT(QC_SRV_ABORT_FLOOR,
        qc_server_m1(&srv, m1, m1_len, m2, sizeof(m2), 1000, &m2_len));
    TEST_ASSERT_EQUAL_UINT64(1, srv.cnt.floor_refusal);
    TEST_ASSERT_EQUAL_UINT(0, m2_len);
    TEST_ASSERT_EQUAL_UINT64(0, srv.decaps_calls);
}

/* Structural rejects: unknown L/version/truncation -> DROP_PARSE. */
static void test_parse_rejects(void) {
    static uint8_t m1[8192], m2[QC_SRV_M2_MAX], eph_sk[3168];
    size_t m1_len, m2_len;

    server_up(QC_WIRE_L768, QC_WIRE_L512);
    device_m1(QC_WIRE_L768, 1u, 0u, m1, &m1_len, eph_sk, NULL);
    m1[17] = 9;
    TEST_ASSERT_EQUAL_INT(QC_SRV_DROP_PARSE,
        qc_server_m1(&srv, m1, m1_len, m2, sizeof(m2), 1000, &m2_len));
    TEST_ASSERT_EQUAL_UINT64(1, srv.cnt.parse_fail);
    device_m1(QC_WIRE_L768, 1u, 0u, m1, &m1_len, eph_sk, NULL);
    m1[0] = 2;
    TEST_ASSERT_EQUAL_INT(QC_SRV_DROP_PARSE,
        qc_server_m1(&srv, m1, m1_len, m2, sizeof(m2), 1000, &m2_len));
    TEST_ASSERT_EQUAL_INT(QC_SRV_DROP_PARSE,
        qc_server_m1(&srv, m1, 10, m2, sizeof(m2), 1000, &m2_len));
    TEST_ASSERT_EQUAL_UINT64(3, srv.cnt.parse_fail);
}

/* Wrong device identity (valid HMAC recomputed: shared-credential case):
 * DROP_PARSE — the cache key is built from the provisioned id. */
static void test_wrong_identity(void) {
    static uint8_t m1[8192], m2[QC_SRV_M2_MAX], eph_sk[3168];
    size_t m1_len, m2_len;

    server_up(QC_WIRE_L768, QC_WIRE_L768);
    device_m1(QC_WIRE_L768, 1u, 0u, m1, &m1_len, eph_sk, NULL);
    m1[1] ^= 0x01;
    {
        uint8_t tag[32];
        qc_hmac_sha256(KDEV, 32, m1, m1_len - 32, tag);
        memcpy(m1 + m1_len - 32, tag, 32);
    }
    TEST_ASSERT_EQUAL_INT(QC_SRV_DROP_PARSE,
        qc_server_m1(&srv, m1, m1_len, m2, sizeof(m2), 1000, &m2_len));
    TEST_ASSERT_EQUAL_UINT64(1, srv.cnt.parse_fail);
    TEST_ASSERT_EQUAL_UINT64(0, srv.decaps_calls);
}

/* Corrupt server sk: decaps fails -> ABORT_DECAPS (code surfaced). */
static void test_decaps_abort(void) {
    static uint8_t m1[8192], m2[QC_SRV_M2_MAX], eph_sk[3168];
    size_t m1_len, m2_len;

    server_up(QC_WIRE_L768, QC_WIRE_L768);
    srv.server_sk[2400 - 64] ^= 0x01; /* break embedded H(pk) region. */
    device_m1(QC_WIRE_L768, 1u, 0u, m1, &m1_len, eph_sk, NULL);
    TEST_ASSERT_EQUAL_INT(QC_SRV_ABORT_DECAPS,
        qc_server_m1(&srv, m1, m1_len, m2, sizeof(m2), 1000, &m2_len));
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0, srv.session_valid, "no session");
}

/* Undersize caller M2 buffer: ABORT_EMIT pre-KEM (zero crypto work),
 * counted as caller-side structural. */
static void test_emit_small_buf(void) {
    static uint8_t m1[8192], m2[16], eph_sk[3168];
    size_t m1_len, m2_len = 0x5A5A;

    server_up(QC_WIRE_L768, QC_WIRE_L768);
    device_m1(QC_WIRE_L768, 1u, 0u, m1, &m1_len, eph_sk, NULL);
    TEST_ASSERT_EQUAL_INT(QC_SRV_ABORT_EMIT,
        qc_server_m1(&srv, m1, m1_len, m2, sizeof(m2), 1000, &m2_len));
    TEST_ASSERT_EQUAL_UINT(0, m2_len);
    TEST_ASSERT_EQUAL_UINT64(0, srv.decaps_calls);
    TEST_ASSERT_EQUAL_UINT64(0, srv.encaps_calls);
    TEST_ASSERT_EQUAL_UINT64(1, srv.cnt.parse_fail);
}

/* In-flight hit (M2 not yet stored — arranged by manual insert, models
 * the async race): DROP_REPLAY, never an empty resend. */
static void test_inflight_hit_drops(void) {
    static uint8_t m1[8192], m2[QC_SRV_M2_MAX], eph_sk[3168];
    size_t m1_len, m2_len;
    uint8_t key[QC_CACHE_KEY_LEN];

    server_up(QC_WIRE_L768, QC_WIRE_L768);
    device_m1(QC_WIRE_L768, 1u, 0u, m1, &m1_len, eph_sk, NULL);
    /* Same key the pipeline will compute: id || epoch || N_W || H(ct).
     * M1 layout 768: ver[1] id[16] L[1] ek[1184] ct[1088]@1202
     * nonce[12]@2290 hmac[32]. */
    {
        uint8_t nw[12];
        memcpy(nw, m1 + 2290, 12);
        qc_cache_key(srv.identity, 1u, nw, m1 + 1202, 1088, key);
    }
    TEST_ASSERT_EQUAL_INT(QC_CACHE_OK,
                          qc_cache_insert(&srv.cache, key, 1000));
    TEST_ASSERT_EQUAL_INT(QC_SRV_DROP_REPLAY,
        qc_server_m1(&srv, m1, m1_len, m2, sizeof(m2), 1001, &m2_len));
    TEST_ASSERT_EQUAL_UINT64(1, srv.cnt.replay_drop);
    TEST_ASSERT_EQUAL_UINT64(0, srv.decaps_calls);
}

/* Handshake-attempt counts every post-HMAC M1 (incl. drops/resends). */
static void test_attempt_counter(void) {
    static uint8_t m1[8192], m2[QC_SRV_M2_MAX], eph_sk[3168];
    size_t m1_len, m2_len;

    server_up(QC_WIRE_L768, QC_WIRE_L768);
    device_m1(QC_WIRE_L768, 1u, 0u, m1, &m1_len, eph_sk, NULL);
    TEST_ASSERT_EQUAL_INT(QC_SRV_OK_EMIT,
        qc_server_m1(&srv, m1, m1_len, m2, sizeof(m2), 1000, &m2_len));
    TEST_ASSERT_EQUAL_UINT64(1, srv.cnt.hs_attempt);
    TEST_ASSERT_EQUAL_INT(QC_SRV_RESEND,
        qc_server_m1(&srv, m1, m1_len, m2, sizeof(m2), 1001, &m2_len));
    TEST_ASSERT_EQUAL_UINT64(2, srv.cnt.hs_attempt);
    m1[m1_len - 1] ^= 0x01;
    TEST_ASSERT_EQUAL_INT(QC_SRV_DROP_HMAC,
        qc_server_m1(&srv, m1, m1_len, m2, sizeof(m2), 1002, &m2_len));
    TEST_ASSERT_EQUAL_UINT64(2, srv.cnt.hs_attempt);
}

void setUp(void) {
    test_rng_seed(0x1D107A5E9C3B4D07ull);
    memset(srv_pk, 0, sizeof(srv_pk));
    memset(srv_sk, 0, sizeof(srv_sk));
}

void tearDown(void) {}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_handshake_512);
    RUN_TEST(test_handshake_768);
    RUN_TEST(test_handshake_1024);
    RUN_TEST(test_bad_hmac);
    RUN_TEST(test_replay_equal_nonce);
    RUN_TEST(test_stale_epoch);
    RUN_TEST(test_floor_refuse);
    RUN_TEST(test_inflight_hit_drops);
    RUN_TEST(test_emit_small_buf);
    RUN_TEST(test_wrong_identity);
    RUN_TEST(test_parse_rejects);
    RUN_TEST(test_decaps_abort);
    RUN_TEST(test_attempt_counter);
    return UNITY_END();
}