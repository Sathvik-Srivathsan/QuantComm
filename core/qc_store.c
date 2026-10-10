/* qc_store.c — secure storage logic (B-13.3, backend-agnostic).
 * Pure item logic + image encode/parse/MAC; bytes move through caller
 * hooks (file/NVS). Endianness fixed big-endian; layout fixed-size
 * (no length variables reach any size arithmetic).
 *
 * Image (146 B fixed): magic "QCS1"[4] || schema u16 || present u16 ||
 * klen u16 || kdev_wrapped[60] (nonce12 || ct32 || tag16) ||
 * manifest u32 || epoch u64 || replay[48] || backoff[2] u64.
 * File = image || HMAC-32(Kmac, image). Total 178 B.
 * present bits: 0x01 kdev, 0x02 manifest version, 0x04 epoch.
 */
#include "qc_store.h"

#include <string.h>

#include "qc_aead.h"
#include "qc_hkdf.h"
#include "qc_hmac.h"
#include "qc_zeroize.h"

#define QC_STORE_MAGIC_0 'Q'
#define QC_STORE_MAGIC_1 'C'
#define QC_STORE_MAGIC_2 'S'
#define QC_STORE_MAGIC_3 '1'

/* Image layout (146 B fixed): magic "QCS1"[4] || schema u16 || present
 * u16 || klen u16 || kdev_wrapped[60] (nonce12 || ct32 || tag16) ||
 * manifest u32 || epoch u64 || replay[48] || backoff[2] u64.
 * File = image || HMAC-32(Kmac, image). (Sizes in the header.) */

static void put_u16be(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void put_u32be(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void put_u64be(uint8_t *p, uint64_t v) {
    int i;
    for (i = 0; i < 8; i++) {
        p[i] = (uint8_t)(v >> (8 * (7 - i)));
    }
}

static uint16_t get_u16be(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t get_u32be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint64_t get_u64be(const uint8_t *p) {
    uint64_t v = 0;
    int i;
    for (i = 0; i < 8; i++) {
        v = (v << 8) | p[i];
    }
    return v;
}

/* Item keys: HKDF-Expand(root-as-PRK, label, 32). Root is 32 B uniform,
 * i.e. already PRK-quality (documented, not Extract-ed). */
static int item_key(const uint8_t root[32], const char *label, size_t llen,
                    uint8_t out[32]) {
    return qc_hkdf_expand(root, (const uint8_t *)label, llen, out, 32);
}

qc_store_rc qc_store_open(qc_store *s, const uint8_t root[32]) {
    if (s == NULL || root == NULL) {
        return QC_STORE_BAD_ARG;
    }
    memset(s, 0, sizeof(*s));
    memcpy(s->root, root, 32);
    s->has_root = 1;
    s->schema_version = QC_STORE_SCHEMA_CURRENT;
    return QC_STORE_OK;
}

void qc_store_close(qc_store *s) {
    if (s == NULL) {
        return;
    }
    qc_zeroize(s, sizeof(*s));
}

qc_store_rc qc_store_set_kdev(qc_store *s, const uint8_t kdev[32]) {
    if (s == NULL || !s->has_root || kdev == NULL) {
        return QC_STORE_BAD_ARG;
    }
    memcpy(s->kdev, kdev, 32);
    s->has_kdev = 1;
    return QC_STORE_OK;
}

qc_store_rc qc_store_get_kdev(const qc_store *s, uint8_t kdev[32]) {
    if (s == NULL || kdev == NULL) {
        return QC_STORE_BAD_ARG;
    }
    if (!s->has_kdev) {
        return QC_STORE_NOT_FOUND;
    }
    memcpy(kdev, s->kdev, 32);
    return QC_STORE_OK;
}

qc_store_rc qc_store_set_manifest_version(qc_store *s, uint32_t v) {
    if (s == NULL) {
        return QC_STORE_BAD_ARG;
    }
    if (s->has_manifest_version && v < s->manifest_version) {
        return QC_STORE_STALE;
    }
    s->manifest_version = v;
    s->has_manifest_version = 1;
    return QC_STORE_OK;
}

qc_store_rc qc_store_set_epoch(qc_store *s, uint64_t epoch) {
    if (s == NULL) {
        return QC_STORE_BAD_ARG;
    }
    if (epoch == UINT64_MAX) {
        return QC_STORE_SATURATED;
    }
    if (s->has_epoch && epoch < s->epoch) {
        return QC_STORE_STALE;
    }
    s->epoch = epoch;
    s->has_epoch = 1;
    return QC_STORE_OK;
}

qc_store_rc qc_store_set_replay(qc_store *s,
                                const uint8_t replay[QC_STORE_REPLAY_LEN]) {
    if (s == NULL || replay == NULL) {
        return QC_STORE_BAD_ARG;
    }
    memcpy(s->replay, replay, QC_STORE_REPLAY_LEN);
    return QC_STORE_OK;
}

qc_store_rc qc_store_set_backoff(qc_store *s, int idx, uint64_t v) {
    if (s == NULL || (idx != 0 && idx != 1)) {
        return QC_STORE_BAD_ARG;
    }
    s->backoff[idx] = v;
    return QC_STORE_OK;
}

/* Build the file image (plaintext part) + wrap Kdev. wrap_nonce must be
 * fresh per save when a Kdev is stored (GCM nonce discipline); NULL iff
 * no Kdev stored. */
static int build_image(const qc_store *s, const uint8_t *wrap_nonce,
                       uint8_t img[QC_STORE_IMAGE_LEN]) {
    uint8_t kkey[32], tag[16];
    uint8_t *p = img;

    p[0] = QC_STORE_MAGIC_0;
    p[1] = QC_STORE_MAGIC_1;
    p[2] = QC_STORE_MAGIC_2;
    p[3] = QC_STORE_MAGIC_3;
    put_u16be(p + 4, s->schema_version);
    put_u16be(p + 6, (uint16_t)((s->has_kdev ? 0x01 : 0) |
                               (s->has_manifest_version ? 0x02 : 0) |
                               (s->has_epoch ? 0x04 : 0)));
    if (s->has_kdev) {
        uint8_t ct[32];
        if (wrap_nonce == NULL) {
            return -1;
        }
        if (item_key(s->root, "QC-STORE-KDEV", 13, kkey) != 0) {
            return -1;
        }
        /* AES-GCM encrypt Kdev (fixed 32 B, no AAD needed: nonce binds). */
        if (qc_aead_encrypt(kkey, 32, wrap_nonce, 12, NULL, 0,
                            s->kdev, 32, ct, tag) != 0) {
            qc_zeroize(kkey, sizeof(kkey));
            return -1;
        }
        qc_zeroize(kkey, sizeof(kkey));
        put_u16be(p + 8, 60);
        memcpy(p + 10, wrap_nonce, 12);
        memcpy(p + 22, ct, 32);
        memcpy(p + 54, tag, 16);
        qc_zeroize(ct, sizeof(ct));
        qc_zeroize(tag, sizeof(tag));
    } else {
        put_u16be(p + 8, 0);
        memset(p + 10, 0, 60);
    }
    put_u32be(p + 70, s->manifest_version);
    put_u64be(p + 74, s->epoch);
    memcpy(p + 82, s->replay, QC_STORE_REPLAY_LEN);
    put_u64be(p + 130, s->backoff[0]);
    put_u64be(p + 138, s->backoff[1]);
    return 0;
}

qc_store_rc qc_store_save(qc_store *s, const uint8_t *wrap_nonce,
                          qc_store_write_fn write_fn) {
    uint8_t img[QC_STORE_IMAGE_LEN];
    uint8_t file[QC_STORE_FILE_LEN];
    uint8_t mkey[32], mac[32];

    if (s == NULL || !s->has_root || write_fn == NULL) {
        return QC_STORE_BAD_ARG;
    }
    if (s->has_kdev && wrap_nonce == NULL) {
        return QC_STORE_BAD_ARG;
    }
    if (build_image(s, wrap_nonce, img) != 0) {
        qc_zeroize(img, sizeof(img));
        return QC_STORE_IO_FAIL;
    }
    if (item_key(s->root, "QC-STORE-MAC", 13, mkey) != 0) {
        qc_zeroize(img, sizeof(img));
        return QC_STORE_IO_FAIL;
    }
    memcpy(file, img, QC_STORE_IMAGE_LEN);
    qc_hmac_sha256(mkey, 32, img, QC_STORE_IMAGE_LEN, mac);
    qc_zeroize(mkey, sizeof(mkey));
    qc_zeroize(img, sizeof(img));
    memcpy(file + QC_STORE_IMAGE_LEN, mac, 32);
    qc_zeroize(mac, sizeof(mac));
    if (write_fn(file, QC_STORE_FILE_LEN) != 0) {
        qc_zeroize(file, sizeof(file));
        return QC_STORE_IO_FAIL;
    }
    qc_zeroize(file, sizeof(file));
    return QC_STORE_OK;
}

qc_store_rc qc_store_load(qc_store *s, qc_store_read_fn read_fn) {
    uint8_t file[QC_STORE_FILE_LEN];
    uint8_t mkey[32], mac[32], kkey[32], kdev[32];
    size_t n = 0;
    uint16_t schema, present, klen;

    if (s == NULL || !s->has_root || read_fn == NULL) {
        return QC_STORE_BAD_ARG;
    }
    if (read_fn(file, sizeof(file), &n) != 0 || n == 0) {
        /* Audit F6a/F7b: wipe even here (a failing backend may have left
         * partial bytes). Hard backend errors conflate into NOT_FOUND —
         * fail-safe direction (caller halts either way), audit-poor;
         * documented, not split: splitting would need a backend error
         * taxonomy this hook contract deliberately avoids. */
        qc_zeroize(file, sizeof(file));
        return QC_STORE_NOT_FOUND;
    }
    if (n != QC_STORE_FILE_LEN) {
        qc_zeroize(file, sizeof(file));
        return QC_STORE_CORRUPT;
    }
    /* Integrity first (constant-time compare via HMAC output diff). */
    if (item_key(s->root, "QC-STORE-MAC", 13, mkey) != 0) {
        qc_zeroize(file, sizeof(file));
        return QC_STORE_IO_FAIL;
    }
    qc_hmac_sha256(mkey, 32, file, QC_STORE_IMAGE_LEN, mac);
    qc_zeroize(mkey, sizeof(mkey));
    {
        uint8_t diff = 0;
        size_t i;
        for (i = 0; i < 32; i++) {
            diff |= (uint8_t)(mac[i] ^ file[QC_STORE_IMAGE_LEN + i]);
        }
        qc_zeroize(mac, sizeof(mac));
        if (diff != 0) {
            qc_zeroize(file, sizeof(file));
            return QC_STORE_CORRUPT;
        }
    }
    /* Structure: magic, then schema major gate. */
    if (file[0] != QC_STORE_MAGIC_0 || file[1] != QC_STORE_MAGIC_1 ||
        file[2] != QC_STORE_MAGIC_2 || file[3] != QC_STORE_MAGIC_3) {
        qc_zeroize(file, sizeof(file));
        return QC_STORE_CORRUPT;
    }
    schema = get_u16be(file + 4);
    /* Only v1 exists: anything else halts (never guess, never migrate
     * silently — forward migration arrives with v2, not before). */
    if (schema != QC_STORE_SCHEMA_CURRENT) {
        qc_zeroize(file, sizeof(file));
        return QC_STORE_HALT_VERSION;
    }
    present = get_u16be(file + 6);
    klen = get_u16be(file + 8);
    if ((klen != 0 && klen != QC_STORE_KDEV_WRAP_LEN) ||
        (klen == 0 && (present & 0x01))) {
        /* Length/capability mismatch: corrupt image (not a partial
         * read — length exact-checked above). Audit F7d: the reverse
         * inconsistency (klen=60 with kdev-bit clear) is TOLERATED —
         * unwrap proceeds and sets has_kdev. Only our own writer can
         * produce it (MAC covers both fields), so refusal buys nothing. */
        qc_zeroize(file, sizeof(file));
        return QC_STORE_CORRUPT;
    }
    /* Anti-rollback on load (audit F1): a MAC-valid but OLDER image must
     * not move live state backward. Setters enforce this (STALE); load
     * bypassed it. Gate here BEFORE mutating s (including before the Kdev
     * unwrap below, so a refused load leaves RAM fully intact). (Loaded
     * epoch == UINT64_MAX is accepted as-recorded; the next set_epoch
     * refuses it, so the store is effectively halted — noted, not
     * refused, since the persisted state itself is faithfully
     * reported.) */
    {
        uint32_t file_mv = get_u32be(file + 70);
        uint64_t file_epoch = get_u64be(file + 74);
        if (s->has_manifest_version && (present & 0x02) &&
            file_mv < s->manifest_version) {
            qc_zeroize(file, sizeof(file));
            return QC_STORE_STALE;
        }
        if (s->has_epoch && (present & 0x04) &&
            file_epoch < s->epoch) {
            qc_zeroize(file, sizeof(file));
            return QC_STORE_STALE;
        }
    }
    /* Unwrap Kdev if present. */
    if (klen > 0) {
        if (item_key(s->root, "QC-STORE-KDEV", 13, kkey) != 0) {
            qc_zeroize(file, sizeof(file));
            return QC_STORE_IO_FAIL;
        }
        if (qc_aead_decrypt(kkey, 32, file + 10, 12, NULL, 0,
                            file + 22, 32, file + 54, kdev) != 0) {
            /* Audit F6b: wipe kdev too (defense in depth — the adapter
             * already wipes on AUTH_FAIL per the B-12 deviation, but this
             * frame must not depend on callee wipe discipline). */
            qc_zeroize(kkey, sizeof(kkey));
            qc_zeroize(kdev, sizeof(kdev));
            qc_zeroize(file, sizeof(file));
            return QC_STORE_CORRUPT;
        }
        qc_zeroize(kkey, sizeof(kkey));
        memcpy(s->kdev, kdev, 32);
        qc_zeroize(kdev, sizeof(kdev));
        s->has_kdev = 1;
    } else {
        s->has_kdev = 0;
    }
    s->schema_version = schema;
    s->manifest_version = get_u32be(file + 70);
    s->has_manifest_version = (uint8_t)((present & 0x02) != 0);
    s->epoch = get_u64be(file + 74);
    s->has_epoch = (uint8_t)((present & 0x04) != 0);
    memcpy(s->replay, file + 82, QC_STORE_REPLAY_LEN);
    s->backoff[0] = get_u64be(file + 130);
    s->backoff[1] = get_u64be(file + 138);
    qc_zeroize(file, sizeof(file));
    return QC_STORE_OK;
}
