/* qc_manifest_persist.c — manifest NVS wiring (B-25 over B-13.3).
 * No heap, no threads, caller clock unnecessary (no TTLs here).
 * Static staging buffers (image ~7.2 KB): never stack (house rule).
 */
#include "qc_manifest_persist.h"

#include <stdio.h>
#include <string.h>

#include "qc_dsa.h"
#include "qc_hkdf.h"
#include "qc_hmac.h"
#include "qc_zeroize.h"

/* Image cap: 4 magic + 4 ver + 4 body_len + 4096 body + 4 level +
 * 2 pk_len + 2592 pk + 32 MAC. */
#define QC_MFT_IMG_CAP (4u + 4u + 4u + QC_MFT_MAX_BODY + 4u + 2u + 2592u + 32u)

static uint8_t s_img[QC_MFT_IMG_CAP];

static void put_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void put_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static uint32_t get_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint16_t get_u16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

/* HMAC key for the image (store-root-derived, per-item label). */
static int mft_key(const uint8_t root[32], uint8_t out[32]) {
    static const uint8_t label[] = "QC-STORE-MFT";
    return qc_hkdf_expand(root, label, sizeof(label) - 1, out, 32);
}

static int valid_level_u32(uint32_t lv) {
    return lv == QC_DSA_44 || lv == QC_DSA_65 || lv == QC_DSA_87;
}

qc_mft_rc qc_manifest_persist(const qc_manifest_store *ms, qc_store *ns,
                              const char *store_path, const char *img_path,
                              const uint8_t *store_nonce) {
    uint8_t mkey[32], mac[32];
    uint8_t root[32];
    size_t n, pk_len;
    char tmp[512];
    FILE *f;
    qc_store_rc src;

    if (ms == NULL || ns == NULL || store_path == NULL ||
        img_path == NULL) {
        return QC_MFT_BAD_ARG;
    }
    if (!ms->initialized || !ms->has_manifest || ms->version == 0 ||
        ms->body_len > QC_MFT_MAX_BODY || !ns->has_root) {
        return QC_MFT_BAD_ARG;
    }
    if (strlen(img_path) + 4 >= sizeof(tmp)) {
        return QC_MFT_BAD_ARG;
    }
    pk_len = qc_dsa_pk_bytes(ms->enrolled_level);
    if (pk_len == 0 || pk_len > sizeof(ms->enrolled_pk)) {
        return QC_MFT_BAD_ARG;
    }
    memcpy(root, ns->root, 32);
    /* Image first (crash order: torn pair converges via max-wins). */
    s_img[0] = 'Q';
    s_img[1] = 'C';
    s_img[2] = 'M';
    s_img[3] = '1';
    put_u32(s_img + 4, ms->version);
    put_u32(s_img + 8, (uint32_t)ms->body_len);
    memcpy(s_img + 12, ms->body, ms->body_len);
    n = 12 + ms->body_len;
    put_u32(s_img + n, (uint32_t)ms->enrolled_level);
    n += 4;
    put_u16(s_img + n, (uint16_t)pk_len);
    n += 2;
    memcpy(s_img + n, ms->enrolled_pk, pk_len);
    n += pk_len;
    if (mft_key(root, mkey) != 0) {
        qc_zeroize(root, sizeof(root));
        qc_zeroize(s_img, sizeof(s_img));
        return QC_MFT_MALFORMED;
    }
    qc_hmac_sha256(mkey, 32, s_img, n, mac);
    qc_zeroize(mkey, sizeof(mkey));
    memcpy(s_img + n, mac, 32);
    qc_zeroize(mac, sizeof(mac));
    n += 32;
    memcpy(tmp, img_path, strlen(img_path) + 1);
    memcpy(tmp + strlen(img_path), ".tmp", 5);
    f = fopen(tmp, "wb");
    if (f == NULL) {
        qc_zeroize(root, sizeof(root));
        qc_zeroize(s_img, sizeof(s_img));
        return QC_MFT_MALFORMED;
    }
    if (fwrite(s_img, 1, n, f) != n) {
        fclose(f);
        remove(tmp);
        qc_zeroize(root, sizeof(root));
        qc_zeroize(s_img, sizeof(s_img));
        return QC_MFT_MALFORMED;
    }
    if (fclose(f) != 0) {
        remove(tmp);
        qc_zeroize(root, sizeof(root));
        qc_zeroize(s_img, sizeof(s_img));
        return QC_MFT_MALFORMED;
    }
    if (rename(tmp, img_path) != 0) {
        remove(img_path);
        if (rename(tmp, img_path) != 0) {
            remove(tmp);
            qc_zeroize(root, sizeof(root));
            qc_zeroize(s_img, sizeof(s_img));
            return QC_MFT_MALFORMED;
        }
    }
    qc_zeroize(s_img, sizeof(s_img));
    /* Anchor second: slot bump then whole-store save. */
    if (qc_store_set_manifest_version(ns, ms->version) != QC_STORE_OK) {
        qc_zeroize(root, sizeof(root));
        return QC_MFT_STALE;
    }
    src = qc_store_file_save(ns, store_path, store_nonce);
    qc_zeroize(root, sizeof(root));
    if (src == QC_STORE_OK) {
        return QC_MFT_OK;
    }
    if (src == QC_STORE_BAD_ARG) {
        return QC_MFT_BAD_ARG;
    }
    return QC_MFT_MALFORMED;
}

qc_mft_rc qc_manifest_restore(qc_manifest_store *ms, qc_store *ns,
                              const uint8_t root[32],
                              const char *store_path,
                              const char *img_path) {
    uint8_t mkey[32], mac[32];
    FILE *f;
    size_t n, body_len, pk_len;
    uint32_t version, level;
    int store_missing, img_missing;

    if (ms == NULL || ns == NULL || root == NULL || store_path == NULL ||
        img_path == NULL) {
        return QC_MFT_BAD_ARG;
    }
    if (qc_store_open(ns, root) != QC_STORE_OK) {
        return QC_MFT_BAD_ARG;
    }
    /* Presence matrix BEFORE parsing either (torn-pair rule). */
    {
        qc_store_rc src = qc_store_file_load(ns, store_path);
        store_missing = (src == QC_STORE_NOT_FOUND);
        if (!store_missing && src != QC_STORE_OK) {
            return QC_MFT_MALFORMED;
        }
    }
    f = fopen(img_path, "rb");
    img_missing = (f == NULL);
    if (!img_missing) {
        n = fread(s_img, 1, sizeof(s_img), f);
        fclose(f);
    } else {
        n = 0;
    }
    if (store_missing && img_missing) {
        return QC_MFT_NOT_FOUND;
    }
    if (store_missing || img_missing) {
        return QC_MFT_MALFORMED;
    }
    /* Structure, then MAC (constant-time), then fields. */
    if (n < 4 + 4 + 4 + 4 + 2 + 32 || s_img[0] != 'Q' ||
        s_img[1] != 'C' || s_img[2] != 'M' || s_img[3] != '1') {
        return QC_MFT_MALFORMED;
    }
    version = get_u32(s_img + 4);
    body_len = get_u32(s_img + 8);
    if (version == 0 || body_len > QC_MFT_MAX_BODY) {
        return QC_MFT_MALFORMED;
    }
    /* Audit hardening: bound the field offsets by READ bytes before
     * touching them (short files otherwise read stale static content —
     * bounded and outcome-safe via exact-fit below, but never reason
     * about stale bytes when a 3-line gate avoids it). */
    if (12 + body_len + 4 + 2 > n) {
        return QC_MFT_MALFORMED;
    }
    level = get_u32(s_img + 12 + body_len);
    pk_len = get_u16(s_img + 12 + body_len + 4);
    /* Exact fit: no trailing garbage (torn writes are impossible via
     * temp+rename, so trailing bytes mean tamper). */
    if (!valid_level_u32(level) ||
        pk_len != qc_dsa_pk_bytes((qc_dsa_level)level) ||
        12 + body_len + 4 + 2 + pk_len + 32 != n) {
        return QC_MFT_MALFORMED;
    }
    if (mft_key(root, mkey) != 0) {
        return QC_MFT_MALFORMED;
    }
    qc_hmac_sha256(mkey, 32, s_img, n - 32, mac);
    qc_zeroize(mkey, sizeof(mkey));
    {
        uint8_t diff = 0;
        size_t i;
        for (i = 0; i < 32; i++) {
            diff |= (uint8_t)(mac[i] ^ s_img[n - 32 + i]);
        }
        qc_zeroize(mac, sizeof(mac));
        if (diff != 0) {
            qc_zeroize(s_img, sizeof(s_img));
            return QC_MFT_MALFORMED;
        }
    }
    /* Anchor: image older than slot is rollback (ms untouched). */
    if (ns->has_manifest_version && version < ns->manifest_version) {
        qc_zeroize(s_img, sizeof(s_img));
        return QC_MFT_STALE;
    }
    /* Adopt + sync slot upward (next persist writes it). */
    if (!ns->has_manifest_version || version > ns->manifest_version) {
        ns->manifest_version = version;
        ns->has_manifest_version = 1;
    }
    memset(ms, 0, sizeof(*ms));
    ms->initialized = 1;
    ms->enrolled_level = (qc_dsa_level)level;
    memset(ms->enrolled_pk, 0, sizeof(ms->enrolled_pk));
    memcpy(ms->enrolled_pk, s_img + 12 + body_len + 4 + 2, pk_len);
    ms->version = version;
    ms->has_manifest = 1;
    memcpy(ms->body, s_img + 12, body_len);
    ms->body_len = body_len;
    qc_zeroize(s_img, sizeof(s_img));
    return QC_MFT_OK;
}
