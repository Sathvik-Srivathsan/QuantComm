/* qc_frame.c — telemetry frame protect/open (B-24.1).
 * Pure functions of bytes + key: no state, no RNG, no alloc. Counter and
 * epoch arrive as values; AAD binding makes any header mutation fail the
 * tag check on open (verified per-region by tests).
 */
#include "qc_frame.h"

#include <string.h>

#include "qc_aead.h"

static void put_u64be(uint8_t *p, uint64_t v) {
    int i;
    for (i = 0; i < 8; i++) {
        p[i] = (uint8_t)(v >> (8 * (7 - i)));
    }
}

static uint64_t get_u64be(const uint8_t *p) {
    uint64_t v = 0;
    int i;
    for (i = 0; i < 8; i++) {
        v = (v << 8) | p[i];
    }
    return v;
}

static void put_u32be(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static int valid_class(uint8_t c) {
    return c == QC_CLS_C0 || c == QC_CLS_C1 || c == QC_CLS_C2;
}

static int valid_level(uint8_t l) {
    return l == 1 || l == 2 || l == 3;
}

size_t qc_frame_len(size_t payload_len) {
    if (payload_len > QC_FRAME_MAX_PAYLOAD) {
        return 0;
    }
    /* 74 + 4 + payload + 16: no 32-bit overflow (payload <= 65535). */
    return QC_FRAME_HDR_LEN + 4 + payload_len + QC_FRAME_TAG_LEN;
}

qc_frame_rc qc_frame_protect(const qc_frame_fields *f, uint32_t epoch,
                             const uint8_t key[32],
                             uint8_t *out, size_t out_len) {
    uint8_t *p;
    uint8_t nonce[12];
    size_t need;
    int rc;

    if (f == NULL || key == NULL || out == NULL) {
        return QC_FRAME_BAD_ARG;
    }
    if (!valid_class(f->cls) || !valid_level(f->level)) {
        return QC_FRAME_BAD_VALUE;
    }
    if (f->payload_len > 0 && f->payload == NULL) {
        return QC_FRAME_BAD_ARG;
    }
    need = qc_frame_len(f->payload_len);
    if (need == 0 || out_len != need) {
        return QC_FRAME_OVERSIZE;
    }
    /* Header (AAD). */
    p = out;
    memcpy(p, f->identity, 16);
    p[16] = f->cls;
    p[17] = f->level;
    put_u64be(p + 18, f->counter);
    memcpy(p + 26, f->last_root, 32);
    put_u64be(p + 58, f->range_start);
    put_u64be(p + 66, f->range_end);
    put_u32be(p + 74, (uint32_t)f->payload_len);
    /* Nonce: epoch-BE32 || counter-BE64 (single source of truth). */
    nonce[0] = (uint8_t)(epoch >> 24);
    nonce[1] = (uint8_t)(epoch >> 16);
    nonce[2] = (uint8_t)(epoch >> 8);
    nonce[3] = (uint8_t)epoch;
    put_u64be(nonce + 4, f->counter);
    /* Payload -> ct + tag (ct length == payload length under GCM). */
    rc = qc_aead_encrypt(key, 32, nonce, 12, p, QC_FRAME_HDR_LEN,
                         f->payload_len > 0 ? f->payload : NULL,
                         f->payload_len, p + 78,
                         p + 78 + f->payload_len);
    if (rc != QC_AEAD_OK) {
        return QC_FRAME_AUTH_FAIL;
    }
    return QC_FRAME_OK;
}

qc_frame_rc qc_frame_parse_header(const uint8_t *frame, size_t frame_len,
                                  qc_frame_parsed *out) {
    uint32_t plen;
    size_t want;

    if (frame == NULL || out == NULL) {
        return QC_FRAME_BAD_ARG;
    }
    if (frame_len < QC_FRAME_HDR_LEN + 4 + QC_FRAME_TAG_LEN) {
        return QC_FRAME_OVERSIZE;
    }
    if (!valid_class(frame[16]) || !valid_level(frame[17])) {
        return QC_FRAME_BAD_VALUE;
    }
    plen = ((uint32_t)frame[74] << 24) | ((uint32_t)frame[75] << 16) |
           ((uint32_t)frame[76] << 8) | (uint32_t)frame[77];
    if (plen > QC_FRAME_MAX_PAYLOAD) {
        return QC_FRAME_OVERSIZE;
    }
    want = QC_FRAME_HDR_LEN + 4 + plen + QC_FRAME_TAG_LEN;
    if (frame_len != want) {
        return QC_FRAME_OVERSIZE;
    }
    memcpy(out->identity, frame, 16);
    out->cls = frame[16];
    out->level = frame[17];
    out->counter = get_u64be(frame + 18);
    memcpy(out->last_root, frame + 26, 32);
    out->range_start = get_u64be(frame + 58);
    out->range_end = get_u64be(frame + 66);
    out->payload_len = plen;
    return QC_FRAME_OK;
}

qc_frame_rc qc_frame_open(const uint8_t *frame, size_t frame_len,
                          const uint8_t key[32], uint32_t epoch,
                          uint8_t *pt_out, size_t pt_cap,
                          qc_frame_parsed *out) {
    qc_frame_parsed h;
    uint8_t nonce[12];
    uint8_t tag[16];
    int rc;

    if (frame == NULL || key == NULL || out == NULL) {
        return QC_FRAME_BAD_ARG;
    }
    {
        qc_frame_rc prc = qc_frame_parse_header(frame, frame_len, &h);
        if (prc == QC_FRAME_BAD_VALUE) {
            return QC_FRAME_BAD_VALUE;
        }
        if (prc != QC_FRAME_OK) {
            return QC_FRAME_OVERSIZE;
        }
    }
    if (pt_cap < h.payload_len ||
        (h.payload_len > 0 && pt_out == NULL)) {
        return QC_FRAME_SMALL_BUF;
    }
    nonce[0] = (uint8_t)(epoch >> 24);
    nonce[1] = (uint8_t)(epoch >> 16);
    nonce[2] = (uint8_t)(epoch >> 8);
    nonce[3] = (uint8_t)epoch;
    put_u64be(nonce + 4, h.counter);
    memcpy(tag, frame + QC_FRAME_HDR_LEN + 4 + h.payload_len,
           QC_FRAME_TAG_LEN);
    rc = qc_aead_decrypt(key, 32, nonce, 12, frame, QC_FRAME_HDR_LEN,
                         frame + QC_FRAME_HDR_LEN + 4, h.payload_len,
                         tag, h.payload_len > 0 ? pt_out : NULL);
    if (rc != QC_AEAD_OK) {
        return QC_FRAME_AUTH_FAIL;
    }
    memcpy(out, &h, sizeof(h));
    return QC_FRAME_OK;
}
