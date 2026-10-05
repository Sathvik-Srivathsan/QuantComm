/* qc_codec.c — M1/M2 codecs: fixed-order, fixed-width, no prefixes. */
#include "qc_codec.h"

#include <string.h>

size_t qc_m1_len(size_t ek_len, size_t ct_len) {
    if (ek_len > QC_CODEC_MAX_FIELD || ct_len > QC_CODEC_MAX_FIELD) {
        return 0;
    }
    return 1 + QC_ID_LEN + 1 + ek_len + ct_len + QC_NONCE_LEN + QC_MAC_LEN;
}

size_t qc_m2_len(size_t ct_len) {
    if (ct_len > QC_CODEC_MAX_FIELD) {
        return 0;
    }
    return 1 + ct_len + QC_NS_LEN + QC_MAC_LEN;
}

qc_codec_rc qc_m1_encode(const qc_m1_fields *f, uint8_t *out, size_t out_len) {
    size_t o;

    if (f == NULL || out == NULL) {
        return QC_CODEC_BAD_LENGTH;
    }
    if (f->version != QC_M1_VERSION) {
        return QC_CODEC_BAD_VERSION;
    }
    if (f->ek == NULL || f->ct_s == NULL) {
        return QC_CODEC_BAD_LENGTH;
    }
    /* Field caps before any length arithmetic (same wraparound class as
     * parse; absurd size is a length problem -> OVERSIZE, like wire). */
    if (f->ek_len > QC_CODEC_MAX_FIELD || f->ct_len > QC_CODEC_MAX_FIELD) {
        return QC_CODEC_OVERSIZE;
    }
    if (out_len != qc_m1_len(f->ek_len, f->ct_len)) {
        return QC_CODEC_OVERSIZE;
    }
    o = 0;
    out[o++] = f->version;
    memcpy(out + o, f->identity, QC_ID_LEN);
    o += QC_ID_LEN;
    out[o++] = f->level;
    memcpy(out + o, f->ek, f->ek_len);
    o += f->ek_len;
    memcpy(out + o, f->ct_s, f->ct_len);
    o += f->ct_len;
    memcpy(out + o, f->nonce, QC_NONCE_LEN);
    o += QC_NONCE_LEN;
    memcpy(out + o, f->hmac, QC_MAC_LEN);
    return QC_CODEC_OK;
}

qc_codec_rc qc_m2_encode(const qc_m2_fields *f, uint8_t *out, size_t out_len) {
    size_t o;

    if (f == NULL || out == NULL) {
        return QC_CODEC_BAD_LENGTH;
    }
    if (f->version != QC_M1_VERSION) {
        return QC_CODEC_BAD_VERSION;
    }
    if (f->ct_w == NULL) {
        return QC_CODEC_BAD_LENGTH;
    }
    if (f->ct_len > QC_CODEC_MAX_FIELD) {
        return QC_CODEC_OVERSIZE;
    }
    if (out_len != qc_m2_len(f->ct_len)) {
        return QC_CODEC_OVERSIZE;
    }
    o = 0;
    out[o++] = f->version;
    memcpy(out + o, f->ct_w, f->ct_len);
    o += f->ct_len;
    memcpy(out + o, f->nonce_s, QC_NS_LEN);
    o += QC_NS_LEN;
    memcpy(out + o, f->confirm, QC_MAC_LEN);
    return QC_CODEC_OK;
}

qc_codec_rc qc_m1_parse(const uint8_t *buf, size_t len, size_t ek_len,
                        size_t ct_len, qc_m1_fields *f) {
    size_t want, o;

    if (buf == NULL || f == NULL) {
        return QC_CODEC_BAD_LENGTH;
    }
    if (ek_len > QC_CODEC_MAX_FIELD || ct_len > QC_CODEC_MAX_FIELD) {
        return QC_CODEC_OVERSIZE;
    }
    want = qc_m1_len(ek_len, ct_len);
    if (len != want) {
        return QC_CODEC_OVERSIZE;
    }
    o = 0;
    if (buf[o] != QC_M1_VERSION) {
        return QC_CODEC_BAD_VERSION;
    }
    f->version = buf[o++];
    memcpy(f->identity, buf + o, QC_ID_LEN);
    o += QC_ID_LEN;
    f->level = buf[o++];
    f->ek = buf + o;
    f->ek_len = ek_len;
    o += ek_len;
    f->ct_s = buf + o;
    f->ct_len = ct_len;
    o += ct_len;
    memcpy(f->nonce, buf + o, QC_NONCE_LEN);
    o += QC_NONCE_LEN;
    memcpy(f->hmac, buf + o, QC_MAC_LEN);
    return QC_CODEC_OK;
}

qc_codec_rc qc_m2_parse(const uint8_t *buf, size_t len, size_t ct_len,
                        uint8_t m1_version, qc_m2_fields *f) {
    size_t want, o;

    if (buf == NULL || f == NULL) {
        return QC_CODEC_BAD_LENGTH;
    }
    if (ct_len > QC_CODEC_MAX_FIELD) {
        return QC_CODEC_OVERSIZE;
    }
    want = qc_m2_len(ct_len);
    if (len != want) {
        return QC_CODEC_OVERSIZE;
    }
    o = 0;
    if (buf[o] != QC_M1_VERSION) {
        return QC_CODEC_BAD_VERSION;
    }
    if (buf[o] != m1_version) {
        return QC_CODEC_VERSION_MISMATCH;
    }
    f->version = buf[o++];
    f->ct_w = buf + o;
    f->ct_len = ct_len;
    o += ct_len;
    memcpy(f->nonce_s, buf + o, QC_NS_LEN);
    o += QC_NS_LEN;
    memcpy(f->confirm, buf + o, QC_MAC_LEN);
    return QC_CODEC_OK;
}

size_t qc_transcript_len(size_t m1_len, size_t m2_len) {
    /* M2-body = M2 minus trailing 32-B confirmation MAC. */
    if (m2_len < QC_MAC_LEN) {
        return 0;
    }
    if (m1_len > QC_CODEC_MAX_MSG || m2_len > QC_CODEC_MAX_MSG) {
        return 0;
    }
    return m1_len + (m2_len - QC_MAC_LEN);
}

qc_codec_rc qc_transcript_build(const uint8_t *m1, size_t m1_len,
                                const uint8_t *m2, size_t m2_len,
                                uint8_t *out, size_t out_len) {
    if (m1 == NULL || m2 == NULL || out == NULL) {
        return QC_CODEC_BAD_LENGTH;
    }
    if (m2_len < QC_MAC_LEN) {
        return QC_CODEC_OVERSIZE;
    }
    /* Exact destination, subtraction form (no addition to wrap):
     * out_len must equal m1_len + (m2_len - 32). */
    if (out_len < m2_len - QC_MAC_LEN ||
        out_len - (m2_len - QC_MAC_LEN) != m1_len) {
        return QC_CODEC_OVERSIZE;
    }
    memcpy(out, m1, m1_len);
    memcpy(out + m1_len, m2, m2_len - QC_MAC_LEN);
    return QC_CODEC_OK;
}
