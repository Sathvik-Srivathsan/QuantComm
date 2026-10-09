/* qc_manifest.c — policy manifest schema + verify + store (B-25.1/.2).
 * Pure byte logic + one ML-DSA verify; no heap, no clock (caller `now`).
 * All size arithmetic is overflow-safe by construction (single total
 * computed incrementally against QC_MFT_MAX_BODY with early rejects;
 * field counts bounded by remaining length before use).
 */
#include "qc_manifest.h"

#include <stddef.h>
#include <string.h>

static void put_u32be(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void put_u16be(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static uint32_t get_u32be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint16_t get_u16be(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static int valid_class(uint8_t c) {
    return c <= 2;
}

static int valid_wire_level(uint8_t l) {
    return l == 1 || l == 2 || l == 3;
}

/* qc_manifest_parse borrows qc_floor_entry overlay: two u8 fields need
 * alignment 1, so any address overlays safely — but member ORDER and
 * padding are ABI-defined. Verify (standard offsetof, no extensions)
 * before every overlay use (parse AND init paths). */
static int floor_layout_ok(void) {
    return sizeof(qc_floor_entry) == 2 &&
           offsetof(qc_floor_entry, cls) == 0 &&
           offsetof(qc_floor_entry, min_level) == 1;
}

/* Exact length or 0 (invalid/oversize). Shared by encode (pre-size) so
 * encode and parse agree on every boundary by construction. */
static size_t body_len_for(size_t n_floors, size_t n_profiles,
                           size_t key_len) {
    /* Fixed overhead: 4+2 + 2+4+4+2+2 = 20 B. */
    size_t total = 20;
    if (n_floors > (QC_MFT_MAX_BODY - total) / 2) {
        return 0;
    }
    total += 2 * n_floors;
    if (n_profiles > QC_MFT_MAX_BODY - total) {
        return 0;
    }
    total += n_profiles;
    if (key_len > QC_MFT_MAX_BODY - total) {
        return 0;
    }
    total += key_len;
    return total;
}

size_t qc_manifest_encode_len(const qc_manifest_fields *f) {
    size_t i;

    if (f == NULL) {
        return 0;
    }
    if ((f->n_floors > 0 && f->floors == NULL) ||
        (f->n_profiles > 0 && f->profiles == NULL) ||
        (f->next_key_len > 0 && f->next_key == NULL)) {
        return 0;
    }
    /* Canonical order + codepoints validated here (encode rejects what
     * parse would reject: same predicate, one place each). */
    for (i = 0; i < f->n_floors; i++) {
        if (!valid_class(f->floors[i].cls) ||
            !valid_wire_level(f->floors[i].min_level)) {
            return 0;
        }
        if (i > 0 && f->floors[i].cls <= f->floors[i - 1].cls) {
            return 0;
        }
    }
    return body_len_for(f->n_floors, f->n_profiles, f->next_key_len);
}

qc_mft_rc qc_manifest_encode(const qc_manifest_fields *f,
                             uint8_t *out, size_t out_len) {
    size_t need, o, i;

    if (f == NULL || out == NULL) {
        return QC_MFT_BAD_ARG;
    }
    need = qc_manifest_encode_len(f);
    if (need == 0 || out_len != need) {
        return QC_MFT_MALFORMED;
    }
    o = 0;
    put_u32be(out + o, f->version);
    o += 4;
    put_u16be(out + o, (uint16_t)f->n_floors);
    o += 2;
    for (i = 0; i < f->n_floors; i++) {
        out[o++] = f->floors[i].cls;
        out[o++] = f->floors[i].min_level;
    }
    put_u16be(out + o, (uint16_t)f->n_profiles);
    o += 2;
    for (i = 0; i < f->n_profiles; i++) {
        out[o++] = f->profiles[i];
    }
    put_u32be(out + o, f->hmax);
    o += 4;
    put_u32be(out + o, f->t_cool);
    o += 4;
    put_u16be(out + o, f->c2_threshold);
    o += 2;
    put_u16be(out + o, (uint16_t)f->next_key_len);
    o += 2;
    if (f->next_key_len > 0) {
        if (f->next_key == NULL) {
            return QC_MFT_MALFORMED;
        }
        memcpy(out + o, f->next_key, f->next_key_len);
        o += f->next_key_len;
    }
    return o == need ? QC_MFT_OK_APPLIED : QC_MFT_MALFORMED;
}

qc_mft_rc qc_manifest_parse(const uint8_t *body, size_t len,
                            qc_manifest_parsed *out) {
    size_t o, i, n_floors, n_profiles, key_len;

    if (body == NULL || out == NULL) {
        return QC_MFT_BAD_ARG;
    }
    /* Overlay safety independent of init (parse is standalone public):
     * same check as init performs, negligible cost. */
    if (!floor_layout_ok()) {
        return QC_MFT_MALFORMED;
    }
    /* Minimum viable body: 20 B fixed overhead, empty tables/key. */
    if (len < 20 || len > QC_MFT_MAX_BODY) {
        return QC_MFT_MALFORMED;
    }
    o = 0;
    out->version = get_u32be(body + o);
    o += 4;
    n_floors = get_u16be(body + o);
    o += 2;
    if (20 + 2 * n_floors > len) {
        return QC_MFT_MALFORMED;
    }
    out->floors = (const qc_floor_entry *)(body + o);
    out->n_floors = n_floors;
    for (i = 0; i < n_floors; i++) {
        uint8_t c = body[o + 2 * i], l = body[o + 2 * i + 1];
        if (!valid_class(c) || !valid_wire_level(l)) {
            return QC_MFT_MALFORMED;
        }
        if (i > 0 && c <= body[o + 2 * (i - 1)]) {
            return QC_MFT_MALFORMED;
        }
    }
    o += 2 * n_floors;
    n_profiles = get_u16be(body + o);
    o += 2;
    if (o + n_profiles + 4 + 4 + 2 + 2 > len) {
        return QC_MFT_MALFORMED;
    }
    out->profiles = body + o;
    out->n_profiles = n_profiles;
    o += n_profiles;
    out->hmax = get_u32be(body + o);
    o += 4;
    out->t_cool = get_u32be(body + o);
    o += 4;
    out->c2_threshold = get_u16be(body + o);
    o += 2;
    key_len = get_u16be(body + o);
    o += 2;
    if (o + key_len != len) {
        return QC_MFT_MALFORMED;
    }
    out->next_key = body + o;
    out->next_key_len = key_len;
    return QC_MFT_OK_APPLIED;
}

qc_mft_rc qc_manifest_init(qc_manifest_store *s, qc_dsa_level level,
                           const uint8_t *pk) {
    size_t pk_len;

    if (s == NULL || pk == NULL) {
        return QC_MFT_BAD_ARG;
    }
    if (!floor_layout_ok()) {
        return QC_MFT_MALFORMED;
    }
    pk_len = qc_dsa_pk_bytes(level);
    if (pk_len == 0) {
        return QC_MFT_BAD_ARG;
    }
    memset(s, 0, sizeof(*s));
    s->enrolled_level = level;
    memcpy(s->enrolled_pk, pk, pk_len);
    s->initialized = 1;
    return QC_MFT_OK_APPLIED;
}

/* Infer DSA level from public-key length (1312/1952/2592 -> 44/65/87).
 * Returns 0 if unrecognized (rotation refused). */
static qc_dsa_level key_level_from_len(size_t n) {
    if (n == 1312) {
        return QC_DSA_44;
    }
    if (n == 1952) {
        return QC_DSA_65;
    }
    if (n == 2592) {
        return QC_DSA_87;
    }
    return 0;
}

/* Sliding 6/hour window: allow iff fewer than 6 verifies in (now-3600,
 * now]. Timestamps pushed on every verify ATTEMPT reaching this point
 * (post version/rate gates... attempt counted when crypto runs). */
static int rate_allow(qc_manifest_store *s, uint64_t now) {
    size_t kept = 0, i;

    for (i = 0; i < s->n_times; i++) {
        if (s->verify_times[i] + QC_MFT_RATE_WINDOW_S > now &&
            s->verify_times[i] <= now) {
            s->verify_times[kept++] = s->verify_times[i];
        }
    }
    s->n_times = kept;
    if (kept >= QC_MFT_VERIFY_PER_HOUR) {
        return 0;
    }
    s->verify_times[kept++] = now;
    s->n_times = kept;
    return 1;
}

qc_mft_rc qc_manifest_verify_apply(qc_manifest_store *s,
                                   const uint8_t *body, size_t body_len,
                                   const uint8_t *sig, size_t sig_len,
                                   uint64_t now) {
    qc_manifest_parsed p;
    qc_dsa_level sig_level, next_level;
    size_t need_sig;
    int rc;

    if (s == NULL || !s->initialized || body == NULL || sig == NULL) {
        return QC_MFT_BAD_ARG;
    }
    /* (1) structural parse first (no crypto on malformed input). */
    if (qc_manifest_parse(body, body_len, &p) != QC_MFT_OK_APPLIED) {
        return QC_MFT_MALFORMED;
    }
    /* (2) strict-greater version pre-check: zero public-key work.
     * First manifest (none stored) always proceeds, including version 0. */
    if (s->has_manifest && p.version <= s->version) {
        return QC_MFT_STALE;
    }
    /* (3) rate cap before public-key work. */
    if (!rate_allow(s, now)) {
        return QC_MFT_RATE_LIMITED;
    }
    /* (4) ML-DSA verify under the enrolled key, empty ctx. */
    sig_level = s->enrolled_level;
    need_sig = qc_dsa_sig_bytes(sig_level);
    if (need_sig == 0 || sig_len != need_sig) {
        return QC_MFT_MALFORMED;
    }
    rc = qc_dsa_verify(sig_level, body, body_len, NULL, 0,
                       sig, s->enrolled_pk);
    if (rc != QC_DSA_OK) {
        return QC_MFT_BAD_SIG;
    }
    /* (5) apply: store body+version; rotate iff next key recognized. */
    if (p.next_key_len > 0) {
        next_level = key_level_from_len(p.next_key_len);
        if (next_level == 0 ||
            qc_dsa_pk_bytes(next_level) != p.next_key_len) {
            return QC_MFT_MALFORMED;
        }
        s->enrolled_level = next_level;
        memcpy(s->enrolled_pk, p.next_key, p.next_key_len);
    }
    if (body_len > sizeof(s->body)) {
        return QC_MFT_MALFORMED;
    }
    memcpy(s->body, body, body_len);
    s->body_len = body_len;
    s->version = p.version;
    s->has_manifest = 1;
    return QC_MFT_OK_APPLIED;
}
