/* qc_trace.c — trace/policy-log schema codec (B-30.3). Tooling side.
 * Fixed layouts, exact-or-tolerant parsing per the version gate.
 */
#include "qc_trace.h"

#include <string.h>

static void put_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void put_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void put_u64(uint8_t *p, uint64_t v) {
    int i;
    for (i = 0; i < 8; i++) {
        p[i] = (uint8_t)(v >> (8 * (7 - i)));
    }
}

static void put_f32(uint8_t *p, float v) {
    uint32_t u;
    memcpy(&u, &v, 4);
    put_u32(p, u);
}

static uint16_t get_u16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t get_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint64_t get_u64(const uint8_t *p) {
    uint64_t v = 0;
    int i;
    for (i = 0; i < 8; i++) {
        v = (v << 8) | p[i];
    }
    return v;
}

static float get_f32(const uint8_t *p) {
    uint32_t u = get_u32(p);
    float v;
    memcpy(&v, &u, 4);
    return v;
}

static uint16_t ver_now(void) {
    return (uint16_t)(((uint16_t)QC_TRACE_MAJOR << 8) | QC_TRACE_MINOR);
}

/* Returns 0 ok, else rc. Checks major, reports minor for tolerance. */
static qc_trace_rc ver_gate(const uint8_t *in, size_t len, size_t need,
                            uint8_t *minor_out) {
    uint16_t v;
    uint8_t major, minor;

    if (len < 2) {
        return QC_TRACE_MALFORMED;
    }
    v = get_u16(in);
    major = (uint8_t)(v >> 8);
    minor = (uint8_t)v;
    if (major != QC_TRACE_MAJOR) {
        return QC_TRACE_BAD_VERSION;
    }
    if (len < need) {
        return QC_TRACE_MALFORMED;
    }
    /* Same-minor trailing garbage is malformation; higher-minor tail
     * is forward-compat (ignored by all decoders below). */
    if (minor == QC_TRACE_MINOR && len != need) {
        return QC_TRACE_MALFORMED;
    }
    if (minor_out != NULL) {
        *minor_out = minor;
    }
    return QC_TRACE_OK;
}

qc_trace_rc qc_trace_vec_encode(const qc_state *s, uint64_t ts,
                                uint8_t *out, size_t cap) {
    if (s == NULL || !s->init || out == NULL || cap < QC_TRACE_VEC_LEN) {
        return QC_TRACE_BAD_ARG;
    }
    put_u16(out, ver_now());
    put_u64(out + 2, ts);
    put_f32(out + 10, s->b_j);
    out[14] = s->b_soc;
    put_f32(out + 15, s->r);
    out[19] = s->s;
    put_f32(out + 20, s->c);
    put_u32(out + 24, s->m);
    put_u16(out + 28, (uint16_t)s->l_rssi);
    put_u16(out + 30, s->l_retries);
    put_f32(out + 32, s->q);
    put_u16(out + 36, s->mask);
    return QC_TRACE_OK;
}

qc_trace_rc qc_trace_vec_decode(const uint8_t *in, size_t len,
                                qc_state *s, uint64_t *ts_out) {
    qc_trace_rc rc;

    if (in == NULL || s == NULL) {
        return QC_TRACE_BAD_ARG;
    }
    rc = ver_gate(in, len, QC_TRACE_VEC_LEN, NULL);
    if (rc != QC_TRACE_OK) {
        return rc;
    }
    uint64_t ts;

    memset(s, 0, sizeof(*s));
    ts = get_u64(in + 2);
    if (ts_out != NULL) {
        *ts_out = ts;
    }
    s->b_j = get_f32(in + 10);
    s->b_soc = in[14];
    s->r = get_f32(in + 15);
    s->s = in[19];
    s->c = get_f32(in + 20);
    s->m = get_u32(in + 24);
    s->l_rssi = (int16_t)get_u16(in + 28);
    s->l_retries = get_u16(in + 30);
    s->q = get_f32(in + 32);
    s->mask = get_u16(in + 36);
    s->b_at = s->r_at = s->s_at = s->c_at = s->m_at = s->l_at = s->q_at =
        ts;
    s->init = 1;
    return QC_TRACE_OK;
}

qc_trace_rc qc_trace_evt_encode(uint64_t ts, uint8_t type, uint64_t a,
                                uint64_t b, uint8_t *out, size_t cap) {
    if (out == NULL || cap < QC_TRACE_EVT_LEN || type > QC_TRACE_LINK) {
        return QC_TRACE_BAD_ARG;
    }
    put_u16(out, ver_now());
    put_u64(out + 2, ts);
    out[10] = type;
    put_u64(out + 11, a);
    put_u64(out + 19, b);
    return QC_TRACE_OK;
}

qc_trace_rc qc_trace_evt_decode(const uint8_t *in, size_t len,
                                uint64_t *ts_out, uint8_t *type_out,
                                uint64_t *a_out, uint64_t *b_out) {
    qc_trace_rc rc;

    if (in == NULL) {
        return QC_TRACE_BAD_ARG;
    }
    rc = ver_gate(in, len, QC_TRACE_EVT_LEN, NULL);
    if (rc != QC_TRACE_OK) {
        return rc;
    }
    /* Unknown types tolerated (forward-compat); encode restricts. */
    if (ts_out != NULL) {
        *ts_out = get_u64(in + 2);
    }
    if (type_out != NULL) {
        *type_out = in[10];
    }
    if (a_out != NULL) {
        *a_out = get_u64(in + 11);
    }
    if (b_out != NULL) {
        *b_out = get_u64(in + 19);
    }
    return QC_TRACE_OK;
}

qc_trace_rc qc_trace_pol_encode(const qc_state *s, uint64_t ts,
                                uint32_t action, float energy_j,
                                uint8_t *out, size_t cap) {
    qc_trace_rc rc;

    if (out == NULL || cap < QC_TRACE_POL_LEN) {
        return QC_TRACE_BAD_ARG;
    }
    rc = qc_trace_vec_encode(s, ts, out, QC_TRACE_VEC_LEN);
    if (rc != QC_TRACE_OK) {
        return rc;
    }
    put_u32(out + QC_TRACE_VEC_LEN, action);
    put_f32(out + QC_TRACE_VEC_LEN + 4, energy_j);
    return QC_TRACE_OK;
}

qc_trace_rc qc_trace_pol_decode(const uint8_t *in, size_t len,
                                qc_state *s, uint64_t *ts_out,
                                uint32_t *action_out, float *energy_out) {
    qc_trace_rc rc;

    if (in == NULL || s == NULL) {
        return QC_TRACE_BAD_ARG;
    }
    /* Audit fix: gate on the FULL policy length (gating the 38-byte
     * prefix here rejected the 46-byte record as "trailing garbage").
     * Same-minor exact, higher-minor tolerant, short always refused. */
    rc = ver_gate(in, len, QC_TRACE_POL_LEN, NULL);
    if (rc != QC_TRACE_OK) {
        return rc;
    }
    rc = qc_trace_vec_decode(in, QC_TRACE_VEC_LEN, s, ts_out);
    if (rc != QC_TRACE_OK) {
        return rc;
    }
    if (action_out != NULL) {
        *action_out = get_u32(in + QC_TRACE_VEC_LEN);
    }
    if (energy_out != NULL) {
        *energy_out = get_f32(in + QC_TRACE_VEC_LEN + 4);
    }
    return QC_TRACE_OK;
}
