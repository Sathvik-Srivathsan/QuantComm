/* qc_gov.c — token-bucket governor + shed + restore (B-35.1-.4).
 * Bucket in float32 (normative); shed/restore pure parameter stepping;
 * persist MAC'd. No heap, no threads, caller clocks.
 */
#include "qc_gov.h"

#include <string.h>

#include "qc_hmac.h"

qc_gov_rc qc_gov_init(qc_gov *g, float tau_max, double rho,
                      float restore_frac, uint16_t restore_dwell) {
    if (g == NULL) {
        return QC_GOV_BAD_ARG;
    }
    /* Finite positive max; finite non-negative rate; finite frac in
     * [0,1] (frac > 1 = never-restore degenerate, allowed as operator
     * intent — documented, not refused). NaN-safe forms throughout. */
    if (!(tau_max > 0.0f) || !(rho >= 0.0) || !(restore_frac >= 0.0f)) {
        return QC_GOV_BAD_ARG;
    }
    memset(g, 0, sizeof(*g));
    g->tau = tau_max;
    g->tau_max = tau_max;
    g->rho = rho;
    g->restore_frac = restore_frac;
    g->restore_dwell = restore_dwell;
    g->init = 1;
    return 0;
}

float qc_gov_tau(const qc_gov *g) {
    if (g == NULL || !g->init) {
        return 0.0f; /* unknown budget reads empty (shed-safe). */
    }
    return g->tau;
}

qc_gov_rc qc_gov_charge(qc_gov *g, double ehat_sec, double delta_t_s) {
    double t;

    if (g == NULL || !g->init) {
        return QC_GOV_BAD_ARG;
    }
    if (!(delta_t_s >= 0.0)) {
        return QC_GOV_BAD_ARG; /* clock regression: freeze, never corrupt. */
    }
    /* Equation-literal (see header phase-gate note): NaN anywhere pins
     * to max debt (fail-safe + self-healing via later refills). */
    t = (double)g->tau + g->rho * delta_t_s - ehat_sec;
    if (!(t >= -(double)g->tau_max)) {
        t = -(double)g->tau_max;
    }
    if (t > (double)g->tau_max) {
        t = (double)g->tau_max;
    }
    g->tau = (float)t;
    g->c.charges++;
    return 0;
}

static int finite_nonneg(double v) {
    if (!(v >= 0.0)) {
        return 0;
    }
    {
        double d = v - v;
        if (!(d == 0.0)) {
            return 0;
        }
    }
    return 1;
}

qc_gov_rc qc_gov_shed(qc_gov *g, const qc_shed_in *in,
                      const qc_shed_floors *f, qc_shed_out *out,
                      uint64_t now) {
    int moved = 0;

    if (g == NULL || !g->init || in == NULL || f == NULL || out == NULL) {
        return QC_GOV_BAD_ARG;
    }
    if (!finite_nonneg(in->c0_rate) || !(f->c0_min > 0.0) ||
        f->ta_cap_s <= 0) {
        return QC_GOV_BAD_ARG;
    }
    if (in->action.profile < 1 || in->action.profile > 3) {
        return QC_GOV_BAD_ARG;
    }
    out->a_shed = in->action;
    out->c0_directive = in->c0_rate;
    out->exhausted = 0;
    /* Fixed order: C0 rate, then Nb depth, then Ta cadence. */
    if (in->c0_rate > f->c0_min) {
        double half = in->c0_rate / 2.0;
        out->c0_directive = (half < f->c0_min) ? f->c0_min : half;
        moved = 1;
    } else if (in->action.nb > 1) {
        uint8_t half = (uint8_t)(in->action.nb / 2u);
        out->a_shed.nb = half < 1 ? 1 : half;
        moved = 1;
    } else if (in->action.ta_s > 0 && in->action.ta_s < f->ta_cap_s) {
        /* Timed Ta below cap: double toward it (overflow-guarded);
         * sentinel Ta (event/msg/none paths) counts as floored. */
        int32_t t = in->action.ta_s;
        out->a_shed.ta_s =
            (t > f->ta_cap_s / 2) ? f->ta_cap_s : (int32_t)(t * 2);
        moved = 1;
    }
    if (!moved) {
        out->exhausted = 1;
        g->c.exhaustions++;
    }
    g->last_shed = now;
    g->has_shed = 1;
    g->c.sheds++;
    return 0;
}

int qc_gov_restore_ready(const qc_gov *g, uint64_t now, uint64_t delta_s) {
    uint64_t elapsed;

    if (g == NULL || !g->init) {
        return -1;
    }
    if (!g->has_shed) {
        return 0; /* nothing stepped down: restore is a no-op. */
    }
    if ((double)g->tau < (double)g->restore_frac * (double)g->tau_max) {
        return 0;
    }
    if (now < g->last_shed) {
        return 0; /* regression fails toward held-shed (safe). */
    }
    elapsed = now - g->last_shed;
    if (delta_s == 0) {
        return 1; /* degenerate zero window: dwell vacuous. */
    }
    /* Division form (never multiplies: dwell*delta could overflow). */
    return (elapsed / delta_s >= g->restore_dwell) ? 1 : 0;
}

int qc_gov_restore_step(const qc_shed_in *cur, const qc_shed_in *des,
                        qc_shed_in *out) {
    if (cur == NULL || des == NULL || out == NULL) {
        return -1;
    }
    *out = *cur;
    /* Reverse order: attestation, then C1 depth, then C0 rate. */
    if (cur->action.ta_s != des->action.ta_s) {
        if (cur->action.ta_s < 0 || des->action.ta_s < 0) {
            /* Sentinel transitions are discrete: adopt directly. */
            out->action.ta_s = des->action.ta_s;
        } else if (cur->action.ta_s > des->action.ta_s) {
            int32_t half = cur->action.ta_s / 2;
            out->action.ta_s =
                (half < des->action.ta_s) ? des->action.ta_s : half;
        } else {
            /* Doubling guard BEFORE multiplying (post-check would
             * already be UB on int32 overflow — audit-caught shape). */
            int32_t dbl = (cur->action.ta_s > INT32_MAX / 2)
                              ? des->action.ta_s
                              : (int32_t)(cur->action.ta_s * 2);
            out->action.ta_s =
                (dbl > des->action.ta_s) ? des->action.ta_s : dbl;
        }
        return QC_RESTORE_TA;
    }
    if (cur->action.nb != des->action.nb) {
        uint8_t dbl;
        if (cur->action.nb < des->action.nb) {
            dbl = (uint8_t)(cur->action.nb * 2u);
            out->action.nb =
                (dbl > des->action.nb) ? des->action.nb : dbl;
        } else {
            out->action.nb = (uint8_t)(cur->action.nb / 2u);
            if (out->action.nb < des->action.nb) {
                out->action.nb = des->action.nb;
            }
        }
        return QC_RESTORE_NB;
    }
    if (cur->c0_rate != des->c0_rate) {
        double dbl;
        if (cur->c0_rate < des->c0_rate) {
            dbl = cur->c0_rate * 2.0;
            out->c0_rate =
                (dbl > des->c0_rate) ? des->c0_rate : dbl;
        } else {
            out->c0_rate = cur->c0_rate / 2.0;
            if (out->c0_rate < des->c0_rate) {
                out->c0_rate = des->c0_rate;
            }
        }
        return QC_RESTORE_C0;
    }
    return QC_RESTORE_DONE;
}

void qc_gov_counts(const qc_gov *g, qc_gov_counters *out) {
    if (g == NULL || out == NULL) {
        return;
    }
    *out = g->c;
}

/* Export layout: magic "QCG1" || ver u8=1 || tau f32 || tau_max f32 ||
 * rho f64 || restore_frac f32 || restore_dwell u16 || last_shed u64 ||
 * MAC-32. Total 4+1+4+4+8+4+2+8 = 35 + 32 = 67. */
#define QC_GOV_EXP_LEN 67

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

static void put_f64(uint8_t *p, double v) {
    uint64_t u;
    memcpy(&u, &v, 8);
    put_u64(p, u);
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

static double get_f64(const uint8_t *p) {
    uint64_t u = get_u64(p);
    double v;
    memcpy(&v, &u, 8);
    return v;
}

qc_gov_rc qc_gov_export(const qc_gov *g, const uint8_t key[32],
                        uint8_t *out, size_t cap, size_t *len_out) {
    static uint8_t img[QC_GOV_EXP_LEN];
    uint8_t mac[32];
    size_t n = 0;

    if (g == NULL || !g->init || key == NULL || out == NULL ||
        len_out == NULL || cap < QC_GOV_EXP_LEN) {
        return QC_GOV_BAD_ARG;
    }
    img[0] = 'Q';
    img[1] = 'C';
    img[2] = 'G';
    img[3] = '1';
    img[4] = 1;
    n = 5;
    put_f32(img + n, g->tau);
    n += 4;
    put_f32(img + n, g->tau_max);
    n += 4;
    put_f64(img + n, g->rho);
    n += 8;
    put_f32(img + n, g->restore_frac);
    n += 4;
    put_u16(img + n, g->restore_dwell);
    n += 2;
    put_u64(img + n, g->last_shed);
    n += 8;
    /* n == 35 here (audit: 5+4+4+8+4+2+8). */
    qc_hmac_sha256(key, 32, img, n, mac);
    memcpy(img + n, mac, 32);
    memset(mac, 0, sizeof(mac));
    n += 32;
    memcpy(out, img, n);
    memset(img, 0, sizeof(img));
    *len_out = n;
    return QC_GOV_OK;
}

qc_gov_rc qc_gov_import(qc_gov *g, const uint8_t key[32],
                        const uint8_t *in, size_t len) {
    uint8_t mac[32];
    size_t n;
    int i;

    if (g == NULL || key == NULL || in == NULL) {
        return QC_GOV_BAD_ARG;
    }
    if (len != QC_GOV_EXP_LEN || in[0] != 'Q' || in[1] != 'C' ||
        in[2] != 'G' || in[3] != '1' || in[4] != 1) {
        return (len != QC_GOV_EXP_LEN) ? QC_GOV_BAD_ARG
                                       : QC_GOV_BAD_VERSION;
    }
    n = len - 32;
    qc_hmac_sha256(key, 32, in, n, mac);
    {
        uint8_t diff = 0;
        for (i = 0; i < 32; i++) {
            diff |= (uint8_t)(mac[i] ^ in[n + i]);
        }
        memset(mac, 0, sizeof(mac));
        if (diff != 0) {
            return QC_GOV_BAD_MAC;
        }
    }
    /* Config restores verbatim WITH state (all fields MAC-covered):
     * cross-firmware import carries old config — operator error, same
     * class as risk/store (documented, not separately detected). */
    /* Audit fix: field order must mirror export (tau@5, max@9) — the
     * first cut had them swapped, restoring max into tau (caught by
     * the persist roundtrip: 60 vs 100). */
    memset(g, 0, sizeof(*g));
    g->tau = get_f32(in + 5);
    g->tau_max = get_f32(in + 9);
    g->rho = get_f64(in + 13);
    g->restore_frac = get_f32(in + 21);
    g->restore_dwell = get_u16(in + 25);
    g->last_shed = get_u64(in + 27);
    g->has_shed = 1; /* conservative: assume shed history exists. */
    g->init = 1;
    return QC_GOV_OK;
}
