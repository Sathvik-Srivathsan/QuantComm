/* qc_floor.c — floor engine + feasibility solver (B-31.1-.5).
 * Pure functions over caller values; no sensors, no policy memory, no
 * alloc. Compiled tables are provisional PAPER-PARAM (labeled).
 */
#include "qc_floor.h"

#include "qc_batch.h" /* Nb cross-unit bound (owned by B-24.2). */

void qc_floor_cfg_default(qc_floor_cfg *c) {
    if (c == NULL) {
        return;
    }
    c->lmax_s[0] = QC_FLOOR_LMAX_C0_DFLT;
    c->lmax_s[1] = QC_FLOOR_LMAX_C1_DFLT;
    c->lmax_s[2] = QC_FLOOR_LMAX_C2_DFLT;
    c->nb_max = QC_FLOOR_NB_MAX_DFLT;
}

static uint32_t tpq_cap(uint8_t s_eff) {
    if (s_eff == 2) {
        return QC_FLOOR_TPQ_C2;
    }
    if (s_eff == 1) {
        return QC_FLOOR_TPQ_C1;
    }
    return QC_FLOOR_TPQ_C0;
}

/* Cadence rank (higher = more stringent). Timed buckets by interval. */
static int ta_rank(int32_t ta) {
    if (ta == QC_TA_NONE) {
        return 0;
    }
    if (ta == QC_TA_EVENT) {
        return 4;
    }
    if (ta == QC_TA_MSG) {
        return 5;
    }
    if (ta < 0) {
        return -1; /* unknown sentinel: fails closed. */
    }
    if (ta > 600) {
        return 1;
    }
    if (ta > 60) {
        return 2;
    }
    return 3;
}

static int ta_floor_rank(uint8_t s_eff) {
    if (s_eff == 2) {
        return 4;
    }
    if (s_eff == 1) {
        return 2;
    }
    return 0;
}

qc_floor_rc qc_floor_select(const qc_state *s, int r_high,
                            qc_floor_basis *out) {
    int i;

    if (s == NULL || !s->init || out == NULL) {
        return QC_FLOOR_BAD_ARG;
    }
    /* M-component flag (pair 4, any of 01/10/11) wins over everything. */
    if (((s->mask >> (2 * QC_STATE_COMP_M)) & 3u) != 0) {
        return QC_FLOOR_HOLD;
    }
    for (i = 0; i < QC_STATE_NCOMP; i++) {
        if (i != QC_STATE_COMP_M &&
            ((s->mask >> (2 * i)) & 3u) != 0) {
            out->s_eff = 2;
            out->r_high = 1;
            return QC_FLOOR_OK;
        }
    }
    /* Clean vector: measured S stepped by the MACHINE band (defensive
     * C2/high if S escaped the sampler — unreachable, guarded). */
    if (s->s > 2) {
        out->s_eff = 2;
        out->r_high = 1;
        return QC_FLOOR_OK;
    }
    if (r_high) {
        out->s_eff = s->s == 2 ? 2 : (uint8_t)(s->s + 1);
        out->r_high = 1;
    } else {
        out->s_eff = s->s;
        out->r_high = 0;
    }
    return QC_FLOOR_OK;
}

int qc_floor_c1(uint8_t profile, const qc_floor_table *t, uint8_t s_eff) {
    uint8_t fl;

    if (t == NULL || profile < 1 || profile > 3 || s_eff > 2) {
        return 0;
    }
    if (!t->has[s_eff]) {
        return 0; /* missing row fails closed (never guess floors). */
    }
    fl = t->min_level[s_eff];
    if (fl < 1 || fl > 3) {
        return 0; /* malformed row fails closed (parse guards first). */
    }
    return profile >= fl;
}

int qc_floor_c2(uint32_t tpq_s, uint8_t s_eff) {
    if (s_eff > 2) {
        return 0;
    }
    return tpq_s <= tpq_cap(s_eff) && tpq_s > 0;
}

int qc_floor_c3(int32_t ta_s, uint8_t s_eff) {
    int r;

    if (s_eff > 2) {
        return 0;
    }
    /* C0 none carve-out (sole class allowed none). */
    if (ta_s == QC_TA_NONE) {
        return s_eff == 0;
    }
    /* Zero/unknown sentinels fail closed — but AFTER the known negative
     * sentinels (EVENT/MSG): audit fix, the first cut rejected them too
     * (caught by test_c3 + solver count halving to 96). */
    if (ta_s <= 0 && ta_s != QC_TA_EVENT && ta_s != QC_TA_MSG) {
        return 0;
    }
    r = ta_rank(ta_s);
    if (r < 0) {
        return 0;
    }
    return r >= ta_floor_rank(s_eff);
}

int qc_floor_c4(const qc_action *a, const qc_res_tables *rt,
                uint32_t m_free, uint32_t *ram_out) {
    uint64_t ram;

    if (a == NULL || rt == NULL || a->profile < 1 || a->profile > 3) {
        return 0;
    }
    ram = (uint64_t)rt->base_ram +
          (uint64_t)rt->stack_ram[a->profile - 1] +
          (uint64_t)rt->ram_per_byte * (uint64_t)rt->msg_bytes *
              (uint64_t)a->nb;
    if (ram_out != NULL) {
        *ram_out = ram > 0xFFFFFFFFu ? 0xFFFFFFFFu : (uint32_t)ram;
    }
    return ram <= (uint64_t)m_free;
}

int qc_floor_c5(const qc_action *a, const qc_res_tables *rt,
                const qc_floor_cfg *c, uint8_t s_eff,
                uint32_t *lat_out_ms) {
    uint64_t lat, lim;

    if (a == NULL || rt == NULL || c == NULL || s_eff > 2) {
        return 0;
    }
    lat = (uint64_t)rt->lat_base_ms +
          (uint64_t)rt->lat_per_msg_ms * (uint64_t)a->nb;
    lim = (uint64_t)c->lmax_s[s_eff] * 1000u;
    if (lat_out_ms != NULL) {
        *lat_out_ms = lat > 0xFFFFFFFFu ? 0xFFFFFFFFu : (uint32_t)lat;
    }
    return lat <= lim;
}

size_t qc_floor_feasible(const uint8_t admitted[3],
                         const qc_floor_table *t, uint8_t s_eff,
                         const qc_res_tables *rt, const qc_floor_cfg *c,
                         uint32_t m_free, qc_feas_cb cb, void *ctx) {
    static const int32_t TAS[5] = { QC_TA_NONE, 600, 60, QC_TA_EVENT,
                                    QC_TA_MSG };
    static const uint8_t NBS[4] = { 1, 2, 4, 8 };
    uint32_t tpq_opts[3];
    size_t n = 0;
    int pi, ti, ri, ai, ni;

    if (admitted == NULL || t == NULL || rt == NULL || c == NULL ||
        cb == NULL || s_eff > 2 || c->nb_max == 0 ||
        c->nb_max > QC_BATCH_MAX_READINGS) {
        return 0;
    }
    tpq_opts[0] = tpq_cap(s_eff);
    tpq_opts[1] = tpq_cap(s_eff) / 2;
    tpq_opts[2] = tpq_cap(s_eff) / 4;
    for (pi = 0; pi < 3; pi++) {
        if (!admitted[pi]) {
            continue;
        }
        for (ti = 0; ti < 3; ti++) {
            uint32_t tpq = tpq_opts[ti];
            uint32_t tr_opts[2];
            if (tpq == 0 || !qc_floor_c2(tpq, s_eff)) {
                continue;
            }
            tr_opts[0] = tpq;
            tr_opts[1] = tpq / 2;
            for (ri = 0; ri < 2; ri++) {
                uint32_t tr = tr_opts[ri];
                if (tr == 0 || tr > tpq) {
                    continue; /* Tr<=Tpq prune (structural). */
                }
                for (ai = 0; ai < 5; ai++) {
                    if (!qc_floor_c3(TAS[ai], s_eff)) {
                        continue;
                    }
                    for (ni = 0; ni < 4; ni++) {
                        qc_action a;
                        if (NBS[ni] > c->nb_max ||
                            NBS[ni] > QC_BATCH_MAX_READINGS) {
                            continue;
                        }
                        a.profile = (uint8_t)(pi + 1);
                        a.tpq_s = tpq;
                        a.tr_s = tr;
                        a.ta_s = TAS[ai];
                        a.nb = NBS[ni];
                        if (!qc_floor_c1(a.profile, t, s_eff)) {
                            continue;
                        }
                        if (!qc_floor_c4(&a, rt, m_free, NULL) ||
                            !qc_floor_c5(&a, rt, c, s_eff, NULL)) {
                            continue;
                        }
                        cb(&a, ctx);
                        n++;
                    }
                }
            }
        }
    }
    return n;
}
