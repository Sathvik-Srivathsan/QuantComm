/* qc_state.c — controller state vector x_t (B-30.1/.2/.4).
 * Pure sample/validate/flag logic; no sensors, no policy, no alloc.
 * Mask bits: pair per component, 00 ok / 01 stale / 10 invalid.
 */
#include "qc_state.h"

#include <float.h>
#include <string.h>

#define QC_STATE_MASK(comp, flag) \
    ((uint16_t)((uint16_t)(flag) << (2 * (comp))))

static void set_flag(qc_state *s, int comp, unsigned flag) {
    s->mask = (uint16_t)((s->mask & (uint16_t)~QC_STATE_MASK(comp, 3)) |
                         QC_STATE_MASK(comp, flag));
}

static void clear_invalid(qc_state *s, int comp) {
    unsigned cur =
        (unsigned)((s->mask >> (2 * comp)) & 3u);
    if (cur == QC_STATE_F_INVALID) {
        set_flag(s, comp, QC_STATE_F_OK);
    } else if (cur == QC_STATE_F_BOTH) {
        set_flag(s, comp, QC_STATE_F_STALE);
    }
}

void qc_state_init(qc_state *s) {
    int i;

    if (s == NULL) {
        return;
    }
    /* Zero state, then fail-safe boot: every component invalid until
     * its first good sample (R additionally spec-mandated). Zeroed
     * timestamps + the at!=0 monotonicity guard mean a first sample at
     * any now (incl. 0) is accepted; staleness uses caller delta_max. */
    memset(s, 0, sizeof(*s));
    for (i = 0; i < QC_STATE_NCOMP; i++) {
        set_flag(s, i, QC_STATE_F_INVALID);
    }
    s->init = 1;
}

qc_state_rc qc_state_sample_b(qc_state *s, float joules, uint8_t soc_pct,
                              uint64_t now) {
    if (s == NULL || !s->init) {
        return QC_STATE_BAD_ARG;
    }
    /* Audit hardening: finite-only (spec says >= 0; +Inf is spec-
     * literally in range but unrepresentable energy that would defeat
     * feasibility math — refused as sensor failure, flagged here). */
    if (!(joules >= 0.0f) || !(joules <= FLT_MAX) || soc_pct > 100) {
        set_flag(s, QC_STATE_COMP_B, QC_STATE_F_INVALID);
        return QC_STATE_INVALID;
    }
    /* Monotonicity against last ACCEPTED sample only (at!=0 guard:
     * never-sampled components accept any now). Regression refused. */
    if (now < s->b_at && s->b_at != 0) {
        return QC_STATE_NONMONOTONIC;
    }
    s->b_j = joules;
    s->b_soc = soc_pct;
    s->b_at = now;
    clear_invalid(s, QC_STATE_COMP_B);
    return QC_STATE_OK;
}

qc_state_rc qc_state_sample_r(qc_state *s, float risk, uint64_t now) {
    if (s == NULL || !s->init) {
        return QC_STATE_BAD_ARG;
    }
    if (!(risk >= 0.0f) || !(risk <= 1.0f)) {
        set_flag(s, QC_STATE_COMP_R, QC_STATE_F_INVALID);
        return QC_STATE_INVALID;
    }
    if (now < s->r_at && s->r_at != 0) {
        return QC_STATE_NONMONOTONIC;
    }
    s->r = risk;
    s->r_at = now;
    clear_invalid(s, QC_STATE_COMP_R);
    return QC_STATE_OK;
}

qc_state_rc qc_state_sample_s(qc_state *s, uint8_t cls, uint64_t now) {
    if (s == NULL || !s->init) {
        return QC_STATE_BAD_ARG;
    }
    if (cls > 2) {
        set_flag(s, QC_STATE_COMP_S, QC_STATE_F_INVALID);
        return QC_STATE_INVALID;
    }
    if (now < s->s_at && s->s_at != 0) {
        return QC_STATE_NONMONOTONIC;
    }
    s->s = cls;
    s->s_at = now;
    clear_invalid(s, QC_STATE_COMP_S);
    if (cls == 2) {
        s->s_immediate = 1;
        return QC_STATE_C2;
    }
    return QC_STATE_OK;
}

qc_state_rc qc_state_sample_c(qc_state *s, float load, uint64_t now) {
    if (s == NULL || !s->init) {
        return QC_STATE_BAD_ARG;
    }
    if (!(load >= 0.0f) || !(load <= 1.0f)) {
        set_flag(s, QC_STATE_COMP_C, QC_STATE_F_INVALID);
        return QC_STATE_INVALID;
    }
    if (now < s->c_at && s->c_at != 0) {
        return QC_STATE_NONMONOTONIC;
    }
    s->c = load;
    s->c_at = now;
    clear_invalid(s, QC_STATE_COMP_C);
    return QC_STATE_OK;
}

qc_state_rc qc_state_sample_m(qc_state *s, uint32_t free_bytes,
                              uint64_t now) {
    if (s == NULL || !s->init) {
        return QC_STATE_BAD_ARG;
    }
    if (now < s->m_at && s->m_at != 0) {
        return QC_STATE_NONMONOTONIC;
    }
    s->m = free_bytes;
    s->m_at = now;
    clear_invalid(s, QC_STATE_COMP_M);
    return QC_STATE_OK;
}

qc_state_rc qc_state_sample_l(qc_state *s, int16_t rssi_dbm,
                              uint16_t retries, uint64_t now) {
    if (s == NULL || !s->init) {
        return QC_STATE_BAD_ARG;
    }
    if (now < s->l_at && s->l_at != 0) {
        return QC_STATE_NONMONOTONIC;
    }
    s->l_rssi = rssi_dbm;
    s->l_retries = retries;
    s->l_at = now;
    clear_invalid(s, QC_STATE_COMP_L);
    return QC_STATE_OK;
}

qc_state_rc qc_state_sample_q(qc_state *s, float rate,
                              uint64_t counters_consumed, uint64_t now) {
    if (s == NULL || !s->init) {
        return QC_STATE_BAD_ARG;
    }
    /* Audit hardening: finite-only (same rationale as budget). */
    if (!(rate >= 0.0f) || !(rate <= FLT_MAX)) {
        set_flag(s, QC_STATE_COMP_Q, QC_STATE_F_INVALID);
        return QC_STATE_INVALID;
    }
    if (now < s->q_at && s->q_at != 0) {
        return QC_STATE_NONMONOTONIC;
    }
    s->q = rate;
    s->q_counters = counters_consumed;
    s->q_at = now;
    clear_invalid(s, QC_STATE_COMP_Q);
    return QC_STATE_OK;
}

qc_state_rc qc_state_snapshot_risk(qc_state *s, const uint32_t counts[6],
                                   uint64_t now) {
    int i;

    if (s == NULL || !s->init || counts == NULL) {
        return QC_STATE_BAD_ARG;
    }
    if (now < s->risk_at && s->risk_at != 0) {
        return QC_STATE_NONMONOTONIC;
    }
    for (i = 0; i < 6; i++) {
        s->risk[i] = counts[i];
    }
    s->risk_at = now;
    return QC_STATE_OK;
}

int qc_state_take_s_immediate(qc_state *s) {
    int v;

    if (s == NULL || !s->init) {
        return 0;
    }
    v = s->s_immediate != 0;
    s->s_immediate = 0;
    return v;
}

static uint64_t comp_at(const qc_state *s, int comp) {
    switch (comp) {
    case QC_STATE_COMP_B:
        return s->b_at;
    case QC_STATE_COMP_R:
        return s->r_at;
    case QC_STATE_COMP_S:
        return s->s_at;
    case QC_STATE_COMP_C:
        return s->c_at;
    case QC_STATE_COMP_M:
        return s->m_at;
    case QC_STATE_COMP_L:
        return s->l_at;
    default:
        return s->q_at;
    }
}

uint16_t qc_state_check(qc_state *s, uint64_t now, uint64_t delta_max,
                        uint32_t mem_min, uint64_t counters_now,
                        float q_eps) {
    int i;

    if (s == NULL || !s->init) {
        return 0;
    }
    for (i = 0; i < QC_STATE_NCOMP; i++) {
        unsigned cur = (unsigned)((s->mask >> (2 * i)) & 3u);
        uint64_t age = (now >= comp_at(s, i)) ? now - comp_at(s, i) : 0;
        /* Staleness accrues AND recovers with age (never touches
         * invalid — only good samples clear that): OK<->STALE on the
         * delta_max boundary; INVALID->BOTH on expiry. */
        if (age > delta_max) {
            if (cur == QC_STATE_F_OK) {
                set_flag(s, i, QC_STATE_F_STALE);
            } else if (cur == QC_STATE_F_INVALID) {
                set_flag(s, i, QC_STATE_F_BOTH);
            }
        } else if (cur == QC_STATE_F_STALE) {
            set_flag(s, i, QC_STATE_F_OK);
        }
    }
    /* M below crypto minimum: immediately invalid (no policy step on
     * unmeasurable memory). mem_min==0 disables. */
    if (mem_min != 0 && s->m < mem_min) {
        unsigned cur =
            (unsigned)((s->mask >> (2 * QC_STATE_COMP_M)) & 3u);
        set_flag(s, QC_STATE_COMP_M,
                 cur == QC_STATE_F_STALE ? QC_STATE_F_BOTH
                                         : QC_STATE_F_INVALID);
    }
    /* Q cross-sanity: near-zero rate while B-23 counters advance
     * flags sensor fault (independent sources). */
    if (s->q < q_eps && counters_now > s->q_counters) {
        unsigned cur =
            (unsigned)((s->mask >> (2 * QC_STATE_COMP_Q)) & 3u);
        set_flag(s, QC_STATE_COMP_Q,
                 cur == QC_STATE_F_STALE ? QC_STATE_F_BOTH
                                         : QC_STATE_F_INVALID);
    }
    return s->mask;
}
