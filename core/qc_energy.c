/* qc_energy.c — energy model Eq.(1) + tables + calibration (B-33).
 * Pure arithmetic over caller values; doubles; no alloc, no threads.
 * Includes qc_floor.h for the res_tables converter (B-31 consumes).
 */
#include "qc_energy.h"

#include <string.h>

#include "qc_batch.h" /* QC_TA_* sentinels (E5 set, owned by B-24.2). */
#include "qc_floor.h" /* res_tables converter target. */

/* FIPS 203 sizes (|ek| + 2|ct| per level). Cross-checked against
 * qc_kem_pk_bytes/ct_bytes in tests (never silently redefined). */
static const uint32_t KEM_SIZES[3][2] = {
    { 800, 768 },    /* 512: 800 + 2*768 = 2336. */
    { 1184, 1088 },  /* 768: 1184 + 2*1088 = 3360. */
    { 1568, 1568 }   /* 1024: 1568 + 2*1568 = 4704. */
};

void qc_energy_priors(qc_e_coeff *c) {
    int l, o, s;

    if (c == NULL) {
        return;
    }
    /* KEM base 3 mJ within 1-5 mJ; spec multipliers x1.6/x2.4. */
    for (l = 0; l < 3; l++) {
        double m = l == 0 ? 1.0 : (l == 1 ? 1.6 : 2.4);
        for (o = 0; o < 3; o++) {
            c->e_kem[l][o] = 3e-3 * m;
        }
    }
    /* DSA-87 sign 50 mJ within 26-80 mJ; spec x0.45/x0.7. Verify at
     * 0.15x sign (order-of-magnitude seed pending E1). */
    c->e_dsa_sign[2] = 50e-3;
    c->e_dsa_sign[0] = 50e-3 * 0.45;
    c->e_dsa_sign[1] = 50e-3 * 0.7;
    for (l = 0; l < 3; l++) {
        c->e_dsa_verify[l] = c->e_dsa_sign[l] * 0.15;
    }
    c->e_aes_b = 1e-6;      /* placeholder pending E1. */
    c->e_hkdf_ext = 100e-6; /* ~128 B fixed work at SHA rate. */
    c->e_hkdf_exp = 100e-6;
    c->e_sha_b = 1e-6;      /* placeholder pending E1. */
    c->eB = 6e-6;           /* within 2-20 uJ/B. */
    c->e_ev = 100e-6;       /* placeholder pending E3. */
    /* Ebase states (deployment-wild placeholders pending E2). */
    c->ebase_jps[QC_EBASE_OFF] = 0.005;
    c->ebase_jps[QC_EBASE_ADV] = 0.02;
    c->ebase_jps[QC_EBASE_CONN] = 0.05;
    c->ebase_jps[QC_EBASE_SLEEP] = 0.0005;
    c->assumed = 0;
    for (s = 0; s < QC_ASSUMED_NFIELDS; s++) {
        c->assumed |= (uint32_t)(1u << s);
    }
}

static int nonneg_finite(double v) {
    /* Rejects negatives, NaN, and +Inf (all fail the bound test or the
     * finite test; -0.0 passes as zero — physically identical). */
    if (!(v >= 0.0)) {
        return 0;
    }
    /* Finite check without math.h: v - v is 0 for finite, NaN for Inf
     * (NaN already excluded above; Inf - Inf = NaN -> excluded here). */
    {
        double d = v - v;
        if (!(d == 0.0)) {
            return 0;
        }
    }
    return 1;
}

int qc_energy_calibrate(qc_e_coeff *c, int field, int idx, int sub,
                        double value) {
    if (c == NULL || !nonneg_finite(value)) {
        return -1;
    }
    switch (field) {
    case QC_ASSUMED_EB:
        c->eB = value;
        break;
    case QC_ASSUMED_EV:
        c->e_ev = value;
        break;
    case QC_ASSUMED_AES:
        c->e_aes_b = value;
        break;
    case QC_ASSUMED_HKDF:
        /* HKDF covers ext+expand together (single E1 record). */
        c->e_hkdf_ext = value;
        c->e_hkdf_exp = value;
        break;
    case QC_ASSUMED_SHA:
        c->e_sha_b = value;
        break;
    case QC_EFIELD_KEM:
        if (idx < 0 || idx > 2 || sub < 0 || sub > 2) {
            return -1;
        }
        c->e_kem[idx][sub] = value;
        field = QC_ASSUMED_KEM512 + idx;
        break;
    case QC_EFIELD_DSA_SIGN:
        if (idx < 0 || idx > 2) {
            return -1;
        }
        c->e_dsa_sign[idx] = value;
        field = QC_ASSUMED_DSA44 + idx;
        break;
    case QC_EFIELD_DSA_VERIFY:
        if (idx < 0 || idx > 2) {
            return -1;
        }
        c->e_dsa_verify[idx] = value;
        field = QC_ASSUMED_DSA44 + idx;
        break;
    case QC_EFIELD_EBASE:
        if (idx < 0 || idx > 3) {
            return -1;
        }
        c->ebase_jps[idx] = value;
        field = QC_ASSUMED_EBASE;
        break;
    default:
        return -1;
    }
    /* Clear the ASSUMED bit (DSA families share one bit per level —
     * sign and verify at the same level clear together: E1 records
     * arrive per level in practice; documented simplification). */
    if (field >= 0 && field < 32) {
        c->assumed &= (uint32_t) ~(1u << field);
    }
    return 0;
}

void qc_energy_invalidate_all(qc_e_coeff *c) {
    int s;

    if (c == NULL) {
        return;
    }
    for (s = 0; s < QC_ASSUMED_NFIELDS; s++) {
        c->assumed |= (uint32_t)(1u << s);
    }
}

void qc_derive_counts(const qc_workload *w, qc_e_counts *n) {
    double rekeys_h, expands_h, signs_h;
    int li;

    if (w == NULL || n == NULL) {
        return;
    }
    memset(n, 0, sizeof(*n));
    li = w->profile - 1;
    if (li < 0 || li > 2) {
        return; /* zeroed counts (caller bug surfaces as zero energy). */
    }
    /* AEAD bytes = rate x size x (1 + resend). */
    n->aes_enc_b = w->msg_per_h * w->msg_bytes * (1.0 + w->resend);
    n->aes_dec_b = 0.0; /* device-side decrypts counted by the caller. */
    /* Ratchet expands at 1/Tr (Tr == 0 disables: no ratchet traffic). */
    expands_h = (w->tr_s == 0) ? 0.0 : 3600.0 / (double)w->tr_s;
    n->hkdf_exp = expands_h;
    n->hkdf_ext = 0.0; /* extracts happen at handshake (E_ctrl). */
    /* DSA signs: 1/Ta (+ C2 evidence rate); EVENT/MSG need the trace
     * estimate (no closed form — default 0 documents the gap). */
    if (w->ta_s == QC_TA_NONE) {
        signs_h = 0.0;
    } else if (w->ta_s == QC_TA_EVENT || w->ta_s == QC_TA_MSG) {
        signs_h = w->ta_event_per_h;
    } else if (w->ta_s <= 0) {
        signs_h = 0.0;
    } else {
        signs_h = 3600.0 / (double)w->ta_s;
    }
    n->dsa_sign[li] = signs_h + w->c2_per_h;
    n->dsa_verify[li] = w->dsa_verify_per_h;
    /* Transcript const per handshake x rekey rate (see header note). */
    rekeys_h = (w->tpq_s == 0) ? 0.0 : 3600.0 / (double)w->tpq_s;
    n->sha_b = w->transcript_b * rekeys_h + 2.0 * w->readings_per_h;
    /* Steady-state KEM ops are zero (handshakes live in E_ctrl). */
    n->bytes = w->msg_per_h * w->msg_bytes;
    n->events = w->msg_per_h; /* one event per first transmission. */
}

void qc_energy_eval(const qc_e_counts *n, const qc_e_coeff *c,
                    double ebase_jps, double ectrl_j, double t_s,
                    qc_e_groups *g) {
    double crypto = 0.0, comm, adapt;
    int l, o;

    if (n == NULL || c == NULL || g == NULL) {
        return;
    }
    for (l = 0; l < 3; l++) {
        for (o = 0; o < 3; o++) {
            crypto += n->kem[l][o] * c->e_kem[l][o];
        }
        crypto += n->dsa_sign[l] * c->e_dsa_sign[l];
        crypto += n->dsa_verify[l] * c->e_dsa_verify[l];
    }
    crypto += n->aes_enc_b * c->e_aes_b + n->aes_dec_b * c->e_aes_b;
    crypto += n->hkdf_ext * c->e_hkdf_ext + n->hkdf_exp * c->e_hkdf_exp;
    crypto += n->sha_b * c->e_sha_b;
    comm = n->bytes * c->eB + n->events * c->e_ev;
    /* Per-hour rates scaled to the window T (T <= 0 yields zero
     * rate-proportional terms; E_ctrl is already window-scaled). */
    if (t_s > 0.0) {
        double k = t_s / 3600.0;
        crypto *= k;
        comm *= k;
    } else {
        crypto = 0.0;
        comm = 0.0;
    }
    adapt = ectrl_j;
    g->base = ebase_jps * (t_s > 0.0 ? t_s : 0.0);
    g->crypto = crypto;
    g->comm = comm;
    g->adapt = adapt;
    g->total = g->base + crypto + comm + adapt;
}

double qc_ehat_sec(const qc_e_counts *n, const qc_e_coeff *c) {
    qc_e_groups g;

    if (n == NULL || c == NULL) {
        return 0.0;
    }
    /* T = 3600 evaluates exactly one hour of rates; baseline excluded
     * by construction (summed groups, never total-minus-base). */
    qc_energy_eval(n, c, 0.0, 0.0, 3600.0, &g);
    return (g.crypto + g.comm + g.adapt) / 3600.0;
}

double qc_energy_ehs(const qc_e_coeff *c, int profile, double n_ev_hs) {
    double ekem, air;
    int li, o;

    if (c == NULL || profile < 1 || profile > 3 || n_ev_hs < 0.0) {
        return 0.0;
    }
    li = profile - 1;
    ekem = 0.0;
    for (o = 0; o < 3; o++) {
        if (c->e_kem[li][o] > ekem) {
            ekem = c->e_kem[li][o];
        }
    }
    air = (double)(KEM_SIZES[li][0] + 2u * KEM_SIZES[li][1]) * c->eB;
    return 3.0 * ekem + air + n_ev_hs * c->e_ev;
}

double qc_energy_prekey(double ehs_j, uint32_t tpq_s) {
    if (!(ehs_j >= 0.0) || tpq_s == 0) {
        return 0.0;
    }
    return ehs_j / (double)tpq_s;
}

double qc_energy_hmax_rate(double ehs_j, double rekeys_per_h) {
    if (!(ehs_j >= 0.0) || !(rekeys_per_h >= 0.0)) {
        return 0.0;
    }
    return ehs_j * rekeys_per_h;
}

void qc_foot_priors(qc_foot_tables *t) {
    if (t == NULL) {
        return;
    }
    /* BLE baseline + DSA-dominated crypto stacks (108 KB sign stack at
     * 87 per B-11; 44/65 scaled x0.45/x0.7 mirroring the energy seeds;
     * KEM stacks inside the noise — folded, not itemized). All ASSUMED
     * pending B-10.5/E1 records. */
    t->base_ram = 32768u;
    t->stack_ram[0] = 49152u;
    t->stack_ram[1] = 77824u;
    t->stack_ram[2] = 110592u;
    t->ram_per_byte = 2u;
    t->msg_bytes = 64u; /* manuscript nominal anchor. */
    t->lat_base_ms = 5u;
    t->lat_per_msg_ms = 2u;
    t->assumed = 0xFFu;
}

int qc_foot_calibrate(qc_foot_tables *t, int field, int idx,
                      uint32_t value) {
    if (t == NULL) {
        return -1;
    }
    switch (field) {
    case QC_FFOOT_BASE:
        t->base_ram = value;
        break;
    case QC_FFOOT_STACK:
        if (idx < 0 || idx > 2) {
            return -1;
        }
        t->stack_ram[idx] = value;
        field = QC_FFOOT_STACK + idx;
        break;
    case QC_FFOOT_PER_BYTE:
        t->ram_per_byte = value;
        break;
    case QC_FFOOT_MSG_BYTES:
        t->msg_bytes = value;
        break;
    case QC_FFOOT_LAT_BASE:
        t->lat_base_ms = value;
        break;
    case QC_FFOOT_LAT_MSG:
        t->lat_per_msg_ms = value;
        break;
    default:
        return -1;
    }
    /* Stack bits 1..3 per profile; singletons at 0,4,5,6,7. */
    if (field >= 0 && field < 8) {
        t->assumed &= (uint32_t) ~(1u << field);
    }
    return 0;
}

void qc_foot_to_res(const qc_foot_tables *t, qc_res_tables *out) {
    if (t == NULL || out == NULL) {
        return;
    }
    /* Same layout, flags stripped (B-31 evaluates; ASSUMED-ness stays
     * in the foot record for B-54/H5 gating, never silently laundered
     * — callers carry t alongside when provenance matters). */
    out->base_ram = t->base_ram;
    out->stack_ram[0] = t->stack_ram[0];
    out->stack_ram[1] = t->stack_ram[1];
    out->stack_ram[2] = t->stack_ram[2];
    out->ram_per_byte = t->ram_per_byte;
    out->msg_bytes = t->msg_bytes;
    out->lat_base_ms = t->lat_base_ms;
    out->lat_per_msg_ms = t->lat_per_msg_ms;
}
