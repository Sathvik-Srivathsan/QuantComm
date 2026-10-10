/* qc_energy.h — energy model Eq.(1) + tables + calibration (plan B-33).
 *
 * E(T,a) = Ebase*T + crypto + comm + adapt, reported per group
 * (Baseline | Cryptographic | Communication | Adaptation — never merged
 * early: a saving in one term can hide in the total). doubles throughout
 * (uJ terms summed at J scale need the headroom; R_t-style float32 does
 * NOT apply here). T in seconds; op rates per hour (/3600 inside).
 *
 * Single counting (manuscript rule): handshake KEM/bytes/events live in
 * E_ctrl ONLY (caller lump into the adapt group); the crypto/comm sums
 * count non-handshake ops — EXCEPT transcript-hash bytes (const per
 * handshake × rekey rate: not part of the Ehs triple, counted here —
 * documented reading of the B-33.1/B-33.2 overlap). Ehat_sec sums the
 * crypto+comm+adapt groups directly (baseline excluded by construction,
 * never by subtraction — bit-exact by identical op order).
 *
 * Coefficients PAPER-PARAM with ASSUMED flags (priors() fills labeled
 * placeholders; E1-E4 calibration clears flags via calibrate()).
 * Spec-ranged priors use the stated multipliers (KEM 512 base ×1.6/×2.4,
 * DSA-87 ×0.45/×0.7); unvalued fields (e_ev, AES/SHA per-byte, HKDF ops,
 * Ebase states, verifies) take flagged order-of-magnitude seeds —
 * labeled WAGs pending E1/E3, never results. Sizes per FIPS 203 +
 * qc_kem.h (cross-checked in tests, never silently redefined).
 * No security scalar anywhere (manuscript invariant — no function here
 * scores security). H5/MAPE + DOE + E1-E4 campaigns are B-51/B-54/B-62
 * scope (interface + triggers here, execution there).
 */
#ifndef QC_ENERGY_H
#define QC_ENERGY_H

#include <stddef.h>
#include <stdint.h>

#include "qc_floor.h" /* res_tables (B-31 consumes; no cycle: floor
 * owns no energy types). */

/* Assumed-bit positions (also calibrate() field IDs). */
enum {
    QC_ASSUMED_EB = 0,
    QC_ASSUMED_EV,
    QC_ASSUMED_KEM512,
    QC_ASSUMED_KEM768,
    QC_ASSUMED_KEM1024,
    QC_ASSUMED_DSA44,
    QC_ASSUMED_DSA65,
    QC_ASSUMED_DSA87,
    QC_ASSUMED_AES,
    QC_ASSUMED_HKDF,
    QC_ASSUMED_SHA,
    QC_ASSUMED_EBASE,
    QC_ASSUMED_FOOT,
    QC_ASSUMED_NFIELDS
};

typedef enum {
    QC_EBASE_OFF = 0,
    QC_EBASE_ADV = 1,
    QC_EBASE_CONN = 2,
    QC_EBASE_SLEEP = 3,
    QC_EBASE_NSTATES = 4
} qc_ebase_state;

typedef struct {
    double e_kem[3][3];      /* [level 0..2][keygen,encaps,decaps], J/op. */
    double e_dsa_sign[3];    /* J/op. */
    double e_dsa_verify[3];  /* J/op. */
    double e_aes_b;          /* J/byte (enc+dec share hardware path). */
    double e_hkdf_ext;       /* J/op. */
    double e_hkdf_exp;       /* J/op. */
    double e_sha_b;          /* J/byte. */
    double eB;               /* J/air-byte. */
    double e_ev;             /* J/radio-event. */
    double ebase_jps[QC_EBASE_NSTATES]; /* J/s per radio/CPU state. */
    uint32_t assumed;        /* bitmask above (1 = prior, uncalibrated). */
} qc_e_coeff;

void qc_energy_priors(qc_e_coeff *c); /* labeled seeds, all ASSUMED. */
/* Calibrate one field (clears its ASSUMED bit; NaN/negative values
 * refused except where physically meaningful — all energy terms are
 * non-negative, so negatives always refuse). Singletons (EB, EV, AES,
 * HKDF, SHA) use their QC_ASSUMED_* id with idx/sub ignored; families
 * use QC_EFIELD_* with idx (level/state) and sub (KEM op only). */
enum {
    QC_EFIELD_KEM = 100,    /* idx level 0..2, sub op 0..2 (kg/enc/dec). */
    QC_EFIELD_DSA_SIGN = 110, /* idx level 0..2. */
    QC_EFIELD_DSA_VERIFY = 120, /* idx level 0..2. */
    QC_EFIELD_EBASE = 130   /* idx state 0..3. */
};
int qc_energy_calibrate(qc_e_coeff *c, int field, int idx, int sub,
                        double value);
/* Recalibration trigger (backend/target change, H5 breach): re-flags
 * everything ASSUMED (values kept as priors). */
void qc_energy_invalidate_all(qc_e_coeff *c);

/* Per-hour op counts (caller/B-34 derives from the action; helper below). */
typedef struct {
    double kem[3][3];
    double dsa_sign[3];
    double dsa_verify[3];
    double aes_enc_b;
    double aes_dec_b;
    double hkdf_ext;
    double hkdf_exp;
    double sha_b;
    double bytes;   /* B(a) air bytes. */
    double events;  /* N_ev(a). */
} qc_e_counts;

/* Derivation inputs (action telemetry; B-34 owns the action). */
typedef struct {
    int profile;            /* SL1..3 (selects level row for keyed ops). */
    double msg_per_h;
    double resend;          /* resend factor (0 = none). */
    double msg_bytes;
    uint32_t tpq_s;         /* rekey period (rekeys/h = 3600/tpq). */
    uint32_t tr_s;          /* ratchet period (expands/h = 3600/tr). */
    int32_t ta_s;           /* E5 sentinels (reuse QC_TA_* values). */
    double ta_event_per_h;  /* signs/h when ta is EVENT/MSG (unvalued:
                               trace-driven estimate, default 0). */
    double c2_per_h;        /* C2 evidence signs/h (trace estimate). */
    double readings_per_h;  /* Merkle bound (<= 2x). */
    double transcript_b;    /* const hash bytes per handshake. */
    double dsa_verify_per_h;
} qc_workload;

void qc_derive_counts(const qc_workload *w, qc_e_counts *n);

typedef struct {
    double base;
    double crypto;
    double comm;
    double adapt;
    double total;
} qc_e_groups;

/* ectrl_j/ebase_jps non-negative precondition (caller bug otherwise;
 * values propagate literally — no silent clamping that could hide a
 * sign error as optimism). */
void qc_energy_eval(const qc_e_counts *n, const qc_e_coeff *c,
                    double ebase_jps, double ectrl_j, double t_s,
                    qc_e_groups *g);
double qc_ehat_sec(const qc_e_counts *n, const qc_e_coeff *c);

/* Ehs(l) = 3*max-kg/enc/dec + (|ek|+2|ct|)*eB + n_ev_hs*e_ev (sizes per
 * FIPS 203; e_kem takes the per-op MAX — conservative energy-cover
 * direction, documented audit choice). profile SL1..3. */
double qc_energy_ehs(const qc_e_coeff *c, int profile, double n_ev_hs);
double qc_energy_prekey(double ehs_j, uint32_t tpq_s); /* Ehs/Tpq. */
double qc_energy_hmax_rate(double ehs_j, double rekeys_per_h);

/* Footprint records (B-33.3 owned; feed B-31's qc_res_tables).
 * Stacks provisional (DSA-dominated; KEM inside noise) + BLE baseline,
 * all ASSUMED pending B-10.5/E1 records. */
typedef struct {
    uint32_t base_ram;
    uint32_t stack_ram[3];
    uint32_t ram_per_byte;
    uint32_t msg_bytes;     /* 64 nominal (manuscript-anchored). */
    uint32_t lat_base_ms;
    uint32_t lat_per_msg_ms;
    uint32_t assumed;       /* bit per field (order above, 0..6). */
} qc_foot_tables;

void qc_foot_priors(qc_foot_tables *t); /* all ASSUMED. */
enum {
    QC_FFOOT_BASE = 0,
    QC_FFOOT_STACK = 1, /* + idx profile 0..2 (one bit per profile). */
    QC_FFOOT_PER_BYTE = 4,
    QC_FFOOT_MSG_BYTES = 5,
    QC_FFOOT_LAT_BASE = 6,
    QC_FFOOT_LAT_MSG = 7
};
int qc_foot_calibrate(qc_foot_tables *t, int field, int idx,
                      uint32_t value);
void qc_foot_to_res(const qc_foot_tables *t, qc_res_tables *out);

#endif
