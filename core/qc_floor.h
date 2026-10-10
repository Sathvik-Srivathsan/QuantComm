/* qc_floor.h — floor engine + feasibility solver (plan B-31.1-.5).
 *
 * Floor basis: manifest min_level per class (LIVE values via the table
 * below — B-25 owned, caller translates the parsed manifest) stepped by
 * R band (high evaluates the next-higher class row, C2 stays). KEM/DSA
 * pairings are definitional per profile (SL1=(512,44), SL2=(768,65),
 * SL3=(1024,87)) so enforcing profile level transitively enforces them;
 * no KEM/DSA table lives here. Tpq caps {24h,1h,10min} and Ta ranks are
 * compiled PAPER-PARAM provisionals (labeled, valued at build).
 *
 * Profiles are SL1..3 (u8 1..3; SL0 excluded from the device lattice).
 * Admitted set arrives as an explicit mask (the B-25 membership
 * predicate exists only as a header comment today — when implemented,
 * callers switch source; this unit does not change).
 *
 * Candidate lattice (structure owned here): profiles admitted ×
 * Tpq {cap,cap/2,cap/4} × Tr {Tpq,Tpq/2} × Ta E5 {none,600,60,
 * per-event,per-message} × Nb {1,2,4,8}∩≤nb_max∩≤32 (batch cap is a
 * cross-unit bound — enforced here, owned by B-24.2). Ta wire form is
 * int32 seconds with NONE=-1, EVENT=-2, MSG=-3 (E5 set exactly).
 * C3 ranks cadences: none 0, >600 s 1, >60 s 2, else-timed 3,
 * per-event 4, per-message 5; floor ranks {C0:0, C1:2, C2:4} with a
 * none-carve-out for C0 only. C4/C5 evaluate caller/B-33 resource
 * tables (B-31 evaluates, never values — tables are inputs).
 *
 * Flagged contract (B-31.4): any M-component flag (pair index 4, any of
 * 01/10/11) -> HOLD (caller holds previous action + alarms; re-checks
 * it with the predicates below each window, escalating to B-26.4 on
 * violation — caller loop, not this unit). Any other flagged pair ->
 * basis (S=C2, R=high) regardless of measured values. Clean vectors use
 * measured S (defensive C2/high if out of range — unreachable via the
 * sampler, guarded anyway) and R vs the caller r_threshold (B-32 owns
 * the threshold; NaN/out-of-range rejected, never defaulted toward the
 * less-restrictive band).
 *
 * Empty feasible set -> count 0 (caller routes B-26.4 fail-secure; never
 * floor relaxation — enforced by absence: no relax path exists here).
 * S0/S1/S4 bypass exists NOWHERE in firmware (CI predicate rejects
 * floor-bypass symbols; the spec-mandated C2_BYPASS mechanism in
 * qc_batch is a different, explicitly out-of-scope concept).
 */
#ifndef QC_FLOOR_H
#define QC_FLOOR_H

#include <stddef.h>
#include <stdint.h>

#include "qc_state.h"

#define QC_TA_NONE ((int32_t)-1)
#define QC_TA_EVENT ((int32_t)-2)
#define QC_TA_MSG ((int32_t)-3)

/* Provisional PAPER-PARAM defaults (labeled; valued at build). */
#define QC_FLOOR_NB_MAX_DFLT 8u
#define QC_FLOOR_LMAX_C0_DFLT 3600u
#define QC_FLOOR_LMAX_C1_DFLT 600u
#define QC_FLOOR_LMAX_C2_DFLT 60u

/* Tpq caps per effective class (24 h / 1 h / 10 min, provisional). */
#define QC_FLOOR_TPQ_C0 86400u
#define QC_FLOOR_TPQ_C1 3600u
#define QC_FLOOR_TPQ_C2 600u

typedef enum {
    QC_FLOOR_OK = 0,
    QC_FLOOR_BAD_ARG, /* NULLs, uninit state, bad profile/lengths. */
    QC_FLOOR_HOLD     /* M-flagged: hold previous + alarm (B-31.4). */
} qc_floor_rc;

/* Manifest floor input (caller translates the parsed manifest). */
typedef struct {
    uint8_t min_level[3]; /* wire 1..3 per class C0..C2. */
    uint8_t has[3];       /* nonzero iff the class row exists. */
} qc_floor_table;

/* Build-time config (PAPER-PARAM; default() fills provisionals). */
typedef struct {
    uint32_t lmax_s[3]; /* C5 per-class latency max, seconds. */
    uint8_t nb_max;     /* batch bound (1..32). */
} qc_floor_cfg;

void qc_floor_cfg_default(qc_floor_cfg *c);

/* B-33-owned resource values (B-31 evaluates, never values). */
typedef struct {
    uint32_t base_ram;        /* fixed footprint, bytes. */
    uint32_t stack_ram[3];    /* per-profile crypto working stacks. */
    uint32_t ram_per_byte;    /* per payload byte. */
    uint32_t msg_bytes;       /* nominal message bytes (PAPER-PARAM). */
    uint32_t lat_base_ms;     /* fixed latency per action. */
    uint32_t lat_per_msg_ms;  /* per-message latency. */
} qc_res_tables;

typedef struct {
    uint8_t profile;  /* SL1..3. */
    uint32_t tpq_s;
    uint32_t tr_s;
    int32_t ta_s;     /* E5 set (sentinels above) or seconds. */
    uint8_t nb;
} qc_action;

typedef struct {
    uint8_t s_eff;  /* effective class C0..C2 (R-stepped). */
    uint8_t r_high; /* nonzero iff high band. */
} qc_floor_basis;

/* Basis selection (flagged contract). Mask read from s. r_high is the
 * B-32 MACHINE band (qc_risk_high: nonzero HIGH, zero NORMAL) — audit
 * correction: an earlier cut re-derived the band from R vs a threshold,
 * which disagrees with the machine pre-enter/post-streak. Spec assigns
 * the band to B-32 hysteresis; B-31 consumes it verbatim (thresholds
 * live in the risk config, never here). */
qc_floor_rc qc_floor_select(const qc_state *s, int r_high,
                            qc_floor_basis *out);

/* Single predicates (also the B-34 hold re-check path). C4/C5 report
 * the computed value alongside the verdict (telemetry/audit duty). */
int qc_floor_c1(uint8_t profile, const qc_floor_table *t, uint8_t s_eff);
int qc_floor_c2(uint32_t tpq_s, uint8_t s_eff);
int qc_floor_c3(int32_t ta_s, uint8_t s_eff);
int qc_floor_c4(const qc_action *a, const qc_res_tables *rt,
                uint32_t m_free, uint32_t *ram_out);
int qc_floor_c5(const qc_action *a, const qc_res_tables *rt,
                const qc_floor_cfg *c, uint8_t s_eff,
                uint32_t *lat_out_ms);

/* Feasible-set enumeration via callback (B-34 optimizes over it).
 * admitted[3]: nonzero iff SL(i+1) allowed. Returns delivered count;
 * 0 = empty (caller routes B-26.4). Invalid config (nb_max 0 or >32)
 * also yields 0 — fail-secure routing, never silent relaxation.
 * Deterministic nested order. */
typedef void (*qc_feas_cb)(const qc_action *a, void *ctx);
size_t qc_floor_feasible(const uint8_t admitted[3],
                         const qc_floor_table *t, uint8_t s_eff,
                         const qc_res_tables *rt, const qc_floor_cfg *c,
                         uint32_t m_free, qc_feas_cb cb, void *ctx);

#endif
