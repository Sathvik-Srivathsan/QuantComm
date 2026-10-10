/* qc_state.h — controller state vector x_t (plan B-30.1/.2/.4).
 *
 * x_t = [B,R,S,C,M,L,Q] sampled per policy window Delta (Delta owned by
 * B-31/B-34 — this unit takes caller clocks, never values Delta).
 * Components: B budget joules float + soc percent (soc logged/telemetered
 * only, NEVER a policy input — enforced by absence: no function here
 * reads soc for decisions); R risk float [0,1] (slot only, B-32 computes);
 * S class {C0,C1,C2} via the classifier below (frame headers inspected
 * by the CALLER — this unit takes class codepoints, never parses wire);
 * C load fraction [0,1]; M free bytes u32; L link tuple (RSSI dBm int16
 * window-min + MAC-retry count u16); Q msg/s float (first transmissions
 * only — the CALLER excludes MAC retries before sampling).
 *
 * Validity mask u16 (B-30.4): two bits per component in B-30.1 order
 * (B=0,R=1,S=2,C=3,M=4,L=5,Q=6): 00 ok, 01 stale, 10 invalid, 11 both.
 * Boot is fail-safe: init marks ALL components invalid; each first good
 * sample clears its bits (R additionally mandated invalid until first
 * B-32 output — same mechanism). Staleness is evaluated at READ
 * (component older than caller Delta_max) — sampling never stamps stale.
 * Out-of-range and time-regressed samples are REFUSED (last-good kept):
 * range violation sets invalid + returns INVALID; time regression
 * returns NONMONOTONIC with the mask untouched (previous standing kept).
 * Good samples clear invalid (fresh age clears stale at next evaluate).
 * Refused values are NOT stored: the caller sees the rc AT the call
 * site (it supplied the value) and logs (component, reason, raw) there
 * for B-40 — this unit keeps no refusal journal (audit-trail contract).
 *
 * Cross-sanity (B-30.4): Q near-zero while B-23 counters advance, and M
 * below the caller mem_min (0 disables), evaluated in qc_state_check()
 * alongside staleness. mem_min is caller-valued (B-00a/B-60 records own
 * it); q_eps ("near zero") is caller-valued (spec unvalued — labeled,
 * not smuggled). S outside {0,1,2} is invalid at sample time.
 *
 * No policy lives here (B-31 responds to flags; flagging owned here).
 * No floats are compared for equality anywhere (range forms are
 * NaN-safe: NaN fails every bound and goes invalid).
 */
#ifndef QC_STATE_H
#define QC_STATE_H

#include <stddef.h>
#include <stdint.h>

enum {
    QC_STATE_COMP_B = 0,
    QC_STATE_COMP_R = 1,
    QC_STATE_COMP_S = 2,
    QC_STATE_COMP_C = 3,
    QC_STATE_COMP_M = 4,
    QC_STATE_COMP_L = 5,
    QC_STATE_COMP_Q = 6,
    QC_STATE_NCOMP = 7
};

enum {
    QC_STATE_F_OK = 0,
    QC_STATE_F_STALE = 1,
    QC_STATE_F_INVALID = 2,
    QC_STATE_F_BOTH = 3
};

typedef enum {
    QC_STATE_OK = 0,
    QC_STATE_BAD_ARG,    /* NULLs. */
    QC_STATE_INVALID,    /* value refused (flagged, last-good kept). */
    QC_STATE_NONMONOTONIC, /* timestamp regressed (dropped, mask kept). */
    QC_STATE_C2          /* S sample accepted AND C2-immediate signaled. */
} qc_state_rc;

typedef struct {
    float b_j;
    uint8_t b_soc;
    uint64_t b_at;
    float r;
    uint64_t r_at;
    uint8_t s;
    uint64_t s_at;
    uint8_t s_immediate;  /* set on C2 arrival, cleared on read. */
    float c;
    uint64_t c_at;
    uint32_t m;
    uint64_t m_at;
    int16_t l_rssi;
    uint16_t l_retries;
    uint64_t l_at;
    float q;
    uint64_t q_at;
    uint64_t q_counters;  /* B-23 counter snapshot at last Q sample. */
    uint32_t risk[6];     /* manuscript counters (B-32 windows these). */
    uint64_t risk_at;
    uint16_t mask;
    uint8_t init;
} qc_state;

void qc_state_init(qc_state *s);

/* Per-component samplers (NaN-safe ranges; monotonic clocks enforced).
 * sample_s: highest-class-wins is CALLER logic over the window (this
 * call records one observation); cls==2 additionally sets s_immediate
 * and returns QC_STATE_C2 (out-of-window sample signal). */
qc_state_rc qc_state_sample_b(qc_state *s, float joules, uint8_t soc_pct,
                              uint64_t now);
qc_state_rc qc_state_sample_r(qc_state *s, float risk, uint64_t now);
qc_state_rc qc_state_sample_s(qc_state *s, uint8_t cls, uint64_t now);
qc_state_rc qc_state_sample_c(qc_state *s, float load, uint64_t now);
qc_state_rc qc_state_sample_m(qc_state *s, uint32_t free_bytes,
                              uint64_t now);
qc_state_rc qc_state_sample_l(qc_state *s, int16_t rssi_dbm,
                              uint16_t retries, uint64_t now);
qc_state_rc qc_state_sample_q(qc_state *s, float rate,
                              uint64_t counters_consumed, uint64_t now);
/* Risk-counter snapshot (counts only; B-32 owns windowing/weights). */
qc_state_rc qc_state_snapshot_risk(qc_state *s, const uint32_t counts[6],
                                   uint64_t now);

/* Consume-and-clear the C2-immediate flag (1 if a C2 arrived since the
 * last read — caller takes an out-of-window S sample). */
int qc_state_take_s_immediate(qc_state *s);

/* Recompute time-derived flags as of now (staleness vs delta_max,
 * M vs mem_min with 0 disabling, Q cross-check vs counters_now with
 * q_eps). Returns the mask. Never clears invalid (only good samples
 * do); never fabricates data. */
uint16_t qc_state_check(qc_state *s, uint64_t now, uint64_t delta_max,
                        uint32_t mem_min, uint64_t counters_now,
                        float q_eps);

#endif
