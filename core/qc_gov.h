/* qc_gov.h — token-bucket governor + shed + restore (plan B-35.1-.4).
 *
 * Bucket: tau float joules, equation-literal
 *   tau <- min(max, max(-max, tau + rho*dt - ehat_sec)) — implemented
 * EXACTLY as written (probed normative). Audit-flagged tension (recorded
 * here for phase gate, NOT resolved in code): the drain term is a RATE
 * (J/s) while refill is window-scaled (J) — dimensionally the drain
 * wants ×dt. The equation stands as written pending phase-gate verdict;
 * the signature already carries dt separately, so either verdict needs
 * no API change. Empty iff tau <= 0. No floor except -max (debt bound).
 * Refill accrues on every charge call (windows without apply make no
 * call — frozen, documented). tau init = tau_max (provisioning).
 *
 * tau values are float32 per spec (energy doubles live in B-33; the
 * bucket is float by normative mandate — conversion at the call
 * boundary is the caller's, documented).
 *
 * Shed is STATELESS (progression derived from live params each call):
 * order C0 rate -> Nb depth -> Ta cadence, one parameter per call,
 * halving toward floors (C0: max(r/2, min); Nb: max(n/2, 1) integer;
 * Ta: timed-only min(t*2, cap), overflow-guarded). Sentinel Ta (event/
 * msg/none paths) counts as floored (C2 evidence never shed). All
 * floored -> unchanged + exhausted=1 (caller applies floored anyway;
 * B-26.4 governs empty-Af only, never shed exhaustion). C0 directive
 * ships separately (sampler path; B-30 unedited per spec).
 *
 * Restore: eligibility = tau >= frac*max AND windows-since-shed >=
 * dwell (fractions/windows caller-valued; spec defaults 0.5 x max and
 * 3 as macros). last_shed stamps on every shed() call (event clocked;
 * progression stays parameter-derived). Steps invert shed in reverse
 * order (Ta, Nb, C0), one parameter per eligible window toward the
 * orchestrator's desired values (sentinels adopted directly — discrete
 * by nature). Restored proposals re-enter through B-34 gates caller-
 * side (restore never bypasses; this unit only computes the step).
 *
 * B-34 wiring: tau_read = qc_gov_tau; spend adapter converts the hook's
 * joules to (ehat_sec = J/dt, dt) — the hook carries joules, the
 * equation consumes the rate form (adapter is one line, orchestrator-
 * side, documented here so both ends agree). ShedNonCritical(a) =
 * qc_gov_shed; update-on-apply = qc_gov_charge (skip-on-failure =
 * caller makes no call). NVS persist: tau + config + last_shed, MAC'd
 * caller key (shed progression needs no persistence — stateless).
 */
#ifndef QC_GOV_H
#define QC_GOV_H

#include <stddef.h>
#include <stdint.h>

#include "qc_floor.h" /* qc_action (shed rides inside it). */

#define QC_GOV_RESTORE_FRAC_DFLT 0.5f
#define QC_GOV_DWELL_DFLT 3u

typedef enum {
    QC_GOV_OK = 0,
    QC_GOV_BAD_ARG,     /* NULLs, uninit, bad config/values. */
    QC_GOV_BAD_VERSION, /* import version mismatch. */
    QC_GOV_BAD_MAC      /* import tamper (never adopt). */
} qc_gov_rc;

typedef struct {
    double c0_rate; /* workload C0 sampling rate (caller units). */
    qc_action action; /* Nb + Ta shed inside; profile untouched. */
} qc_shed_in;

typedef struct {
    double c0_min;   /* deployment minimum, strictly > 0. */
    int32_t ta_cap_s; /* slowest allowed Ta, timed seconds > 0. */
} qc_shed_floors;

typedef struct {
    qc_action a_shed;
    double c0_directive; /* to the sampler path. */
    uint8_t exhausted;
} qc_shed_out;

/* Restore-step legs (return value); 3 = fully restored. */
enum {
    QC_RESTORE_TA = 0,
    QC_RESTORE_NB = 1,
    QC_RESTORE_C0 = 2,
    QC_RESTORE_DONE = 3
};

typedef struct {
    uint32_t sheds;
    uint32_t exhaustions;
    uint32_t charges;
    /* No restores counter: restore_step is pure (no gov state), so the
     * orchestrator counts restorations from its return (audit note). */
} qc_gov_counters;

typedef struct {
    uint8_t init;
    float tau;
    float tau_max;
    double rho;
    float restore_frac;
    uint16_t restore_dwell;
    uint64_t last_shed;
    uint8_t has_shed;
    qc_gov_counters c;
} qc_gov;

qc_gov_rc qc_gov_init(qc_gov *g, float tau_max, double rho,
                      float restore_frac, uint16_t restore_dwell);
float qc_gov_tau(const qc_gov *g); /* 0.0 on null/uninit (empty = shed). */
qc_gov_rc qc_gov_charge(qc_gov *g, double ehat_sec, double delta_t_s);
qc_gov_rc qc_gov_shed(qc_gov *g, const qc_shed_in *in,
                      const qc_shed_floors *f, qc_shed_out *out,
                      uint64_t now);
int qc_gov_restore_ready(const qc_gov *g, uint64_t now, uint64_t delta_s);
int qc_gov_restore_step(const qc_shed_in *cur, const qc_shed_in *des,
                        qc_shed_in *out);
void qc_gov_counts(const qc_gov *g, qc_gov_counters *out);
qc_gov_rc qc_gov_export(const qc_gov *g, const uint8_t key[32],
                        uint8_t *out, size_t cap, size_t *len_out);
qc_gov_rc qc_gov_import(qc_gov *g, const uint8_t key[32],
                        const uint8_t *in, size_t len);

#endif
