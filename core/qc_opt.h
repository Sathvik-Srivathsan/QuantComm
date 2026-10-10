/* qc_opt.h — optimizer: selection, caps, cooldown, queue (plan B-34).
 *
 * Consumes Af action lists (B-31 shape) with caller-computed Ehat values
 * (B-33 evaluates; this unit never links energy math — the derivation
 * caller wires B-33, documented, not stubbed). Bucket TAU is read and
 * charged through B-35 hooks (mechanics owned there); alarms surface as
 * pending bits the caller drains (B-40 sink owns them later).
 *
 * Per-window order (spec): empty-Af guard -> Hmax-cover filter ->
 * argmin (Ehat + lambda*sigma, Model B sigma in {0,1} on profile
 * change) -> bucket gate (over-budget returns SHED exactly once; the
 * caller sheds externally, never re-enters) -> queued/fresh arbitration
 * -> cap check (BEFORE cooldown) -> cooldown check (escalation bypass)
 * -> stage. Commit (caller applied or failed) advances a_prev,
 * last_switch, and the tau charge (skipped on failure).
 *
 *argmin ties: toward a_prev on exact ties (bitwise — deterministic);
 * else lowest profile index. a_prev boots at the highest admitted
 * profile (caller picks; fail-safe start). NaN Ehat/lambda never wins
 * (all-NaN degrades to FAILSECURE, never a blind pick).
 *
 * Escalation (strictly more conservative): higher profile, or shorter
 * Tpq/Ta at equal profile (timed-vs-timed only — sentinel-vs-anything
 * never qualifies; mixed-direction profiles cannot exist in the SL
 * total order and are not specially detected). Cap holds EVEN for
 * escalation (queued, overwrite alarms throttled hourly); cooldown
 * yields to escalation.
 *
 * Hmax counter: 60 one-minute buckets (trailing 60 min, no wall-clock
 * alignment; u16 saturating each — unbounded Hmax supported). Counted
 * via note_handshake (orchestrator reports real handshakes; this unit
 * performs none). Persists with cooldown ts + a_prev + queue via
 * MAC'd export/import under a caller key (rate-limit integrity across
 * reboot; same-firmware precondition as risk). Hmax/T_cool arrive from
 * the manifest (reconfigure() on rotation; counter survives reconfig).
 * Hmax-cover margin default 1.0/h (caller passes explicitly).
 */
#ifndef QC_OPT_H
#define QC_OPT_H

#include <stddef.h>
#include <stdint.h>

#include "qc_floor.h" /* qc_action (Af shape, owned by B-31). */

#define QC_OPT_MARGIN_DFLT 1.0
#define QC_OPT_NBUCKETS 60

typedef enum {
    QC_OPT_OK_STAGED = 0, /* candidate staged (apply + commit it). */
    QC_OPT_BAD_ARG,       /* NULLs, uninit, bad lambda/margin. */
    QC_OPT_FAILSECURE,    /* empty Af (raw or post-cover) or all-NaN:
                             caller routes B-26.4. */
    QC_OPT_SHED,          /* a* over tau: caller sheds externally once. */
    QC_OPT_HOLD,          /* a_prev held (cap/cooldown, routine). */
    QC_OPT_QUEUED,        /* escalation queued under cap (a_prev held). */
    QC_OPT_BAD_MAC,       /* import tamper (never adopt). */
    QC_OPT_BAD_VERSION    /* import version mismatch. */
} qc_opt_rc;

enum {
    QC_OPT_ALARM_CAP_ENTER = 0, /* bit 0: transitioned into cap. */
    QC_OPT_ALARM_CAP_OVERWRITE = 1, /* queue overwrite (throttled). */
    QC_OPT_ALARM_CAP_REMINDER = 2,  /* sustained cap, hourly (throttled). */
    QC_OPT_ALARM_APPLY_FAIL = 3     /* commit(false) reported. */
};

/* B-35 bucket hooks (charge mechanics owned there; the tau READ arrives
 * per decide() call — the caller read the bucket, keeping this unit free
 * of read callbacks). */
typedef struct {
    void *ctx;
    void (*tau_spend)(void *ctx, double joules);   /* charge spend. */
} qc_opt_hooks;

typedef struct {
    qc_action action;
    double ehat_j;      /* Ehat(a) for the window (caller/B-33). */
    double ehat_sec;    /* Ehat_sec(a) J/s for the bucket gate. */
} qc_cand;

typedef struct {
    uint32_t holds;
    uint32_t sheds;
    uint32_t queued;
    uint32_t superseded;  /* queued dropped for fresh escalation. */
    uint32_t stale_dropped; /* queued missing from fresh Af. */
    uint32_t failsecures;
    uint32_t apply_fails;
} qc_opt_counters;

typedef struct {
    uint8_t init;
    qc_action a_prev;
    qc_action staged;
    uint8_t staged_valid;
    uint16_t buckets[QC_OPT_NBUCKETS]; /* per-minute handshake counts. */
    uint64_t bucket_base;  /* minute index of buckets[0]. */
    uint8_t buckets_set;
    uint64_t last_switch;
    uint32_t hmax;
    uint32_t t_cool_s;
    qc_action queue;
    uint8_t queue_valid;
    uint8_t in_cap;
    uint64_t last_cap_alarm;
    qc_opt_counters c;
    uint8_t pending_alarms;
    qc_opt_hooks hooks;
    uint8_t has_hooks;
} qc_opt;

int qc_opt_init(qc_opt *o, const qc_action *a_prev, uint32_t hmax,
                uint32_t t_cool_s, uint64_t last_switch,
                const qc_opt_hooks *hooks);
/* Manifest rotation values (counter/queue/state preserved). */
int qc_opt_reconfigure(qc_opt *o, uint32_t hmax, uint32_t t_cool_s);
/* One policy window (see order above). Staged output read via accessor. */
qc_opt_rc qc_opt_decide(qc_opt *o, const qc_cand *cands, size_t n,
                        double lambda_j, double tau_jps, double margin_hs,
                        uint64_t now);
int qc_opt_staged(const qc_opt *o, qc_action *out); /* 1 if staged. */
/* Report the apply outcome (advances a_prev/last_switch/tau charge;
 * failure raises APPLY_FAIL and skips the charge). applied is the
 * action actually put live (NULL = staged): after a SHED decision the
 * caller applies the shed-modified action, and a_prev must track
 * reality, not the pre-shed candidate. Audit-added parameter. */
qc_opt_rc qc_opt_commit(qc_opt *o, int applied_ok, uint64_t now,
                        double spend_j, const qc_action *applied);
/* Real handshakes feed the rolling cap counter (orchestrator reports). */
int qc_opt_note_handshake(qc_opt *o, uint64_t now);
/* Read rolls the window forward as a side effect (documented). */
uint32_t qc_opt_cap_count(qc_opt *o, uint64_t now);
/* Drain-and-clear pending alarm bits for the caller/B-40. */
uint8_t qc_opt_take_alarms(qc_opt *o);
void qc_opt_counts(const qc_opt *o, qc_opt_counters *out);
/* NVS persist (counter + cooldown + a_prev + queue + cap/throttle,
 * MAC'd caller key; staged + telemetry counters are transient and not
 * persisted — audit-stated). */
int qc_opt_export(const qc_opt *o, const uint8_t key[32], uint8_t *out,
                  size_t cap, size_t *len_out);
int qc_opt_import(qc_opt *o, const uint8_t key[32], const uint8_t *in,
                  size_t len, const qc_opt_hooks *hooks);

#endif
