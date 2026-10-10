/* qc_risk.h — risk scoring + hysteresis + hint merge (plan B-32.1-.4).
 *
 * Window R = clamp01(sum_i w_i * c_i/cmax_i + hint_sum) in float32;
 * ratios pass through uncapped (a flooded counter alone drives 1 —
 * flood is the signal). c_i are per-window INCREMENT sums over the last
 * W policy windows (caller diffs the B-30 snapshots; this unit never
 * touches raw device counters — all counter inputs local by
 * construction). First R emits after the first close on partial counts
 * (no scaling); R reads NaN before first emission (fail-loud: NaN fails
 * every threshold comparison toward safety — no enter, no exit).
 *
 * Hysteresis {NORMAL, HIGH}, init NORMAL: enter iff R > hi for n_e
 * consecutive closes (strict: equality holds); exit iff R < lo for n_x
 * consecutive AND dwell >= T_dwell (dwell counts closes spent in HIGH
 * including the entry close). Missed windows (miss()) slide zero counts
 * and recompute R but FREEZE both streaks (neither reset nor advance);
 * dwell still advances (time passes); emission flag untouched (a miss
 * is never an output). Constructor invariant lo < hi enforced.
 *
 * Hints: one call = one fixed H_hint added to the CURRENT window sum
 * only (consumed at close, never latched). Caller pre-validates via
 * B-25.4 (forgery/rate gates live there — this unit trusts increment
 * calls). Hints inflate only: they can sustain HIGH but never force or
 * trigger exit (exit evaluates the same inflated R; removal of hints
 * alone never exits — only the streak rule does). Hints never touch
 * counters (separate evidence channel; overstatement bounded by
 * H_hint within the caller-side rate cap).
 *
 * Outputs: R (float32) to the B-30 slot; band = state projection
 * (NORMAL 0 / HIGH 1) to B-31. Transitions logged with (from, to,
 * triggering streak, dwell, last-W window-R values) in a 64-ring
 * (staging for B-40; reboot drops the ring — state persists, history
 * does not). Reboot persistence: export/import blob (magic+ver+state,
 * HMAC-32 under a CALLER key — tamper-evident so power-cycling cannot
 * forge a cleared HIGH; same-firmware precondition documented, not
 * enforced). E11 reference arm + DOE sweep execution are B-52/B-53
 * scope (design-only here, no code — stated, not stubbed).
 *
 * Config PAPER-PARAM (valued at build; sweep starting points, not field
 * values): W default 10, theta 0.7/0.3, n_e 3, n_x 5, T_dwell 10,
 * H_hint 0.3. Validation rejects: negative weights, non-positive caps,
 * lo >= hi, n_e/n_x == 0, W outside 1..16 (ring bound, provisional),
 * negative H_hint (a negative hint would de-escalate — forbidden).
 */
#ifndef QC_RISK_H
#define QC_RISK_H

#include <stddef.h>
#include <stdint.h>

#define QC_RISK_NC 6
#define QC_RISK_HIST_MAX 16
#define QC_RISK_LOG_N 64

/* Counter order (B-30 snapshot order): auth failures, replay drops,
 * malformed frames, unexpected disconnects, unknown-central attempts,
 * RSSI anomalies. */
enum {
    QC_RISK_AUTH_FAIL = 0,
    QC_RISK_REPLAY_DROP = 1,
    QC_RISK_MALFORMED = 2,
    QC_RISK_DISCONNECT = 3,
    QC_RISK_UNKNOWN_CENTRAL = 4,
    QC_RISK_RSSI_ANOMALY = 5
};

typedef enum {
    QC_RISK_OK = 0,
    QC_RISK_BAD_ARG,    /* NULLs, uninit, bad config. */
    QC_RISK_BAD_MAC,    /* import tamper (never adopt). */
    QC_RISK_BAD_VERSION /* import version mismatch. */
} qc_risk_rc;

typedef struct {
    float w[QC_RISK_NC];
    float cmax[QC_RISK_NC];
    float theta_hi;
    float theta_lo;
    uint16_t n_e;
    uint16_t n_x;
    uint16_t t_dwell;
    uint8_t window_w;
    float h_hint;
} qc_risk_cfg;

int qc_risk_cfg_check(const qc_risk_cfg *c); /* 0 valid, nonzero why. */

typedef struct {
    uint8_t from;
    uint8_t to;
    uint16_t consec;    /* streak that triggered. */
    uint16_t dwell;
    float hist[QC_RISK_HIST_MAX]; /* last-W window-R values. */
    uint8_t w;          /* W at log time. */
} qc_risk_trans;

typedef struct {
    uint8_t init;
    uint8_t state;      /* 0 NORMAL, 1 HIGH. */
    uint8_t emitted;
    uint16_t n_enter;   /* enter streak. */
    uint16_t n_exit;    /* exit streak. */
    uint16_t dwell;
    float r;
    float h_sum;        /* current-window hint accumulator. */
    uint32_t hist[QC_RISK_HIST_MAX][QC_RISK_NC];
    float hist_r[QC_RISK_HIST_MAX];
    uint8_t hidx;       /* next write slot (0..W-1). */
    uint8_t hcount;     /* windows closed, capped at W. */
    qc_risk_trans log[QC_RISK_LOG_N];
    uint8_t log_n;      /* transitions recorded, capped at 64. */
    qc_risk_cfg cfg;
} qc_risk;

int qc_risk_init(qc_risk *r, const qc_risk_cfg *cfg);
/* Close one policy window on increments; miss() on no-output windows. */
qc_risk_rc qc_risk_window(qc_risk *r, const uint32_t inc[QC_RISK_NC]);
qc_risk_rc qc_risk_miss(qc_risk *r);
/* One validated hint -> +H_hint to the current window (no latch). */
qc_risk_rc qc_risk_hint(qc_risk *r);
float qc_risk_r(const qc_risk *r);   /* NaN before first emission. */
int qc_risk_high(const qc_risk *r);  /* band: 1 HIGH, 0 NORMAL/uninit. */
int qc_risk_emitted(const qc_risk *r);
/* Reboot persistence (caller MAC key, 32 B). Same-firmware precondition:
 * config is NOT in the blob; importing under different config is a
 * caller bug with undefined (but MAC-checked) results. */
qc_risk_rc qc_risk_export(const qc_risk *r, const uint8_t key[32],
                          uint8_t *out, size_t cap, size_t *len_out);
qc_risk_rc qc_risk_import(qc_risk *r, const qc_risk_cfg *cfg,
                          const uint8_t key[32], const uint8_t *in,
                          size_t len);

#endif
