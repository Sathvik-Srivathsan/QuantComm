/* qc_risk.c — risk scoring + hysteresis + hint merge (B-32.1-.4).
 * Windowed sums over a counter ring; float32 R; streak machine with
 * dwell; hint accumulator consumed per close; MAC'd export/import.
 * No heap, no threads, caller clocks. Static staging only in export.
 */
#include "qc_risk.h"

#include <string.h>

#include "qc_hmac.h"
#include "qc_sha256.h"

int qc_risk_cfg_check(const qc_risk_cfg *c) {
    int i;

    if (c == NULL) {
        return -1;
    }
    for (i = 0; i < QC_RISK_NC; i++) {
        if (!(c->w[i] >= 0.0f)) {
            return -1; /* negative or NaN weight. */
        }
        if (!(c->cmax[i] > 0.0f)) {
            return -1; /* zero/negative/NaN cap. */
        }
    }
    /* Thresholds live in [0,1] with lo < hi (NaN-safe: NaN fails every
     * comparison below toward rejection, never toward a band). */
    if (!(c->theta_lo >= 0.0f) || !(c->theta_lo <= 1.0f) ||
        !(c->theta_hi >= 0.0f) || !(c->theta_hi <= 1.0f) ||
        !(c->theta_lo < c->theta_hi)) {
        return -1;
    }
    if (c->n_e == 0 || c->n_x == 0) {
        return -1;
    }
    if (c->window_w < 1 || c->window_w > QC_RISK_HIST_MAX) {
        return -1;
    }
    if (!(c->h_hint >= 0.0f)) {
        return -1; /* negative/NaN hint would de-escalate. */
    }
    return 0;
}

int qc_risk_init(qc_risk *r, const qc_risk_cfg *cfg) {
    if (r == NULL || cfg == NULL || qc_risk_cfg_check(cfg) != 0) {
        return -1;
    }
    memset(r, 0, sizeof(*r));
    r->cfg = *cfg;
    r->init = 1;
    return 0;
}

static float nan_f(void) {
    uint32_t u = 0x7FC00000u;
    float v;
    memcpy(&v, &u, 4);
    return v;
}

/* Window sums over the ring (unwritten slots read zero — partial first
 * windows emit unscaled by construction). */
static double window_score(const qc_risk *r) {
    double s = 0.0;
    uint8_t w = r->cfg.window_w;
    uint8_t k;
    int i;

    for (k = 0; k < w; k++) {
        for (i = 0; i < QC_RISK_NC; i++) {
            s += (double)r->cfg.w[i] *
                 ((double)r->hist[k][i] / (double)r->cfg.cmax[i]);
        }
    }
    return s;
}

static float clamp01(double v) {
    if (!(v >= 0.0)) {
        return 0.0f;
    }
    if (v >= 1.0) {
        return 1.0f;
    }
    return (float)v;
}

static void log_trans(qc_risk *r, uint8_t from, uint8_t to,
                      uint16_t consec) {
    qc_risk_trans *t;
    uint8_t w = r->cfg.window_w;
    uint8_t k;

    if (r->log_n == QC_RISK_LOG_N) {
        memmove(&r->log[0], &r->log[1],
                sizeof(r->log[0]) * (QC_RISK_LOG_N - 1));
    } else {
        r->log_n++;
    }
    t = &r->log[r->log_n - 1];
    t->from = from;
    t->to = to;
    t->consec = consec;
    t->dwell = r->dwell;
    /* Oldest-first: hidx aims at the next write = oldest data. */
    for (k = 0; k < w; k++) {
        t->hist[k] = r->hist_r[(uint8_t)(r->hidx + k) % w];
    }
    for (; k < QC_RISK_HIST_MAX; k++) {
        t->hist[k] = 0.0f;
    }
    t->w = w;
}

/* Shared close path (miss passes zero increments + freezes streaks). */
static void close_common(qc_risk *r, const uint32_t inc[QC_RISK_NC],
                         int is_miss) {
    double score;
    float rnew;
    uint8_t slot = r->hidx;
    int i;

    for (i = 0; i < QC_RISK_NC; i++) {
        r->hist[slot][i] = inc[i];
    }
    score = window_score(r);
    rnew = clamp01(score + (double)r->h_sum);
    r->h_sum = 0.0f;
    r->r = rnew;
    /* hist_r parallels hist slot-for-slot; a missed window banks 0.0
     * (no R sample — transition logs show the gap explicitly). */
    r->hist_r[slot] = is_miss ? 0.0f : rnew;
    r->hidx = (uint8_t)((slot + 1) % r->cfg.window_w);
    if (r->state == 0) {
        if (!is_miss) {
            if (rnew > r->cfg.theta_hi) {
                r->n_enter++;
            } else {
                r->n_enter = 0;
            }
            if (r->n_enter >= r->cfg.n_e) {
                r->state = 1;
                r->dwell = 1;
                r->n_enter = 0;
                r->n_exit = 0;
                log_trans(r, 0, 1, r->cfg.n_e);
            }
        }
    } else {
        r->dwell++;
        if (!is_miss) {
            if (rnew < r->cfg.theta_lo) {
                r->n_exit++;
            } else {
                r->n_exit = 0;
            }
            if (r->n_exit >= r->cfg.n_x && r->dwell >= r->cfg.t_dwell) {
                r->state = 0;
                r->dwell = 0;
                r->n_enter = 0;
                r->n_exit = 0;
                log_trans(r, 1, 0, r->cfg.n_x);
            }
        }
    }
}

qc_risk_rc qc_risk_window(qc_risk *r, const uint32_t inc[QC_RISK_NC]) {
    if (r == NULL || !r->init || inc == NULL) {
        return QC_RISK_BAD_ARG;
    }
    close_common(r, inc, 0);
    r->emitted = 1;
    return QC_RISK_OK;
}

qc_risk_rc qc_risk_miss(qc_risk *r) {
    static const uint32_t zeros[QC_RISK_NC] = { 0, 0, 0, 0, 0, 0 };

    if (r == NULL || !r->init) {
        return QC_RISK_BAD_ARG;
    }
    /* h_sum PRESERVED across a miss (validated hints are evidence that
     * outlives one dead window; consumed at the next close — bounded
     * by the caller-side rate cap, never latched across closes). */
    {
        float kept = r->h_sum;
        close_common(r, zeros, 1);
        r->h_sum = kept;
    }
    return QC_RISK_OK;
}

qc_risk_rc qc_risk_hint(qc_risk *r) {
    if (r == NULL || !r->init) {
        return QC_RISK_BAD_ARG;
    }
    r->h_sum += r->cfg.h_hint;
    return QC_RISK_OK;
}

float qc_risk_r(const qc_risk *r) {
    if (r == NULL || !r->init || !r->emitted) {
        return nan_f();
    }
    return r->r;
}

int qc_risk_high(const qc_risk *r) {
    if (r == NULL || !r->init) {
        return 0;
    }
    return r->state != 0;
}

int qc_risk_emitted(const qc_risk *r) {
    if (r == NULL || !r->init) {
        return 0;
    }
    return r->emitted != 0;
}

/* Export layout: magic "QCR1"(4) || ver u8 || state u8 || emitted u8 ||
 * rsv u8 || n_enter u16 || n_exit u16 || dwell u16 || r f32 ||
 * h_sum f32 || hidx u8 || hist[16][6] u32 (384) || hist_r[16] f32 (64)
 * || MAC-32. Audit fix: header 23 + 384 + 64 = 471, +32 = 503 total
 * (first cut wrote 1655 — bad mental arithmetic that bricked import). */
#define QC_RISK_EXP_LEN 503
#define QC_RISK_EXP_CAP 512

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

static void put_f32(uint8_t *p, float v) {
    uint32_t u;
    memcpy(&u, &v, 4);
    put_u32(p, u);
}

static uint16_t get_u16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t get_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static float get_f32(const uint8_t *p) {
    uint32_t u = get_u32(p);
    float v;
    memcpy(&v, &u, 4);
    return v;
}

qc_risk_rc qc_risk_export(const qc_risk *r, const uint8_t key[32],
                          uint8_t *out, size_t cap, size_t *len_out) {
    static uint8_t img[QC_RISK_EXP_CAP];
    uint8_t mac[32];
    size_t n = 0;
    int i, k;

    if (r == NULL || !r->init || key == NULL || out == NULL ||
        len_out == NULL || cap < QC_RISK_EXP_LEN) {
        return QC_RISK_BAD_ARG;
    }
    img[0] = 'Q';
    img[1] = 'C';
    img[2] = 'R';
    img[3] = '1';
    img[4] = 1;
    img[5] = r->state;
    img[6] = r->emitted;
    img[7] = 0;
    n = 8;
    put_u16(img + n, r->n_enter);
    n += 2;
    put_u16(img + n, r->n_exit);
    n += 2;
    put_u16(img + n, r->dwell);
    n += 2;
    put_f32(img + n, r->r);
    n += 4;
    put_f32(img + n, r->h_sum);
    n += 4;
    img[n++] = r->hidx;
    for (k = 0; k < QC_RISK_HIST_MAX; k++) {
        for (i = 0; i < QC_RISK_NC; i++) {
            put_u32(img + n, r->hist[k][i]);
            n += 4;
        }
    }
    for (k = 0; k < QC_RISK_HIST_MAX; k++) {
        put_f32(img + n, r->hist_r[k]);
        n += 4;
    }
    /* n == 1623 here (audit: 8+2+2+2+4+4+1+1536+64). */
    qc_hmac_sha256(key, 32, img, n, mac);
    memcpy(img + n, mac, 32);
    memset(mac, 0, sizeof(mac));
    n += 32;
    memcpy(out, img, n);
    memset(img, 0, sizeof(img));
    *len_out = n;
    return QC_RISK_OK;
}

qc_risk_rc qc_risk_import(qc_risk *r, const qc_risk_cfg *cfg,
                          const uint8_t key[32], const uint8_t *in,
                          size_t len) {
    uint8_t mac[32];
    size_t n;
    int i, k;

    if (r == NULL || cfg == NULL || key == NULL || in == NULL) {
        return QC_RISK_BAD_ARG;
    }
    if (qc_risk_cfg_check(cfg) != 0) {
        return QC_RISK_BAD_ARG;
    }
    if (len != QC_RISK_EXP_LEN || in[0] != 'Q' || in[1] != 'C' ||
        in[2] != 'R' || in[3] != '1' || in[4] != 1) {
        return (len != QC_RISK_EXP_LEN) ? QC_RISK_BAD_ARG
                                        : QC_RISK_BAD_VERSION;
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
            return QC_RISK_BAD_MAC;
        }
    }
    memset(r, 0, sizeof(*r));
    r->cfg = *cfg;
    r->state = in[5] != 0;
    r->emitted = in[6] != 0;
    n = 8;
    r->n_enter = get_u16(in + n);
    n += 2;
    r->n_exit = get_u16(in + n);
    n += 2;
    r->dwell = get_u16(in + n);
    n += 2;
    r->r = get_f32(in + n);
    n += 4;
    r->h_sum = get_f32(in + n);
    n += 4;
    r->hidx = in[n++];
    if (r->hidx >= QC_RISK_HIST_MAX) {
        memset(r, 0, sizeof(*r));
        return QC_RISK_BAD_MAC; /* tampered index (MAC covers it). */
    }
    /* Normalize to the live W (identity under same-config import, the
     * only supported case; bounds the ring discipline on mismatch). */
    r->hidx = (uint8_t)(r->hidx % cfg->window_w);
    for (k = 0; k < QC_RISK_HIST_MAX; k++) {
        for (i = 0; i < QC_RISK_NC; i++) {
            r->hist[k][i] = get_u32(in + n);
            n += 4;
        }
    }
    for (k = 0; k < QC_RISK_HIST_MAX; k++) {
        r->hist_r[k] = get_f32(in + n);
        n += 4;
    }
    r->init = 1;
    return QC_RISK_OK;
}
