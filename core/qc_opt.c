/* qc_opt.c — optimizer selection + gates (B-34.1-.6).
 * Pure decision logic over caller values; bucket charge via hook; no
 * alloc, no threads, caller clocks (monotonic assumed; regression
 * fails safe toward hold — documented at use).
 */
#include "qc_opt.h"

#include <string.h>

#include "qc_hmac.h"

static int action_eq(const qc_action *x, const qc_action *y) {
    return x->profile == y->profile && x->tpq_s == y->tpq_s &&
           x->tr_s == y->tr_s && x->ta_s == y->ta_s && x->nb == y->nb;
}

/* Strictly-more-conservative (spec-literal): higher profile, or shorter
 * Tpq/Ta at equal profile (timed-vs-timed only; sentinels and zero Tpq
 * never qualify on their leg). */
static int is_escalation(const qc_action *prev, const qc_action *a) {
    if (a->profile > prev->profile) {
        return 1;
    }
    if (a->profile != prev->profile) {
        return 0;
    }
    if (a->tpq_s > 0 && a->tpq_s < prev->tpq_s) {
        return 1;
    }
    if (a->ta_s > 0 && prev->ta_s > 0 && a->ta_s < prev->ta_s) {
        return 1;
    }
    return 0;
}

int qc_opt_init(qc_opt *o, const qc_action *a_prev, uint32_t hmax,
                uint32_t t_cool_s, uint64_t last_switch,
                const qc_opt_hooks *hooks) {
    if (o == NULL || a_prev == NULL || a_prev->profile < 1 ||
        a_prev->profile > 3) {
        return -1;
    }
    memset(o, 0, sizeof(*o));
    o->a_prev = *a_prev;
    o->hmax = hmax;
    o->t_cool_s = t_cool_s;
    o->last_switch = last_switch;
    if (hooks != NULL) {
        o->hooks = *hooks;
        o->has_hooks = (hooks->tau_spend != NULL);
    }
    o->init = 1;
    return 0;
}

/* Roll buckets forward to minute m (clearing lapsed minutes). */
static void roll(qc_opt *o, uint64_t now) {
    uint64_t m = now / 60;
    uint64_t new_base;
    uint16_t fresh[QC_OPT_NBUCKETS];
    int j;

    if (!o->buckets_set) {
        memset(o->buckets, 0, sizeof(o->buckets));
        o->bucket_base = m;
        o->buckets_set = 1;
        return;
    }
    if (m < o->bucket_base) {
        m = o->bucket_base; /* regression: count conservatively. */
    }
    new_base = (m >= (QC_OPT_NBUCKETS - 1)) ? m - (QC_OPT_NBUCKETS - 1)
                                            : 0;
    /* Audit fix: <= not ==. A window already covered (new_base below
     * base — same-minute re-reads, regression clamp) must no-op; the
     * old equality let the copy loop index fresh[] up to 118 (stack
     * smash caught by -fstack-protector on the second decide call). */
    if (new_base <= o->bucket_base) {
        return;
    }
    memset(fresh, 0, sizeof(fresh));
    for (j = 0; j < QC_OPT_NBUCKETS; j++) {
        uint64_t old_min = o->bucket_base + (uint64_t)j;
        if (old_min >= new_base) {
            fresh[old_min - new_base] = o->buckets[j];
        }
    }
    memcpy(o->buckets, fresh, sizeof(fresh));
    o->bucket_base = new_base;
}

static uint32_t cap_sum(qc_opt *o) {
    uint32_t n = 0;
    int j;

    for (j = 0; j < QC_OPT_NBUCKETS; j++) {
        n += o->buckets[j];
    }
    return n;
}

int qc_opt_note_handshake(qc_opt *o, uint64_t now) {
    uint64_t m;

    if (o == NULL || !o->init) {
        return -1;
    }
    roll(o, now);
    m = now / 60;
    if (m < o->bucket_base) {
        m = o->bucket_base;
    }
    {
        uint16_t *slot = &o->buckets[m - o->bucket_base];
        if (*slot < 0xFFFFu) {
            (*slot)++;
        }
    }
    return 0;
}

uint32_t qc_opt_cap_count(qc_opt *o, uint64_t now) {
    if (o == NULL || !o->init) {
        return 0;
    }
    roll(o, now); /* read rolls the window forward (documented). */
    return cap_sum(o);
}

static void raise(qc_opt *o, unsigned bit, uint64_t now,
                  int throttled) {
    /* Audit fix: unthrottled cap alarms must still stamp the throttle
     * clock (first cut only stamped inside the throttled branch, so a
     * post-ENTER reminder fired immediately — caught by test_cap).
     * APPLY_FAIL never touches the cap clock (independent throttle
     * domain; sharing it would suppress cap reminders after apply
     * failures). Regression (now < last) wraps huge and fires once —
     * fail toward alarming. */
    if (throttled && o->last_cap_alarm != 0 &&
        now - o->last_cap_alarm < 3600) {
        return;
    }
    if (bit < 3) {
        o->last_cap_alarm = now;
    }
    o->pending_alarms = (uint8_t)(o->pending_alarms | (uint8_t)(1u << bit));
}

uint8_t qc_opt_take_alarms(qc_opt *o) {
    uint8_t v;

    if (o == NULL || !o->init) {
        return 0;
    }
    v = o->pending_alarms;
    o->pending_alarms = 0;
    return v;
}

void qc_opt_counts(const qc_opt *o, qc_opt_counters *out) {
    if (o == NULL || out == NULL) {
        return;
    }
    *out = o->c;
}

int qc_opt_staged(const qc_opt *o, qc_action *out) {
    if (o == NULL || !o->init || out == NULL) {
        return 0;
    }
    if (!o->staged_valid) {
        return 0;
    }
    *out = o->staged;
    return 1;
}

static int in_af(const qc_action *a, const qc_cand *cands, size_t n) {
    size_t i;

    for (i = 0; i < n; i++) {
        if (action_eq(a, &cands[i].action)) {
            return 1;
        }
    }
    return 0;
}

qc_opt_rc qc_opt_decide(qc_opt *o, const qc_cand *cands, size_t n,
                        double lambda_j, double tau_jps, double margin_hs,
                        uint64_t now) {
    double best = 0.0;
    qc_action star;
    int found = 0;
    size_t i;
    int fresh_esc, had_queued;
    uint32_t count;

    if (o == NULL || !o->init || cands == NULL || n == 0) {
        if (o != NULL && o->init && cands != NULL && n == 0) {
            o->c.failsecures++;
            return QC_OPT_FAILSECURE;
        }
        return QC_OPT_BAD_ARG;
    }
    /* NaN/negative lambda or margin: refuse (optimistic-garbage guard;
     * lambda tunes switching cost — a negative lambda PAYS switching;
     * the !(>=0) form catches NaN too). */
    if (!(lambda_j >= 0.0) || !(margin_hs >= 0.0)) {
        return QC_OPT_BAD_ARG;
    }
    /* A fresh decision supersedes any uncommitted stage (counters
     * already recorded the event; audit trail preserved). */
    o->staged_valid = 0;
    /* Argmin over Hmax-cover survivors (count side here; energy side is
     * the caller's B-33 rate, already inside Ehat). Out-of-range
     * profiles never survive (fail-closed per candidate). */
    for (i = 0; i < n; i++) {
        const qc_action *a = &cands[i].action;
        double rate, v, sigma;
        if (a->profile < 1 || a->profile > 3) {
            continue;
        }
        if (a->tpq_s == 0) {
            continue; /* infinite rekey rate fails cover. */
        }
        rate = 3600.0 / (double)a->tpq_s + margin_hs;
        if (!(rate <= (double)o->hmax)) {
            continue; /* NaN-safe: NaN cover fails closed. */
        }
        sigma = (a->profile != o->a_prev.profile) ? 1.0 : 0.0;
        v = cands[i].ehat_j + lambda_j * sigma;
        /* Skip non-finite/negative (optimistic garbage never wins);
         * strict < keeps the earliest minimum (tie pass below). */
        if (v == v && v >= 0.0 && v <= 1e308 && (!found || v < best)) {
            best = v;
            star = *a;
            found = 1;
        }
    }
    if (!found) {
        o->c.failsecures++;
        return QC_OPT_FAILSECURE;
    }
    /* Tie pass: exact ties toward a_prev, else lowest profile. */
    {
        double emin = best;
        int have_prev = 0, have_low = 0;
        qc_action lowprof;
        memset(&lowprof, 0, sizeof(lowprof));
        for (i = 0; i < n; i++) {
            const qc_action *a = &cands[i].action;
            double rate, v, sigma;
            if (a->profile < 1 || a->profile > 3) {
                continue;
            }
            if (a->tpq_s == 0) {
                continue;
            }
            rate = 3600.0 / (double)a->tpq_s + margin_hs;
            if (!(rate <= (double)o->hmax)) {
                continue;
            }
            sigma = (a->profile != o->a_prev.profile) ? 1.0 : 0.0;
            v = cands[i].ehat_j + lambda_j * sigma;
            if (v == emin) {
                if (action_eq(a, &o->a_prev)) {
                    have_prev = 1;
                }
                if (!have_low || a->profile < lowprof.profile) {
                    lowprof = *a;
                    have_low = 1;
                }
            }
        }
        if (have_prev) {
            star = o->a_prev;
        } else if (have_low) {
            star = lowprof;
        }
    }
    /* Bucket gate (NaN-safe: unknown budget sheds, never passes). */
    {
        double es = 0.0;
        for (i = 0; i < n; i++) {
            if (action_eq(&cands[i].action, &star)) {
                es = cands[i].ehat_sec;
                break;
            }
        }
        if (!(es <= tau_jps)) {
            o->staged = star;
            o->staged_valid = 1;
            o->c.sheds++;
            return QC_OPT_SHED;
        }
    }
    fresh_esc = !action_eq(&star, &o->a_prev) &&
                is_escalation(&o->a_prev, &star);
    had_queued = o->queue_valid;
    if (had_queued && fresh_esc) {
        /* Fresh evaluated first; queued dropped superseded, alarm-free. */
        o->queue_valid = 0;
        o->c.superseded++;
    }
    if (o->queue_valid && !fresh_esc) {
        /* No hmax==0 guard here (audit consistency): degenerate zero
         * cap holds everywhere, including queued service — the main cap
         * path below has no guard either. */
        count = qc_opt_cap_count(o, now);
        if (count >= o->hmax) {
            o->in_cap = 1;
            raise(o, QC_OPT_ALARM_CAP_REMINDER, now, 1);
            o->c.holds++;
            return QC_OPT_HOLD;
        }
        /* Cap clear: serve queued iff still in fresh Af. */
        if (!in_af(&o->queue, cands, n)) {
            o->queue_valid = 0;
            o->c.stale_dropped++;
        } else {
            star = o->queue;
            o->queue_valid = 0;
            fresh_esc = is_escalation(&o->a_prev, &star) &&
                        !action_eq(&star, &o->a_prev);
        }
    }
    /* Cap check (before cooldown, per order). Hmax==0 degenerates to
     * always-capped (fail-secure natural outcome, not a special case:
     * count >= 0 always true — the && hmax guard below would SKIP the
     * cap for hmax==0! Audit note: hmax==0 must cap, so no guard). */
    count = qc_opt_cap_count(o, now);
    if (count >= o->hmax) {
        if (fresh_esc || is_escalation(&o->a_prev, &star)) {
            o->queue = star;
            o->queue_valid = 1;
            o->c.queued++;
            if (had_queued) {
                raise(o, QC_OPT_ALARM_CAP_OVERWRITE, now, 0);
            } else if (!o->in_cap) {
                raise(o, QC_OPT_ALARM_CAP_ENTER, now, 0);
            }
            o->in_cap = 1;
            return QC_OPT_QUEUED;
        }
        o->in_cap = 1;
        raise(o, QC_OPT_ALARM_CAP_REMINDER, now, 1);
        o->c.holds++;
        return QC_OPT_HOLD;
    }
    o->in_cap = 0;
    /* Cooldown (regression fails toward hold — safe direction). */
    if ((now < o->last_switch ||
         now - o->last_switch < o->t_cool_s) &&
        !(fresh_esc || is_escalation(&o->a_prev, &star))) {
        o->c.holds++;
        return QC_OPT_HOLD;
    }
    o->staged = star;
    o->staged_valid = 1;
    return QC_OPT_OK_STAGED;
}

qc_opt_rc qc_opt_commit(qc_opt *o, int applied_ok, uint64_t now,
                        double spend_j, const qc_action *applied) {
    qc_action live;

    if (o == NULL || !o->init || !o->staged_valid) {
        return QC_OPT_BAD_ARG;
    }
    if (applied == NULL) {
        live = o->staged;
    } else {
        if (applied->profile < 1 || applied->profile > 3) {
            return QC_OPT_BAD_ARG;
        }
        live = *applied;
    }
    if (!applied_ok) {
        raise(o, QC_OPT_ALARM_APPLY_FAIL, now, 0);
        o->c.apply_fails++;
        o->staged_valid = 0;
        o->c.holds++;
        return QC_OPT_HOLD; /* a_prev held; alarm via pending bits. */
    }
    if (!action_eq(&live, &o->a_prev)) {
        o->a_prev = live;
        o->last_switch = now;
    }
    if (o->has_hooks && spend_j >= 0.0) {
        o->hooks.tau_spend(o->hooks.ctx, spend_j);
    }
    o->staged_valid = 0;
    return QC_OPT_OK_STAGED;
}

int qc_opt_reconfigure(qc_opt *o, uint32_t hmax, uint32_t t_cool_s) {
    if (o == NULL || !o->init) {
        return -1;
    }
    /* Counter/queue/state preserved (rate-limit integrity survives
     * rotation; a lowered Hmax caps naturally on next decide). */
    o->hmax = hmax;
    o->t_cool_s = t_cool_s;
    return 0;
}

/* Export layout: magic "QCO1" || ver u8=1 || a_prev(14) || last_switch
 * u64 || hmax u32 || t_cool u32 || bucket_base u64 || buckets_set u8 ||
 * buckets 60x u16 (120) || queue_valid u8 || queue(14) || in_cap u8 ||
 * last_cap_alarm u64 || MAC-32. Total 4+1+14+8+4+4+8+1+120+1+14+1+8 =
 * 188 + 32 = 220. */
#define QC_OPT_EXP_LEN 220

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

static void put_u64(uint8_t *p, uint64_t v) {
    int i;
    for (i = 0; i < 8; i++) {
        p[i] = (uint8_t)(v >> (8 * (7 - i)));
    }
}

static void put_action(uint8_t *p, const qc_action *a) {
    p[0] = a->profile;
    put_u32(p + 1, a->tpq_s);
    put_u32(p + 5, a->tr_s);
    put_u32(p + 9, (uint32_t)a->ta_s);
    p[13] = a->nb;
}

static uint16_t get_u16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t get_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint64_t get_u64(const uint8_t *p) {
    uint64_t v = 0;
    int i;
    for (i = 0; i < 8; i++) {
        v = (v << 8) | p[i];
    }
    return v;
}

static void get_action(const uint8_t *p, qc_action *a) {
    a->profile = p[0];
    a->tpq_s = get_u32(p + 1);
    a->tr_s = get_u32(p + 5);
    a->ta_s = (int32_t)get_u32(p + 9);
    a->nb = p[13];
}

static int action_sane(const qc_action *a) {
    return a->profile >= 1 && a->profile <= 3;
}

int qc_opt_export(const qc_opt *o, const uint8_t key[32], uint8_t *out,
                  size_t cap, size_t *len_out) {
    static uint8_t img[QC_OPT_EXP_LEN];
    uint8_t mac[32];
    size_t n = 0;
    int j;

    if (o == NULL || !o->init || key == NULL || out == NULL ||
        len_out == NULL || cap < QC_OPT_EXP_LEN) {
        return QC_OPT_BAD_ARG;
    }
    img[0] = 'Q';
    img[1] = 'C';
    img[2] = 'O';
    img[3] = '1';
    img[4] = 1;
    n = 5;
    put_action(img + n, &o->a_prev);
    n += 14;
    put_u64(img + n, o->last_switch);
    n += 8;
    put_u32(img + n, o->hmax);
    n += 4;
    put_u32(img + n, o->t_cool_s);
    n += 4;
    put_u64(img + n, o->bucket_base);
    n += 8;
    img[n++] = o->buckets_set ? 1 : 0;
    for (j = 0; j < QC_OPT_NBUCKETS; j++) {
        put_u16(img + n, o->buckets[j]);
        n += 2;
    }
    img[n++] = o->queue_valid ? 1 : 0;
    put_action(img + n, &o->queue);
    n += 14;
    img[n++] = o->in_cap ? 1 : 0;
    put_u64(img + n, o->last_cap_alarm);
    n += 8;
    /* n == 188 here (audit: 5+14+8+4+4+8+1+120+1+14+1+8). */
    qc_hmac_sha256(key, 32, img, n, mac);
    memcpy(img + n, mac, 32);
    memset(mac, 0, sizeof(mac));
    n += 32;
    memcpy(out, img, n);
    memset(img, 0, sizeof(img));
    *len_out = n;
    return QC_OPT_OK_STAGED;
}

int qc_opt_import(qc_opt *o, const uint8_t key[32], const uint8_t *in,
                  size_t len, const qc_opt_hooks *hooks) {
    uint8_t mac[32];
    size_t n;
    int j;

    if (o == NULL || key == NULL || in == NULL) {
        return QC_OPT_BAD_ARG;
    }
    if (len != QC_OPT_EXP_LEN || in[0] != 'Q' || in[1] != 'C' ||
        in[2] != 'O' || in[3] != '1' || in[4] != 1) {
        return (len != QC_OPT_EXP_LEN) ? QC_OPT_BAD_ARG
                                       : QC_OPT_BAD_VERSION;
    }
    n = len - 32;
    qc_hmac_sha256(key, 32, in, n, mac);
    {
        uint8_t diff = 0;
        for (j = 0; j < 32; j++) {
            diff |= (uint8_t)(mac[j] ^ in[n + j]);
        }
        memset(mac, 0, sizeof(mac));
        if (diff != 0) {
            return QC_OPT_BAD_MAC;
        }
    }
    memset(o, 0, sizeof(*o));
    n = 5;
    get_action(in + n, &o->a_prev);
    if (!action_sane(&o->a_prev)) {
        memset(o, 0, sizeof(*o));
        return QC_OPT_BAD_MAC;
    }
    n += 14;
    o->last_switch = get_u64(in + n);
    n += 8;
    o->hmax = get_u32(in + n);
    n += 4;
    o->t_cool_s = get_u32(in + n);
    n += 4;
    o->bucket_base = get_u64(in + n);
    n += 8;
    o->buckets_set = in[n++] != 0;
    for (j = 0; j < QC_OPT_NBUCKETS; j++) {
        o->buckets[j] = get_u16(in + n);
        n += 2;
    }
    o->queue_valid = in[n++] != 0;
    get_action(in + n, &o->queue);
    if (o->queue_valid && !action_sane(&o->queue)) {
        memset(o, 0, sizeof(*o));
        return QC_OPT_BAD_MAC;
    }
    n += 14;
    o->in_cap = in[n++] != 0;
    o->last_cap_alarm = get_u64(in + n);
    if (hooks != NULL) {
        o->hooks = *hooks;
        o->has_hooks = (hooks->tau_spend != NULL);
    }
    o->init = 1;
    return QC_OPT_OK_STAGED;
}
