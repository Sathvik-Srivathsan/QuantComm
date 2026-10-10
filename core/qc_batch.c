/* qc_batch.c — transmission batching (B-24.2).
 * Static arena + slot dir; bump append, compact on demand (no eviction
 * — FULL refuses). Caller clock; no crypto, no alloc, no threads.
 */
#include "qc_batch.h"

#include <string.h>

void qc_batch_init(qc_batch *b) {
    if (b == NULL) {
        return;
    }
    memset(b, 0, sizeof(*b));
    b->init = 1;
}

size_t qc_batch_count(const qc_batch *b) {
    size_t n = 0;
    int i;

    if (b == NULL || !b->init) {
        return 0;
    }
    for (i = 0; i < QC_BATCH_MAX_READINGS; i++) {
        if (b->slot[i].valid) {
            n++;
        }
    }
    return n;
}

void qc_batch_counts(const qc_batch *b, qc_batch_counters *out) {
    if (b == NULL || out == NULL) {
        return;
    }
    *out = b->c;
}

static uint64_t bound_for(uint8_t cls, uint64_t t_c0, uint64_t t_c1) {
    return cls == 1 ? t_c1 : t_c0; /* stored classes are 0/1 only. */
}

/* Oldest valid slot (lowest index ties: insertion order = FIFO). */
static int oldest(const qc_batch *b) {
    int best = -1;
    int i;

    for (i = 0; i < QC_BATCH_MAX_READINGS; i++) {
        if (!b->slot[i].valid) {
            continue;
        }
        if (best < 0 || b->slot[i].at < b->slot[best].at) {
            best = i;
        }
    }
    return best;
}

int qc_batch_ready(const qc_batch *b, uint8_t nb, uint64_t t_c0,
                   uint64_t t_c1, uint64_t now, qc_batch_close *reason) {
    int s;

    if (b == NULL || !b->init || reason == NULL || nb == 0 ||
        nb > QC_BATCH_MAX_READINGS) {
        return -1;
    }
    s = oldest(b);
    if (s < 0) {
        *reason = QC_BATCH_OPEN;
        return 0;
    }
    /* Audit note: COUNT checked first — when count AND latency hold in
     * the same call, reason reports COUNT deterministically ("earlier
     * of" is unknowable post-hoc; either closes the batch identically). */
    if (qc_batch_count(b) >= nb) {
        *reason = QC_BATCH_COUNT;
        return 1;
    }
    {
        uint64_t age = (now >= b->slot[s].at) ? now - b->slot[s].at : 0;
        if (age >= bound_for(b->slot[s].cls, t_c0, t_c1)) {
            *reason = QC_BATCH_LATENCY;
            return 1;
        }
    }
    *reason = QC_BATCH_OPEN;
    return 0;
}

static void compact(qc_batch *b) {
    uint16_t w = 0;
    int i;

    for (i = 0; i < QC_BATCH_MAX_READINGS; i++) {
        if (!b->slot[i].valid) {
            continue;
        }
        if (b->slot[i].off != w) {
            memmove(b->arena + w, b->arena + b->slot[i].off,
                    b->slot[i].len);
            b->slot[i].off = w;
        }
        w += b->slot[i].len;
    }
    b->top = w;
}

qc_batch_rc qc_batch_insert(qc_batch *b, const uint8_t *reading,
                            size_t len, uint8_t cls, uint64_t now) {
    int i, s = -1;

    if (b == NULL || !b->init) {
        return QC_BATCH_BAD_ARG;
    }
    /* C2 first: well-formed C2 is bypassed (counted, not an error);
     * malformed C2 still reports BAD_ARG. */
    if (cls == 2) {
        if (len == 0 || len > QC_BATCH_CAP ||
            (len > 0 && reading == NULL)) {
            return QC_BATCH_BAD_ARG;
        }
        b->c.c2_bypassed++;
        return QC_BATCH_C2_BYPASS;
    }
    if ((len > 0 && reading == NULL) || len == 0 ||
        len > QC_BATCH_CAP || (cls != 0 && cls != 1)) {
        return QC_BATCH_BAD_ARG;
    }
    compact(b);
    if (b->top + len > QC_BATCH_CAP) {
        b->c.refused_full++;
        return QC_BATCH_FULL;
    }
    for (i = 0; i < QC_BATCH_MAX_READINGS; i++) {
        if (!b->slot[i].valid) {
            s = i;
            break;
        }
    }
    if (s < 0) {
        b->c.refused_full++;
        return QC_BATCH_FULL;
    }
    memcpy(b->arena + b->top, reading, len);
    b->slot[s].off = b->top;
    b->slot[s].len = (uint16_t)len;
    b->slot[s].cls = cls;
    b->slot[s].valid = 1;
    b->slot[s].at = now;
    b->top += (uint16_t)len;
    b->c.inserted++;
    return QC_BATCH_OK;
}

qc_batch_rc qc_batch_pop(qc_batch *b, uint8_t *out, size_t cap,
                         size_t *len_out, uint8_t *cls_out,
                         uint64_t *age_out, uint64_t now) {
    int s;

    if (b == NULL || !b->init || out == NULL || len_out == NULL) {
        return QC_BATCH_BAD_ARG;
    }
    s = oldest(b);
    if (s < 0) {
        return QC_BATCH_EMPTY;
    }
    if (cap < b->slot[s].len) {
        *len_out = b->slot[s].len;
        return QC_BATCH_SMALL_BUF;
    }
    memcpy(out, b->arena + b->slot[s].off, b->slot[s].len);
    *len_out = b->slot[s].len;
    if (cls_out != NULL) {
        *cls_out = b->slot[s].cls;
    }
    if (age_out != NULL) {
        *age_out = (now >= b->slot[s].at) ? now - b->slot[s].at : 0;
    }
    b->slot[s].valid = 0;
    b->c.drained++;
    return QC_BATCH_OK;
}
