/* qc_buf.c — outage store-and-forward buffer (B-24.5).
 * Static arena + fixed slot directory; bump append, mark-invalid evict,
 * memmove compact on demand. No heap, no threads, caller clock.
 */
#include "qc_buf.h"

#include <string.h>

static uint64_t ttl_for(uint8_t cls) {
    if (cls == 2) {
        return QC_BUF_TTL_C2;
    }
    if (cls == 1) {
        return QC_BUF_TTL_C1;
    }
    return QC_BUF_TTL_C0;
}

static int valid_cls(uint8_t c) {
    return c == 0 || c == 1 || c == 2;
}

uint8_t qc_buf_score(uint8_t cls, int elevated) {
    if (cls == 2) {
        return 0xFF;
    }
    if (cls == 1) {
        return elevated ? 0xF0 : 0x80;
    }
    return elevated ? 0x20 : 0x10;
}

void qc_buf_init(qc_buf *b) {
    if (b == NULL) {
        return;
    }
    memset(b, 0, sizeof(*b));
    b->init = 1;
}

size_t qc_buf_used(const qc_buf *b) {
    size_t n = 0;
    int i;

    if (b == NULL || !b->init) {
        return 0;
    }
    for (i = 0; i < QC_BUF_SLOTS; i++) {
        if (b->slot[i].valid) {
            n += b->slot[i].len;
        }
    }
    return n;
}

void qc_buf_counts(const qc_buf *b, qc_buf_counters *out) {
    if (b == NULL || out == NULL) {
        return;
    }
    *out = b->c;
}

/* Compact: move valid entries down, preserving slot ORDER (slot index
 * doubles as insertion sequence for oldest-tie eviction). */
static void compact(qc_buf *b) {
    uint16_t w = 0;
    int i;

    for (i = 0; i < QC_BUF_SLOTS; i++) {
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

/* Drop expired entries as of now (counts by class). */
static void drop_expired(qc_buf *b, uint64_t now) {
    int i;

    for (i = 0; i < QC_BUF_SLOTS; i++) {
        uint64_t age;

        if (!b->slot[i].valid) {
            continue;
        }
        /* Clock skew (at > now): age 0 here and at pop (same guarded
         * form both places — never wraps, never instantly expires;
         * a rebooted-older clock simply delays expiry, fail-open on
         * retention only, never on acceptance). */
        age = (now >= b->slot[i].at) ? now - b->slot[i].at : 0;
        if (age >= ttl_for(b->slot[i].cls)) {
            b->slot[i].valid = 0;
            if (b->slot[i].cls == 2) {
                b->c.expired_c2++;
            } else {
                b->c.expired_other++;
            }
        }
    }
}

void qc_buf_sweep(qc_buf *b, uint64_t now) {
    if (b == NULL || !b->init) {
        return;
    }
    drop_expired(b, now);
}

static size_t c2_bytes(const qc_buf *b) {
    size_t n = 0;
    int i;

    for (i = 0; i < QC_BUF_SLOTS; i++) {
        if (b->slot[i].valid && b->slot[i].cls == 2) {
            n += b->slot[i].len;
        }
    }
    return n;
}

/* Victim: lowest score among evictable, oldest (lowest slot index) tie.
 * Evictable = non-C2 always + C2 only for bytes past the reservation
 * (approximated per-entry: a C2 entry is evictable iff total C2 exceeds
 * the reservation — uniform rule, documented in header). Returns -1 if
 * only pinned entries remain. */
static int pick_victim(qc_buf *b) {
    int best = -1;
    int i;

    for (i = 0; i < QC_BUF_SLOTS; i++) {
        if (!b->slot[i].valid) {
            continue;
        }
        if (b->slot[i].cls == 2 && c2_bytes(b) <= QC_BUF_C2_RSV) {
            continue; /* pinned */
        }
        if (best < 0 || b->slot[i].score < b->slot[best].score) {
            best = i;
        }
        /* Strict <: earlier slot (older) wins ties automatically. */
    }
    return best;
}

static int free_slot(qc_buf *b) {
    int i;

    for (i = 0; i < QC_BUF_SLOTS; i++) {
        if (!b->slot[i].valid) {
            return i;
        }
    }
    return -1;
}

static qc_buf_rc insert_at(qc_buf *b, const uint8_t *frame, size_t len,
                           uint8_t cls, uint8_t score, uint32_t epoch,
                           uint64_t counter, uint64_t at) {
    int s;

    drop_expired(b, at);
    compact(b);
    while (b->top + len > QC_BUF_CAP) {
        int v = pick_victim(b);
        if (v < 0) {
            break;
        }
        b->slot[v].valid = 0;
        b->c.evicted++;
        compact(b);
    }
    if (b->top + len > QC_BUF_CAP) {
        if (cls == 2) {
            b->c.pressure++;
            return QC_BUF_C2_PRESSURE;
        }
        b->c.dropped++;
        return QC_BUF_DROPPED;
    }
    s = free_slot(b);
    if (s < 0) {
        /* Arena fits but directory full (32 tiny frames): treat like
         * pressure/drop — no silent merge, no slot reuse. */
        if (cls == 2) {
            b->c.pressure++;
            return QC_BUF_C2_PRESSURE;
        }
        b->c.dropped++;
        return QC_BUF_DROPPED;
    }
    memcpy(b->arena + b->top, frame, len);
    b->slot[s].off = b->top;
    b->slot[s].len = (uint16_t)len;
    b->slot[s].score = score;
    b->slot[s].cls = cls;
    b->slot[s].valid = 1;
    b->slot[s].rsv = 0;
    b->slot[s].epoch = epoch;
    b->slot[s].counter = counter;
    b->slot[s].at = at;
    b->top += (uint16_t)len;
    b->c.inserted++;
    return QC_BUF_OK;
}

qc_buf_rc qc_buf_insert(qc_buf *b, const uint8_t *frame, size_t frame_len,
                        uint8_t cls, uint8_t score, uint32_t epoch,
                        uint64_t counter, uint64_t now) {
    if (b == NULL || !b->init || (frame_len > 0 && frame == NULL) ||
        frame_len == 0 || frame_len > QC_BUF_CAP || !valid_cls(cls)) {
        return QC_BUF_BAD_ARG;
    }
    return insert_at(b, frame, frame_len, cls, score, epoch, counter, now);
}

qc_buf_rc qc_buf_reinsert(qc_buf *b, const uint8_t *frame, size_t frame_len,
                          uint8_t cls, uint8_t score, uint32_t epoch,
                          uint64_t counter, uint64_t at, uint64_t now) {
    uint64_t age;

    if (b == NULL || !b->init || (frame_len > 0 && frame == NULL) ||
        frame_len == 0 || frame_len > QC_BUF_CAP || !valid_cls(cls)) {
        return QC_BUF_BAD_ARG;
    }
    age = (now >= at) ? now - at : 0;
    if (age >= ttl_for(cls)) {
        if (cls == 2) {
            b->c.expired_c2++;
        } else {
            b->c.expired_other++;
        }
        return QC_BUF_EXPIRED;
    }
    return insert_at(b, frame, frame_len, cls, score, epoch, counter, at);
}

/* Next-to-drain slot: C2 by (epoch, counter, at); else non-C2 by at
 * ((epoch,counter) tiebreak). Returns -1 when empty. */
static int select_next(qc_buf *b) {
    int best = -1;
    int i;

    for (i = 0; i < QC_BUF_SLOTS; i++) {
        if (!b->slot[i].valid || b->slot[i].cls != 2) {
            continue;
        }
        if (best < 0 ||
            b->slot[i].epoch < b->slot[best].epoch ||
            (b->slot[i].epoch == b->slot[best].epoch &&
             b->slot[i].counter < b->slot[best].counter) ||
            (b->slot[i].epoch == b->slot[best].epoch &&
             b->slot[i].counter == b->slot[best].counter &&
             b->slot[i].at < b->slot[best].at)) {
            best = i;
        }
    }
    if (best >= 0) {
        return best;
    }
    for (i = 0; i < QC_BUF_SLOTS; i++) {
        if (!b->slot[i].valid) {
            continue;
        }
        if (best < 0 || b->slot[i].at < b->slot[best].at ||
            (b->slot[i].at == b->slot[best].at &&
             (b->slot[i].epoch < b->slot[best].epoch ||
              (b->slot[i].epoch == b->slot[best].epoch &&
               b->slot[i].counter < b->slot[best].counter)))) {
            best = i;
        }
    }
    return best;
}

qc_buf_rc qc_buf_pop(qc_buf *b, uint8_t *out, size_t cap, size_t *len_out,
                     uint8_t *cls_out, uint8_t *score_out, uint64_t *age_out,
                     uint64_t now) {
    int s;

    if (b == NULL || !b->init || out == NULL || len_out == NULL) {
        return QC_BUF_BAD_ARG;
    }
    drop_expired(b, now);
    for (;;) {
        s = select_next(b);
        if (s < 0) {
            return QC_BUF_EMPTY;
        }
        /* Expiry re-check at pop (drop_expired above covers now; this
         * loop also skips anything it missed — belt and braces). */
        {
            uint64_t age = (now >= b->slot[s].at) ? now - b->slot[s].at : 0;
            if (age >= ttl_for(b->slot[s].cls)) {
                b->slot[s].valid = 0;
                if (b->slot[s].cls == 2) {
                    b->c.expired_c2++;
                } else {
                    b->c.expired_other++;
                }
                continue;
            }
            if (cap < b->slot[s].len) {
                *len_out = b->slot[s].len;
                return QC_BUF_SMALL_BUF;
            }
            memcpy(out, b->arena + b->slot[s].off, b->slot[s].len);
            *len_out = b->slot[s].len;
            if (cls_out != NULL) {
                *cls_out = b->slot[s].cls;
            }
            if (score_out != NULL) {
                *score_out = b->slot[s].score;
            }
            if (age_out != NULL) {
                *age_out = age;
            }
            b->slot[s].valid = 0;
            b->c.drained++;
            return QC_BUF_OK;
        }
    }
}
