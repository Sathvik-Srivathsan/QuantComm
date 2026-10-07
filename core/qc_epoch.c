/* qc_epoch.c — nonce lifecycle discipline (B-23.1/B-23.2).
 * Slot order (write-then-use, B-23.1): write spare (epoch, CRC, commit
 * flag LAST) -> re-read + verify -> retire old (clear its flag). Power
 * loss at any point leaves the previous slot valid: before commit-flag
 * write the spare fails CRC/flag check (old wins); after commit both are
 * valid and highest wins (same epoch — harmless); retire-old only clears
 * the loser. There is no order in which both slots are invalid unless the
 * medium itself lost committed bytes (UNINIT -> halt, never guess).
 */
#include "qc_epoch.h"

#include <string.h>

/* CRC32-IEEE, bit-at-a-time (clarity over speed: 9-byte slots; the
 * polynomial 0xEDB88320 check value for "123456789" is 0xCBF43926). */
uint32_t qc_crc32(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    size_t i, b;

    for (i = 0; i < len; i++) {
        crc ^= data[i];
        for (b = 0; b < 8; b++) {
            if (crc & 1u) {
                crc = (crc >> 1) ^ 0xEDB88320u;
            } else {
                crc >>= 1;
            }
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

static void encode_slot(uint32_t epoch, uint8_t out[QC_EPOCH_SLOT_LEN]) {
    uint32_t crc;
    uint8_t ebytes[4];

    ebytes[0] = (uint8_t)(epoch >> 24);
    ebytes[1] = (uint8_t)(epoch >> 16);
    ebytes[2] = (uint8_t)(epoch >> 8);
    ebytes[3] = (uint8_t)epoch;
    crc = qc_crc32(ebytes, 4);
    memcpy(out, ebytes, 4);
    out[4] = (uint8_t)(crc >> 24);
    out[5] = (uint8_t)(crc >> 16);
    out[6] = (uint8_t)(crc >> 8);
    out[7] = (uint8_t)crc;
    out[8] = QC_EPOCH_COMMITTED;
}

/* Parse + validate one slot. Returns 1 with *epoch set iff committed AND
 * CRC verifies; 0 otherwise (blank/corrupt/torn write/uncommitted). */
static int read_valid(qc_epoch *e, int slot, uint32_t *epoch) {
    uint8_t buf[QC_EPOCH_SLOT_LEN];
    uint8_t ebytes[4];
    uint32_t crc;

    if (e->read(slot, buf) != 0) {
        return 0;
    }
    if (buf[8] != QC_EPOCH_COMMITTED) {
        return 0;
    }
    memcpy(ebytes, buf, 4);
    crc = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
          ((uint32_t)buf[6] << 8) | (uint32_t)buf[7];
    if (crc != qc_crc32(ebytes, 4)) {
        return 0;
    }
    *epoch = ((uint32_t)ebytes[0] << 24) | ((uint32_t)ebytes[1] << 16) |
             ((uint32_t)ebytes[2] << 8) | (uint32_t)ebytes[3];
    return 1;
}

/* Clear a slot's commit flag (retire). Best-effort: I/O failure here is
 * reported (caller decides; the old slot staying valid is fail-safe —
 * next load picks highest valid, which is still correct). */
static int retire_slot(qc_epoch *e, int slot) {
    uint8_t buf[QC_EPOCH_SLOT_LEN];

    if (e->read(slot, buf) != 0) {
        return -1;
    }
    buf[8] = 0x00;
    if (e->write(slot, buf) != 0) {
        return -1;
    }
    return 0;
}

qc_epoch_rc qc_epoch_format(qc_epoch *e, uint32_t epoch) {
    uint8_t buf[QC_EPOCH_SLOT_LEN];

    if (e == NULL || e->read == NULL || e->write == NULL) {
        return QC_EPOCH_BAD_ARG;
    }
    encode_slot(epoch, buf);
    if (e->write(0, buf) != 0) {
        return QC_EPOCH_IO_FAIL;
    }
    memset(buf, 0, sizeof(buf));
    if (e->write(1, buf) != 0) {
        return QC_EPOCH_IO_FAIL;
    }
    e->epoch = epoch;
    e->counter = 0;
    e->loaded = 1;
    return QC_EPOCH_OK;
}

qc_epoch_rc qc_epoch_load(qc_epoch *e) {
    uint32_t e0, e1;
    int v0, v1;

    if (e == NULL || e->read == NULL || e->write == NULL) {
        return QC_EPOCH_BAD_ARG;
    }
    v0 = read_valid(e, 0, &e0);
    v1 = read_valid(e, 1, &e1);
    if (!v0 && !v1) {
        e->loaded = 0;
        return QC_EPOCH_UNINIT;
    }
    /* Both valid: highest wins. Ties impossible through this API
     * (bump always advances), but >= keeps it deterministic if the
     * medium was written out-of-band. */
    if (v0 && (!v1 || e0 >= e1)) {
        e->epoch = e0;
    } else {
        e->epoch = e1;
    }
    e->counter = 0;
    e->loaded = 1;
    return QC_EPOCH_OK;
}

qc_epoch_rc qc_epoch_bump(qc_epoch *e) {
    uint32_t cur;
    int spare, rc;
    uint8_t buf[QC_EPOCH_SLOT_LEN];
    uint32_t check;

    if (e == NULL || e->read == NULL || e->write == NULL || !e->loaded) {
        return QC_EPOCH_BAD_ARG;
    }
    if (e->epoch == UINT32_MAX) {
        return QC_EPOCH_SATURATED;
    }
    cur = e->epoch + 1;
    /* Spare = the slot NOT holding current epoch. Find current by value;
     * if neither slot holds it (out-of-band medium state), use slot 1
     * and let highest-valid-wins sort it out on next load. */
    if (read_valid(e, 0, &check) && check == e->epoch) {
        spare = 1;
    } else if (read_valid(e, 1, &check) && check == e->epoch) {
        spare = 0;
    } else {
        spare = 1;
    }
    encode_slot(cur, buf);
    if (e->write(spare, buf) != 0) {
        return QC_EPOCH_IO_FAIL;
    }
    /* Verify by re-read BEFORE retiring old (commit-then-verify order:
     * the new slot must read back valid while old is still valid). */
    if (!read_valid(e, spare, &check) || check != cur) {
        return QC_EPOCH_IO_FAIL;
    }
    /* Retire old best-effort (failure leaves two valid slots; highest
     * wins on next load — still correct, just untidy). */
    rc = retire_slot(e, spare ^ 1);
    e->epoch = cur;
    e->counter = 0;
    return rc == 0 ? QC_EPOCH_OK : QC_EPOCH_IO_FAIL;
}

qc_epoch_rc qc_epoch_next(qc_epoch *e, uint8_t nw[12]) {
    uint64_t c;

    if (e == NULL || nw == NULL || !e->loaded) {
        return QC_EPOCH_BAD_ARG;
    }
    if (e->counter == UINT64_MAX) {
        return QC_EPOCH_SATURATED;
    }
    c = e->counter;
    nw[0] = (uint8_t)(e->epoch >> 24);
    nw[1] = (uint8_t)(e->epoch >> 16);
    nw[2] = (uint8_t)(e->epoch >> 8);
    nw[3] = (uint8_t)e->epoch;
    nw[4] = (uint8_t)(c >> 56);
    nw[5] = (uint8_t)(c >> 48);
    nw[6] = (uint8_t)(c >> 40);
    nw[7] = (uint8_t)(c >> 32);
    nw[8] = (uint8_t)(c >> 24);
    nw[9] = (uint8_t)(c >> 16);
    nw[10] = (uint8_t)(c >> 8);
    nw[11] = (uint8_t)c;
    e->counter = c + 1;
    return QC_EPOCH_OK;
}

qc_window_rc qc_window_check(qc_window *w, uint32_t epoch, uint64_t counter) {
    uint64_t d;

    if (w == NULL) {
        return QC_STALE;
    }
    if (!w->armed || epoch != w->epoch) {
        if (!w->armed || epoch > w->epoch) {
            /* First counter, or new epoch: reset window, accept. Older
             * epoch falls through to STALE below. */
            w->epoch = epoch;
            w->highest = counter;
            w->mask[0] = 0;
            w->mask[1] = 0;
            w->armed = 1;
            return QC_ACCEPT;
        }
        return QC_STALE;
    }
    if (counter > w->highest) {
        /* Advance: shift the mask by the gap (gap >= 128 clears all). */
        d = counter - w->highest;
        if (d >= QC_WINDOW_BITS) {
            w->mask[0] = 0;
            w->mask[1] = 0;
        } else {
            /* Shift left by d across the 128-bit pair, then the newly
             * covered range (offsets 1..d-1 below new highest) is unseen
             * (bits stay 0); offset 0 (the new highest itself) is the
             * arriving counter — accepted, not marked (highest needs no
             * bit; bit k tracks highest-1-k). */
            /* Advance also marks the OLD highest seen (bit d-1): it was
             * accepted on arrival, and the shift alone would forget it
             * (a repeat would wrongly ACCEPT instead of DUP). Gap >= 128
             * needs no mark (old highest is outside the window: a repeat
             * reads STALE per the below-window rule — correct). */
            uint64_t lo = w->mask[0], hi = w->mask[1];
            if (d >= 64) {
                w->mask[1] = lo << (d - 64);
                w->mask[0] = 0;
            } else {
                /* d in 1..63 here (counter > highest guarantees d >= 1;
                 * d >= 128 handled above, so no shift-by-64 UB). */
                w->mask[1] = (hi << d) | (lo >> (64 - d));
                w->mask[0] = lo << d;
            }
            if ((d - 1) < 64) {
                w->mask[0] |= (uint64_t)1 << (d - 1);
            } else {
                w->mask[1] |= (uint64_t)1 << (d - 1 - 64);
            }
        }
        w->highest = counter;
        return QC_ACCEPT;
    }
    d = w->highest - counter;
    if (d == 0) {
        /* Equal to highest: the highest itself was accepted on arrival
         * (or armed this window) — a repeat is a duplicate. */
        return QC_DUP;
    }
    if (d >= QC_WINDOW_BITS) {
        return QC_STALE;
    }
    /* Bit (d-1): offset d below highest lives at mask bit d-1. */
    {
        uint64_t bit = (d - 1) < 64 ? (w->mask[0] >> (d - 1)) & 1u
                                    : (w->mask[1] >> (d - 1 - 64)) & 1u;
        if (bit) {
            return QC_DUP;
        }
        if ((d - 1) < 64) {
            w->mask[0] |= (uint64_t)1 << (d - 1);
        } else {
            w->mask[1] |= (uint64_t)1 << (d - 1 - 64);
        }
        return QC_ACCEPT;
    }
}
