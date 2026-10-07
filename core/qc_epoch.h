/* qc_epoch.h — nonce lifecycle: epoch slots, counters, replay window
 * (plan B-23.1/B-23.2; B-23.3 resumption bound excluded — see below).
 *
 * EPOCH (B-23.1): 32-bit monotonic. Write-then-use in TWO redundant slots
 * ((epoch, CRC32, commit-flag) each) through caller-provided slot hooks:
 * the persistence MECHANISM is B-13.3 (file/NVS backend later); this unit
 * owns the DISCIPLINE (order, selection, recovery), testable against RAM
 * hooks today and NVS hooks tomorrow with zero logic change.
 *   - load: highest valid epoch wins (valid = commit-flag set AND CRC
 *     verifies); none valid -> UNINIT (first boot: format() provisions).
 *   - bump: new = current+1; write spare (epoch, CRC, commit LAST),
 *     re-read + verify, then retire old (clear its flag). Power loss at
 *     any point leaves the old slot valid (commit-flag-last ordering).
 *   - saturation at UINT32_MAX -> HALT error, never wrap (handshake and
 *     reboot halt before exceeding range — enforced here by refusing).
 *
 * COUNTERS (B-23.2): independent 64-bit per direction, 0 per epoch,
 * saturating (never wrap; saturation halts new nonces with an error).
 * Wire N_W = epoch-BE32 || counter-BE64 (12 B, matches B-20.1).
 *
 * REPLAY WINDOW (B-23.2): per-direction, per-epoch sliding window over
 * received (epoch, counter): 128 bits = 2x D_re (D_re default 64).
 * Older epoch -> STALE; same epoch: above-highest advances, in-window
 * unseen accepted, in-window seen -> DUP, below window -> STALE.
 * Epoch change resets the window (counters never continue across epochs).
 *
 * NOT HERE: T_res value/bound checks (consumer: resumption, B-21.5/B-26 —
 * needs the session-age clock that does not exist yet); NVS/file backend
 * (B-13.3 provides hooks); server last-seen state (qc_server already
 * enforces handshake-level strict-greater inline — different rule from
 * the traffic window here; the split is documented, not duplicated).
 *
 * SIZE: all state caller-owned static (epoch vote: 2x12 B slots +
 * counters + 16 B window mask). No heap, no threads, no time source
 * (caller drives bumps; determinism for tests).
 */
#ifndef QC_EPOCH_H
#define QC_EPOCH_H

#include <stddef.h>
#include <stdint.h>

/* Slot bytes on the wire/medium: epoch-BE32 || CRC32-IEEE(epoch) || flag.
 * CRC covers the 4 epoch bytes only; flag 0xA5 = committed. */
#define QC_EPOCH_SLOT_LEN 9
#define QC_EPOCH_COMMITTED 0xA5

/* Replay window bits (2x D_re, D_re default 64). */
#define QC_WINDOW_BITS 128

typedef enum {
    QC_EPOCH_OK = 0,
    QC_EPOCH_BAD_ARG,   /* NULL hooks/buffers. */
    QC_EPOCH_UNINIT,    /* no valid slot (first boot: format() first). */
    QC_EPOCH_SATURATED, /* epoch or counter at max: halt, never wrap. */
    QC_EPOCH_IO_FAIL    /* slot hook reported failure. */
} qc_epoch_rc;

/* Slot backend hooks (B-13.3 implements for file/NVS; tests use RAM).
 * Read/write exactly QC_EPOCH_SLOT_LEN bytes at index 0..1. Return 0
 * on success, nonzero on failure (power loss/corruption modeled by
 * failing or short reads/writes in tests). */
typedef int (*qc_slot_read_fn)(int slot, uint8_t out[QC_EPOCH_SLOT_LEN]);
typedef int (*qc_slot_write_fn)(int slot,
                                const uint8_t in[QC_EPOCH_SLOT_LEN]);

typedef struct {
    qc_slot_read_fn read;
    qc_slot_write_fn write;
    uint32_t epoch;     /* current epoch (valid after load/format/bump). */
    uint64_t counter;   /* this endpoint's SEND counter (0 per epoch). */
    uint8_t loaded;     /* nonzero once epoch holds a valid value. */
} qc_epoch;

/* Window state (one per direction per peer). */
typedef struct {
    uint32_t epoch;     /* epoch the window belongs to. */
    uint64_t highest;   /* highest accepted counter in epoch. */
    uint64_t mask[2];   /* bits 0..127: received offsets below highest
                         * (bit k = highest-1-k seen). 128-bit sliding. */
    uint8_t armed;      /* nonzero once first counter accepted. */
} qc_window;

typedef enum {
    QC_ACCEPT = 0,      /* fresh (and recorded). */
    QC_DUP,             /* seen before in window. */
    QC_STALE            /* older epoch, or below window-lowest. */
} qc_window_rc;

/* Provision a fresh store at `epoch` (first boot / re-enrollment).
 * Writes slot 0 committed, clears slot 1. */
qc_epoch_rc qc_epoch_format(qc_epoch *e, uint32_t epoch);

/* Load highest valid epoch via hooks. UNINIT if none valid. */
qc_epoch_rc qc_epoch_load(qc_epoch *e);

/* Advance to epoch+1 with write-then-use discipline; resets the send
 * counter to 0. SATURATED at UINT32_MAX (halt, never wrap). */
qc_epoch_rc qc_epoch_bump(qc_epoch *e);

/* Build the next N_W (epoch-BE32 || counter-BE64) and advance the send
 * counter. SATURATED when counter is at max (halt, never wrap). */
qc_epoch_rc qc_epoch_next(qc_epoch *e, uint8_t nw[12]);

/* Replay-window check + record (receive path). */
qc_window_rc qc_window_check(qc_window *w, uint32_t epoch, uint64_t counter);

/* CRC32-IEEE (zlib semantics) over arbitrary bytes. Exposed for the
 * slot discipline tests (check value "123456789" -> 0xCBF43926) and
 * shared with any future unit needing integrity tags. */
uint32_t qc_crc32(const uint8_t *data, size_t len);

#endif