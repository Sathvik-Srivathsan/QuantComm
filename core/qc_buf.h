/* qc_buf.h — outage store-and-forward buffer (plan B-24.5, normative).
 *
 * Link loss (gateway or server absence, indistinguishable on-device)
 * buffers PROTECTED wire frames instead of dropping them. The buffer
 * stores wire bytes VERBATIM (replay safety needs no crypto changes:
 * the server window advances only on receipt, so drained frames arrive
 * as next-expected under existing B-23/B-22 rules).
 *
 * Entry metadata (stored ALONGSIDE the frame, not in the 74 B wire
 * header — the header has no room): score u8 (caller-computed priority;
 * qc_buf_score() maps class+elevation), class, enqueue time `now`
 * (caller clock, opaque seconds, same convention as cache/DRBG), epoch
 * + counter (drain order + replay position), length.
 *
 * Rules (spec-mapped):
 * - Capacity QC_BUF_CAP (16 KB provisional, B-60 RAM line). A frame
 *   larger than the whole cap is refused (BAD_ARG, never partial).
 * - Eviction: expired first, then lowest-score-first with oldest-first
 *   ties (same-class/same-score degrades to FIFO).
 * - C2 reservation QC_BUF_C2_RSV (50% provisional): C2 bytes within the
 *   reservation are PINNED (never evicted for non-C2). Past reservation
 *   with only fresh C2 left, a new C2 insert returns C2_PRESSURE (drop
 *   counter++; the CALLER alarms locally + actuator path per spec —
 *   audit sink is B-40, so pressure is a code + counter, never silent).
 *   Non-C2 blocked by pinned C2 is DROPPED (counter++).
 * - TTLs (provisional): C2 2 h, C1 24 h, C0 6 h. Expiry enforced on
 *   insert/sweep/pop; expired drops counted (C2 expiry has its own
 *   counter for the audit requirement). Stale delivery: pop returns age
 *   (now - enqueued_at); the CALLER labels stale (never fresh) — the
 *   wire header carries no age field, so the buffer reports it.
 * - C0 decimation (1/min summaries) is PRODUCER duty (sensor layer emits
 *   summaries; payloads are opaque here) — documented, not enforced.
 * - Attestation offline falls out automatically (roots ride as frames).
 * - C2 NVS mirror (qc_buf_file.c, host): write-through file of C2
 *   entries only (bounded QC_BUF_MIRROR_CAP), temp+rename (write-then-
 *   use), repopulated on boot. C0/C1 RAM-only (reboot loss accepted).
 *   ESP32 port swaps the file TU for NVS (same header).
 *
 * Memory: static arena + fixed 32-slot directory (~17.5 KB caller BSS;
 * never stack, never heap, no threads — same discipline as qc_store).
 * Drain order: C2 by (epoch, counter) ascending, enqueued_at tiebreak;
 * then non-C2 by enqueued_at. ((epoch,counter) is the causal order the
 * server expects; counters restart per epoch, hence epoch-major.)
 */
#ifndef QC_BUF_H
#define QC_BUF_H

#include <stddef.h>
#include <stdint.h>

#define QC_BUF_CAP (16u * 1024u)
#define QC_BUF_C2_RSV (8u * 1024u)
#define QC_BUF_SLOTS 32
#define QC_BUF_MIRROR_CAP (8u * 1024u)

#define QC_BUF_TTL_C2 (2u * 3600u)
#define QC_BUF_TTL_C1 (24u * 3600u)
#define QC_BUF_TTL_C0 (6u * 3600u)

typedef enum {
    QC_BUF_OK = 0,
    QC_BUF_BAD_ARG,   /* NULLs, oversize frame (> cap), bad class. */
    QC_BUF_DROPPED,   /* non-C2 refused: only pinned C2 would move. */
    QC_BUF_C2_PRESSURE, /* C2 refused past reservation: caller alarms. */
    QC_BUF_SMALL_BUF, /* pop cap short (len_out set to need; not removed). */
    QC_BUF_EXPIRED,   /* reinsert refused: already past TTL (counted). */
    QC_BUF_EMPTY      /* pop on empty (or all-remaining expired). */
} qc_buf_rc;

typedef struct {
    uint32_t inserted;
    uint32_t evicted;
    uint32_t dropped;
    uint32_t expired_c2;  /* separately counted (audit requirement). */
    uint32_t expired_other;
    uint32_t pressure;    /* C2_PRESSURE events. */
    uint32_t drained;
    uint32_t mirror_writes;
} qc_buf_counters;

/* Score helper: C2 pinned tier, C1 high, C0 low; elevated (within 10%
 * provisional of the C2 threshold — producer evaluates) rises near-C2.
 * Producers may supply raw scores instead (ordering only). */
uint8_t qc_buf_score(uint8_t cls, int elevated);

typedef struct qc_buf qc_buf; /* opaque: state lives in qc_buf.c. */

struct qc_buf {
    uint8_t arena[QC_BUF_CAP];
    struct {
        uint16_t off;
        uint16_t len;
        uint8_t score;
        uint8_t cls;
        uint8_t valid;
        uint8_t rsv;
        uint32_t epoch;
        uint64_t counter;
        uint64_t at;
    } slot[QC_BUF_SLOTS];
    uint16_t top;   /* bump allocator head. */
    uint8_t init;
    qc_buf_counters c;
};

void qc_buf_init(qc_buf *b);

/* Store one protected frame. now = caller clock (seconds). */
qc_buf_rc qc_buf_insert(qc_buf *b, const uint8_t *frame, size_t frame_len,
                        uint8_t cls, uint8_t score, uint32_t epoch,
                        uint64_t counter, uint64_t now);

/* Boot-path reinsert with explicit enqueue time (mirror load ONLY).
 * Same admission as insert, but `at` is caller-supplied so cross-reboot
 * stale age is preserved; already-expired entries are refused COUNTED
 * (EXPIRED), never silently kept. now = current caller clock. */
qc_buf_rc qc_buf_reinsert(qc_buf *b, const uint8_t *frame, size_t frame_len,
                          uint8_t cls, uint8_t score, uint32_t epoch,
                          uint64_t counter, uint64_t at, uint64_t now);

/* Drop expired entries as of now (also runs inside insert/pop). */
void qc_buf_sweep(qc_buf *b, uint64_t now);

/* Drain one frame in drain order. age = now - enqueued_at (stale label
 * duty: caller). Skips (drops+counts) entries expired as of now. */
qc_buf_rc qc_buf_pop(qc_buf *b, uint8_t *out, size_t cap, size_t *len_out,
                     uint8_t *cls_out, uint8_t *score_out, uint64_t *age_out,
                     uint64_t now);

/* Bytes currently held (arena-occupied, for pressure telemetry). */
size_t qc_buf_used(const qc_buf *b);
void qc_buf_counts(const qc_buf *b, qc_buf_counters *out);

/* Host file mirror (qc_buf_file.c): C2 entries only. Write-through on
 * every C2 insert (caller invokes after insert returns OK for C2);
 * temp+rename (no torn mirror). Load repopulates after reboot. */
qc_buf_rc qc_buf_mirror_save(qc_buf *b, const char *path);
qc_buf_rc qc_buf_mirror_load(qc_buf *b, const char *path, uint64_t now);

#endif
