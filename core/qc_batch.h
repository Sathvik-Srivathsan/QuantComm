/* qc_batch.h — transmission batching (plan B-24.2, normative).
 *
 * Batching groups READINGS (raw payloads, pre-framing) into one
 * transmission to cut radio events. Pipeline position: readings ->
 * batch -> frame (B-24.1 assigns counters at frame time, in drain
 * order) -> transport (B-42 packs) or outage buffer (B-24.5) on loss.
 * The batcher never frames, never transmits, never drops for age.
 *
 * Close rule (spec): transmit at the earlier of (N_b readings reached)
 * or (oldest-reading age reaches its CLASS latency bound). N_b is a
 * CONTROLLER ACTION: per-call input (1..32), already governor-
 * overridden upstream under empty budget (B-35 wins there; this unit
 * just obeys the N_b it is given). Per-class latency bounds are B-31-
 * owned values: CALLER-SUPPLIED per call (t_c0, t_c1 seconds) —
 * deliberately NO provisional defaults in code (unlike buffer TTLs,
 * the plan states no defaults; tests use labeled test values only).
 *
 * C2 is NEVER batched (B-24.4 immediate path): insert refuses C2 with
 * C2_BYPASS (not an error — route to the immediate path; counted).
 * Latency bounds never DROP (unlike buffer TTLs): an over-age oldest
 * FORCES close (transmit now). Full batch (32 readings or 4 KB) refuses
 * newest with FULL + counter (shedding is B-35's job; this unit only
 * reports). FIFO drain (oldest first); pop reports age for logging.
 *
 * Memory: static 4 KB arena + 32-slot dir (caller BSS, never stack,
 * never heap, no threads — same discipline as buf/store).
 *
 * Caller contracts (clash-probe findings): the batch never self-flushes
 * — the caller MUST poll ready() (a batch left unpolled holds readings
 * indefinitely; "nothing is batched to the end" holds iff polled). N_b
 * bound 32 is provisional (B-31 values N_b; FULL is reported, never
 * silent, if valued above — fail-loud for re-valuation, not a silent
 * cap). B-40 server-side retention is a SEPARATE future unit (never
 * qc_buf — name reserved here for the device outage buffer).
 */
#ifndef QC_BATCH_H
#define QC_BATCH_H

#include <stddef.h>
#include <stdint.h>

#define QC_BATCH_CAP (4u * 1024u)
#define QC_BATCH_MAX_READINGS 32

typedef enum {
    QC_BATCH_OK = 0,
    QC_BATCH_BAD_ARG, /* NULLs, bad class, oversize, nb out of 1..32. */
    QC_BATCH_FULL,    /* newest refused (count or byte cap) + counter. */
    QC_BATCH_C2_BYPASS, /* C2 offered: use the immediate path (counted). */
    QC_BATCH_SMALL_BUF, /* pop cap short (len set; entry retained). */
    QC_BATCH_EMPTY    /* pop on empty. */
} qc_batch_rc;

typedef enum {
    QC_BATCH_OPEN = 0,  /* keep accumulating. */
    QC_BATCH_COUNT,     /* N_b reached. */
    QC_BATCH_LATENCY    /* oldest hit its class bound. */
} qc_batch_close;

typedef struct {
    uint32_t inserted;
    uint32_t drained;
    uint32_t refused_full;
    uint32_t c2_bypassed;
} qc_batch_counters;

typedef struct {
    uint8_t arena[QC_BATCH_CAP];
    struct {
        uint16_t off;
        uint16_t len;
        uint8_t cls;    /* 0/1 only (C2 never stored). */
        uint8_t valid;
        uint64_t at;
    } slot[QC_BATCH_MAX_READINGS];
    uint16_t top;
    uint8_t init;
    qc_batch_counters c;
} qc_batch;

void qc_batch_init(qc_batch *b);

/* 1 = close now (reason set), 0 = keep accumulating, -1 = bad arg. */
int qc_batch_ready(const qc_batch *b, uint8_t nb, uint64_t t_c0,
                   uint64_t t_c1, uint64_t now, qc_batch_close *reason);

/* Accumulate one reading (bytes copied). */
qc_batch_rc qc_batch_insert(qc_batch *b, const uint8_t *reading,
                            size_t len, uint8_t cls, uint64_t now);

/* Oldest-first drain (caller frames each in order). */
qc_batch_rc qc_batch_pop(qc_batch *b, uint8_t *out, size_t cap,
                         size_t *len_out, uint8_t *cls_out,
                         uint64_t *age_out, uint64_t now);

size_t qc_batch_count(const qc_batch *b);
void qc_batch_counts(const qc_batch *b, qc_batch_counters *out);

#endif
