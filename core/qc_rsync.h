/* qc_rsync.h — ratchet receiver policy + cadence invariant (plan B-26.2,
 * B-26.1-invariant; timers/values/deferred parts noted below).
 *
 * RECEIVER (B-26.2): accept r in [local, local+max_skip] by fast-forwarding
 * (erase-while-advancing inside qc_ratchet_forward_to); older r drops;
 * over-skip (r > local+max_skip) drops AND signals PQ rekey (full
 * handshake — no in-band chain resync exists, so unauthenticated state
 * injection cannot advance the chain). Return codes double as the rekey
 * trigger interface: OVERSKIP_REKEY is the scheduling input the rekey
 * orchestrator (B-20/B-40 phases) consumes. max_skip is PAPER-PARAM
 * (provisional default 16, bounding per-message work to 16 Expands).
 *
 * CADENCE (B-26.1 invariant): T_r <= T_pq enforced as a CHECK, not a
 * timer — the controller proposes (T_r, T_pq), this unit accepts or
 * rejects as infeasible. Timers themselves belong to Phase 3.
 *
 * NOT HERE (explicitly out of scope for this unit):
 * - r WIRE TRANSPORT: B-21.4/B-26.1 require r in the message header as
 *   AAD, but B-24.1 defines no r field (and r != frame counter: many
 *   messages per ratchet step). This is a SPEC GAP, flagged for B-24/B-26
 *   joint resolution at phase gate — this unit consumes r as a VALUE and
 *   does not define its encoding. Do NOT extend the frame header here.
 * - T_r/T_pq VALUES, Hmax scheduling, Af-empty decision (B-26.4 OPEN),
 *   shedding (B-35), exposure accounting sink, alarm sink (B-40 audit).
 * - Rejection sampling/fuzz volume, JSONL (E0-gate formats, later).
 */
#ifndef QC_RSYNC_H
#define QC_RSYNC_H

#include <stddef.h>
#include <stdint.h>

#include "qc_ratchet.h"

/* Provisional default max-skip (PAPER-PARAM; B-26.2 rationale: tolerates
 * burst loss of 16 while bounding per-message work to 16 Expands). */
#define QC_RSYNC_MAX_SKIP_DEFAULT 16

typedef enum {
    QC_RESYNC_ACCEPT = 0, /* fast-forwarded to r; keys out. */
    QC_RESYNC_STALE,      /* r <= local: duplicate/old (caller holds this
                           * generation or newer); dropped, counted, no
                           * keys out. */
    QC_RESYNC_REKEY       /* over-skip: dropped; caller must PQ-rekey
                           * (full handshake). Never bypass. */
} qc_rsync_rc;

/* Receiver step: policy around forward_to. stale_drops counts STALE only
 * (caller-owned counter; NULL to skip counting). Returns keys only on
 * ACCEPT (out untouched otherwise).
 *
 * Disposition truth table (matches the backend exactly):
 * - r > local, within max_skip: ACCEPT (fast-forward, keys out).
 * - r <= local: STALE (duplicate — caller already holds this generation
 *   or newer; no keys out, nothing to do).
 * - r > local + max_skip: REKEY (drop + full-handshake signal).
 * Generation 0 (r == 0 at virgin i == 0) reads STALE here BY DESIGN: the
 * generation-0 keys are the session (KDF) keys, not chain output, so
 * initial-generation traffic is served from session state and MUST NOT
 * enter this unit (route at the B-24 call site). The chain serves
 * advancement (r >= 1), never inception. */
qc_rsync_rc qc_rsync_recv(qc_ratchet_state *st, uint64_t r,
                          uint64_t max_skip, uint64_t *stale_drops,
                          qc_ratchet_keys *out);

/* Cadence feasibility: T_r <= T_pq required (controller-enforced).
 * Returns 0 feasible, nonzero infeasible. Zero/zero edge: T_r == 0
 * means advance-every-message (feasible iff T_pq >= 0, always true —
 * degenerate but not infeasible); T_pq == 0 with T_r > 0 infeasible. */
int qc_rsync_check_cadence(uint64_t t_r, uint64_t t_pq);

#endif