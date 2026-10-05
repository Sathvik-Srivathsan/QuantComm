/* qc_ratchet.h — hash-ratchet chain (plan B-21.4 mechanics).
 * State R (R_0 := K_rat, 32 B). Advance i (i is the transported r, uint64,
 * init 0, increments per advance; single counter, no dual counters):
 *   O_i = Expand(R_{i-1}, "ratchet"||i with i as 8-B big-endian, L=96)
 *   split O_i into (R_i, K_c2s,i, K_s2c,i), 32 B each.
 * Fresh output replaces the directional pair atomically; old R erased at
 * activation (forward-secrecy point). Two-slot commit: derive to spare slot,
 * activate, then erase old; recovery prefers newest complete slot.
 * Skip policy (max-skip value, over-skip=resync-or-reject) is owned by B-26;
 * this unit takes max_skip as a parameter and REPORTS over-skip, never acts.
 *
 * Trace hook: qc_ratchet_trace(r, R_old_erased_flag, R_new, k_c2s, k_s2c)
 * per advance, pre-wipe of old state. Test/debug only.
 */
#ifndef QC_RATCHET_H
#define QC_RATCHET_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t r_cur[32];   /* Active chain state R_{i}. */
    uint8_t r_spare[32]; /* Commit slot: newest complete derivation. */
    uint8_t k_spare_c2s[32]; /* Keys derived with r_spare (survive crash). */
    uint8_t k_spare_s2c[32];
    uint64_t i;          /* Index of r_cur (== transported r). */
    int spare_valid;     /* Whether spare holds a complete derivation. */
} qc_ratchet_state;

typedef struct {
    uint8_t k_c2s[32];
    uint8_t k_s2c[32];
} qc_ratchet_keys;

typedef void (*qc_ratchet_trace_fn)(uint64_t r_new, const uint8_t r_new_state[32],
                                    const uint8_t k_c2s[32],
                                    const uint8_t k_s2c[32]);

extern qc_ratchet_trace_fn qc_ratchet_trace;
/* Fires once per activate_spare call, pre-wipe. A crash between trace and
 * completion followed by retry re-emits the same logical index: per-call
 * exactly-once, per-index at-most-twice-across-crash (consumers dedupe). */

/* Advance one step (i -> i+1). Returns 0 ok, nonzero on bad input.
 * Fails closed if i == UINT64_MAX (never wraps; caller must rekey). */
int qc_ratchet_advance(qc_ratchet_state *st, qc_ratchet_keys *out);

/* Fast-forward to target r: advances iteratively, erasing each intermediate
 * (erase-while-advancing; skipped states never persist).
 * Returns 0 advanced; 1 target <= current (stale/duplicate: no-op, no keys);
 * 2 over-skip (target - current > max_skip: no state change, caller resyncs).
 * max_skip is caller policy (B-26 owns the value; provisional 16 in tests). */
int qc_ratchet_forward_to(qc_ratchet_state *st, uint64_t r_target,
                          uint64_t max_skip, qc_ratchet_keys *out);

/* Crash recovery: prefer newest complete slot. After an interrupted advance,
 * call once: if spare holds a complete derivation newer than r_cur, activate
 * it (and erase old) AND deliver its keys; else keep r_cur. Returns 0 kept,
 * 1 activated. out untouched when returning 0. */
int qc_ratchet_recover(qc_ratchet_state *st, qc_ratchet_keys *out);

#endif
