/* qc_rsync.c — ratchet receiver policy + cadence invariant (B-26).
 * Thin, deliberate: the mechanics live in qc_ratchet_forward_to
 * (fast-forward, erase-while-advancing, over-skip bound); this unit adds
 * the drop counter, the rekey-signal taxonomy, and the cadence check.
 * Nothing here allocates, times, or persists.
 */
#include "qc_rsync.h"

qc_rsync_rc qc_rsync_recv(qc_ratchet_state *st, uint64_t r,
                          uint64_t max_skip, uint64_t *stale_drops,
                          qc_ratchet_keys *out) {
    int rc;

    /* NULL state/keys is a caller bug, not a message disposition — but
     * the taxonomy has no misuse member by design (all returns describe
     * message fate). STALE is the fail-closed member (drop), so misuse
     * degrades to drop, never to advance-or-rekey. */
    if (st == NULL || out == NULL) {
        return QC_RESYNC_STALE;
    }
    rc = qc_ratchet_forward_to(st, r, max_skip, out);
    if (rc == 0) {
        return QC_RESYNC_ACCEPT;
    }
    if (rc == 1) {
        if (stale_drops != NULL) {
            (*stale_drops)++;
        }
        return QC_RESYNC_STALE;
    }
    /* rc == 2 (over-skip) or any unexpected backend code: drop + rekey
     * signal. Fail-closed toward rekey (a fresh handshake), never
     * toward advancing on unauthenticated input. */
    return QC_RESYNC_REKEY;
}

int qc_rsync_check_cadence(uint64_t t_r, uint64_t t_pq) {
    if (t_r <= t_pq) {
        return 0;
    }
    return -1;
}
