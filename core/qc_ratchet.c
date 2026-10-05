/* qc_ratchet.c — hash-ratchet chain over qc_hkdf_expand (SHA-256).
 * info = "ratchet" (7 ASCII bytes) || i as 8-B big-endian, verbatim.
 * No QC- prefix here (manuscript-verbatim info string, recorded in B-12.2).
 */
#include "qc_ratchet.h"

#include <string.h>

#include "qc_hkdf.h"

qc_ratchet_trace_fn qc_ratchet_trace = NULL;

#define QC_RATCHET_LABEL "ratchet"

static int derive_step(const uint8_t r_prev[32], uint64_t i,
                       uint8_t r_next[32], qc_ratchet_keys *keys) {
    /* info = "ratchet" || i-be64. Fixed 15 B buffer, no heap. */
    uint8_t info[7 + 8];
    uint8_t o[96];
    int rc;
    int k;

    memcpy(info, QC_RATCHET_LABEL, 7);
    for (k = 0; k < 8; k++) {
        info[7 + k] = (uint8_t)(i >> (8 * (7 - k)));
    }
    rc = qc_hkdf_expand(r_prev, info, sizeof(info), o, sizeof(o));
    memset(info, 0, sizeof(info));
    if (rc != 0) {
        memset(o, 0, sizeof(o));
        return -1;
    }
    memcpy(r_next, o, 32);
    memcpy(keys->k_c2s, o + 32, 32);
    memcpy(keys->k_s2c, o + 64, 32);
    memset(o, 0, sizeof(o));
    return 0;
}

/* Shared activation tail: publish spare (state + keys), erase old, clear spare. */
static void activate_spare(qc_ratchet_state *st, qc_ratchet_keys *out) {
    if (qc_ratchet_trace != NULL) {
        qc_ratchet_trace(st->i + 1, st->r_spare,
                         st->k_spare_c2s, st->k_spare_s2c);
    }
    memset(st->r_cur, 0, 32);
    memcpy(st->r_cur, st->r_spare, 32);
    memcpy(out->k_c2s, st->k_spare_c2s, 32);
    memcpy(out->k_s2c, st->k_spare_s2c, 32);
    memset(st->r_spare, 0, 32);
    memset(st->k_spare_c2s, 0, 32);
    memset(st->k_spare_s2c, 0, 32);
    st->spare_valid = 0;
    st->i++;
}

int qc_ratchet_advance(qc_ratchet_state *st, qc_ratchet_keys *out) {
    qc_ratchet_keys tmp;
    int rc;

    if (st == NULL || out == NULL) {
        return -1;
    }
    if (st->i == UINT64_MAX) {
        return -1; /* Never wraps; caller must rekey (B-26 path). */
    }
    if (!st->spare_valid) {
        /* Normal path: derive into spare slot (state + keys). */
        rc = derive_step(st->r_cur, st->i + 1, st->r_spare, &tmp);
        if (rc != 0) {
            return -1;
        }
        memcpy(st->k_spare_c2s, tmp.k_c2s, 32);
        memcpy(st->k_spare_s2c, tmp.k_s2c, 32);
        memset(&tmp, 0, sizeof(tmp));
        st->spare_valid = 1;
    }
    /* Else: spare already holds a complete derivation (interrupted earlier);
     * complete it idempotently. Either way the old state dies here. */
    activate_spare(st, out);
    return 0;
}

int qc_ratchet_forward_to(qc_ratchet_state *st, uint64_t r_target,
                          uint64_t max_skip, qc_ratchet_keys *out) {
    if (st == NULL || out == NULL) {
        return -1;
    }
    if (r_target <= st->i) {
        return 1; /* Stale or duplicate: no-op, no keys, no state change. */
    }
    if (r_target - st->i > max_skip) {
        return 2; /* Over-skip: no state change; caller resyncs (B-26 rule). */
    }
    while (st->i < r_target) {
        if (qc_ratchet_advance(st, out) != 0) {
            return -1;
        }
    }
    return 0;
}

int qc_ratchet_recover(qc_ratchet_state *st, qc_ratchet_keys *out) {
    if (st == NULL || out == NULL) {
        return -1;
    }
    if (!st->spare_valid) {
        return 0; /* Nothing newer: keep current. */
    }
    if (st->i == UINT64_MAX) {
        return -1; /* No next generation exists; caller must rekey. */
    }
    /* Newest complete slot wins: same activation as advance tail. */
    activate_spare(st, out);
    return 1;
}
