/* qc_alarm.c — C2 immediate path (B-24.4 mechanism).
 * Thin orchestration over qc_frame (protect) + qc_manifest_c2_sign_p
 * (gate) + qc_dsa_sign (signature). No state, no RNG, no alloc. The only
 * branching is the sign/skip gate and NULL discipline; every path is
 * pinned by tests including RNG_FAIL (explicit-rnd design makes the
 * failure path constructible — a link-time RNG could never be faulted
 * in a unit test).
 */
#include "qc_alarm.h"

#include <string.h>

#include "qc_frame.h"
#include "qc_manifest.h"

qc_alarm_rc qc_alarm_emit(uint16_t threshold, uint16_t metric,
                          qc_dsa_level dsa_level, const uint8_t *sk,
                          const uint8_t identity[16], uint8_t level,
                          uint32_t epoch, uint64_t counter,
                          const uint8_t last_root[32],
                          uint64_t range_start, uint64_t range_end,
                          const uint8_t key[32],
                          const uint8_t *payload, size_t payload_len,
                          const uint8_t rnd[32],
                          uint8_t *frame_out, size_t frame_cap,
                          size_t *frame_len,
                          uint8_t *sig_out, size_t sig_cap,
                          size_t *sig_len) {
    qc_frame_fields ff;
    size_t flen;
    int want_sig;

    if (identity == NULL || key == NULL || payload == NULL ||
        frame_out == NULL || frame_len == NULL || sig_out == NULL ||
        sig_len == NULL) {
        return QC_ALARM_BAD_ARG;
    }
    if (payload_len == 0) {
        /* Empty alarms are caller bugs (alarm carries an event); the
         * frame layer would accept empty, but C2 needs no empty path. */
        return QC_ALARM_BAD_ARG;
    }
    *frame_len = 0;
    *sig_len = 0;

    /* Sign gate: threshold met AND key present. */
    want_sig = (sk != NULL) &&
               (qc_manifest_c2_sign_p(threshold, metric) == 1);
    if (want_sig && rnd == NULL) {
        return QC_ALARM_RNG_FAIL;
    }

    memcpy(ff.identity, identity, 16);
    ff.cls = QC_CLS_C2;
    ff.level = level;
    ff.counter = counter;
    if (last_root != NULL) {
        memcpy(ff.last_root, last_root, 32);
    } else {
        memset(ff.last_root, 0, 32);
    }
    ff.range_start = range_start;
    ff.range_end = range_end;
    ff.payload = payload;
    ff.payload_len = payload_len;
    flen = qc_frame_len(payload_len);
    if (flen == 0 || flen > frame_cap) {
        return QC_ALARM_OVERSIZE;
    }
    if (qc_frame_protect(&ff, epoch, key, frame_out, flen) != QC_FRAME_OK) {
        return QC_ALARM_OVERSIZE;
    }
    *frame_len = flen;

    if (!want_sig) {
        return QC_ALARM_UNSIGNED;
    }
    {
        size_t need = qc_dsa_sig_bytes(dsa_level);
        if (need == 0 || need > sig_cap) {
            return QC_ALARM_OVERSIZE;
        }
        /* Signature covers the framed bytes (header+ct+tag). Any
         * backend failure here is a backend fault (inputs already
         * validated), not a caller or randomness failure — and nothing
         * usable is released with it (frame length zeroed: a valid
         * frame beside an error code invites silent downgrade). */
        if (qc_dsa_sign(dsa_level, sig_out, frame_out, flen,
                        NULL, 0, rnd, sk) != QC_DSA_OK) {
            *sig_len = 0;
            *frame_len = 0;
            return QC_ALARM_INTERNAL;
        }
        *sig_len = need;
    }
    return QC_ALARM_SIGNED;
}
