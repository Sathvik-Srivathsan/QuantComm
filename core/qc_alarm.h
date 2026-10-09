/* qc_alarm.h — C2 immediate path (plan B-24.4 mechanism only).
 *
 * Alarm (class C2) frames bypass batching entirely: this unit builds and
 * emits exactly one frame per call (no queue, no batch-close wait — the
 * immediacy mechanism IS the absence of batching). Signing follows the
 * evidentiary rule: sign iff caller's evidence metric meets the manifest
 * threshold AND a signing key is provided (sk NULL = production-unsigned
 * path, e.g. key unavailable).
 *
 * Randomness is an EXPLICIT parameter (rnd[32]), matching the house
 * derand philosophy (KEM/DSA adapters take coins; no hidden randomness
 * inside crypto paths): signing required but rnd NULL -> RNG_FAIL, frame
 * NOT emitted (fail-closed, visible — never a silent downgrade to
 * unsigned, which would hide an entropy outage as policy). The B-13
 * provider feeds rnd in production; tests pass fixed coins.
 *
 * Wire: frame || sig. Signature covers the framed bytes (header+ct+tag),
 * empty ctx: the device key differs from every other signing key in the
 * system, so no cross-protocol confusion is possible without key
 * compromise (at which point all bets are off anyway — documented, not
 * solved here). Unsigned alarms emit frame only (sig_len 0) and remain
 * AEAD-authenticated under the traffic key (same guarantee as all
 * traffic; signature adds non-repudiation, not confidentiality).
 *
 * NOT HERE: batching interaction (none by construction), shed order and
 * saturation policy (B-35 governor), threshold VALUE (manifest/B-25),
 * metric function (deployment-defined), audit sink (B-40), immediacy
 * measurement harness (needs the transport this bypasses; bound owned
 * here per B-24.4 but measured in E-runs, not unit tests).
 */
#ifndef QC_ALARM_H
#define QC_ALARM_H

#include <stddef.h>
#include <stdint.h>

#include "qc_dsa.h"

typedef enum {
    QC_ALARM_OK = 0,
    QC_ALARM_BAD_ARG,   /* NULL pointers (frame/sig/length outs, key...). */
    QC_ALARM_OVERSIZE,  /* payload beyond frame cap; bad DSA level or
                         * short sig buffer (sizing failures). */
    QC_ALARM_RNG_FAIL,  /* signing required but rnd NULL: nothing emitted,
                         * frame_len set 0. Fail-closed and visible. */
    QC_ALARM_UNSIGNED,  /* emitted WITHOUT signature: sk NULL (policy) or
                         * metric < threshold. Normal, expected. */
    QC_ALARM_SIGNED,    /* emitted WITH signature. */
    QC_ALARM_INTERNAL   /* backend fault with valid inputs (defensive;
                         * unreachable — all inputs validated above). */
} qc_alarm_rc;

/* Emit one C2 alarm frame (class forced C2; level = wire codepoint).
 * Epoch/counter build the frame nonce; key = traffic key (K_c2s direction
 * by convention — caller owns direction policy). last_root + range carry
 * the B-24.3 drop-distinguisher reference (NULL root and 0 range = null
 * convention for unattested sessions; WITHOUT them every C2 frame would
 * read as a dropped attestation to the verifier). rnd[32] is consumed
 * ONLY on the signing path (NULL with metric>=threshold+sk present ->
 * RNG_FAIL). frame_out must hold qc_frame_len(payload_len); sig_out must
 * hold the DSA sig bytes when signing. Lengths always set (sig_len 0
 * when unsigned; both 0 on RNG_FAIL/INTERNAL — nothing usable released). */
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
                          size_t *sig_len);

#endif