/* qc_manifest.h — policy manifest schema + verify + store (plan B-25.1/.2).
 *
 * Canonical body (fixed order, big-endian, exact sizes):
 *   version u32 | n_floors u16 | floors[class u8, min_level u8]* |
 *   n_profiles u16 | profile_id u8* | hmax u32 | t_cool u32 |
 *   c2_threshold u16 | next_key_len u16 | next_key bytes.
 * Total capped at QC_MFT_MAX_BODY (4 KB provisional). Floor entries must
 * be in strictly ascending class order (canonical form — same manifest
 * always encodes identically, so signatures are stable); duplicates or
 * disorder fail closed. Class codes reuse QC_CLS_C0/C1/C2 (0/1/2);
 * min_level reuses wire codepoints 1/2/3. Profile IDs are opaque u8
 * (B-30 owns meaning; membership predicate lives here).
 *
 * Verify-before-apply order (B-25.2): structural parse -> version
 * strictly-greater pre-check (drop, zero public-key work) -> rate cap
 * (6/hour sliding, drop) -> ML-DSA verify under the ENROLLED key over
 * the canonical bytes (empty ctx) -> apply (store body+version; rotate
 * enrolled key iff next_key non-empty with recognized length).
 * Next-key level is inferred from length (1312/1952/2592 -> 44/65/87 —
 * unambiguous); unrecognized length refuses the rotation (MALFORMED).
 *
 * Rate limiting uses caller `now` (opaque monotonic seconds; clock
 * discipline is the caller's, same convention as the replay cache).
 * Version persistence across reboot is B-13 NVS (this store is RAM;
 * save/load hooks arrive with the backend — the store bytes ARE the
 * persistable image: version + body + enrolled key, all fixed layout).
 *
 * NOT HERE: floor-change authorization semantics (B-25.3), risk hints
 * (B-25.4), threshold evaluation (B-25.5) — next chunk. Audit sink is
 * B-40 (return codes carry outcomes; no-secret rule: bodies hold no keys
 * except public next_server_key by design).
 */
#ifndef QC_MANIFEST_H
#define QC_MANIFEST_H

#include <stddef.h>
#include <stdint.h>

#include "qc_dsa.h"

#define QC_MFT_MAX_BODY 4096
#define QC_MFT_VERIFY_PER_HOUR 6
#define QC_MFT_RATE_WINDOW_S 3600

typedef enum {
    QC_MFT_OK_APPLIED = 0,
    QC_MFT_OK = 0,          /* alias: non-applying checks passed. */
    QC_MFT_NOT_FOUND,   /* no persisted state (neither store nor image):
                          * fresh device — SL1 static floors + B-41
                          * re-enrollment own this path (added for the
                          * NVS wiring; no other unit returns it). */
    QC_MFT_BAD_ARG,     /* NULL pointers. */
    QC_MFT_MALFORMED,   /* structural/schema violation (incl. disorder,
                         * duplicates, oversize, bad codepoints, unknown
                         * next-key length). */
    QC_MFT_STALE,       /* version <= stored (dropped pre-verify: zero
                         * public-key work performed). */
    QC_MFT_RATE_LIMITED,/* >6 verify attempts in the sliding hour. */
    QC_MFT_BAD_SIG,     /* ML-DSA verify failed. */
    QC_MFT_FLOOR_REFUSED, /* floor entry lost in restructure (implicit
                         * lowering): manifest must not apply its floors. */
    QC_MFT_HINT_REPLAY, /* hint seq <= last-seen (replay/duplicate). */
    QC_MFT_HINT_RATE,   /* >10 hints in the sliding minute. */
    QC_MFT_HINT_DEESCALATE /* level below current: ignored (never acts). */
} qc_mft_rc;

typedef struct {
    uint8_t cls;        /* 0/1/2. */
    uint8_t min_level;  /* wire 1/2/3. */
} qc_floor_entry;

typedef struct {
    uint32_t version;
    const qc_floor_entry *floors;
    size_t n_floors;
    const uint8_t *profiles;
    size_t n_profiles;
    uint32_t hmax;
    uint32_t t_cool;
    uint16_t c2_threshold;
    const uint8_t *next_key;    /* NULL iff len 0 (no rotation). */
    size_t next_key_len;
} qc_manifest_fields;

/* Parsed view (borrows into body; no copy, no alloc). */
typedef struct {
    uint32_t version;
    const qc_floor_entry *floors;
    size_t n_floors;
    const uint8_t *profiles;
    size_t n_profiles;
    uint32_t hmax;
    uint32_t t_cool;
    uint16_t c2_threshold;
    const uint8_t *next_key;
    size_t next_key_len;
} qc_manifest_parsed;

/* Store: enrolled key + current manifest + rate window. ~7 KB:
 * static storage, never stack (same rule as server/cache units).
 * The persistable image (B-13) is exactly: version || body_len ||
 * body || enrolled_level || enrolled_pk — fixed layout, no pointers. */
typedef struct {
    uint8_t initialized;
    qc_dsa_level enrolled_level;
    uint8_t enrolled_pk[2592];
    uint32_t version;       /* 0 = none stored yet. */
    uint8_t has_manifest;
    uint8_t body[QC_MFT_MAX_BODY];
    size_t body_len;
    uint64_t verify_times[QC_MFT_VERIFY_PER_HOUR];
    size_t n_times;
} qc_manifest_store;

/* Provisioning: enroll server key (level + exact-size bytes). Clears. */
qc_mft_rc qc_manifest_init(qc_manifest_store *s, qc_dsa_level level,
                           const uint8_t *pk);

/* Exact encoded length (0 = oversize/invalid: never a valid length —
 * smallest real body is 20 B). */
size_t qc_manifest_encode_len(const qc_manifest_fields *f);

/* Encode (out_len must equal encode_len exactly). */
qc_mft_rc qc_manifest_encode(const qc_manifest_fields *f,
                             uint8_t *out, size_t out_len);

/* Parse + validate (canonical order, codepoints, cap). */
qc_mft_rc qc_manifest_parse(const uint8_t *body, size_t len,
                            qc_manifest_parsed *out);

/* Verify-before-apply in B-25.2 order. sig fixed per enrolled level. */
qc_mft_rc qc_manifest_verify_apply(qc_manifest_store *s,
                                   const uint8_t *body, size_t body_len,
                                   const uint8_t *sig, size_t sig_len,
                                   uint64_t now);

/* Floor authorization (B-25.3): pure pre-check, no mutation. Caller order
 * is parse -> check_floors -> verify_apply (emit-before-apply: the event
 * below is constructed before anything mutates; the B-40 sink consumes it
 * later). Every CURRENT floor id must exist in the new table (absent =
 * implicit lowering via restructure -> FLOOR_REFUSED, whole manifest's
 * floors must not apply). Present-with-lower-value IS allowed here
 * (authorized reduction rides on the manifest's own signature+version,
 * verified by the caller next); unchanged floors are omitted from the
 * event. No stored manifest yet -> OK with empty event. */
#define QC_FLOOR_EVENT_MAX 64

typedef struct {
    uint8_t cls;
    uint8_t old_level;
    uint8_t new_level;
} qc_floor_change;

typedef struct {
    uint32_t version;       /* new manifest version. */
    size_t n_changes;
    uint8_t truncated;      /* nonzero if changes exceeded MAX (caller
                             * must treat as audit gap, not silent). */
    qc_floor_change changes[QC_FLOOR_EVENT_MAX];
} qc_floor_event;

qc_mft_rc qc_manifest_check_floors(const qc_manifest_store *s,
                                   const qc_manifest_parsed *p,
                                   qc_floor_event *ev);

/* Risk-hint gate (B-25.4): input bytes are already AEAD-authenticated by
 * the caller (hint processing never triggers public-key work). Accepts
 * iff seq > last-seen AND level >= current AND rate allows; updates
 * (last_seq, last_level) on accept only. Level ordering is opaque u8
 * (B-32 owns semantics; escalate = numerically >=). Reset on every new
 * handshake/epoch (last 0/0/empty). Caller clock `now` in seconds. */
#define QC_HINT_PER_MIN 10
#define QC_HINT_WINDOW_S 60

typedef struct {
    uint64_t last_seq;
    uint8_t last_level;
    uint8_t has_seen;
    uint64_t times[QC_HINT_PER_MIN];
    size_t n_times;
} qc_hint_state;

void qc_hint_reset(qc_hint_state *h);
qc_mft_rc qc_hint_check(qc_hint_state *h, uint64_t seq, uint8_t level,
                        uint64_t now);

/* C2 evidentiary rule (B-25.5): sign the alarm iff metric >= threshold.
 * Both from the manifest (threshold) and deployment metric function;
 * this unit owns the comparison only. Boundary inclusive. */
int qc_manifest_c2_sign_p(uint16_t threshold, uint16_t metric);

#endif
