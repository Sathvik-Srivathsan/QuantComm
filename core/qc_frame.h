/* qc_frame.h — telemetry frame protect/open (plan B-24.1).
 *
 * Wire: header[74] || plen u32-BE || ct[plen] || tag[16].
 * Header (74 B, ALL associated data, never encrypted):
 *   identity[16] | class u8 | level u8 | counter u64-BE |
 *   last_root[32] | range_start u64-BE | range_end u64-BE.
 * AEAD = AES-256-GCM under the directional traffic key; nonce is
 * epoch-BE32 || counter-BE64 built here from explicit (epoch, counter)
 * (single source of truth: the header counter always matches the nonce).
 * GCM preserves length, so ct length == payload length; the explicit plen
 * prefix is structural per B-20.1 canonical discipline (variable-length
 * fields carry length prefixes) and is validated against the frame.
 *
 * Classes: QC_CLS_C0/C1/C2 = 0/1/2 (gap fill, flagged for phase gate —
 * B-31 owns per-class parameters, not codepoints; ordinal preserved).
 * Level reuses the M1 wire codepoints 1/2/3 (same gap-fill origin).
 * last_root/last_range are OPAQUE here (B-24.3 attestation layer sets
 * them; zeros = null/first-frame convention); this unit only binds them
 * in AAD. C2 is encodable (class field) — batching/immediacy (B-24.2/.4)
 * and buffering (B-24.5) are separate chunks; this unit neither batches
 * nor prioritizes.
 *
 * Counter/epoch discipline is the CALLER's (qc_epoch for generation,
 * qc_window for reception): this unit binds given values, never mints
 * or tracks them. Receiver session epoch is a caller input (header
 * carries counter only, per B-24.1 — no epoch field on the wire).
 *
 * Payload cap QC_FRAME_MAX_PAYLOAD (32-bit size_t safety: 74+4+len+16
 * must not approach 2^32; transport MTU bound owned by B-42).
 */
#ifndef QC_FRAME_H
#define QC_FRAME_H

#include <stddef.h>
#include <stdint.h>

#define QC_CLS_C0 0
#define QC_CLS_C1 1
#define QC_CLS_C2 2

#define QC_FRAME_HDR_LEN 74
#define QC_FRAME_TAG_LEN 16
#define QC_FRAME_MAX_PAYLOAD 65535

typedef enum {
    QC_FRAME_OK = 0,
    QC_FRAME_BAD_ARG,   /* NULL pointers. */
    QC_FRAME_OVERSIZE,  /* payload beyond cap, or length mismatch. */
    QC_FRAME_BAD_VALUE, /* class/level codepoint unknown. */
    QC_FRAME_AUTH_FAIL, /* AEAD tag mismatch (tamper). */
    QC_FRAME_SMALL_BUF  /* caller pt buffer too small (sizes first). */
} qc_frame_rc;

typedef struct {
    uint8_t identity[16];
    uint8_t cls;            /* QC_CLS_C0/C1/C2. */
    uint8_t level;          /* wire codepoint 1/2/3. */
    uint64_t counter;       /* B-23 per-direction counter value. */
    uint8_t last_root[32];  /* opaque (zeros = null). */
    uint64_t range_start;   /* opaque counter-range (zeros = empty). */
    uint64_t range_end;
    const uint8_t *payload; /* payload_len bytes (NULL iff 0). */
    size_t payload_len;
} qc_frame_fields;

/* Parsed view (borrows header pointers into frame; pt copied out). */
typedef struct {
    uint8_t identity[16];
    uint8_t cls;
    uint8_t level;
    uint64_t counter;
    uint8_t last_root[32];
    uint64_t range_start;
    uint64_t range_end;
    size_t payload_len;
} qc_frame_parsed;

/* Exact wire length for a payload (0 = over cap, never valid). */
size_t qc_frame_len(size_t payload_len);

/* Protect: header -> AAD, payload -> ct+tag. Epoch + counter build the
 * nonce (epoch-BE32 || counter-BE64); header carries counter. */
qc_frame_rc qc_frame_protect(const qc_frame_fields *f, uint32_t epoch,
                             const uint8_t key[32],
                             uint8_t *out, size_t out_len);

/* Parse header only (structural; no crypto). Fills lengths for sizing. */
qc_frame_rc qc_frame_parse_header(const uint8_t *frame, size_t frame_len,
                                  qc_frame_parsed *out);

/* Open: verify + decrypt. Caller sizes pt_out via parsed payload_len
 * (SMALL_BUF if short). epoch = receiver session epoch (nonce rebuild). */
qc_frame_rc qc_frame_open(const uint8_t *frame, size_t frame_len,
                          const uint8_t key[32], uint32_t epoch,
                          uint8_t *pt_out, size_t pt_cap,
                          qc_frame_parsed *out);

#endif