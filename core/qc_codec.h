/* qc_codec.h — M1/M2 codecs + transcript (plan B-20.1).
 *
 * M1 (W->S): version u8(=1) | identity[16] | L u8 | ek_W[ek_len] |
 *   ct_S[ct_len] | N_W[12] | HMAC-Kdev[32] over all preceding, exact order.
 * M2 (S->W): version u8(==M1) | ct_W[ct_len] | N_S[32] |
 *   confirm-MAC[32] (HMAC-K_conf over transcript incl. L).
 * All integers fixed-width big-endian; byte strings concatenated with no
 * length prefixes (every field fixed-size given ek_len/ct_len).
 * ek/ct material is OPAQUE here (filled by the KEM layer later); the codec
 * takes byte lengths, never a level table (single-source: B-10.1 owns sizes;
 * tests use B-10.1 values as cited test constants).
 * Transcript = FULL M1 bytes || M2-body bytes (MAC-inclusion rule and
 * step-visibility statement defined at qc_transcript_build below; this
 * header states each rule exactly once).
 */
#ifndef QC_CODEC_H
#define QC_CODEC_H

#include <stddef.h>
#include <stdint.h>

#define QC_M1_VERSION 1
#define QC_ID_LEN 16
#define QC_NONCE_LEN 12
#define QC_NS_LEN 32
#define QC_MAC_LEN 32

/* Largest single variable field accepted (frames bigger than this are
 * nonsense on the target transports and would risk size_t wraparound
 * in length arithmetic). Way above the largest level size (1568 B). */
#define QC_CODEC_MAX_FIELD 65535

/* Largest single message this unit will ever size (M1 with maxed fields).
 * Length helpers return 0 for inputs beyond cap/total (0 is never a valid
 * length: smallest real message is 65 B). Callers treat 0 as reject. */
#define QC_CODEC_MAX_MSG (62 + 2 * QC_CODEC_MAX_FIELD)

typedef struct {
    uint8_t version;
    uint8_t identity[QC_ID_LEN];
    uint8_t level;
    const uint8_t *ek;      /* ek_len bytes, caller-owned */
    size_t ek_len;
    const uint8_t *ct_s;    /* ct_len bytes, caller-owned */
    size_t ct_len;
    uint8_t nonce[QC_NONCE_LEN]; /* 4-B epoch + 8-B counter */
    uint8_t hmac[QC_MAC_LEN];    /* over all preceding, filled by caller/HMAC */
} qc_m1_fields;

typedef struct {
    uint8_t version;
    const uint8_t *ct_w;    /* ct_len bytes, caller-owned */
    size_t ct_len;
    uint8_t nonce_s[QC_NS_LEN];
    uint8_t confirm[QC_MAC_LEN];
} qc_m2_fields;

/* Reject codes (fail-closed taxonomy; caller maps to drop/abort). */
typedef enum {
    QC_CODEC_OK = 0,
    QC_CODEC_OVERSIZE,
    QC_CODEC_BAD_VERSION,
    QC_CODEC_VERSION_MISMATCH,
    QC_CODEC_BAD_LENGTH
} qc_codec_rc;

/* Encoded lengths (exact, no padding). */
size_t qc_m1_len(size_t ek_len, size_t ct_len);
size_t qc_m2_len(size_t ct_len);

/* Encode into out (out_len must equal qc_m*_len exactly). */
qc_codec_rc qc_m1_encode(const qc_m1_fields *f, uint8_t *out, size_t out_len);
qc_codec_rc qc_m2_encode(const qc_m2_fields *f, uint8_t *out, size_t out_len);

/* Parse from bytes (borrows pointers into buf; no copy, no alloc).
 * M2 parse additionally requires expected M1 version for mismatch check. */
qc_codec_rc qc_m1_parse(const uint8_t *buf, size_t len, size_t ek_len,
                        size_t ct_len, qc_m1_fields *f);
qc_codec_rc qc_m2_parse(const uint8_t *buf, size_t len, size_t ct_len,
                        uint8_t m1_version, qc_m2_fields *f);

/* Transcript bytes = FULL M1 bytes (including its HMAC tag) || M2-body
 * bytes (M2 without its confirmation MAC). Rationale recorded: each MAC is
 * excluded from its own input (a tag cannot cover itself); M1-HMAC input
 * and transcript input are therefore distinct objects — do not conflate.
 * M2's confirmation transitively covers M1's tag.
 * No trace hooks in this unit: codecs are pure functions of bytes, and
 * every field is observable through round-trip tests (offsets asserted
 * per field). Step visibility here means test vectors, not callbacks. */
size_t qc_transcript_len(size_t m1_len, size_t m2_len);
qc_codec_rc qc_transcript_build(const uint8_t *m1, size_t m1_len,
                                const uint8_t *m2, size_t m2_len,
                                uint8_t *out, size_t out_len);

#endif
