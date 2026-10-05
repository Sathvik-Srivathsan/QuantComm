/* qc_sha256.h — SHA-256, FIPS 180-4.
 * Contract: one-shot qc_sha256(msg, len, out32). Streaming via init/update/final.
 * Deterministic: no RNG, no time, no heap. All state caller-owned.
 * Trace hook (L1 step visibility): if qc_sha256_trace != NULL, it is called
 * once per compression with (block[64], state_in[8], state_out[8], verbose_rounds).
 * Production builds leave it NULL (zero cost: single predictable branch).
 */
#ifndef QC_SHA256_H
#define QC_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define QC_SHA256_DIGEST_LEN 32
#define QC_SHA256_BLOCK_LEN 64

typedef struct {
    uint32_t h[8];
    uint64_t total_len;
    uint8_t buf[QC_SHA256_BLOCK_LEN];
    size_t buf_used;
} qc_sha256_ctx;

/* Optional per-compression trace callback. NULL disables. rounds!=0 also
 * dumps all 64 working-variable states (verbose; test/debug only). */
typedef void (*qc_sha256_trace_fn)(const uint8_t block[64],
                                   const uint32_t state_in[8],
                                   const uint32_t state_out[8]);

extern qc_sha256_trace_fn qc_sha256_trace;

void qc_sha256_init(qc_sha256_ctx *ctx);
void qc_sha256_update(qc_sha256_ctx *ctx, const uint8_t *msg, size_t len);
void qc_sha256_final(qc_sha256_ctx *ctx, uint8_t out[QC_SHA256_DIGEST_LEN]);

static inline void qc_sha256(const uint8_t *msg, size_t len,
                             uint8_t out[QC_SHA256_DIGEST_LEN]) {
    qc_sha256_ctx ctx;
    qc_sha256_init(&ctx);
    qc_sha256_update(&ctx, msg, len);
    qc_sha256_final(&ctx, out);
}

#endif
