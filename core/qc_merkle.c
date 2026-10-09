/* qc_merkle.c — Merkle batch attestation core (B-24.3).
 * Level-by-level fold, index-bit proof paths. All arithmetic overflow-safe
 * by construction (n bounded by scratch/32 before any multiply; depth
 * counted before any proof write; shifts bounded below).
 */
#include "qc_merkle.h"

#include <string.h>

#include "qc_sha256.h"

/* Hash prefix || body in one streaming pass (no concat buffer). */
static void hash2(const uint8_t *a, size_t alen,
                  const uint8_t *b, size_t blen,
                  uint8_t out[32]) {
    qc_sha256_ctx ctx;

    qc_sha256_init(&ctx);
    if (alen > 0) {
        qc_sha256_update(&ctx, a, alen);
    }
    if (blen > 0) {
        qc_sha256_update(&ctx, b, blen);
    }
    qc_sha256_final(&ctx, out);
}

qc_merkle_rc qc_merkle_leaf(uint8_t cls, uint64_t counter,
                            const uint8_t *reading, size_t reading_len,
                            uint8_t leaf[QC_MERKLE_HASH_LEN]) {
    /* Fixed prefix block: label(9) || cls(1) || counter-BE(8) = 18 B. */
    uint8_t pre[18];
    int i;

    if (leaf == NULL) {
        return QC_MERKLE_BAD_ARG;
    }
    if (reading_len > 0 && reading == NULL) {
        return QC_MERKLE_BAD_ARG;
    }
    memcpy(pre, QC_MERKLE_LABEL_ATTEST, 9);
    pre[9] = cls;
    for (i = 0; i < 8; i++) {
        pre[10 + i] = (uint8_t)(counter >> (8 * (7 - i)));
    }
    hash2(pre, sizeof(pre), reading, reading_len, leaf);
    return QC_MERKLE_OK;
}

/* Fold one level in place: pairs hashed, odd tail promoted. Returns the
 * next-level count. Reads level[0..count), writes level[0..next). */
static size_t fold_level(uint8_t *level, size_t count) {
    size_t i, o = 0;

    for (i = 0; i + 1 < count; i += 2) {
        hash2(level + 32 * i, 32, level + 32 * (i + 1), 32,
              level + 32 * o);
        o++;
    }
    if (count % 2 == 1) {
        memcpy(level + 32 * o, level + 32 * (count - 1), 32);
        o++;
    }
    return o;
}

qc_merkle_rc qc_merkle_root(const uint8_t *leaves, size_t n,
                            uint8_t *scratch, size_t scratch_len,
                            uint8_t root[QC_MERKLE_HASH_LEN]) {
    size_t count;

    if (leaves == NULL || root == NULL) {
        return QC_MERKLE_BAD_ARG;
    }
    if (n == 0) {
        return QC_MERKLE_BAD_ARG;
    }
    /* n*32 cannot overflow: scratch_len (a real buffer size) bounds it
     * (n <= scratch_len/32 < SIZE_MAX/32 whenever the check passes). */
    if (scratch == NULL || scratch_len < n * 32) {
        return QC_MERKLE_BAD_ARG;
    }
    memcpy(scratch, leaves, n * 32);
    count = n;
    while (count > 1) {
        count = fold_level(scratch, count);
    }
    memcpy(root, scratch, 32);
    return QC_MERKLE_OK;
}

size_t qc_merkle_proof_max(size_t n) {
    size_t d = 0;

    /* Ceiling log2: depth of a binary tree over n leaves. n <= 1 needs
     * 0 entries (single leaf IS the root; n == 0 rejected by callers).
     * Bound checked FIRST: ((size_t)1 << 64) would be UB for absurd n
     * (unreachable in practice — n is scratch-bounded — but exact). */
    while (d < 64 && ((size_t)1 << d) < n) {
        d++;
    }
    return d;
}

/* Pass 1 (integers only): count real proof entries for (n, index),
 * skipping promoted levels. A level with `count` nodes promotes its last
 * node iff count is odd and our position is last. */
static size_t count_entries(size_t n, size_t index) {
    size_t count = n, pos = index, depth = 0;

    while (count > 1) {
        if (!(count % 2 == 1 && pos == count - 1)) {
            depth++;
        }
        pos >>= 1;
        count = (count + 1) / 2;
    }
    return depth;
}

qc_merkle_rc qc_merkle_proof(const uint8_t *leaves, size_t n, size_t index,
                             uint8_t *scratch, size_t scratch_len,
                             uint8_t *proof, size_t proof_cap,
                             size_t *depth_out) {
    size_t count, pos, recorded = 0;
    size_t need;

    if (leaves == NULL || proof == NULL || depth_out == NULL) {
        return QC_MERKLE_BAD_ARG;
    }
    if (n == 0 || index >= n) {
        return QC_MERKLE_BAD_ARG;
    }
    if (scratch == NULL || scratch_len < n * 32) {
        return QC_MERKLE_BAD_ARG;
    }
    need = count_entries(n, index);
    if (proof_cap < need) {
        return QC_MERKLE_BAD_ARG;
    }
    /* Pass 2: build levels in scratch, recording siblings. */
    memcpy(scratch, leaves, n * 32);
    count = n;
    pos = index;
    while (count > 1) {
        if (!(count % 2 == 1 && pos == count - 1)) {
            /* Sibling exists: position ^ 1 within this level. */
            size_t sib = pos ^ (size_t)1;
            memcpy(proof + 32 * recorded, scratch + 32 * sib, 32);
            recorded++;
        }
        /* Fold to next level (same order as root: pairs + promote). */
        {
            size_t i, o = 0;
            for (i = 0; i + 1 < count; i += 2) {
                hash2(scratch + 32 * i, 32, scratch + 32 * (i + 1), 32,
                      scratch + 32 * o);
                o++;
            }
            if (count % 2 == 1) {
                memcpy(scratch + 32 * o, scratch + 32 * (count - 1), 32);
                o++;
            }
            count = o;
        }
        pos >>= 1;
    }
    *depth_out = recorded;
    return QC_MERKLE_OK;
}

qc_merkle_rc qc_merkle_verify(const uint8_t leaf[QC_MERKLE_HASH_LEN],
                              size_t n, size_t index,
                              const uint8_t *proof, size_t depth,
                              const uint8_t root[QC_MERKLE_HASH_LEN]) {
    uint8_t acc[32];
    size_t count, pos, used = 0;

    if (leaf == NULL || root == NULL) {
        return QC_MERKLE_BAD_ARG;
    }
    if (n == 0 || index >= n) {
        return QC_MERKLE_BAD_ARG;
    }
    if (depth > 0 && proof == NULL) {
        return QC_MERKLE_BAD_ARG;
    }
    /* Replay the prover's level walk (same skip rule): promoted levels
     * halve the position without consuming an entry; other levels
     * consume one entry, ordered by the running position bit. */
    memcpy(acc, leaf, 32);
    count = n;
    pos = index;
    while (count > 1) {
        if (!(count % 2 == 1 && pos == count - 1)) {
            uint8_t step[64];
            if (used >= depth) {
                return QC_MERKLE_BAD_ARG;
            }
            if (pos & (size_t)1) {
                memcpy(step, proof + 32 * used, 32);
                memcpy(step + 32, acc, 32);
            } else {
                memcpy(step, acc, 32);
                memcpy(step + 32, proof + 32 * used, 32);
            }
            hash2(step, 64, NULL, 0, acc);
            used++;
        }
        pos >>= 1;
        count = (count + 1) / 2;
    }
    if (used != depth) {
        return QC_MERKLE_BAD_ARG;
    }
    {
        uint8_t diff = 0;
        size_t i;
        for (i = 0; i < 32; i++) {
            diff |= (uint8_t)(acc[i] ^ root[i]);
        }
        return diff == 0 ? QC_MERKLE_OK : QC_MERKLE_BAD_ARG;
    }
}
